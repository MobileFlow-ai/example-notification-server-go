package pushpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"sync/atomic"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
)

// ErrUnauthorized means a delivery implementation was called without the
// exact, unconsumed authorization issued by AuthorizeDelivery.
var ErrUnauthorized = errors.New("push delivery not authorized")

// AuthorizeDelivery enforces the outer XMTP contract. Conversation delivery
// requires an explicit shouldPush=true. Missing, false, malformed, unknown, and
// Welcome inputs fail closed. Welcome delivery remains closed until supported
// outer data can prove an exact pre-decryption correlation.
func AuthorizeDelivery(
	ctx context.Context,
	req interfaces.SendRequest,
) (context.Context, bool) {
	if !eligible(req) {
		return ctx, false
	}
	return authorize(ctx, req), true
}

// AllowsDelivery is defense in depth for delivery implementations. The
// authorization is bound to every SendRequest field and can be consumed once.
func AllowsDelivery(ctx context.Context, req interfaces.SendRequest) bool {
	if !eligible(req) {
		return false
	}
	return consumeAuthorization(ctx, req)
}

func eligible(req interfaces.SendRequest) bool {
	if isSender(req) {
		return false
	}
	return req.MessageContext.MessageType == topics.V3Conversation &&
		req.MessageContext.ShouldPush != nil &&
		*req.MessageContext.ShouldPush
}

func isSender(req interfaces.SendRequest) bool {
	hmacKey := req.Subscription.HmacKey
	return hmacKey != nil &&
		len(hmacKey.Key) > 0 &&
		req.MessageContext.IsSender(hmacKey.Key)
}

type deliveryAuthorizationKey struct{}

type deliveryAuthorization struct {
	fingerprint [sha256.Size]byte
	consumed    atomic.Bool
}

func authorize(ctx context.Context, req interfaces.SendRequest) context.Context {
	authorization := &deliveryAuthorization{fingerprint: requestFingerprint(req)}
	return context.WithValue(ctx, deliveryAuthorizationKey{}, authorization)
}

func consumeAuthorization(ctx context.Context, req interfaces.SendRequest) bool {
	authorization, ok := ctx.Value(deliveryAuthorizationKey{}).(*deliveryAuthorization)
	if !ok || authorization == nil {
		return false
	}
	if authorization.fingerprint != requestFingerprint(req) {
		return false
	}
	return authorization.consumed.CompareAndSwap(false, true)
}

func requestFingerprint(req interfaces.SendRequest) [sha256.Size]byte {
	digest := sha256.New()

	writeFingerprintField(digest, []byte(req.IdempotencyKey))
	writeFingerprintField(digest, []byte(req.Topic))
	writeFingerprintField(digest, []byte(req.TopicBytesB64))
	writeFingerprintField(digest, req.EncryptedMessage)
	writeFingerprintUint64(digest, uint64(req.PayloadFormat))

	writeFingerprintField(digest, []byte(req.Installation.Id))
	writeFingerprintField(digest, []byte(req.Installation.DeliveryMechanism.Kind))
	writeFingerprintField(digest, []byte(req.Installation.DeliveryMechanism.Token))
	writeFingerprintTime(digest, req.Installation.DeliveryMechanism.UpdatedAt)
	writeFingerprintUint64(digest, uint64(req.Installation.PayloadFormat))

	writeFingerprintInt64(digest, req.Subscription.Id)
	writeFingerprintTime(digest, req.Subscription.CreatedAt)
	writeFingerprintField(digest, []byte(req.Subscription.InstallationId))
	writeFingerprintField(digest, []byte(req.Subscription.Topic))
	if req.Subscription.TopicV4 == nil {
		writeFingerprintBool(digest, false)
	} else {
		writeFingerprintBool(digest, true)
		writeFingerprintField(digest, req.Subscription.TopicV4.Bytes())
	}
	writeFingerprintBool(digest, req.Subscription.IsActive)
	writeFingerprintBool(digest, req.Subscription.IsSilent)
	if req.Subscription.HmacKey == nil {
		writeFingerprintBool(digest, false)
	} else {
		writeFingerprintBool(digest, true)
		writeFingerprintInt64(
			digest,
			int64(req.Subscription.HmacKey.ThirtyDayPeriodsSinceEpoch),
		)
		writeFingerprintField(digest, req.Subscription.HmacKey.Key)
	}

	writeFingerprintField(digest, []byte(req.MessageContext.MessageType))
	writeFingerprintOptionalBool(digest, req.MessageContext.ShouldPush)
	writeFingerprintOptionalBytes(digest, req.MessageContext.HmacInputs)
	writeFingerprintOptionalBytes(digest, req.MessageContext.SenderHmac)

	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], digest.Sum(nil))
	return fingerprint
}

func writeFingerprintOptionalBytes(digest hash.Hash, value *[]byte) {
	if value == nil {
		writeFingerprintBool(digest, false)
		return
	}
	writeFingerprintBool(digest, true)
	writeFingerprintField(digest, *value)
}

func writeFingerprintOptionalBool(digest hash.Hash, value *bool) {
	if value == nil {
		writeFingerprintBool(digest, false)
		return
	}
	writeFingerprintBool(digest, true)
	writeFingerprintBool(digest, *value)
}

func writeFingerprintTime(digest hash.Hash, value time.Time) {
	encoded, err := value.MarshalBinary()
	if err != nil {
		writeFingerprintField(digest, nil)
		return
	}
	writeFingerprintField(digest, encoded)
}

func writeFingerprintUint64(digest hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeFingerprintField(digest, encoded[:])
}

func writeFingerprintInt64(digest hash.Hash, value int64) {
	writeFingerprintUint64(digest, uint64(value))
}

func writeFingerprintField(digest hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(value)
}

func writeFingerprintBool(digest hash.Hash, value bool) {
	if value {
		writeFingerprintField(digest, []byte{1})
		return
	}
	writeFingerprintField(digest, []byte{0})
}
