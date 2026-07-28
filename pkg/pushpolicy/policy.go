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
// requires an explicit shouldPush=true. Welcome delivery requires a silent
// SecureRoute created by the exact, one-use pre-decryption correlator.
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
	switch req.MessageContext.MessageType {
	case topics.V3Welcome:
		route := req.Subscription.SecureRoute
		return route != nil &&
			route.WelcomeAuthorized &&
			req.Subscription.IsActive &&
			req.Subscription.IsSilent &&
			req.MessageContext.ShouldPush == nil &&
			req.MessageContext.HmacInputs == nil &&
			req.MessageContext.SenderHmac == nil
	case topics.V3Conversation:
		// Continue below. The HMAC can prove only that this installation
		// originated the message; it does not reveal or classify any sender.
		// Welcome authorization makes no sender-attribution claim.
	default:
		return false
	}
	if req.MessageContext.ShouldPush == nil || !*req.MessageContext.ShouldPush {
		return false
	}
	if !req.Subscription.IsActive || req.Subscription.IsSilent {
		return false
	}

	hmacKey, valid := exactPeriodHmacKey(req)
	if !valid || !req.MessageContext.HasValidSenderHmac() {
		return false
	}
	return !req.MessageContext.IsSender(hmacKey)
}

func exactPeriodHmacKey(req interfaces.SendRequest) ([]byte, bool) {
	hmacKey := req.Subscription.HmacKey
	expectedPeriod := req.Subscription.ExpectedHmacKeyPeriod
	if hmacKey == nil ||
		expectedPeriod == nil ||
		!hmacKey.IsValid() ||
		hmacKey.ThirtyDayPeriodsSinceEpoch != *expectedPeriod {
		return nil, false
	}
	return hmacKey.Key, true
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
	if req.Subscription.ExpectedHmacKeyPeriod == nil {
		writeFingerprintBool(digest, false)
	} else {
		writeFingerprintBool(digest, true)
		writeFingerprintInt64(digest, int64(*req.Subscription.ExpectedHmacKeyPeriod))
	}
	if req.Subscription.SecureRoute == nil {
		writeFingerprintBool(digest, false)
	} else {
		writeFingerprintBool(digest, true)
		route := req.Subscription.SecureRoute
		writeFingerprintField(digest, route.LeaseID)
		writeFingerprintField(digest, route.RouteKey)
		writeFingerprintUint64(digest, uint64(route.RouteKeyEpoch))
		writeFingerprintUint64(digest, uint64(route.NoncePrefix))
		writeFingerprintUint64(digest, route.DeliverySequence)
		writeFingerprintField(digest, []byte(route.AliasDay))
		writeFingerprintField(digest, route.RouteAlias)
		writeFingerprintField(digest, route.ReceiveCapability)
		writeFingerprintTime(digest, route.LeaseExpiresAt)
		writeFingerprintTime(digest, route.ControlExpiresAt)
		writeFingerprintUint64(digest, route.PolicyEpoch)
		writeFingerprintBool(digest, route.WelcomeAuthorized)
		writeFingerprintField(digest, route.WelcomeAuthorizationID)
		writeFingerprintField(digest, route.WelcomeEnvelopeDigest)
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
