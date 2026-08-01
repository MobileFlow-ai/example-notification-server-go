package delivery

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/sideshow/apns2"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
)

const (
	maxAPNSPayloadBytes = 4096
	genericAlertText    = "New message"
)

var (
	ErrSecurePayloadInvalid  = errors.New("secure APNS payload invalid")
	ErrSecurePayloadTooLarge = errors.New("secure APNS payload too large")
)

type secureAPNSAPS struct {
	Alert            string `json:"alert,omitempty"`
	ContentAvailable int    `json:"content-available,omitempty"`
	MutableContent   int    `json:"mutable-content,omitempty"`
}

type secureAPNSWrapper struct {
	Header     json.RawMessage `json:"header"`
	Ciphertext string          `json:"ciphertext"`
}

type secureAPNSPayload struct {
	APS     secureAPNSAPS     `json:"aps"`
	Wrapper secureAPNSWrapper `json:"hytch_wrapper"`
}

func (a ApnsDelivery) buildSecureNotification(
	req interfaces.SendRequest,
) (*apns2.Notification, error) {
	route := req.Subscription.SecureRoute
	if route == nil ||
		len(route.RouteKey) != gate8wrapper.RouteKeySize ||
		len(route.RouteAlias) != gate8wrapper.RouteAliasSize ||
		route.AliasDay == "" ||
		len(route.ReceiveCapability) == 0 ||
		route.RouteKeyEpoch == 0 ||
		req.Subscription.TopicV4 == nil ||
		req.Installation.DeliveryMechanism.Token == "" {
		return nil, ErrSecurePayloadInvalid
	}

	now := time.Now().UTC()
	if a.now != nil {
		now = a.now().UTC()
	}
	if !now.Before(route.LeaseExpiresAt) ||
		!now.Before(route.ControlExpiresAt) ||
		(route.A9 != nil &&
			!now.Before(route.A9.AssertionExpiresAt)) ||
		gate8wrapper.UTCDay(now) != route.AliasDay {
		return nil, ErrSecurePayloadInvalid
	}
	if route.A9 != nil &&
		(req.MessageContext.MessageType != topics.V3Conversation ||
			route.A9.SubscriptionGeneration == 0 ||
			route.A9.SubscriptionGeneration >
				gate8wrapper.MaxCanonicalInteger ||
			route.A9.BindingVersion == 0 ||
			route.A9.BindingVersion > gate8wrapper.MaxCanonicalInteger ||
			route.A9.AssertionStreamSequence == 0 ||
			route.A9.AssertionStreamSequence >
				gate8wrapper.MaxCanonicalInteger ||
			route.A9.TopicKeyEpoch == 0 ||
			route.A9.RouteKeyEpoch != route.RouteKeyEpoch ||
			route.A9.KeysetSequence == 0 ||
			route.A9.KeysetSequence > gate8wrapper.MaxCanonicalInteger ||
			route.A9.WatermarkSequence == 0 ||
			route.A9.WatermarkSequence >
				gate8wrapper.MaxCanonicalInteger) {
		return nil, ErrSecurePayloadInvalid
	}

	environment := gate8wrapper.Environment(a.opts.SecureEnvironment)
	if environment == "" {
		environment = gate8wrapper.EnvironmentDev
	}
	var noncePrefix [gate8wrapper.NoncePrefixSize]byte
	binary.BigEndian.PutUint32(noncePrefix[:], route.NoncePrefix)
	aliasDay := route.AliasDay
	topicBytes := req.Subscription.TopicV4.Bytes()
	if route.A9 != nil && len(topicBytes) != 33 {
		return nil, ErrSecurePayloadInvalid
	}
	expectedAlias, err := gate8wrapper.DeriveRouteAlias(
		route.RouteKey,
		topicBytes,
		environment,
		aliasDay,
	)
	if err != nil {
		return nil, ErrSecurePayloadInvalid
	}
	var alias gate8wrapper.RouteAlias
	copy(alias[:], route.RouteAlias)
	if alias != expectedAlias {
		return nil, ErrSecurePayloadInvalid
	}
	header := gate8wrapper.Header{
		SchemaVersion:    gate8wrapper.SchemaVersion,
		Environment:      environment,
		AliasDay:         aliasDay,
		RouteAlias:       alias,
		RouteKeyEpoch:    route.RouteKeyEpoch,
		NoncePrefix:      noncePrefix,
		DeliverySequence: route.DeliverySequence,
	}
	headerAAD, err := header.CanonicalAAD()
	if err != nil {
		return nil, ErrSecurePayloadInvalid
	}

	silent := req.MessageContext.MessageType == topics.V3Welcome
	if silent != req.Subscription.IsSilent {
		return nil, ErrSecurePayloadInvalid
	}
	fits := func(estimate gate8wrapper.SizeEstimate) bool {
		encodedLength := base64.RawURLEncoding.EncodedLen(
			estimate.SealedCiphertextBytes,
		)
		candidate, marshalErr := marshalSecurePayload(
			headerAAD,
			strings.Repeat("A", encodedLength),
			silent,
		)
		return marshalErr == nil && len(candidate) < maxAPNSPayloadBytes
	}
	randomSource := a.random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	inlinePadding, err := boundedRandomPadding(randomSource, 127)
	if err != nil {
		return nil, ErrSecurePayloadInvalid
	}
	foregroundPadding, err := boundedRandomPadding(randomSource, 127)
	if err != nil {
		return nil, ErrSecurePayloadInvalid
	}
	wrapped, err := gate8wrapper.Seal(gate8wrapper.SealRequest{
		RouteKey:          route.RouteKey,
		Topic:             topicBytes,
		Environment:       environment,
		AliasDay:          aliasDay,
		RouteKeyEpoch:     route.RouteKeyEpoch,
		NoncePrefix:       noncePrefix,
		DeliverySequence:  route.DeliverySequence,
		Capability:        route.ReceiveCapability,
		XMTPEnvelope:      req.EncryptedMessage,
		InlinePadding:     inlinePadding,
		ForegroundPadding: foregroundPadding,
		FitsWrapper:       fits,
	})
	if err != nil {
		if errors.Is(err, gate8wrapper.ErrPayloadTooLarge) ||
			errors.Is(err, gate8wrapper.ErrSizeLimit) {
			return nil, ErrSecurePayloadTooLarge
		}
		return nil, ErrSecurePayloadInvalid
	}
	actualAAD, err := wrapped.Header.CanonicalAAD()
	if err != nil || !equalPayloadBytes(actualAAD, headerAAD) {
		return nil, ErrSecurePayloadInvalid
	}
	payloadBytes, err := marshalSecurePayload(
		actualAAD,
		base64.RawURLEncoding.EncodeToString(wrapped.Ciphertext),
		silent,
	)
	if err != nil || len(payloadBytes) >= maxAPNSPayloadBytes {
		return nil, ErrSecurePayloadTooLarge
	}

	pushType := apns2.PushTypeAlert
	priority := apns2.PriorityHigh
	if silent {
		pushType = apns2.PushTypeBackground
		priority = apns2.PriorityLow
	}
	expiry := earliestTime(
		route.LeaseExpiresAt,
		route.ControlExpiresAt,
		now.Add(15*time.Minute),
	)
	if route.A9 != nil {
		expiry = earliestTime(expiry, route.A9.AssertionExpiresAt)
	}
	return &apns2.Notification{
		DeviceToken: req.Installation.DeliveryMechanism.Token,
		Topic:       a.opts.Topic,
		Payload:     json.RawMessage(payloadBytes),
		PushType:    pushType,
		Priority:    priority,
		Expiration:  expiry,
	}, nil
}

func boundedRandomPadding(source io.Reader, maximum int) ([]byte, error) {
	if source == nil || maximum < 0 || maximum > gate8wrapper.MaxPaddingBytes {
		return nil, ErrSecurePayloadInvalid
	}
	var selector [1]byte
	if _, err := io.ReadFull(source, selector[:]); err != nil {
		return nil, ErrSecurePayloadInvalid
	}
	length := int(selector[0]) % (maximum + 1)
	padding := make([]byte, length)
	if _, err := io.ReadFull(source, padding); err != nil {
		return nil, ErrSecurePayloadInvalid
	}
	return padding, nil
}

func marshalSecurePayload(
	header json.RawMessage,
	ciphertext string,
	silent bool,
) ([]byte, error) {
	aps := secureAPNSAPS{
		Alert:          genericAlertText,
		MutableContent: 1,
	}
	if silent {
		aps = secureAPNSAPS{ContentAvailable: 1}
	}
	return json.Marshal(secureAPNSPayload{
		APS: aps,
		Wrapper: secureAPNSWrapper{
			Header:     header,
			Ciphertext: ciphertext,
		},
	})
}

func earliestTime(values ...time.Time) time.Time {
	var earliest time.Time
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		if earliest.IsZero() || value.Before(earliest) {
			earliest = value
		}
	}
	return earliest
}

func equalPayloadBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
