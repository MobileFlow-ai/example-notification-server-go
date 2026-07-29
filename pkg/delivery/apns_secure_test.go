package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/sideshow/apns2"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
)

type decodedSecurePayload struct {
	APS     map[string]any `json:"aps"`
	Wrapper struct {
		Header     json.RawMessage `json:"header"`
		Ciphertext string          `json:"ciphertext"`
	} `json:"hytch_wrapper"`
}

func secureDeliveryFixture(
	t *testing.T,
) (ApnsDelivery, interfaces.SendRequest, time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 26, 15, 30, 0, 0, time.UTC)
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)
	req.IdempotencyKey = "opaque-idempotency-key"
	routeKey := bytes.Repeat([]byte{2}, gate8wrapper.RouteKeySize)
	aliasDay := gate8wrapper.UTCDay(now)
	routeAlias, err := gate8wrapper.DeriveRouteAlias(
		routeKey,
		req.Subscription.TopicV4.Bytes(),
		gate8wrapper.EnvironmentDev,
		aliasDay,
	)
	require.NoError(t, err)
	req.Subscription.SecureRoute = &interfaces.SecureRoute{
		LeaseID:           bytes.Repeat([]byte{1}, 16),
		RouteKey:          routeKey,
		RouteKeyEpoch:     3,
		NoncePrefix:       0x01020304,
		DeliverySequence:  8,
		AliasDay:          aliasDay,
		RouteAlias:        append([]byte(nil), routeAlias[:]...),
		ReceiveCapability: []byte(`{"signed":"capability"}`),
		LeaseExpiresAt:    now.Add(7 * 24 * time.Hour),
		ControlExpiresAt:  now.Add(45 * time.Second),
		PolicyEpoch:       9,
	}
	delivery := ApnsDelivery{
		opts: options.ApnsOptions{
			Topic:                 "com.example.app.dev",
			SecureWrapperRequired: true,
			SecureEnvironment:     "dev",
		},
		now: func() time.Time { return now },
	}
	return delivery, req, now
}

func decodeSecureNotification(
	t *testing.T,
	notification *apns2.Notification,
) (decodedSecurePayload, gate8wrapper.Envelope) {
	t.Helper()
	payloadBytes, ok := notification.Payload.(json.RawMessage)
	require.True(t, ok)
	require.Less(t, len(payloadBytes), maxAPNSPayloadBytes)

	var decoded decodedSecurePayload
	require.NoError(t, json.Unmarshal(payloadBytes, &decoded))
	header, err := gate8wrapper.ParseCanonicalAAD(decoded.Wrapper.Header)
	require.NoError(t, err)
	ciphertext, err := base64.RawURLEncoding.DecodeString(decoded.Wrapper.Ciphertext)
	require.NoError(t, err)
	return decoded, gate8wrapper.Envelope{
		Header:     header,
		Ciphertext: ciphertext,
	}
}

func TestSecureAPNSPayloadContainsOnlyAliasWrapperAndGenericAlert(t *testing.T) {
	delivery, req, now := secureDeliveryFixture(t)
	notification, err := delivery.buildNotification(req)
	require.NoError(t, err)
	require.Equal(t, apns2.PushTypeAlert, notification.PushType)
	require.Equal(t, apns2.PriorityHigh, notification.Priority)
	require.Equal(t, now.Add(45*time.Second), notification.Expiration)

	decoded, wrapped := decodeSecureNotification(t, notification)
	require.Equal(t, genericAlertText, decoded.APS["alert"])
	require.Equal(t, float64(1), decoded.APS["mutable-content"])
	require.NotContains(t, decoded.APS, "content-available")

	payloadBytes := []byte(notification.Payload.(json.RawMessage))
	topicDigest := sha256Hex(req.Subscription.TopicV4.Bytes())
	for _, forbidden := range [][]byte{
		[]byte(req.Topic),
		[]byte(req.TopicBytesB64),
		[]byte(topicDigest),
		[]byte(req.Installation.Id),
		[]byte(req.Installation.DeliveryMechanism.Token),
		[]byte(string(req.MessageContext.MessageType)),
		[]byte(req.PayloadFormat.String()),
		req.Subscription.SecureRoute.ReceiveCapability,
	} {
		if len(forbidden) > 0 {
			require.NotContains(t, payloadBytes, forbidden)
		}
	}

	opened, err := gate8wrapper.Open(gate8wrapper.OpenRequest{
		RouteKey:              req.Subscription.SecureRoute.RouteKey,
		Topic:                 req.Subscription.TopicV4.Bytes(),
		ExpectedEnvironment:   gate8wrapper.EnvironmentDev,
		ExpectedAliasDay:      gate8wrapper.UTCDay(now),
		ExpectedRouteKeyEpoch: req.Subscription.SecureRoute.RouteKeyEpoch,
		Envelope:              wrapped,
		Replay:                &gate8wrapper.ReplayWindow{},
	})
	require.NoError(t, err)
	require.Equal(t, gate8wrapper.ModeCiphertextInline, opened.DeliveryMode)
	require.Equal(t, req.EncryptedMessage, opened.XMTPEnvelope)
	require.Equal(t, req.Subscription.SecureRoute.ReceiveCapability, opened.Capability)
}

func TestSecureAPNSCompactWelcomeRegression(t *testing.T) {
	delivery, req, now := secureDeliveryFixture(t)
	req.MessageContext = interfaces.MessageContext{MessageType: topics.V3Welcome}
	req.Subscription.IsSilent = true
	req.Subscription.SecureRoute.WelcomeAuthorized = true
	req.EncryptedMessage = bytes.Repeat([]byte{0x5a}, 8192)

	notification, err := delivery.buildNotification(req)
	require.NoError(t, err)
	require.Equal(t, apns2.PushTypeBackground, notification.PushType)
	require.Equal(t, apns2.PriorityLow, notification.Priority)
	decoded, wrapped := decodeSecureNotification(t, notification)
	require.Equal(t, float64(1), decoded.APS["content-available"])
	require.NotContains(t, decoded.APS, "alert")
	require.NotContains(t, decoded.APS, "mutable-content")

	opened, err := gate8wrapper.Open(gate8wrapper.OpenRequest{
		RouteKey:              req.Subscription.SecureRoute.RouteKey,
		Topic:                 req.Subscription.TopicV4.Bytes(),
		ExpectedEnvironment:   gate8wrapper.EnvironmentDev,
		ExpectedAliasDay:      gate8wrapper.UTCDay(now),
		ExpectedRouteKeyEpoch: req.Subscription.SecureRoute.RouteKeyEpoch,
		Envelope:              wrapped,
		Replay:                &gate8wrapper.ReplayWindow{},
	})
	require.NoError(t, err)
	require.Equal(t, gate8wrapper.ModeForegroundSync, opened.DeliveryMode)
	require.Empty(t, opened.XMTPEnvelope)
}

func TestSecureAPNSFailsClosedWithoutRouteOrFreshControl(t *testing.T) {
	delivery, req, now := secureDeliveryFixture(t)
	req.Subscription.SecureRoute = nil
	_, err := delivery.buildNotification(req)
	require.ErrorIs(t, err, ErrSecurePayloadInvalid)

	_, req, _ = secureDeliveryFixture(t)
	req.Subscription.SecureRoute.ControlExpiresAt = now
	_, err = delivery.buildNotification(req)
	require.ErrorIs(t, err, ErrSecurePayloadInvalid)
}

func TestSecureAPNSFailsClosedAcrossUTCDayBoundary(t *testing.T) {
	delivery, req, now := secureDeliveryFixture(t)
	req.Subscription.SecureRoute.LeaseExpiresAt = now.Add(24 * time.Hour)
	req.Subscription.SecureRoute.ControlExpiresAt = now.Add(24 * time.Hour)
	delivery.now = func() time.Time {
		return now.Add(24 * time.Hour)
	}

	_, err := delivery.buildNotification(req)
	require.ErrorIs(t, err, ErrSecurePayloadInvalid)
}

func sha256Hex(value []byte) string {
	sum := sha256Sum(value)
	return hex.EncodeToString(sum[:])
}

func sha256Sum(value []byte) [32]byte {
	// Kept in a helper so the leak assertion is visually separate from the
	// production derivation under test.
	return sha256.Sum256(value)
}
