package xmtp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/pushpolicy"
	topicutil "github.com/xmtp/example-notification-server-go/pkg/topics"
	"github.com/xmtp/xmtpd/pkg/envelopes"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	"github.com/xmtp/xmtpd/pkg/topic"
)

type exactWelcomeSubscriptions struct {
	expectedDigest []byte
	routes         []interfaces.WelcomeSubscription
	err            error
	consumed       bool
	calls          int
}

type welcomeRecordingDelivery struct {
	requests []interfaces.SendRequest
}

func (d *welcomeRecordingDelivery) CanDeliver(interfaces.SendRequest) bool {
	return true
}

func (d *welcomeRecordingDelivery) Send(
	ctx context.Context,
	request interfaces.SendRequest,
) error {
	if !pushpolicy.AllowsDelivery(ctx, request) {
		return pushpolicy.ErrUnauthorized
	}
	d.requests = append(d.requests, request)
	return nil
}

func (s *exactWelcomeSubscriptions) Subscribe(
	context.Context,
	string,
	[]*topic.Topic,
) error {
	return nil
}

func (s *exactWelcomeSubscriptions) Unsubscribe(
	context.Context,
	string,
	[]*topic.Topic,
) error {
	return nil
}

func (s *exactWelcomeSubscriptions) GetSubscriptions(
	context.Context,
	*topic.Topic,
	int,
) ([]interfaces.Subscription, error) {
	return nil, nil
}

func (s *exactWelcomeSubscriptions) SubscribeWithMetadata(
	context.Context,
	string,
	[]interfaces.SubscriptionInput,
) error {
	return nil
}

func (s *exactWelcomeSubscriptions) GetWelcomeSubscriptions(
	_ context.Context,
	_ *topic.Topic,
	outerEnvelopeDigest []byte,
) ([]interfaces.WelcomeSubscription, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if s.consumed || !bytes.Equal(outerEnvelopeDigest, s.expectedDigest) {
		return nil, nil
	}
	s.consumed = true
	return s.routes, nil
}

func welcomeRoute(targetTopic *topic.Topic) interfaces.WelcomeSubscription {
	return interfaces.WelcomeSubscription{
		Installation: interfaces.Installation{
			Id: "opaque-lease",
			DeliveryMechanism: interfaces.DeliveryMechanism{
				Kind:  interfaces.APNS,
				Token: "opaque-token",
			},
			PayloadFormat: interfaces.PayloadFormatV3,
		},
		Subscription: interfaces.Subscription{
			InstallationId: "opaque-lease",
			Topic:          topicutil.TopicToString(targetTopic),
			TopicV4:        targetTopic,
			IsActive:       true,
			IsSilent:       true,
			SecureRoute: &interfaces.SecureRoute{
				WelcomeAuthorized: true,
				LeaseExpiresAt:    time.Now().Add(time.Minute),
				ControlExpiresAt:  time.Now().Add(time.Minute),
			},
		},
	}
}

func TestV3WelcomeAuthorizationBeforeStreamRoutesExactlyOnce(t *testing.T) {
	targetTopic := topic.NewTopic(
		topic.TopicKindWelcomeMessagesV1,
		bytes.Repeat([]byte{0x31}, 16),
	)
	envelope := &v1.Envelope{
		ContentTopic: topicutil.TopicToString(targetTopic),
		Message:      []byte("encrypted-welcome"),
		TimestampNs:  uint64(time.Now().UnixNano()),
	}
	digest, err := V3WelcomeEnvelopeDigest(targetTopic, envelope.Message)
	require.NoError(t, err)
	subscriptions := &exactWelcomeSubscriptions{
		expectedDigest: digest[:],
		routes:         []interfaces.WelcomeSubscription{welcomeRoute(targetTopic)},
	}
	delivery := &welcomeRecordingDelivery{}
	listener := &Listener{
		ctx:           t.Context(),
		subscriptions: subscriptions,
		dispatcher: newDeliveryDispatcher(
			t.Context(),
			[]interfaces.Delivery{delivery},
		),
	}

	require.NoError(t, listener.processEnvelope(envelope))
	require.NoError(t, listener.processEnvelope(envelope))
	require.Len(t, delivery.requests, 1)
	require.Nil(t, delivery.requests[0].MessageContext.HmacInputs)
	require.Nil(t, delivery.requests[0].MessageContext.SenderHmac)
	require.True(
		t,
		delivery.requests[0].Subscription.SecureRoute.WelcomeAuthorized,
	)
	require.True(t, delivery.requests[0].Subscription.IsSilent)
}

func TestV3WelcomeHostileMismatchAndStoreAmbiguityDeliverNothing(t *testing.T) {
	targetTopic := topic.NewTopic(
		topic.TopicKindWelcomeMessagesV1,
		bytes.Repeat([]byte{0x32}, 16),
	)
	envelope := &v1.Envelope{
		ContentTopic: topicutil.TopicToString(targetTopic),
		Message:      []byte("hostile-welcome"),
	}
	mismatch := sha256.Sum256([]byte("different-envelope"))
	subscriptions := &exactWelcomeSubscriptions{
		expectedDigest: mismatch[:],
		routes:         []interfaces.WelcomeSubscription{welcomeRoute(targetTopic)},
	}
	delivery := &welcomeRecordingDelivery{}
	listener := &Listener{
		ctx:           t.Context(),
		subscriptions: subscriptions,
		dispatcher: newDeliveryDispatcher(
			t.Context(),
			[]interfaces.Delivery{delivery},
		),
	}
	require.NoError(t, listener.processEnvelope(envelope))
	require.Empty(t, delivery.requests)

	subscriptions.err = errors.New("ambiguous database state")
	require.Error(t, listener.processEnvelope(envelope))
	require.Empty(t, delivery.requests)
}

func TestV4WelcomeAuthorizationUsesRawOriginatorEnvelopeAndRoutesOnce(t *testing.T) {
	installationKeyID := bytes.Repeat([]byte{0x41}, 16)
	envelope := buildWelcomeMessageOriginatorEnvelope(
		t,
		7,
		11,
		time.Now().UnixNano(),
		installationKeyID,
		[]byte("encrypted-v4-welcome"),
	)
	parsed, err := envelopes.NewOriginatorEnvelope(envelope)
	require.NoError(t, err)
	rawEnvelope, err := parsed.Bytes()
	require.NoError(t, err)
	targetTopic := topic.NewTopic(
		topic.TopicKindWelcomeMessagesV1,
		installationKeyID,
	)
	digest, err := V4WelcomeEnvelopeDigest(targetTopic, rawEnvelope)
	require.NoError(t, err)
	subscriptions := &exactWelcomeSubscriptions{
		expectedDigest: digest[:],
		routes:         []interfaces.WelcomeSubscription{welcomeRoute(targetTopic)},
	}
	delivery := &welcomeRecordingDelivery{}
	listener := &V4Listener{
		ctx:           t.Context(),
		subscriptions: subscriptions,
		dispatcher: newDeliveryDispatcher(
			t.Context(),
			[]interfaces.Delivery{delivery},
		),
	}

	require.NoError(t, listener.processOriginatorEnvelope(envelope))
	require.NoError(t, listener.processOriginatorEnvelope(envelope))
	require.Len(t, delivery.requests, 1)
	require.Equal(
		t,
		topicutil.V3Welcome,
		delivery.requests[0].MessageContext.MessageType,
	)
	require.Nil(t, delivery.requests[0].MessageContext.HmacInputs)
	require.Nil(t, delivery.requests[0].MessageContext.SenderHmac)
}

func TestWelcomeEnvelopeDigestWireOrder(t *testing.T) {
	targetTopic := topic.NewTopic(
		topic.TopicKindWelcomeMessagesV1,
		bytes.Repeat([]byte{0x51}, 16),
	)
	envelope := []byte("outer-envelope")
	v3Digest, err := V3WelcomeEnvelopeDigest(targetTopic, envelope)
	require.NoError(t, err)
	require.Equal(
		t,
		"0151515151515151515151515151515151",
		hex.EncodeToString(targetTopic.Bytes()),
	)
	require.Equal(
		t,
		"5446092e148d7c48643e2bf60bd95964a4a6bf54aecd129e0bb21b09939c0e97",
		hex.EncodeToString(v3Digest[:]),
	)
	expectedV3 := sha256.New()
	_, _ = expectedV3.Write([]byte(v3WelcomeDigestDomain))
	_, _ = expectedV3.Write(targetTopic.Bytes())
	_, _ = expectedV3.Write(envelope)
	require.Equal(t, expectedV3.Sum(nil), v3Digest[:])

	v4Digest, err := V4WelcomeEnvelopeDigest(targetTopic, envelope)
	require.NoError(t, err)
	require.Equal(
		t,
		"cf2341d0f8b3e9d83e639aa375cd7e98285a3ae8d601ac84085c9f40f50b420a",
		hex.EncodeToString(v4Digest[:]),
	)
	expectedV4 := sha256.New()
	_, _ = expectedV4.Write([]byte(v4WelcomeDigestDomain))
	_, _ = expectedV4.Write(targetTopic.Bytes())
	_, _ = expectedV4.Write(envelope)
	require.Equal(t, expectedV4.Sum(nil), v4Digest[:])
	require.NotEqual(t, v3Digest, v4Digest)
}
