package xmtp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/installations"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/subscriptions"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	topicutil "github.com/xmtp/example-notification-server-go/pkg/topics"
	mlsV1 "github.com/xmtp/xmtpd/pkg/proto/mls/api/v1"
	envelopesProto "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/envelopes"
	testEnvelopes "github.com/xmtp/xmtpd/pkg/testutils/envelopes"
	"github.com/xmtp/xmtpd/pkg/topic"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/proto"
)

func TestV4Listener_NewAndStop(t *testing.T) {
	logger := testutils.TestLogger(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	db := testutils.CreateTestDb(t)
	instSvc := installations.NewInstallationsService(logger, db)
	subsSvc := subscriptions.NewSubscriptionsService(logger, db)
	mockDelivery := mocks.NewDelivery(t)

	l, err := NewV4Listener(ctx, logger, options.XmtpOptions{
		ListenerEnabled: true,
		GrpcAddress:     "localhost:5556",
		NumWorkers:      5,
	}, instSvc, subsSvc, []interfaces.Delivery{mockDelivery}, "test", "test")
	require.NoError(t, err)
	require.NotNil(t, l)
	l.Stop()
}

// buildV4TestListener creates a V4Listener with real DB services and mock delivery.
func buildV4TestListener(t *testing.T, deliveryService interfaces.Delivery) *V4Listener {
	t.Helper()
	logger := testutils.TestLogger(t)
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	instSvc := installations.NewInstallationsService(logger, db)
	subsSvc := subscriptions.NewSubscriptionsService(logger, db)

	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)

	namedLogger := logger.Named("xmtp-v4-listener")
	return &V4Listener{
		ctx:             ctx,
		cancelFunc:      cancel,
		logger:          namedLogger,
		opts:            options.XmtpOptions{NumWorkers: 5},
		envelopeChannel: make(chan *envelopesProto.OriginatorEnvelope, 100),
		installations:   instSvc,
		subscriptions:   subsSvc,
		dispatcher: newDeliveryDispatcher(
			ctx,
			[]interfaces.Delivery{deliveryService},
		),
	}
}

// registerV4Installation registers an installation with the given payload format.
func registerV4Installation(t *testing.T, l *V4Listener, installationID string, format interfaces.PayloadFormat) {
	t.Helper()
	_, err := l.installations.Register(t.Context(), interfaces.Installation{
		Id: installationID,
		DeliveryMechanism: interfaces.DeliveryMechanism{
			Kind:  interfaces.APNS,
			Token: "test-token",
		},
		PayloadFormat: format,
	})
	require.NoError(t, err)
}

// subscribeV4ToTopic subscribes the given installation to a topic.
func subscribeV4ToTopic(t *testing.T, l *V4Listener, installationID string, tp *topic.Topic, hmacKeys ...interfaces.HmacKey) {
	t.Helper()
	if len(hmacKeys) == 0 && tp.Kind() == topic.TopicKindGroupMessagesV1 {
		hmacKeys = []interfaces.HmacKey{{
			ThirtyDayPeriodsSinceEpoch: 0,
			Key:                        testHmacKey(0x11),
		}}
	}
	input := interfaces.SubscriptionInput{Topic: tp, HmacKeys: hmacKeys}
	err := l.subscriptions.SubscribeWithMetadata(t.Context(), installationID, []interfaces.SubscriptionInput{input})
	require.NoError(t, err)
}

// buildGroupMessageOriginatorEnvelope creates an OriginatorEnvelope containing a GroupMessageInput.
func buildGroupMessageOriginatorEnvelope(
	t *testing.T,
	nodeID uint32,
	sequenceID uint64,
	timestampNs int64,
	groupID []byte,
	data []byte,
	senderHmac []byte,
	shouldPush bool,
) *envelopesProto.OriginatorEnvelope {
	t.Helper()
	if senderHmac == nil {
		senderHmac = testSenderHmac(testHmacKey(0x22), data)
	}

	groupInput := &mlsV1.GroupMessageInput{
		Version: &mlsV1.GroupMessageInput_V1_{
			V1: &mlsV1.GroupMessageInput_V1{
				Data:       data,
				SenderHmac: senderHmac,
				ShouldPush: shouldPush,
			},
		},
	}

	clientEnv := &envelopesProto.ClientEnvelope{
		Payload: &envelopesProto.ClientEnvelope_GroupMessage{
			GroupMessage: groupInput,
		},
		Aad: &envelopesProto.AuthenticatedData{
			TargetTopic: topic.NewTopic(topic.TopicKindGroupMessagesV1, groupID).Bytes(),
		},
	}

	payerEnv := testEnvelopes.CreatePayerEnvelope(t, nodeID, clientEnv)
	return testEnvelopes.CreateOriginatorEnvelopeWithTimestamp(t, nodeID, sequenceID, time.Unix(0, timestampNs), payerEnv)
}

// buildWelcomeMessageOriginatorEnvelope creates an OriginatorEnvelope containing a WelcomeMessageInput.
func buildWelcomeMessageOriginatorEnvelope(
	t *testing.T,
	nodeID uint32,
	sequenceID uint64,
	timestampNs int64,
	installationKeyID []byte,
	data []byte,
) *envelopesProto.OriginatorEnvelope {
	t.Helper()

	welcomeInput := &mlsV1.WelcomeMessageInput{
		Version: &mlsV1.WelcomeMessageInput_V1_{
			V1: &mlsV1.WelcomeMessageInput_V1{
				InstallationKey: installationKeyID,
				Data:            data,
			},
		},
	}

	clientEnv := &envelopesProto.ClientEnvelope{
		Payload: &envelopesProto.ClientEnvelope_WelcomeMessage{
			WelcomeMessage: welcomeInput,
		},
		Aad: &envelopesProto.AuthenticatedData{
			TargetTopic: topic.NewTopic(topic.TopicKindWelcomeMessagesV1, installationKeyID).Bytes(),
		},
	}

	payerEnv := testEnvelopes.CreatePayerEnvelope(t, nodeID, clientEnv)
	return testEnvelopes.CreateOriginatorEnvelopeWithTimestamp(t, nodeID, sequenceID, time.Unix(0, timestampNs), payerEnv)
}

func TestBuildGroupMessageContext_MissingVersionLeavesShouldPushUnknown(t *testing.T) {
	messageContext := buildGroupMessageContext(nil)

	require.Equal(t, topicutil.V3Conversation, messageContext.MessageType)
	require.Nil(t, messageContext.ShouldPush)
}

// TestV4Listener_ProcessGroupMessage_V3Format tests that a GroupMessageInput envelope is converted
// to V3 format and delivered to a V3 installation.
func TestV4Listener_ProcessGroupMessage_V3Format(t *testing.T) {
	mockDelivery := testutils.MockDeliveryAcceptAll(t)

	l := buildV4TestListener(t, mockDelivery)

	groupID := []byte{0x01, 0x02, 0x03, 0x04}
	groupTopic := topic.NewTopic(topic.TopicKindGroupMessagesV1, groupID)

	registerV4Installation(t, l, "inst-v3", interfaces.PayloadFormatV3)
	subscribeV4ToTopic(t, l, "inst-v3", groupTopic)

	env := buildGroupMessageOriginatorEnvelope(t, 1, 1, int64(time.Second), groupID, []byte("data"), nil, true)
	err := l.processOriginatorEnvelope(env)
	require.NoError(t, err)

	mockDelivery.AssertNumberOfCalls(t, "Send", 1)

	// Verify payload format is V3
	sendReqs := testutils.GetSendRequests(mockDelivery)
	require.Len(t, sendReqs, 1)
	capturedReq := testutils.RequireSendRequestForInstallation(t, sendReqs, "inst-v3")
	require.Equal(t, interfaces.PayloadFormatV3, capturedReq.PayloadFormat)
	require.Equal(t, topicutil.TopicToLegacy(groupTopic), capturedReq.Topic)
	require.NotEmpty(t, capturedReq.EncryptedMessage)
	require.Equal(t, topicutil.V3Conversation, capturedReq.MessageContext.MessageType)

	// Deserialize and verify it's a V3 GroupMessage
	var groupMsg mlsV1.GroupMessage
	require.NoError(t, proto.Unmarshal(capturedReq.EncryptedMessage, &groupMsg))
	require.NotNil(t, groupMsg.GetV1())
	require.Equal(t, groupID, groupMsg.GetV1().GetGroupId())
	require.True(t, groupMsg.GetV1().GetShouldPush())
}

// TestV4Listener_ProcessGroupMessage_V4Format tests that a GroupMessageInput envelope is delivered
// as raw OriginatorEnvelope bytes to a V4 installation.
func TestV4Listener_ProcessGroupMessage_V4Format(t *testing.T) {
	mockDelivery := testutils.MockDeliveryAcceptAll(t)

	l := buildV4TestListener(t, mockDelivery)

	groupID := []byte{0x05, 0x06, 0x07, 0x08}
	groupTopic := topic.NewTopic(topic.TopicKindGroupMessagesV1, groupID)

	registerV4Installation(t, l, "inst-v4", interfaces.PayloadFormatV4)
	subscribeV4ToTopic(t, l, "inst-v4", groupTopic)

	env := buildGroupMessageOriginatorEnvelope(t, 1, 2, int64(time.Second), groupID, []byte("v4-data"), nil, true)
	err := l.processOriginatorEnvelope(env)
	require.NoError(t, err)

	mockDelivery.AssertNumberOfCalls(t, "Send", 1)

	sendReqs := testutils.GetSendRequests(mockDelivery)
	require.Len(t, sendReqs, 1)
	capturedReq := testutils.RequireSendRequestForInstallation(t, sendReqs, "inst-v4")
	require.Equal(t, interfaces.PayloadFormatV4, capturedReq.PayloadFormat)
	require.Equal(t, topicutil.TopicToLegacy(groupTopic), capturedReq.Topic)
	require.Equal(t, topicutil.TopicToBase64(groupTopic), capturedReq.TopicBytesB64)
	require.NotEmpty(t, capturedReq.EncryptedMessage)
	require.Equal(t, topicutil.V3Conversation, capturedReq.MessageContext.MessageType)

	// Verify it's a valid OriginatorEnvelope
	var deliveredEnv envelopesProto.OriginatorEnvelope
	require.NoError(t, proto.Unmarshal(capturedReq.EncryptedMessage, &deliveredEnv))
	require.True(t, proto.Equal(env, &deliveredEnv))
}

// TestV4Listener_ProcessWelcomeMessage_V3Format tests that an uncorrelated
// Welcome fails closed even when its V3 conversion succeeds.
func TestV4Listener_ProcessWelcomeMessage_V3Format(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)

	l := buildV4TestListener(t, mockDelivery)

	installationKeyID := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	welcomeTopic := topic.NewTopic(topic.TopicKindWelcomeMessagesV1, installationKeyID)

	registerV4Installation(t, l, "inst-welcome-v3", interfaces.PayloadFormatV3)
	subscribeV4ToTopic(t, l, "inst-welcome-v3", welcomeTopic)

	env := buildWelcomeMessageOriginatorEnvelope(t, 1, 3, int64(time.Second), installationKeyID, []byte("welcome-data"))
	err := l.processOriginatorEnvelope(env)
	require.NoError(t, err)

	mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
	mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}

// TestV4Listener_ProcessGroupMessage_MixedFormats tests that a GroupMessageInput envelope is
// delivered to both V3 and V4 installations, each with the appropriate format.
func TestV4Listener_ProcessGroupMessage_MixedFormats(t *testing.T) {
	mockDelivery := testutils.MockDeliveryAcceptAll(t)

	l := buildV4TestListener(t, mockDelivery)

	groupID := []byte{0x11, 0x22, 0x33, 0x44}
	groupTopic := topic.NewTopic(topic.TopicKindGroupMessagesV1, groupID)

	registerV4Installation(t, l, "inst-mixed-v3", interfaces.PayloadFormatV3)
	registerV4Installation(t, l, "inst-mixed-v4", interfaces.PayloadFormatV4)
	subscribeV4ToTopic(t, l, "inst-mixed-v3", groupTopic)
	subscribeV4ToTopic(t, l, "inst-mixed-v4", groupTopic)

	env := buildGroupMessageOriginatorEnvelope(t, 1, 4, int64(time.Second), groupID, []byte("mixed-data"), nil, true)
	err := l.processOriginatorEnvelope(env)
	require.NoError(t, err)

	mockDelivery.AssertNumberOfCalls(t, "Send", 2)

	sendReqs := testutils.GetSendRequests(mockDelivery)
	require.Len(t, sendReqs, 2)

	v3Req := testutils.RequireSendRequestForInstallation(t, sendReqs, "inst-mixed-v3")
	require.Equal(t, interfaces.PayloadFormatV3, v3Req.PayloadFormat)
	require.Equal(t, topicutil.TopicToLegacy(groupTopic), v3Req.Topic)

	v4Req := testutils.RequireSendRequestForInstallation(t, sendReqs, "inst-mixed-v4")
	require.Equal(t, interfaces.PayloadFormatV4, v4Req.PayloadFormat)
	require.Equal(t, topicutil.TopicToLegacy(groupTopic), v4Req.Topic)
	require.Equal(t, topicutil.TopicToBase64(groupTopic), v4Req.TopicBytesB64)
}

// TestV4Listener_SkipNonConvertiblePayload_V3Format tests that a non-group/welcome payload
// is skipped for V3 installations (no delivery).
func TestV4Listener_SkipNonConvertiblePayload_V3Format(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)
	// No Send calls expected

	l := buildV4TestListener(t, mockDelivery)

	// Build a payer report envelope targeting a specific topic, then subscribe to that exact topic.
	// We construct the clientEnv inline (matching TestV4Listener_DeliverNonConvertiblePayload_V4Format)
	// to ensure the subscription topic bytes match exactly.
	payerReportTopic := topic.NewTopic(topic.TopicKindPayerReportsV1, []byte{0x00, 0x00, 0x00, 0x01})

	registerV4Installation(t, l, "inst-payer-v3", interfaces.PayloadFormatV3)
	subscribeV4ToTopic(t, l, "inst-payer-v3", payerReportTopic)

	clientEnv := &envelopesProto.ClientEnvelope{
		Payload: &envelopesProto.ClientEnvelope_PayerReport{
			PayerReport: &envelopesProto.PayerReport{},
		},
		Aad: &envelopesProto.AuthenticatedData{
			TargetTopic: payerReportTopic.Bytes(),
		},
	}
	payerEnv := testEnvelopes.CreatePayerEnvelope(t, 1, clientEnv)
	env := testEnvelopes.CreateOriginatorEnvelopeWithTimestamp(t, 1, 5, time.Unix(0, int64(time.Second)), payerEnv)

	err := l.processOriginatorEnvelope(env)
	require.NoError(t, err)

	mockDelivery.AssertNotCalled(t, "Send")
}

// TestV4Listener_DeliverNonConvertiblePayload_V4Format tests that an unknown
// payload is denied even when a V4 installation could receive its raw bytes.
func TestV4Listener_DeliverNonConvertiblePayload_V4Format(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)

	l := buildV4TestListener(t, mockDelivery)

	payerReportTopic := topic.NewTopic(topic.TopicKindPayerReportsV1, []byte{0x00, 0x00, 0x00, 0x02})

	registerV4Installation(t, l, "inst-payer-v4", interfaces.PayloadFormatV4)
	subscribeV4ToTopic(t, l, "inst-payer-v4", payerReportTopic)

	// Build a payer report envelope targeting this specific topic
	clientEnv := &envelopesProto.ClientEnvelope{
		Payload: &envelopesProto.ClientEnvelope_PayerReport{
			PayerReport: &envelopesProto.PayerReport{},
		},
		Aad: &envelopesProto.AuthenticatedData{
			TargetTopic: payerReportTopic.Bytes(),
		},
	}
	payerEnv := testEnvelopes.CreatePayerEnvelope(t, 1, clientEnv)
	env := testEnvelopes.CreateOriginatorEnvelopeWithTimestamp(t, 1, 6, time.Unix(0, int64(time.Second)), payerEnv)

	err := l.processOriginatorEnvelope(env)
	require.NoError(t, err)

	mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
	mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}

// TestV4Listener_ShouldPushFalse_SkipsDelivery tests that a GroupMessageInput with
// ShouldPush=false results in no delivery.
func TestV4Listener_ShouldPushFalse_SkipsDelivery(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)
	// No Send calls expected

	l := buildV4TestListener(t, mockDelivery)

	groupID := []byte{0x55, 0x66, 0x77, 0x88}
	groupTopic := topic.NewTopic(topic.TopicKindGroupMessagesV1, groupID)

	registerV4Installation(t, l, "inst-nopush-v3", interfaces.PayloadFormatV3)
	subscribeV4ToTopic(t, l, "inst-nopush-v3", groupTopic)

	// ShouldPush = false
	env := buildGroupMessageOriginatorEnvelope(t, 1, 7, int64(time.Second), groupID, []byte("data"), nil, false)
	err := l.processOriginatorEnvelope(env)
	require.NoError(t, err)

	mockDelivery.AssertNotCalled(t, "Send")
}

// TestV4Listener_HmacSelfMessageSuppression verifies that an installation is
// not notified for a message it originated. It makes no sender identity claim.
func TestV4Listener_HmacSelfMessageSuppression(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)
	// No Send calls are expected for the originating installation.

	l := buildV4TestListener(t, mockDelivery)

	groupID := []byte{0x99, 0xAA, 0xBB, 0xCC}
	groupTopic := topic.NewTopic(topic.TopicKindGroupMessagesV1, groupID)

	// Build the installation HMAC key and the protocol's sender_hmac value.
	hmacKey := testHmacKey(0x33)
	messageData := []byte("group-message-data")
	senderHmac := testSenderHmac(hmacKey, messageData)

	// Compute thirty day period
	timestampNs := int64(time.Second)
	thirtyDayPeriod := int(timestampNs / 1_000_000_000 / 60 / 60 / 24 / 30)

	registerV4Installation(t, l, "inst-hmac-v3", interfaces.PayloadFormatV3)
	subscribeV4ToTopic(t, l, "inst-hmac-v3", groupTopic, interfaces.HmacKey{
		ThirtyDayPeriodsSinceEpoch: thirtyDayPeriod,
		Key:                        hmacKey,
	})

	env := buildGroupMessageOriginatorEnvelope(t, 1, 8, timestampNs, groupID, messageData, senderHmac, true)
	err := l.processOriginatorEnvelope(env)
	require.NoError(t, err)

	// This installation originated the message, so delivery is suppressed.
	mockDelivery.AssertNotCalled(t, "Send")
}

func TestV4Listener_PeriodRolloverFailsClosedUntilExactKeyRefresh(t *testing.T) {
	mockDelivery := testutils.MockDeliveryAcceptAll(t)
	l := buildV4TestListener(t, mockDelivery)

	groupID := []byte{0xA9, 0xBA, 0xCB, 0xDC}
	groupTopic := topic.NewTopic(topic.TopicKindGroupMessagesV1, groupID)
	currentPeriod := 21
	timestampNs := int64((time.Duration(currentPeriod)*30*24*time.Hour + time.Second).Nanoseconds())
	subscriberKey := testHmacKey(0x51)
	messageData := []byte("message-from-another-member")
	senderHmac := testSenderHmac(testHmacKey(0x52), messageData)

	registerV4Installation(t, l, "inst-rollover-v3", interfaces.PayloadFormatV3)
	subscribeV4ToTopic(t, l, "inst-rollover-v3", groupTopic, interfaces.HmacKey{
		ThirtyDayPeriodsSinceEpoch: currentPeriod - 1,
		Key:                        subscriberKey,
	})

	env := buildGroupMessageOriginatorEnvelope(
		t,
		1,
		81,
		timestampNs,
		groupID,
		messageData,
		senderHmac,
		true,
	)
	require.NoError(t, l.processOriginatorEnvelope(env))
	mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)

	require.NoError(t, l.subscriptions.SubscribeWithMetadata(
		t.Context(),
		"inst-rollover-v3",
		[]interfaces.SubscriptionInput{{
			Topic: groupTopic,
			HmacKeys: []interfaces.HmacKey{{
				ThirtyDayPeriodsSinceEpoch: currentPeriod,
				Key:                        subscriberKey,
			}},
		}},
	))

	require.NoError(t, l.processOriginatorEnvelope(env))
	mockDelivery.AssertNumberOfCalls(t, "Send", 1)
	sendRequests := testutils.GetSendRequests(mockDelivery)
	require.Len(t, sendRequests, 1)
	require.NotNil(t, sendRequests[0].Subscription.ExpectedHmacKeyPeriod)
	require.Equal(t, currentPeriod, *sendRequests[0].Subscription.ExpectedHmacKeyPeriod)
	require.Equal(t, currentPeriod, sendRequests[0].Subscription.HmacKey.ThirtyDayPeriodsSinceEpoch)
}

// TestV4Listener_ProcessWelcomePointer_V3Format tests that an uncorrelated
// WelcomePointer fails closed.
func TestV4Listener_ProcessWelcomePointer_V3Format(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)

	l := buildV4TestListener(t, mockDelivery)

	installationKeyID := []byte{0xEE, 0xFF, 0x00, 0x11}
	welcomeTopic := topic.NewTopic(topic.TopicKindWelcomeMessagesV1, installationKeyID)

	registerV4Installation(t, l, "inst-wp-v3", interfaces.PayloadFormatV3)
	subscribeV4ToTopic(t, l, "inst-wp-v3", welcomeTopic)

	// Build a WelcomePointer envelope
	wpInput := &mlsV1.WelcomeMessageInput{
		Version: &mlsV1.WelcomeMessageInput_WelcomePointer_{
			WelcomePointer: &mlsV1.WelcomeMessageInput_WelcomePointer{
				InstallationKey: installationKeyID,
				WelcomePointer:  []byte("pointer-data"),
				HpkePublicKey:   []byte("hpke-key"),
			},
		},
	}

	clientEnv := &envelopesProto.ClientEnvelope{
		Payload: &envelopesProto.ClientEnvelope_WelcomeMessage{
			WelcomeMessage: wpInput,
		},
		Aad: &envelopesProto.AuthenticatedData{
			TargetTopic: welcomeTopic.Bytes(),
		},
	}
	payerEnv := testEnvelopes.CreatePayerEnvelope(t, 1, clientEnv)
	env := testEnvelopes.CreateOriginatorEnvelopeWithTimestamp(t, 1, 10, time.Unix(0, int64(time.Second)), payerEnv)

	err := l.processOriginatorEnvelope(env)
	require.NoError(t, err)

	mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
	mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}

// TestV4Listener_NonConvertiblePayload_DoesNotCreateEventLog verifies that
// suppressed envelope timing is not written to operational logs.
func TestV4Listener_NonConvertiblePayload_DoesNotCreateEventLog(t *testing.T) {
	observedCore, logs := observer.New(zap.WarnLevel)
	testLogger := zap.New(observedCore)

	db := testutils.CreateTestDb(t)
	instSvc := installations.NewInstallationsService(testutils.TestLogger(t), db)
	subsSvc := subscriptions.NewSubscriptionsService(testutils.TestLogger(t), db)
	mockDelivery := mocks.NewDelivery(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	l := &V4Listener{
		ctx: ctx, cancelFunc: cancel, logger: testLogger,
		opts:            options.XmtpOptions{NumWorkers: 5},
		envelopeChannel: make(chan *envelopesProto.OriginatorEnvelope, 100),
		installations:   instSvc,
		subscriptions:   subsSvc,
		dispatcher:      deliveryDispatcher{ctx: ctx, deliveryServices: []interfaces.Delivery{mockDelivery}},
	}

	payerReportTopic := topic.NewTopic(topic.TopicKindPayerReportsV1, []byte{0x00, 0x00, 0x00, 0x03})
	registerV4Installation(t, l, "inst-log-test", interfaces.PayloadFormatV3)
	subscribeV4ToTopic(t, l, "inst-log-test", payerReportTopic)

	clientEnv := &envelopesProto.ClientEnvelope{
		Payload: &envelopesProto.ClientEnvelope_PayerReport{PayerReport: &envelopesProto.PayerReport{}},
		Aad:     &envelopesProto.AuthenticatedData{TargetTopic: payerReportTopic.Bytes()},
	}
	payerEnv := testEnvelopes.CreatePayerEnvelope(t, 1, clientEnv)
	env := testEnvelopes.CreateOriginatorEnvelopeWithTimestamp(t, 1, 20, time.Unix(0, int64(time.Second)), payerEnv)

	err := l.processOriginatorEnvelope(env)
	require.NoError(t, err)

	mockDelivery.AssertNotCalled(t, "Send")
	require.Zero(t, logs.Len())
}
