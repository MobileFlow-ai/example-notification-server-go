package xmtp

import (
	"context"
	"errors"
	"sync/atomic"
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
	topics "github.com/xmtp/example-notification-server-go/pkg/topics"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	mlsV1 "github.com/xmtp/xmtpd/pkg/proto/mls/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const (
	XMTP_ADDRESS      = "localhost:5556"
	INSTALLATION_ID   = "test_installation"
	INSTALLATION_ID_2 = "test_installation_2"
	TEST_TOPIC        = "/xmtp/mls/1/w-abcdef0123456789/proto"
	DELIVERY_TOKEN    = "test_token"
)

func buildTestListener(t *testing.T, deliveryService interfaces.Delivery) *Listener {
	t.Helper()
	logger := testutils.TestLogger(t)
	ctx, cancel := context.WithCancel(t.Context())
	opts := options.XmtpOptions{ListenerEnabled: true, GrpcAddress: XMTP_ADDRESS, UseTls: false, NumWorkers: 5}
	db := testutils.CreateTestDb(t)
	installations := installations.NewInstallationsService(logger, db)
	subscriptions := subscriptions.NewSubscriptionsService(logger, db)

	l, err := NewListener(
		ctx,
		logger,
		opts,
		installations,
		subscriptions,
		[]interfaces.Delivery{deliveryService},
		"test",
		"test",
	)
	if err != nil {
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		cancel()
		l.Stop()
	})

	return l
}

func testEnvelope(topic string, message []byte) *v1.Envelope {
	return &v1.Envelope{
		ContentTopic: topic,
		Message:      message,
		TimestampNs:  uint64(time.Now().UnixNano()),
	}
}

func TestBuildV3IdempotencyKeyIsStableAndFieldBound(t *testing.T) {
	left := &v1.Envelope{
		ContentTopic: "ab",
		Message:      []byte("c"),
		TimestampNs:  42,
	}
	right := &v1.Envelope{
		ContentTopic: "a",
		Message:      []byte("bc"),
		TimestampNs:  42,
	}

	leftKey := buildIdempotencyKey(left)
	require.Len(t, leftKey, 64)
	require.Equal(t, leftKey, buildIdempotencyKey(left))
	require.NotEqual(t, leftKey, buildIdempotencyKey(right))
}

func subscribeToTopic(
	t *testing.T,
	l *Listener,
	installationId string,
	topicStr string,
	isSilent bool,
	hmacKeys ...interfaces.HmacKey,
) {
	_, err := l.installations.Register(t.Context(), interfaces.Installation{
		Id: installationId,
		DeliveryMechanism: interfaces.DeliveryMechanism{
			Kind:  interfaces.APNS,
			Token: DELIVERY_TOKEN,
		},
	})
	require.NoError(t, err)

	parsed, err := topics.ParseV3Topic(topicStr)
	require.NoError(t, err)

	err = l.subscriptions.SubscribeWithMetadata(t.Context(), installationId, []interfaces.SubscriptionInput{{
		Topic:    parsed,
		IsSilent: isSilent,
		HmacKeys: hmacKeys,
	}})
	require.NoError(t, err)
}

func buildV3ConversationEnvelope(
	t *testing.T,
	topic string,
	timestamp time.Time,
	data []byte,
	senderHmac []byte,
) *v1.Envelope {
	t.Helper()

	message, err := proto.Marshal(&mlsV1.GroupMessage{
		Version: &mlsV1.GroupMessage_V1_{
			V1: &mlsV1.GroupMessage_V1{
				CreatedNs:  uint64(timestamp.UnixNano()),
				Data:       data,
				SenderHmac: senderHmac,
				ShouldPush: true,
			},
		},
	})
	require.NoError(t, err)
	return &v1.Envelope{
		ContentTopic: topic,
		Message:      message,
		TimestampNs:  uint64(timestamp.UnixNano()),
	}
}

func Test_UncorrelatedWelcomeFailsClosed(t *testing.T) {
	mockDeliveryService := mocks.NewDelivery(t)
	l := buildTestListener(t, mockDeliveryService)

	subscribeToTopic(t, l, INSTALLATION_ID, TEST_TOPIC, false)
	require.NoError(t, l.processEnvelope(testEnvelope(TEST_TOPIC, []byte("test"))))

	mockDeliveryService.AssertNotCalled(t, "CanDeliver", mock.Anything)
	mockDeliveryService.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}

func Test_MultipleDeliveries(t *testing.T) {
	mockDeliveryService := mocks.NewDelivery(t)
	l := buildTestListener(t, mockDeliveryService)

	mockDeliveryService.On("CanDeliver", mock.Anything).Return(true)
	var sendCount atomic.Int32
	mockDeliveryService.On("Send", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) {
			sendCount.Add(1)
		}).
		Once().
		Return(errors.New("failed"))
	mockDeliveryService.On("Send", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) {
			sendCount.Add(1)
		}).
		Once().
		Return(nil)

	rawFixture := getRawFixture(t, "v3-conversation")
	envelope := getEnvelope(t, rawFixture)
	hmacKey := interfaces.HmacKey{
		ThirtyDayPeriodsSinceEpoch: getThirtyDayPeriodsFromEpoch(envelope),
		Key:                        testHmacKey(0x11),
	}

	subscribeToTopic(t, l, INSTALLATION_ID, envelope.ContentTopic, false, hmacKey)
	subscribeToTopic(t, l, INSTALLATION_ID_2, envelope.ContentTopic, false, hmacKey)

	require.EqualError(t, l.processEnvelope(envelope), "failed")
	require.Equal(t, int32(2), sendCount.Load())

	mockDeliveryService.AssertCalled(t, "CanDeliver", mock.Anything)
	mockDeliveryService.AssertNumberOfCalls(t, "Send", 2)

	sendReqs := testutils.GetSendRequests(mockDeliveryService)
	require.Len(t, sendReqs, 2)
	require.ElementsMatch(t, []string{INSTALLATION_ID, INSTALLATION_ID_2}, []string{
		sendReqs[0].Installation.Id,
		sendReqs[1].Installation.Id,
	})
	require.Equal(t, envelope.ContentTopic, sendReqs[0].Topic)
	require.Equal(t, envelope.ContentTopic, sendReqs[1].Topic)
}

func Test_V3Listener_ExactPeriodSelfHmacSkipsDelivery(t *testing.T) {
	mockDeliveryService := mocks.NewDelivery(t)
	l := buildTestListener(t, mockDeliveryService)
	topic := "/xmtp/mls/1/g-24ce39d660600b3a98adff3075b6d1f4/proto"
	timestamp := time.Unix(int64(20*30*24*time.Hour/time.Second), 0)
	key := testHmacKey(0x31)
	data := []byte("self-message")
	envelope := buildV3ConversationEnvelope(
		t,
		topic,
		timestamp,
		data,
		testSenderHmac(key, data),
	)
	period := getThirtyDayPeriodsFromEpoch(envelope)
	subscribeToTopic(t, l, INSTALLATION_ID, topic, false, interfaces.HmacKey{
		ThirtyDayPeriodsSinceEpoch: period,
		Key:                        key,
	})

	require.NoError(t, l.processEnvelope(envelope))
	mockDeliveryService.AssertNotCalled(t, "CanDeliver", mock.Anything)
	mockDeliveryService.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}

func Test_V3Listener_PeriodRolloverFailsClosedUntilExactKeyRefresh(t *testing.T) {
	mockDeliveryService := testutils.MockDeliveryAcceptAll(t)
	l := buildTestListener(t, mockDeliveryService)
	topic := "/xmtp/mls/1/g-34ce39d660600b3a98adff3075b6d1f4/proto"
	timestamp := time.Unix(int64(21*30*24*time.Hour/time.Second)+1, 0)
	subscriberKey := testHmacKey(0x41)
	data := []byte("message-from-another-member")
	envelope := buildV3ConversationEnvelope(
		t,
		topic,
		timestamp,
		data,
		testSenderHmac(testHmacKey(0x42), data),
	)
	currentPeriod := getThirtyDayPeriodsFromEpoch(envelope)
	subscribeToTopic(t, l, INSTALLATION_ID, topic, false, interfaces.HmacKey{
		ThirtyDayPeriodsSinceEpoch: currentPeriod - 1,
		Key:                        subscriberKey,
	})

	require.NoError(t, l.processEnvelope(envelope))
	mockDeliveryService.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)

	parsed := testutils.MustParseTopic(t, topic)
	require.NoError(t, l.subscriptions.SubscribeWithMetadata(
		t.Context(),
		INSTALLATION_ID,
		[]interfaces.SubscriptionInput{{
			Topic: parsed,
			HmacKeys: []interfaces.HmacKey{{
				ThirtyDayPeriodsSinceEpoch: currentPeriod,
				Key:                        subscriberKey,
			}},
		}},
	))

	require.NoError(t, l.processEnvelope(envelope))
	mockDeliveryService.AssertNumberOfCalls(t, "Send", 1)
	sendRequests := testutils.GetSendRequests(mockDeliveryService)
	require.Len(t, sendRequests, 1)
	require.NotNil(t, sendRequests[0].Subscription.ExpectedHmacKeyPeriod)
	require.Equal(t, currentPeriod, *sendRequests[0].Subscription.ExpectedHmacKeyPeriod)
	require.Equal(t, currentPeriod, sendRequests[0].Subscription.HmacKey.ThirtyDayPeriodsSinceEpoch)
}

type subscribeAllOnlyMessageAPIClient struct {
	subscribeAll func(context.Context, *v1.SubscribeAllRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[v1.Envelope], error)
}

func (c *subscribeAllOnlyMessageAPIClient) Publish(context.Context, *v1.PublishRequest, ...grpc.CallOption) (*v1.PublishResponse, error) {
	panic("unexpected Publish call")
}

func (c *subscribeAllOnlyMessageAPIClient) Subscribe(context.Context, *v1.SubscribeRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[v1.Envelope], error) {
	panic("unexpected Subscribe call")
}

func (c *subscribeAllOnlyMessageAPIClient) Subscribe2(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[v1.SubscribeRequest, v1.Envelope], error) {
	panic("unexpected Subscribe2 call")
}

func (c *subscribeAllOnlyMessageAPIClient) SubscribeAll(ctx context.Context, req *v1.SubscribeAllRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[v1.Envelope], error) {
	return c.subscribeAll(ctx, req, opts...)
}

func (c *subscribeAllOnlyMessageAPIClient) Query(context.Context, *v1.QueryRequest, ...grpc.CallOption) (*v1.QueryResponse, error) {
	panic("unexpected Query call")
}

func (c *subscribeAllOnlyMessageAPIClient) BatchQuery(context.Context, *v1.BatchQueryRequest, ...grpc.CallOption) (*v1.BatchQueryResponse, error) {
	panic("unexpected BatchQuery call")
}

func Test_StartMessageListenerStopsOnCanceledSubscribe(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	listener := &Listener{
		ctx:            ctx,
		cancelFunc:     cancel,
		logger:         testutils.TestLogger(t),
		messageChannel: make(chan *v1.Envelope),
		xmtpClient: &subscribeAllOnlyMessageAPIClient{
			subscribeAll: func(ctx context.Context, _ *v1.SubscribeAllRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[v1.Envelope], error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		},
	}

	done := make(chan struct{})
	go func() {
		listener.startMessageListener()
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("startMessageListener did not exit after context cancellation")
	}

	select {
	case _, ok := <-listener.messageChannel:
		require.False(t, ok, "messageChannel should be closed when listener exits")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("messageChannel was not closed after listener exit")
	}
}
