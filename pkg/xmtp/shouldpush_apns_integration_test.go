package xmtp

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/sideshow/apns2"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/delivery"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	mlsV1 "github.com/xmtp/xmtpd/pkg/proto/mls/api/v1"
	"github.com/xmtp/xmtpd/pkg/topic"
	"google.golang.org/protobuf/proto"
)

type wireRecordingAPNSClient struct {
	pushes atomic.Int32
}

func (c *wireRecordingAPNSClient) PushWithContext(
	_ apns2.Context,
	_ *apns2.Notification,
) (*apns2.Response, error) {
	c.pushes.Add(1)
	return &apns2.Response{StatusCode: apns2.StatusSent}, nil
}

func newWireAPNSDelivery(
	t *testing.T,
) (*delivery.ApnsDelivery, *wireRecordingAPNSClient) {
	t.Helper()
	client := &wireRecordingAPNSClient{}
	service, err := delivery.NewApnsDeliveryWithClient(
		testutils.TestLogger(t),
		options.ApnsOptions{
			Mode:  "development",
			Topic: "com.example.hytch.dev",
		},
		client,
	)
	require.NoError(t, err)
	return service, client
}

func serializedV3ConversationEnvelope(
	t *testing.T,
	topicName string,
	timestamp time.Time,
	data []byte,
	senderHmac []byte,
	shouldPush bool,
) *v1.Envelope {
	t.Helper()
	message, err := proto.Marshal(&mlsV1.GroupMessage{
		Version: &mlsV1.GroupMessage_V1_{
			V1: &mlsV1.GroupMessage_V1{
				CreatedNs:  uint64(timestamp.UnixNano()),
				Data:       data,
				SenderHmac: senderHmac,
				ShouldPush: shouldPush,
			},
		},
	})
	require.NoError(t, err)
	return &v1.Envelope{
		ContentTopic: topicName,
		Message:      message,
		TimestampNs:  uint64(timestamp.UnixNano()),
	}
}

func TestSerializedV3ShouldPushFalseOuterMetadataMakesZeroAPNSCalls(
	t *testing.T,
) {
	// Message content is encrypted at this boundary. These cases deliberately
	// prove only the authenticated outer shouldPush=false metadata emitted for
	// client-classified control and ephemeral traffic.
	for _, outerClass := range []string{"control", "ephemeral"} {
		t.Run(outerClass, func(t *testing.T) {
			service, client := newWireAPNSDelivery(t)
			listener := buildTestListener(t, service)
			topicName :=
				"/xmtp/mls/1/g-44ce39d660600b3a98adff3075b6d1f4/proto"
			timestamp := time.Unix(
				int64(22*30*24*time.Hour/time.Second),
				0,
			)
			subscriberKey := testHmacKey(0x61)
			data := []byte("opaque-" + outerClass)
			envelope := serializedV3ConversationEnvelope(
				t,
				topicName,
				timestamp,
				data,
				testSenderHmac(testHmacKey(0x62), data),
				false,
			)
			period := getThirtyDayPeriodsFromEpoch(envelope)
			subscribeToTopic(
				t,
				listener,
				INSTALLATION_ID,
				topicName,
				false,
				interfaces.HmacKey{
					ThirtyDayPeriodsSinceEpoch: period,
					Key:                        subscriberKey,
				},
			)

			require.NoError(t, listener.processEnvelope(envelope))
			require.Zero(t, client.pushes.Load())
		})
	}
}

func TestSerializedV4ShouldPushFalseOuterMetadataMakesZeroAPNSCalls(
	t *testing.T,
) {
	// Both output formats consume the same authenticated outer decision. The
	// encrypted data labels below are fixture provenance, not bridge-side
	// content classification.
	for _, payloadFormat := range []interfaces.PayloadFormat{
		interfaces.PayloadFormatV3,
		interfaces.PayloadFormatV4,
	} {
		for _, outerClass := range []string{"control", "ephemeral"} {
			name := payloadFormat.String() + "_" + outerClass
			t.Run(name, func(t *testing.T) {
				service, client := newWireAPNSDelivery(t)
				listener := buildV4TestListener(t, service)
				groupID := []byte{0x65, 0x76, 0x87, 0x98}
				groupTopic := topic.NewTopic(
					topic.TopicKindGroupMessagesV1,
					groupID,
				)
				registerV4Installation(
					t,
					listener,
					"outer-metadata-installation",
					payloadFormat,
				)
				subscribeV4ToTopic(
					t,
					listener,
					"outer-metadata-installation",
					groupTopic,
					interfaces.HmacKey{
						ThirtyDayPeriodsSinceEpoch: 0,
						Key:                        testHmacKey(0x71),
					},
				)
				data := []byte("opaque-" + outerClass)
				envelope := buildGroupMessageOriginatorEnvelope(
					t,
					1,
					91,
					int64(time.Second),
					groupID,
					data,
					testSenderHmac(testHmacKey(0x72), data),
					false,
				)

				require.NoError(
					t,
					listener.processOriginatorEnvelope(envelope),
				)
				require.Zero(t, client.pushes.Load())
			})
		}
	}
}
