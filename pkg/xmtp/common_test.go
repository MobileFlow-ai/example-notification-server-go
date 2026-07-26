package xmtp

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
)

// Compile-time assertions: both listeners must implement NotificationListener
var _ NotificationListener = (*Listener)(nil)
var _ NotificationListener = (*V4Listener)(nil)

func testConversationRequest(shouldPush *bool) interfaces.SendRequest {
	return interfaces.SendRequest{
		Installation: interfaces.Installation{
			DeliveryMechanism: interfaces.DeliveryMechanism{Kind: interfaces.APNS},
		},
		MessageContext: interfaces.MessageContext{
			MessageType: topics.V3Conversation,
			ShouldPush:  shouldPush,
		},
	}
}

func TestDeliveryDispatcher_SkipsSender(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)
	shouldPush := true
	hmacKey := []byte("test-key")
	data := []byte("test-data")
	h := hmac.New(sha256.New, hmacKey)
	h.Write(data)
	senderHmac := h.Sum(nil)

	req := testConversationRequest(&shouldPush)
	req.MessageContext.SenderHmac = &senderHmac
	req.MessageContext.HmacInputs = &data
	req.Subscription.HmacKey = &interfaces.HmacKey{Key: hmacKey}
	dispatcher := newDeliveryDispatcher(
		t.Context(),
		[]interfaces.Delivery{mockDelivery},
	)

	require.NoError(t, dispatcher.dispatch(req))
	mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
	mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}

func TestDeliveryDispatcher_RespectsFalseShouldPush(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)
	shouldPush := false
	dispatcher := newDeliveryDispatcher(
		t.Context(),
		[]interfaces.Delivery{mockDelivery},
	)

	require.NoError(t, dispatcher.dispatch(testConversationRequest(&shouldPush)))
	mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
	mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}

func TestDeliveryDispatcher_ExactTrueConversationReachesMatchingService(t *testing.T) {
	mockDelivery := testutils.MockDeliveryAcceptAll(t)
	shouldPush := true
	dispatcher := newDeliveryDispatcher(
		t.Context(),
		[]interfaces.Delivery{mockDelivery},
	)
	req := testConversationRequest(&shouldPush)
	req.Topic = "/test/topic"
	req.EncryptedMessage = []byte("msg")

	require.NoError(t, dispatcher.dispatch(req))
	mockDelivery.AssertCalled(t, "Send", mock.Anything, req)
}

func TestDeliveryDispatcher_MissingMalformedAndUnknownShouldPushFailClosed(t *testing.T) {
	shouldPush := true
	tests := []struct {
		name string
		req  interfaces.SendRequest
	}{
		{
			name: "missing",
			req:  testConversationRequest(nil),
		},
		{
			name: "malformed envelope context",
			req:  testConversationRequest(nil),
		},
		{
			name: "unknown message type",
			req: interfaces.SendRequest{
				MessageContext: interfaces.MessageContext{
					MessageType: topics.Unknown,
					ShouldPush:  &shouldPush,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockDelivery := mocks.NewDelivery(t)
			dispatcher := newDeliveryDispatcher(
				t.Context(),
				[]interfaces.Delivery{mockDelivery},
			)

			require.NoError(t, dispatcher.dispatch(test.req))
			mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
			mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
		})
	}
}

func TestDeliveryDispatcher_Dispatch_NoPushNeverReachesEgress(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)
	shouldPush := false
	dispatcher := newDeliveryDispatcher(
		t.Context(),
		[]interfaces.Delivery{mockDelivery},
	)
	req := testConversationRequest(&shouldPush)
	req.Topic = "/sensitive/raw/topic"

	require.NoError(t, dispatcher.dispatch(req))
	mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
	mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}
