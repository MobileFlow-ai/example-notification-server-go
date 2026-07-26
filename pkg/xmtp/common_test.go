package xmtp

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// Compile-time assertions: both listeners must implement NotificationListener
var _ NotificationListener = (*Listener)(nil)
var _ NotificationListener = (*V4Listener)(nil)

func TestDeliveryDispatcher_ShouldDeliver_SkipsSender(t *testing.T) {
	dispatcher := &deliveryDispatcher{
		logger: testutils.TestLogger(t),
	}
	hmacKey := []byte("test-key")
	data := []byte("test-data")
	h := hmac.New(sha256.New, hmacKey)
	h.Write(data)
	senderHmac := h.Sum(nil)

	mc := interfaces.MessageContext{
		SenderHmac: &senderHmac,
		HmacInputs: &data,
	}
	sub := interfaces.Subscription{
		HmacKey: &interfaces.HmacKey{Key: hmacKey},
	}
	require.False(t, dispatcher.shouldDeliver(mc, sub))
}

func TestDeliveryDispatcher_ShouldDeliver_RespectsNotPush(t *testing.T) {
	dispatcher := &deliveryDispatcher{
		logger: testutils.TestLogger(t),
	}
	shouldPush := false
	mc := interfaces.MessageContext{ShouldPush: &shouldPush}
	sub := interfaces.Subscription{}
	require.False(t, dispatcher.shouldDeliver(mc, sub))
}

func TestDeliveryDispatcher_Deliver_CallsMatchingService(t *testing.T) {
	mockDelivery := testutils.MockDeliveryAcceptAll(t)

	dispatcher := &deliveryDispatcher{
		logger:           testutils.TestLogger(t),
		ctx:              t.Context(),
		deliveryServices: []interfaces.Delivery{mockDelivery},
	}
	req := interfaces.SendRequest{
		Topic:            "/test/topic",
		EncryptedMessage: []byte("msg"),
	}
	err := dispatcher.deliver(req)
	require.NoError(t, err)
	mockDelivery.AssertCalled(t, "Send", mock.Anything, mock.Anything)
}

func TestDeliveryDispatcher_Dispatch_NoPushNeverReachesEgress(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)
	shouldPush := false
	observedCore, logs := observer.New(zap.DebugLevel)
	dispatcher := &deliveryDispatcher{
		logger:           zap.New(observedCore),
		ctx:              t.Context(),
		deliveryServices: []interfaces.Delivery{mockDelivery},
	}
	req := interfaces.SendRequest{
		Topic: "/sensitive/raw/topic",
		MessageContext: interfaces.MessageContext{
			ShouldPush: &shouldPush,
		},
	}

	require.NoError(t, dispatcher.dispatch(req))
	mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
	mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
	for _, entry := range logs.All() {
		rendered := fmt.Sprintf("%s %#v", entry.Message, entry.ContextMap())
		require.NotContains(t, rendered, req.Topic)
		require.NotContains(t, rendered, "message_context")
	}
}
