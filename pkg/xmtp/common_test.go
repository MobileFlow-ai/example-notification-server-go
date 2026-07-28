package xmtp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

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

func TestRetryEnvelopeProcessingRecoversTransientFailure(t *testing.T) {
	attempts := 0
	failures := 0
	recovered := retryEnvelopeProcessing(
		t.Context(),
		time.Second,
		func(context.Context) error {
			attempts++
			if attempts < 3 {
				return errors.New("transient")
			}
			return nil
		},
		func() {
			failures++
		},
	)

	require.True(t, recovered)
	require.Equal(t, 3, attempts)
	require.Equal(t, 2, failures)
}

func TestRetryEnvelopeProcessingStopsAtCallerDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	attempts := 0
	recovered := retryEnvelopeProcessing(
		ctx,
		time.Second,
		func(context.Context) error {
			attempts++
			return errors.New("unavailable")
		},
		nil,
	)

	require.False(t, recovered)
	require.Equal(t, 1, attempts)
}

func TestListenerReadinessReflectsProcessingDegradation(t *testing.T) {
	v3 := &Listener{}
	v3.ready.Store(true)
	require.True(t, v3.Ready())
	v3.processing.Add(1)
	require.False(t, v3.Ready())
	v3.processing.Add(-1)
	v3.processingUnsafe.Store(true)
	require.False(t, v3.Ready())

	v4 := &V4Listener{}
	v4.ready.Store(true)
	require.True(t, v4.Ready())
	v4.processing.Add(1)
	require.False(t, v4.Ready())
	v4.processing.Add(-1)
	v4.processingUnsafe.Store(true)
	require.False(t, v4.Ready())
}

func testHmacKey(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, sha256.Size)
}

func testSenderHmac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func testConversationRequest(shouldPush *bool) interfaces.SendRequest {
	data := []byte("test-data")
	hmacKey := testHmacKey(0x11)
	senderHmac := testSenderHmac(testHmacKey(0x22), data)
	expectedPeriod := 1
	return interfaces.SendRequest{
		Installation: interfaces.Installation{
			DeliveryMechanism: interfaces.DeliveryMechanism{Kind: interfaces.APNS},
		},
		Subscription: interfaces.Subscription{
			IsActive:              true,
			ExpectedHmacKeyPeriod: &expectedPeriod,
			HmacKey: &interfaces.HmacKey{
				ThirtyDayPeriodsSinceEpoch: expectedPeriod,
				Key:                        hmacKey,
			},
		},
		MessageContext: interfaces.MessageContext{
			MessageType: topics.V3Conversation,
			ShouldPush:  shouldPush,
			HmacInputs:  &data,
			SenderHmac:  &senderHmac,
		},
	}
}

func TestDeliveryDispatcher_SuppressesSelfOriginatedMessage(t *testing.T) {
	mockDelivery := mocks.NewDelivery(t)
	shouldPush := true
	hmacKey := testHmacKey(0x33)
	data := []byte("test-data")
	senderHmac := testSenderHmac(hmacKey, data)

	req := testConversationRequest(&shouldPush)
	req.MessageContext.SenderHmac = &senderHmac
	req.MessageContext.HmacInputs = &data
	req.Subscription.HmacKey = &interfaces.HmacKey{
		ThirtyDayPeriodsSinceEpoch: *req.Subscription.ExpectedHmacKeyPeriod,
		Key:                        hmacKey,
	}
	dispatcher := newDeliveryDispatcher(
		t.Context(),
		[]interfaces.Delivery{mockDelivery},
	)

	require.NoError(t, dispatcher.dispatch(req))
	mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
	mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}

func TestDeliveryDispatcher_MissingAndStaleHmacStateNeverReachesEgress(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*interfaces.SendRequest)
	}{
		{
			name: "missing exact-period key",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.HmacKey = nil
			},
		},
		{
			name: "stale key period",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.HmacKey.ThirtyDayPeriodsSinceEpoch++
			},
		},
		{
			name: "malformed key",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.HmacKey.Key = []byte("short")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockDelivery := mocks.NewDelivery(t)
			shouldPush := true
			req := testConversationRequest(&shouldPush)
			test.mutate(&req)
			dispatcher := newDeliveryDispatcher(
				t.Context(),
				[]interfaces.Delivery{mockDelivery},
			)

			require.NoError(t, dispatcher.dispatch(req))
			mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
			mockDelivery.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
		})
	}
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

func TestDeliveryDispatcher_ControlAndEphemeralOuterDecisionsNeverReachEgress(
	t *testing.T,
) {
	// The bridge cannot decrypt or classify content. These fixtures prove the
	// authenticated outer shouldPush=false contract used by both content
	// classes is enforced before any delivery implementation is consulted.
	for _, trafficClass := range []string{"control", "ephemeral"} {
		t.Run(trafficClass, func(t *testing.T) {
			mockDelivery := mocks.NewDelivery(t)
			dispatcher := newDeliveryDispatcher(
				t.Context(),
				[]interfaces.Delivery{mockDelivery},
			)
			shouldPush := false
			request := testConversationRequest(&shouldPush)

			require.NoError(t, dispatcher.dispatch(request))
			mockDelivery.AssertNotCalled(t, "CanDeliver", mock.Anything)
			mockDelivery.AssertNotCalled(
				t,
				"Send",
				mock.Anything,
				mock.Anything,
			)
		})
	}
}
