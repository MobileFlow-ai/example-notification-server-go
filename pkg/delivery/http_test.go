package delivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/pushpolicy"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"go.uber.org/zap/zaptest"
)

func newTestRequest() interfaces.SendRequest {
	shouldPush := true
	hmacInputs := []byte("hmac-input")
	hmacKey := bytes.Repeat([]byte{0x11}, sha256.Size)
	otherKey := bytes.Repeat([]byte{0x22}, sha256.Size)
	hash := hmac.New(sha256.New, otherKey)
	_, _ = hash.Write(hmacInputs)
	senderHmac := hash.Sum(nil)
	expectedPeriod := 1
	return interfaces.SendRequest{
		IdempotencyKey: "test-key",
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
			ShouldPush:  &shouldPush,
			HmacInputs:  &hmacInputs,
			SenderHmac:  &senderHmac,
		},
	}
}

// testServerAndDelivery creates an httptest server with the given handler and
// an HttpDelivery pointed at it. The caller should defer server.Close().
func testServerAndDelivery(t *testing.T, handler http.HandlerFunc, maxAttempts int, initialDelayMs int) (*httptest.Server, *HttpDelivery) {
	t.Helper()
	server := httptest.NewServer(handler)
	d := NewHttpDelivery(zaptest.NewLogger(t), options.HttpDeliveryOptions{
		Address:             server.URL,
		MaxAttempts:         maxAttempts,
		InitialRetryDelayMs: initialDelayMs,
	})
	return server, d
}

// countingHandler returns an http.HandlerFunc that counts requests and responds
// with the given status code.
func countingHandler(counter *int32, statusCode int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(counter, 1)
		w.WriteHeader(statusCode)
	}
}

func TestHttpDelivery_SendSuccess(t *testing.T) {
	var requestCount int32
	server, d := testServerAndDelivery(t, countingHandler(&requestCount, http.StatusOK), 3, 10)
	defer server.Close()

	authorizedContext, authorizedRequest := authorizeTestDeliveryRequest(t, t.Context(), newTestRequest())
	err := d.Send(authorizedContext, authorizedRequest)
	require.NoError(t, err)
	require.Equal(t, int32(1), atomic.LoadInt32(&requestCount))
}

func TestHttpDelivery_RetryOnFailureThenSuccess(t *testing.T) {
	var requestCount int32
	server, d := testServerAndDelivery(t, func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}, 3, 10)
	defer server.Close()

	authorizedContext, authorizedRequest := authorizeTestDeliveryRequest(t, t.Context(), newTestRequest())
	err := d.Send(authorizedContext, authorizedRequest)
	require.NoError(t, err)
	require.Equal(t, int32(2), atomic.LoadInt32(&requestCount))
}

func TestHttpDelivery_ExhaustsAttempts(t *testing.T) {
	var requestCount int32
	maxAttempts := 3
	server, d := testServerAndDelivery(t, countingHandler(&requestCount, http.StatusInternalServerError), maxAttempts, 10)
	defer server.Close()

	authorizedContext, authorizedRequest := authorizeTestDeliveryRequest(t, t.Context(), newTestRequest())
	err := d.Send(authorizedContext, authorizedRequest)
	require.Error(t, err)
	require.Equal(t, "HTTP request failed", err.Error())
	require.Equal(t, int32(maxAttempts), atomic.LoadInt32(&requestCount))
}

func TestHttpDelivery_ContextCancellation(t *testing.T) {
	var requestCount int32
	retryDelay := time.Minute
	server, d := testServerAndDelivery(
		t,
		countingHandler(&requestCount, http.StatusInternalServerError),
		5,
		int(retryDelay/time.Millisecond),
	)
	defer server.Close()

	waitStarted := make(chan time.Duration, 1)
	d.waitForRetry = func(
		ctx context.Context,
		delay time.Duration,
	) error {
		waitStarted <- delay
		return waitForRetryDelay(ctx, delay)
	}

	ctx, cancel := context.WithCancel(t.Context())
	authorizedContext, authorizedRequest := authorizeTestDeliveryRequest(t, ctx, newTestRequest())

	done := make(chan error, 1)
	go func() {
		done <- d.Send(authorizedContext, authorizedRequest)
	}()

	select {
	case delay := <-waitStarted:
		require.Equal(t, retryDelay, delay)
	case <-time.After(time.Second):
		t.Fatal("delivery did not enter retry wait")
	}
	cancel()

	var err error
	select {
	case err = <-done:
	case <-time.After(time.Second):
		t.Fatal("delivery did not stop after context cancellation")
	}
	require.Error(t, err)
	require.Equal(t, context.Canceled, err)
	// Should have made only 1 request before context was cancelled during backoff
	require.Equal(t, int32(1), atomic.LoadInt32(&requestCount))
}

func TestHttpDelivery_DefaultConfig(t *testing.T) {
	d := NewHttpDelivery(zaptest.NewLogger(t), options.HttpDeliveryOptions{
		Address:             "http://localhost:9999",
		MaxAttempts:         1,
		InitialRetryDelayMs: 250,
	})

	require.Equal(t, 1, d.maxAttempts)
	require.Equal(t, 250*time.Millisecond, d.initialRetryDelay)
}

func TestHttpDelivery_ExponentialBackoff(t *testing.T) {
	var requestCount int32
	server, d := testServerAndDelivery(
		t,
		countingHandler(&requestCount, http.StatusInternalServerError),
		4,
		50,
	)
	defer server.Close()

	var delays []time.Duration
	d.waitForRetry = func(
		ctx context.Context,
		delay time.Duration,
	) error {
		require.NoError(t, ctx.Err())
		delays = append(delays, delay)
		return nil
	}

	authorizedContext, authorizedRequest := authorizeTestDeliveryRequest(t, t.Context(), newTestRequest())
	require.Error(t, d.Send(authorizedContext, authorizedRequest))
	require.Equal(t, int32(4), atomic.LoadInt32(&requestCount))
	require.Equal(
		t,
		[]time.Duration{
			50 * time.Millisecond,
			100 * time.Millisecond,
			200 * time.Millisecond,
		},
		delays,
	)
}

func TestHttpDelivery_SingleAttempt(t *testing.T) {
	var requestCount int32
	server, d := testServerAndDelivery(t, countingHandler(&requestCount, http.StatusInternalServerError), 1, 10)
	defer server.Close()

	authorizedContext, authorizedRequest := authorizeTestDeliveryRequest(t, t.Context(), newTestRequest())
	err := d.Send(authorizedContext, authorizedRequest)
	require.Error(t, err)
	// With maxAttempts=1, only one attempt is made (no retries)
	require.Equal(t, int32(1), atomic.LoadInt32(&requestCount))
}

func TestHttpDelivery_MaxAttemptsClampsToMinimumOne(t *testing.T) {
	d := NewHttpDelivery(zaptest.NewLogger(t), options.HttpDeliveryOptions{
		Address:             "http://localhost:9999",
		MaxAttempts:         0,
		InitialRetryDelayMs: 10,
	})

	// Value of 0 should be clamped to 1
	require.Equal(t, 1, d.maxAttempts)
}

func TestHttp_PayloadIncludesPayloadFormat(t *testing.T) {
	req := interfaces.SendRequest{
		IdempotencyKey:   "test-key",
		Topic:            "test-topic",
		EncryptedMessage: []byte("test"),
		PayloadFormat:    interfaces.PayloadFormatV4,
	}

	jsonData, err := json.Marshal(req)
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(jsonData, &p))
	require.Equal(t, "v4", p["payload_format"])
}

func TestHttp_WelcomePayloadIsCompact(t *testing.T) {
	req := interfaces.SendRequest{
		Topic:            "welcome-topic",
		EncryptedMessage: make([]byte, 8_192),
		MessageContext:   interfaces.MessageContext{MessageType: topics.V3Welcome},
	}

	jsonData, err := json.Marshal(req)
	require.NoError(t, err)
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(jsonData, &payload))
	message := payload["message"].(map[string]interface{})
	require.NotContains(t, message, "message")
	require.Less(t, len(jsonData), 1_024)
}

func TestHttpDelivery_UnsealedRequestReturnsUnauthorized(t *testing.T) {
	d := NewHttpDelivery(zaptest.NewLogger(t), options.HttpDeliveryOptions{})
	require.ErrorIs(t, d.Send(t.Context(), newTestRequest()), pushpolicy.ErrUnauthorized)
}

func TestHttpDelivery_CanDeliver(t *testing.T) {
	d := NewHttpDelivery(zaptest.NewLogger(t), options.HttpDeliveryOptions{})
	require.True(t, d.CanDeliver(newTestRequest()))
}

func TestHttpDelivery_AuthHeader(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewHttpDelivery(zaptest.NewLogger(t), options.HttpDeliveryOptions{
		Address:             server.URL,
		AuthHeader:          "Bearer test-token",
		MaxAttempts:         1,
		InitialRetryDelayMs: 10,
	})

	authorizedContext, authorizedRequest := authorizeTestDeliveryRequest(t, t.Context(), newTestRequest())
	err := d.Send(authorizedContext, authorizedRequest)
	require.NoError(t, err)
	require.Equal(t, "Bearer test-token", receivedAuth)
}
