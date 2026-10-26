package delivery

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
)

type fixedResponseApnsClient struct {
	response *apns2.Response
	err      error
}

func (c fixedResponseApnsClient) PushWithContext(apns2.Context, *apns2.Notification) (*apns2.Response, error) {
	return c.response, c.err
}

func sendAuthorizedPlainAPNS(t *testing.T, client APNSPushClient) error {
	t.Helper()
	a := ApnsDelivery{apnsClient: client, opts: options.ApnsOptions{Topic: "com.example.app"}}
	ctx, req := authorizeTestDeliveryRequest(t, t.Context(), buildDeliveryRequest(t, interfaces.PayloadFormatV3))
	return a.Send(ctx, req)
}

func TestApns_SendRejectsProviderFailure(t *testing.T) {
	for _, tc := range []struct {
		name               string
		status             int
		reason             string
		permanent, invalid bool
		transient          bool
	}{
		{"unregistered", 410, apns2.ReasonUnregistered, true, true, false},
		{"expired_token", 410, apns2.ReasonExpiredToken, true, true, false},
		// Apple returns BadDeviceToken for a sandbox/production mismatch too.
		{"bad_token_or_environment_mismatch", 400, apns2.ReasonBadDeviceToken, true, false, false},
		{"wrong_topic", 400, apns2.ReasonDeviceTokenNotForTopic, true, false, false},
		{"malformed_payload", 400, apns2.ReasonBadPriority, true, false, false},
		{"credentials", 403, apns2.ReasonInvalidProviderToken, false, false, false},
		{"missing_credentials", 403, apns2.ReasonMissingProviderToken, false, false, false},
		{"bad_certificate", 403, apns2.ReasonBadCertificate, false, false, false},
		{"forbidden", 403, apns2.ReasonForbidden, false, false, false},
		{"expired_credentials", 403, apns2.ReasonExpiredProviderToken, false, false, false},
		{"rate_limit", 429, apns2.ReasonTooManyRequests, false, false, true},
		{"server_error", 500, apns2.ReasonInternalServerError, false, false, true},
		{"unavailable", 503, apns2.ReasonServiceUnavailable, false, false, true},
		{"unexpected_redirect", 302, "", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sendAuthorizedPlainAPNS(t, fixedResponseApnsClient{response: &apns2.Response{StatusCode: tc.status, Reason: tc.reason}})
			var rejection *ApnsRejection
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, tc.permanent, rejection.Permanent)
			require.Equal(t, tc.invalid, rejection.InvalidToken)
			if tc.transient {
				require.ErrorIs(t, err, ErrAPNSUnavailable)
			} else {
				require.ErrorIs(t, err, ErrAPNSRejected)
			}
			// The error text stays the fixed sentinel: no status or reason.
			if tc.reason != "" {
				require.NotContains(t, err.Error(), tc.reason)
			}
		})
	}
}

func TestApns_SendRequiresAcknowledgement(t *testing.T) {
	transportError := errors.New("Post https://api.push.apple.com/3/device/secret-token: network unavailable")
	for _, tc := range []struct {
		name     string
		response *apns2.Response
		err      error
		success  bool
	}{
		{"accepted", &apns2.Response{StatusCode: http.StatusOK}, nil, true},
		{"missing_response", nil, nil, false},
		{"transport", nil, transportError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sendAuthorizedPlainAPNS(t, fixedResponseApnsClient{response: tc.response, err: tc.err})
			if tc.success {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrAPNSUnavailable)
			// Transport errors embed the device URL; they must not escape.
			require.NotErrorIs(t, err, transportError)
			require.NotContains(t, err.Error(), "secret-token")
		})
	}
}

// Exercise the pinned provider client: APNs rejection is a response with nil
// transport error, exactly the behavior an adapter must not treat as success.
func TestApns_RealClientRejectionIsNotAcknowledged(t *testing.T) {
	for _, status := range []int{200, 410, 429, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "POST", r.Method)
				require.Equal(t, "/3/device/device-token", r.URL.Path)
				w.Header().Set("apns-id", "test-receipt")
				w.WriteHeader(status)
				if status != 200 {
					_, _ = w.Write([]byte(`{"reason":"test-rejection"}`))
				}
			}))
			defer server.Close()
			err := sendAuthorizedPlainAPNS(t, &apns2.Client{Host: server.URL, HTTPClient: server.Client()})
			if status == 200 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestApns_PreservesInvalidationTimestamp(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var rejection *ApnsRejection
	err := apnsRejectionError(&apns2.Response{StatusCode: 410, Reason: apns2.ReasonUnregistered, Timestamp: apns2.Time{Time: at}}, nil)
	require.ErrorAs(t, err, &rejection)
	require.True(t, rejection.InvalidToken)
	require.Equal(t, at, rejection.UnregisteredAt)
}

func TestApns_RetryRetainsNotificationIdentity(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)
	req.IdempotencyKey = "message-key"
	req.Installation.Id = "first-device"
	first := mustBuildNotification(t, a, req)
	require.NotEmpty(t, first.ApnsID)
	require.Equal(t, first.ApnsID, mustBuildNotification(t, a, req).ApnsID)
	payloadBytes, err := first.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)
	var value map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &value))
	require.Equal(t, req.IdempotencyKey, value["notification_id"])
	req.Installation.Id = "other-device"
	require.NotEqual(t, first.ApnsID, mustBuildNotification(t, a, req).ApnsID)
}

func TestApns_RealTopicMismatchPreservesRegistration(t *testing.T) {
	for _, reason := range []string{apns2.ReasonDeviceTokenNotForTopic, apns2.ReasonBadDeviceToken} {
		t.Run(reason, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"reason":"` + reason + `"}`))
			}))
			defer server.Close()
			err := sendAuthorizedPlainAPNS(t, &apns2.Client{Host: server.URL, HTTPClient: server.Client()})
			var rejection *ApnsRejection
			require.ErrorAs(t, err, &rejection)
			require.True(t, rejection.Permanent, "do not retry this notification unchanged")
			require.False(t, rejection.InvalidToken, "a topic or environment mismatch must not retire the device registration")
		})
	}
}
