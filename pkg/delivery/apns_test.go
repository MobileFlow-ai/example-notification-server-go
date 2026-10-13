package delivery

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const deliveryTestTopic = "/xmtp/mls/1/g-24ce39d660600b3a98adff3075b6d1f4/proto"

func buildDeliveryRequest(t *testing.T, payloadFormat interfaces.PayloadFormat) interfaces.SendRequest {
	t.Helper()

	parsed, err := topics.ParseV3Topic(deliveryTestTopic)
	require.NoError(t, err)
	topicStr := topics.TopicToString(parsed)
	req := interfaces.SendRequest{
		Topic:            topicStr,
		EncryptedMessage: []byte("test"),
		PayloadFormat:    payloadFormat,
		Subscription: interfaces.Subscription{
			TopicV4: parsed,
			Topic:   topicStr,
		},
		Installation: interfaces.Installation{
			DeliveryMechanism: interfaces.DeliveryMechanism{Token: "device-token"},
		},
		MessageContext: interfaces.MessageContext{MessageType: topics.V3Conversation},
	}
	if payloadFormat == interfaces.PayloadFormatV4 {
		req.TopicBytesB64 = topics.TopicToBase64(parsed)
	}
	return req
}

func TestApns_PayloadIncludesPayloadFormat(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)

	notification := a.buildNotification(req)
	payloadBytes, err := notification.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &p))
	require.Equal(t, "v3", p["payloadFormat"])
}

func Test_ApnsDelivery_BuildNotification_TopicField(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)

	notification := a.buildNotification(req)
	payloadBytes, err := notification.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &p))
	require.Equal(t, deliveryTestTopic, p["topic"])
	require.NotContains(t, p, "topicBytesB64")
	require.Equal(t, "device-token", notification.DeviceToken)
	require.Equal(t, "com.example.app", notification.Topic)
}

func Test_ApnsDelivery_BuildNotification_V4TopicBytesB64(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV4)

	notification := a.buildNotification(req)
	payloadBytes, err := notification.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &p))
	require.Equal(t, deliveryTestTopic, p["topic"])
	require.Equal(t, req.TopicBytesB64, p["topicBytesB64"])
	require.Equal(t, "v4", p["payloadFormat"])
}

type fakeApnsSender struct {
	response *apns2.Response
	err      error
}

func (s fakeApnsSender) PushWithContext(apns2.Context, *apns2.Notification) (*apns2.Response, error) {
	return s.response, s.err
}

func TestApns_SendRejectsProviderFailure(t *testing.T) {
	for _, tc := range []struct {
		name               string
		status             int
		reason             string
		permanent, invalid bool
	}{
		{"unregistered", 410, "Unregistered", true, true},
		{"bad_token", 400, "BadDeviceToken", true, true},
		{"wrong_topic", 400, "DeviceTokenNotForTopic", true, true},
		{"malformed_payload", 400, "BadPriority", true, false},
		{"credentials", 403, "InvalidProviderToken", true, false},
		{"expired_credentials", 403, "ExpiredProviderToken", false, false},
		{"rate_limit", 429, "TooManyRequests", false, false},
		{"server_error", 500, "InternalServerError", false, false},
		{"unavailable", 503, "ServiceUnavailable", false, false},
		{"unexpected_redirect", 302, "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, observed := observer.New(zap.InfoLevel)
			a := ApnsDelivery{logger: zap.New(core), apnsClient: fakeApnsSender{response: &apns2.Response{StatusCode: tc.status, Reason: tc.reason}}}
			err := a.Send(t.Context(), buildDeliveryRequest(t, interfaces.PayloadFormatV3))
			var rejection *ApnsRejection
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, tc.permanent, rejection.Permanent)
			require.Equal(t, tc.invalid, rejection.InvalidToken)
			require.Empty(t, observed.FilterMessage("Sent notification").All())
		})
	}
}

func TestApns_SendRequiresAcknowledgement(t *testing.T) {
	transportError := errors.New("network unavailable")
	for _, tc := range []struct {
		name     string
		response *apns2.Response
		err      error
		success  bool
	}{
		{"accepted", &apns2.Response{StatusCode: http.StatusOK}, nil, true},
		{"missing_response", nil, nil, false},
		{"transport", nil, transportError, false},
		{"response_with_transport_error", &apns2.Response{StatusCode: http.StatusOK}, transportError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, observed := observer.New(zap.InfoLevel)
			a := ApnsDelivery{logger: zap.New(core), apnsClient: fakeApnsSender{response: tc.response, err: tc.err}}
			err := a.Send(t.Context(), buildDeliveryRequest(t, interfaces.PayloadFormatV3))
			if tc.success {
				require.NoError(t, err)
				require.Len(t, observed.FilterMessage("Sent notification").All(), 1)
			} else {
				require.Error(t, err)
				require.Empty(t, observed.FilterMessage("Sent notification").All())
			}
			if tc.err != nil {
				require.ErrorIs(t, err, transportError)
			}
		})
	}
}

// Exercise the pinned provider client: APNs rejection is a response with nil
// transport error, exactly the behavior the old adapter treated as success.
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
			core, observed := observer.New(zap.InfoLevel)
			client := &apns2.Client{Host: server.URL, HTTPClient: server.Client()}
			a := ApnsDelivery{logger: zap.New(core), apnsClient: client}
			err := a.Send(t.Context(), buildDeliveryRequest(t, interfaces.PayloadFormatV3))
			if status == 200 {
				require.NoError(t, err)
				require.Len(t, observed.FilterMessage("Sent notification").All(), 1)
			} else {
				require.Error(t, err)
				require.Empty(t, observed.FilterMessage("Sent notification").All())
			}
		})
	}
}
