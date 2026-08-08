package delivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/pushpolicy"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
)

const deliveryTestTopic = "/xmtp/mls/1/g-24ce39d660600b3a98adff3075b6d1f4/proto"

type recordingApnsClient struct {
	pushCount    int
	notification *apns2.Notification
	response     *apns2.Response
	err          error
}

func deliveryBoolPointer(value bool) *bool {
	return &value
}

func (c *recordingApnsClient) PushWithContext(_ apns2.Context, notification *apns2.Notification) (*apns2.Response, error) {
	c.pushCount++
	c.notification = notification
	if c.response == nil && c.err == nil {
		return &apns2.Response{StatusCode: apns2.StatusSent}, nil
	}
	return c.response, c.err
}

func buildDeliveryRequest(t *testing.T, payloadFormat interfaces.PayloadFormat) interfaces.SendRequest {
	t.Helper()

	parsed, err := topics.ParseV3Topic(deliveryTestTopic)
	require.NoError(t, err)
	topicStr := topics.TopicToString(parsed)
	shouldPush := true
	hmacInputs := []byte("hmac-input")
	hmacKey := bytes.Repeat([]byte{0x11}, sha256.Size)
	otherKey := bytes.Repeat([]byte{0x22}, sha256.Size)
	hash := hmac.New(sha256.New, otherKey)
	_, _ = hash.Write(hmacInputs)
	senderHmac := hash.Sum(nil)
	expectedPeriod := 1
	req := interfaces.SendRequest{
		Topic:            topicStr,
		EncryptedMessage: []byte("test"),
		PayloadFormat:    payloadFormat,
		Subscription: interfaces.Subscription{
			IsActive:              true,
			TopicV4:               parsed,
			Topic:                 topicStr,
			ExpectedHmacKeyPeriod: &expectedPeriod,
			HmacKey: &interfaces.HmacKey{
				ThirtyDayPeriodsSinceEpoch: expectedPeriod,
				Key:                        hmacKey,
			},
		},
		Installation: interfaces.Installation{
			DeliveryMechanism: interfaces.DeliveryMechanism{
				Kind:  interfaces.APNS,
				Token: "device-token",
			},
			PayloadFormat: payloadFormat,
		},
		MessageContext: interfaces.MessageContext{
			MessageType: topics.V3Conversation,
			ShouldPush:  &shouldPush,
			HmacInputs:  &hmacInputs,
			SenderHmac:  &senderHmac,
		},
	}
	if payloadFormat == interfaces.PayloadFormatV4 {
		req.TopicBytesB64 = topics.TopicToBase64(parsed)
	}
	return req
}

func authorizeTestDeliveryRequest(
	t *testing.T,
	ctx context.Context,
	req interfaces.SendRequest,
) (context.Context, interfaces.SendRequest) {
	t.Helper()
	authorizedContext, allowed := pushpolicy.AuthorizeDelivery(ctx, req)
	require.True(t, allowed)
	return authorizedContext, req
}

func mustBuildNotification(
	t *testing.T,
	delivery ApnsDelivery,
	req interfaces.SendRequest,
) *apns2.Notification {
	t.Helper()
	notification, err := delivery.buildNotification(req)
	require.NoError(t, err)
	return notification
}

func TestApns_PayloadIncludesPayloadFormat(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)

	notification := mustBuildNotification(t, a, req)
	payloadBytes, err := notification.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &p))
	require.Equal(t, "v3", p["payloadFormat"])
}

func Test_ApnsDelivery_BuildNotification_TopicField(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)

	notification := mustBuildNotification(t, a, req)
	payloadBytes, err := notification.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &p))
	require.Equal(t, deliveryTestTopic, p["topic"])
	require.NotContains(t, p, "topicBytesB64")
	require.Equal(t, "device-token", notification.DeviceToken)
	require.Equal(t, "com.example.app", notification.Topic)
}

func Test_ApnsDelivery_BuildNotification_WelcomeOmitsEncryptedMessage(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)
	req.MessageContext.MessageType = topics.V3Welcome
	req.EncryptedMessage = make([]byte, 8_192)

	notification := mustBuildNotification(t, a, req)
	payloadBytes, err := notification.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &p))
	require.Equal(t, string(topics.V3Welcome), p["messageKind"])
	require.NotContains(t, p, "encryptedMessage")
	require.Less(t, len(payloadBytes), 4_096)
}

func Test_ApnsDelivery_BuildNotification_ConversationIncludesEncryptedMessage(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)

	notification := mustBuildNotification(t, a, req)
	payloadBytes, err := notification.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &p))
	require.Equal(t, "dGVzdA==", p["encryptedMessage"])
}

func Test_ApnsDelivery_BuildNotification_V4TopicBytesB64(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV4)

	notification := mustBuildNotification(t, a, req)
	payloadBytes, err := notification.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &p))
	require.Equal(t, deliveryTestTopic, p["topic"])
	require.Equal(t, req.TopicBytesB64, p["topicBytesB64"])
	require.Equal(t, "v4", p["payloadFormat"])
}

func Test_ApnsDelivery_BuildNotification_AlertHeaders(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)

	notification := mustBuildNotification(t, a, req)
	require.Equal(t, apns2.PushTypeAlert, notification.PushType)
	require.Equal(t, apns2.PriorityHigh, notification.Priority)

	payloadBytes, err := notification.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &p))
	aps := p["aps"].(map[string]interface{})
	require.Equal(t, float64(1), aps["mutable-content"])
	require.Equal(t, "New message from XMTP", aps["alert"])
	require.NotContains(t, aps, "content-available")
}

func Test_ApnsDelivery_BuildNotification_SilentHeaders(t *testing.T) {
	a := ApnsDelivery{opts: options.ApnsOptions{Topic: "com.example.app"}}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)
	req.Subscription.IsSilent = true

	notification := mustBuildNotification(t, a, req)
	require.Equal(t, apns2.PushTypeBackground, notification.PushType)
	require.Equal(t, apns2.PriorityLow, notification.Priority)

	payloadBytes, err := notification.Payload.(*payload.Payload).MarshalJSON()
	require.NoError(t, err)

	var p map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &p))
	aps := p["aps"].(map[string]interface{})
	require.Equal(t, float64(1), aps["content-available"])
	require.NotContains(t, aps, "mutable-content")
	require.NotContains(t, aps, "alert")
}

func Test_ApnsResponseError(t *testing.T) {
	require.ErrorIs(t, apnsResponseError(nil), ErrAPNSUnavailable)
	require.NoError(t, apnsResponseError(&apns2.Response{StatusCode: apns2.StatusSent}))

	err := apnsResponseError(&apns2.Response{
		StatusCode: 400,
		Reason:     apns2.ReasonBadPriority,
		ApnsID:     "test-apns-id",
	})
	require.EqualError(
		t,
		err,
		"APNS rejected notification",
	)
	require.NotContains(t, err.Error(), "test-apns-id")
	require.NotContains(t, err.Error(), apns2.ReasonBadPriority)
}

func TestApnsDelivery_OuterPolicyFixtures(t *testing.T) {
	tests := []struct {
		name       string
		shouldPush *bool
		wantPush   bool
	}{
		{
			name:       "visible exact true sends",
			shouldPush: deliveryBoolPointer(true),
			wantPush:   true,
		},
		{
			name:       "control explicit false does not send",
			shouldPush: deliveryBoolPointer(false),
		},
		{
			name:       "ephemeral explicit false does not send",
			shouldPush: deliveryBoolPointer(false),
		},
		{
			name: "missing does not send",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &recordingApnsClient{}
			req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)
			req.MessageContext.ShouldPush = test.shouldPush
			a := ApnsDelivery{
				apnsClient: client,
				opts:       options.ApnsOptions{Topic: "com.example.app"},
			}

			authorizedContext, allowed := pushpolicy.AuthorizeDelivery(t.Context(), req)
			if test.wantPush {
				require.True(t, allowed)
				require.NoError(t, a.Send(authorizedContext, req))
				require.Equal(t, 1, client.pushCount)
				return
			}

			require.False(t, allowed)
			require.ErrorIs(t, a.Send(authorizedContext, req), pushpolicy.ErrUnauthorized)
			require.Zero(t, client.pushCount)
		})
	}
}

func TestApnsDelivery_ControlAndEphemeralOuterDecisionsMakeZeroAPNSCalls(t *testing.T) {
	// The bridge cannot decrypt or classify message content. These cases test
	// only the authenticated outer shouldPush decision supplied by XMTP.
	for _, outerDecision := range []string{"control", "ephemeral"} {
		t.Run(outerDecision, func(t *testing.T) {
			client := &recordingApnsClient{}
			req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)
			req.MessageContext.ShouldPush = deliveryBoolPointer(false)
			delivery := &ApnsDelivery{
				apnsClient: client,
				opts:       options.ApnsOptions{Topic: "com.example.app"},
			}

			authorizedContext, allowed := pushpolicy.AuthorizeDelivery(
				t.Context(),
				req,
			)
			require.False(t, allowed)
			require.ErrorIs(
				t,
				delivery.Send(authorizedContext, req),
				pushpolicy.ErrUnauthorized,
			)
			require.Zero(t, client.pushCount)
		})
	}
}

func TestApnsDelivery_UnsealedVisibleMessageNeverCallsClient(t *testing.T) {
	client := &recordingApnsClient{}
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)
	a := ApnsDelivery{
		apnsClient: client,
		opts:       options.ApnsOptions{Topic: "com.example.app"},
	}

	require.ErrorIs(t, a.Send(t.Context(), req), pushpolicy.ErrUnauthorized)
	require.Zero(t, client.pushCount)
}

func TestApnsDelivery_WelcomeRemainsClosed(t *testing.T) {
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)
	req.MessageContext = interfaces.MessageContext{MessageType: topics.V3Welcome}
	req.EncryptedMessage = make([]byte, 8_192)

	client := &recordingApnsClient{}
	a := ApnsDelivery{
		apnsClient: client,
		opts:       options.ApnsOptions{Topic: "com.example.app"},
	}
	authorizedContext, allowed := pushpolicy.AuthorizeDelivery(t.Context(), req)
	require.False(t, allowed)
	require.ErrorIs(t, a.Send(authorizedContext, req), pushpolicy.ErrUnauthorized)
	require.Zero(t, client.pushCount)
}

func TestApnsDelivery_SuccessResponseApnsIDIsNotSurfaced(t *testing.T) {
	const sensitiveApnsID = "sensitive-apns-id"
	client := &recordingApnsClient{
		response: &apns2.Response{
			StatusCode: apns2.StatusSent,
			ApnsID:     sensitiveApnsID,
		},
	}
	a := ApnsDelivery{
		apnsClient: client,
		opts:       options.ApnsOptions{Topic: "com.example.app"},
	}

	authorizedContext, authorizedRequest := authorizeTestDeliveryRequest(
		t,
		t.Context(),
		buildDeliveryRequest(t, interfaces.PayloadFormatV3),
	)
	require.NoError(t, a.Send(authorizedContext, authorizedRequest))
	require.Equal(t, 1, client.pushCount)
}

func Test_LoadApnsCertificate(t *testing.T) {
	t.Run("raw escaped newlines", func(t *testing.T) {
		got, err := loadApnsCertificate(options.ApnsOptions{
			P8Certificate: "line-1\\nline-2",
		})
		require.NoError(t, err)
		require.Equal(t, []byte("line-1\nline-2"), got)
	})

	t.Run("base64", func(t *testing.T) {
		got, err := loadApnsCertificate(options.ApnsOptions{
			P8CertificateBase64: base64.StdEncoding.EncodeToString(
				[]byte("test-p8"),
			),
		})
		require.NoError(t, err)
		require.Equal(t, []byte("test-p8"), got)
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := loadApnsCertificate(options.ApnsOptions{
			P8CertificateBase64: "not-valid-base64!",
		})
		require.ErrorContains(t, err, "decode APNS .p8 certificate base64")
	})

	t.Run("missing", func(t *testing.T) {
		_, err := loadApnsCertificate(options.ApnsOptions{})
		require.EqualError(t, err, "APNS .p8 certificate is not configured")
	})
}

func TestSecureAPNSConfigurationRequiresOneBase64CredentialAndMatchingEnvironment(
	t *testing.T,
) {
	valid := options.ApnsOptions{
		SecureWrapperRequired: true,
		SecureEnvironment:     "dev",
		Mode:                  "development",
		P8CertificateBase64:   "encoded-p8",
		KeyId:                 "key-id",
		TeamId:                "team-id",
		Topic:                 "com.example.hytch.dev",
	}
	require.NoError(t, validateSecureAPNSOptions(valid))
	production := valid
	production.SecureEnvironment = "production"
	production.Mode = "production"
	require.NoError(t, validateSecureAPNSOptions(production))

	testCases := []func(*options.ApnsOptions){
		func(opts *options.ApnsOptions) { opts.P8CertificateBase64 = "" },
		func(opts *options.ApnsOptions) { opts.P8Certificate = "raw-p8" },
		func(opts *options.ApnsOptions) { opts.P8CertificateFilePath = "/tmp/key.p8" },
		func(opts *options.ApnsOptions) { opts.KeyId = "" },
		func(opts *options.ApnsOptions) { opts.TeamId = "" },
		func(opts *options.ApnsOptions) { opts.Topic = "" },
		func(opts *options.ApnsOptions) { opts.SecureEnvironment = "production" },
		func(opts *options.ApnsOptions) { opts.SecureEnvironment = "development" },
	}
	for _, mutate := range testCases {
		candidate := valid
		mutate(&candidate)
		require.EqualError(
			t,
			validateSecureAPNSOptions(candidate),
			"secure APNS configuration invalid",
		)
	}

	legacy := options.ApnsOptions{
		P8Certificate: "legacy-inline-p8",
		Mode:          "development",
	}
	require.NoError(t, validateSecureAPNSOptions(legacy))
}
