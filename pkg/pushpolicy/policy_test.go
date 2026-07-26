package pushpolicy

import (
	"crypto/hmac"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"github.com/xmtp/xmtpd/pkg/topic"
)

func boolPointer(value bool) *bool {
	return &value
}

func conversationRequest(shouldPush *bool) interfaces.SendRequest {
	return interfaces.SendRequest{
		MessageContext: interfaces.MessageContext{
			MessageType: topics.V3Conversation,
			ShouldPush:  shouldPush,
		},
	}
}

func TestAuthorizeDeliveryRequiresExactTrueConversation(t *testing.T) {
	trueValue := true
	falseValue := false
	tests := []struct {
		name        string
		req         interfaces.SendRequest
		wantAllowed bool
	}{
		{
			name:        "exact true conversation",
			req:         conversationRequest(&trueValue),
			wantAllowed: true,
		},
		{
			name: "false conversation",
			req:  conversationRequest(&falseValue),
		},
		{
			name: "missing conversation",
			req:  conversationRequest(nil),
		},
		{
			name: "unknown type",
			req: interfaces.SendRequest{MessageContext: interfaces.MessageContext{
				MessageType: topics.Unknown,
				ShouldPush:  &trueValue,
			}},
		},
		{
			name: "welcome remains closed",
			req: interfaces.SendRequest{MessageContext: interfaces.MessageContext{
				MessageType: topics.V3Welcome,
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, allowed := AuthorizeDelivery(t.Context(), test.req)
			require.Equal(t, test.wantAllowed, allowed)
			require.Equal(t, test.wantAllowed, AllowsDelivery(ctx, test.req))
		})
	}
}

func TestAuthorizeDeliverySkipsSender(t *testing.T) {
	hmacKey := []byte("test-key")
	data := []byte("test-data")
	hash := hmac.New(sha256.New, hmacKey)
	_, _ = hash.Write(data)
	senderHmac := hash.Sum(nil)

	req := conversationRequest(boolPointer(true))
	req.MessageContext.HmacInputs = &data
	req.MessageContext.SenderHmac = &senderHmac
	req.Subscription.HmacKey = &interfaces.HmacKey{Key: hmacKey}

	ctx, allowed := AuthorizeDelivery(t.Context(), req)
	require.False(t, allowed)
	require.False(t, AllowsDelivery(ctx, req))
}

func TestDeliveryAuthorizationIsSingleUseUnderConcurrency(t *testing.T) {
	req := conversationRequest(boolPointer(true))
	ctx, allowed := AuthorizeDelivery(t.Context(), req)
	require.True(t, allowed)

	var successful atomic.Int32
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if AllowsDelivery(ctx, req) {
				successful.Add(1)
			}
		}()
	}
	workers.Wait()
	require.Equal(t, int32(1), successful.Load())
}

func fullRequest() interfaces.SendRequest {
	hmacInputs := []byte("hmac-input")
	senderHmac := []byte("non-matching-hmac")
	return interfaces.SendRequest{
		IdempotencyKey:   "idempotency",
		Topic:            "legacy-topic",
		TopicBytesB64:    "binary-topic",
		EncryptedMessage: []byte("ciphertext"),
		PayloadFormat:    interfaces.PayloadFormatV4,
		Installation: interfaces.Installation{
			Id: "installation",
			DeliveryMechanism: interfaces.DeliveryMechanism{
				Kind:      interfaces.APNS,
				Token:     "token",
				UpdatedAt: time.Unix(100, 200).UTC(),
			},
			PayloadFormat: interfaces.PayloadFormatV4,
		},
		Subscription: interfaces.Subscription{
			Id:             7,
			CreatedAt:      time.Unix(300, 400).UTC(),
			InstallationId: "installation",
			Topic:          "legacy-topic",
			TopicV4: topic.NewTopic(
				topic.TopicKindGroupMessagesV1,
				[]byte("topic-id"),
			),
			IsActive: true,
			IsSilent: true,
			HmacKey: &interfaces.HmacKey{
				ThirtyDayPeriodsSinceEpoch: 9,
				Key:                        []byte("hmac-key"),
			},
		},
		MessageContext: interfaces.MessageContext{
			MessageType: topics.V3Conversation,
			ShouldPush:  boolPointer(true),
			HmacInputs:  &hmacInputs,
			SenderHmac:  &senderHmac,
		},
	}
}

func TestDeliveryAuthorizationBindsPreviouslyOmittedFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*interfaces.SendRequest)
	}{
		{
			name: "installation payload format",
			mutate: func(req *interfaces.SendRequest) {
				req.Installation.PayloadFormat = interfaces.PayloadFormatV3
			},
		},
		{
			name: "delivery mechanism updated at",
			mutate: func(req *interfaces.SendRequest) {
				req.Installation.DeliveryMechanism.UpdatedAt = time.Unix(101, 200).UTC()
			},
		},
		{
			name: "subscription created at",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.CreatedAt = time.Unix(301, 400).UTC()
			},
		},
		{
			name: "subscription v4 topic",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.TopicV4 = topic.NewTopic(
					topic.TopicKindGroupMessagesV1,
					[]byte("other-topic"),
				)
			},
		},
		{
			name: "subscription active state",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.IsActive = false
			},
		},
		{
			name: "subscription hmac key",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.HmacKey = &interfaces.HmacKey{
					ThirtyDayPeriodsSinceEpoch: 10,
					Key:                        []byte("other-key"),
				}
			},
		},
		{
			name: "hmac inputs",
			mutate: func(req *interfaces.SendRequest) {
				value := []byte("other-input")
				req.MessageContext.HmacInputs = &value
			},
		},
		{
			name: "sender hmac",
			mutate: func(req *interfaces.SendRequest) {
				value := []byte("other-hmac")
				req.MessageContext.SenderHmac = &value
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := fullRequest()
			ctx, allowed := AuthorizeDelivery(t.Context(), req)
			require.True(t, allowed)

			mutated := req
			test.mutate(&mutated)
			require.False(t, AllowsDelivery(ctx, mutated))
			require.True(t, AllowsDelivery(ctx, req))
		})
	}
}
