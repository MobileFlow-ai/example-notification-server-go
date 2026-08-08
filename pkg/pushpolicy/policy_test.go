package pushpolicy

import (
	"bytes"
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
	hmacInputs := []byte("hmac-input")
	hmacKey := bytes.Repeat([]byte{0x11}, sha256.Size)
	otherKey := bytes.Repeat([]byte{0x22}, sha256.Size)
	hash := hmac.New(sha256.New, otherKey)
	_, _ = hash.Write(hmacInputs)
	senderHmac := hash.Sum(nil)
	expectedPeriod := 9

	return interfaces.SendRequest{
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
			HmacInputs:  &hmacInputs,
			SenderHmac:  &senderHmac,
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

func TestAuthorizeDeliveryRequiresExactSilentWelcomeRouteWithoutSenderClaim(
	t *testing.T,
) {
	request := interfaces.SendRequest{
		Subscription: interfaces.Subscription{
			IsActive: true,
			IsSilent: true,
			SecureRoute: &interfaces.SecureRoute{
				WelcomeAuthorized: true,
			},
		},
		MessageContext: interfaces.MessageContext{
			MessageType: topics.V3Welcome,
		},
	}
	ctx, allowed := AuthorizeDelivery(t.Context(), request)
	require.True(t, allowed)
	require.True(t, AllowsDelivery(ctx, request))
	require.False(t, AllowsDelivery(ctx, request))

	tests := []struct {
		name   string
		mutate func(*interfaces.SendRequest)
	}{
		{
			name: "missing exact correlation",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.SecureRoute.WelcomeAuthorized = false
			},
		},
		{
			name: "non-silent route",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.IsSilent = false
			},
		},
		{
			name: "inactive route",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.IsActive = false
			},
		},
		{
			name: "sender attribution is not valid welcome authority",
			mutate: func(req *interfaces.SendRequest) {
				value := bytes.Repeat([]byte{0x44}, sha256.Size)
				req.MessageContext.SenderHmac = &value
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			routeCopy := *request.Subscription.SecureRoute
			candidate.Subscription.SecureRoute = &routeCopy
			test.mutate(&candidate)
			authorizationContext, candidateAllowed := AuthorizeDelivery(
				t.Context(),
				candidate,
			)
			require.False(t, candidateAllowed)
			require.False(t, AllowsDelivery(authorizationContext, candidate))
		})
	}
}

func TestAuthorizeDeliverySuppressesSelfOriginatedMessage(t *testing.T) {
	hmacKey := bytes.Repeat([]byte{0x33}, sha256.Size)
	data := []byte("test-data")
	hash := hmac.New(sha256.New, hmacKey)
	_, _ = hash.Write(data)
	senderHmac := hash.Sum(nil)

	req := conversationRequest(boolPointer(true))
	req.MessageContext.HmacInputs = &data
	req.MessageContext.SenderHmac = &senderHmac
	req.Subscription.HmacKey = &interfaces.HmacKey{
		ThirtyDayPeriodsSinceEpoch: *req.Subscription.ExpectedHmacKeyPeriod,
		Key:                        hmacKey,
	}

	ctx, allowed := AuthorizeDelivery(t.Context(), req)
	require.False(t, allowed)
	require.False(t, AllowsDelivery(ctx, req))
}

func TestAuthorizeDeliveryFailsClosedWithoutUsableExactPeriodHmacState(t *testing.T) {
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
			name: "missing expected period",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.ExpectedHmacKeyPeriod = nil
			},
		},
		{
			name: "stale key period",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.HmacKey.ThirtyDayPeriodsSinceEpoch++
			},
		},
		{
			name: "negative key period",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.HmacKey.ThirtyDayPeriodsSinceEpoch = -1
				expected := -1
				req.Subscription.ExpectedHmacKeyPeriod = &expected
			},
		},
		{
			name: "malformed short key",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.HmacKey.Key = []byte("short")
			},
		},
		{
			name: "missing HMAC inputs",
			mutate: func(req *interfaces.SendRequest) {
				req.MessageContext.HmacInputs = nil
			},
		},
		{
			name: "inactive route",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.IsActive = false
			},
		},
		{
			name: "silent conversation route",
			mutate: func(req *interfaces.SendRequest) {
				req.Subscription.IsSilent = true
			},
		},
		{
			name: "missing sender HMAC",
			mutate: func(req *interfaces.SendRequest) {
				req.MessageContext.SenderHmac = nil
			},
		},
		{
			name: "malformed sender HMAC",
			mutate: func(req *interfaces.SendRequest) {
				value := []byte("short")
				req.MessageContext.SenderHmac = &value
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := conversationRequest(boolPointer(true))
			test.mutate(&req)

			ctx, allowed := AuthorizeDelivery(t.Context(), req)
			require.False(t, allowed)
			require.False(t, AllowsDelivery(ctx, req))
		})
	}
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
	hmacKey := bytes.Repeat([]byte{0x44}, sha256.Size)
	otherKey := bytes.Repeat([]byte{0x55}, sha256.Size)
	hash := hmac.New(sha256.New, otherKey)
	_, _ = hash.Write(hmacInputs)
	senderHmac := hash.Sum(nil)
	expectedPeriod := 9
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
			IsActive:              true,
			IsSilent:              false,
			ExpectedHmacKeyPeriod: &expectedPeriod,
			HmacKey: &interfaces.HmacKey{
				ThirtyDayPeriodsSinceEpoch: expectedPeriod,
				Key:                        hmacKey,
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
					ThirtyDayPeriodsSinceEpoch: *req.Subscription.ExpectedHmacKeyPeriod,
					Key:                        bytes.Repeat([]byte{0x66}, sha256.Size),
				}
			},
		},
		{
			name: "expected hmac key period",
			mutate: func(req *interfaces.SendRequest) {
				value := *req.Subscription.ExpectedHmacKeyPeriod + 1
				req.Subscription.ExpectedHmacKeyPeriod = &value
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
				value := bytes.Repeat([]byte{0x77}, sha256.Size)
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
			require.True(
				t,
				requestFingerprint(req) != requestFingerprint(mutated),
				"authorization fingerprint must change",
			)
			require.False(t, AllowsDelivery(ctx, mutated))
			require.True(t, AllowsDelivery(ctx, req))
		})
	}
}

func requestWithA9Route() interfaces.SendRequest {
	request := fullRequest()
	snapshot := &interfaces.A9RouteSnapshot{
		SubscriptionGeneration:  1,
		BindingVersion:          2,
		AssertionStreamSequence: 3,
		AssertionExpiresAt:      time.Unix(500, 600).UTC(),
		TopicKeyEpoch:           4,
		RouteKeyEpoch:           5,
		KeysetSequence:          6,
		WatermarkSequence:       7,
	}
	copy(snapshot.InstallationBindingID[:], bytes.Repeat([]byte{0x11}, 16))
	copy(snapshot.SequencerEpoch[:], bytes.Repeat([]byte{0x12}, 16))
	copy(snapshot.BindingID[:], bytes.Repeat([]byte{0x13}, 16))
	copy(snapshot.AssertionHash[:], bytes.Repeat([]byte{0x14}, 32))
	copy(snapshot.TopicBinding[:], bytes.Repeat([]byte{0x15}, 32))
	copy(snapshot.KeysetHash[:], bytes.Repeat([]byte{0x16}, 32))
	request.Subscription.SecureRoute = &interfaces.SecureRoute{
		A9: snapshot,
	}
	return request
}

func TestDeliveryAuthorizationBindsEveryA9RouteField(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*interfaces.A9RouteSnapshot)
	}{
		{
			name: "installation binding",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.InstallationBindingID[0] ^= 0xff
			},
		},
		{
			name: "sequencer epoch",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.SequencerEpoch[0] ^= 0xff
			},
		},
		{
			name: "subscription generation",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.SubscriptionGeneration++
			},
		},
		{
			name: "binding id",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.BindingID[0] ^= 0xff
			},
		},
		{
			name: "binding version",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.BindingVersion++
			},
		},
		{
			name: "assertion hash",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.AssertionHash[0] ^= 0xff
			},
		},
		{
			name: "assertion stream sequence",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.AssertionStreamSequence++
			},
		},
		{
			name: "assertion expiry",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.AssertionExpiresAt = snapshot.
					AssertionExpiresAt.Add(time.Nanosecond)
			},
		},
		{
			name: "topic key epoch",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.TopicKeyEpoch++
			},
		},
		{
			name: "topic binding",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.TopicBinding[0] ^= 0xff
			},
		},
		{
			name: "route key epoch",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.RouteKeyEpoch++
			},
		},
		{
			name: "keyset sequence",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.KeysetSequence++
			},
		},
		{
			name: "keyset hash",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.KeysetHash[0] ^= 0xff
			},
		},
		{
			name: "watermark sequence",
			mutate: func(snapshot *interfaces.A9RouteSnapshot) {
				snapshot.WatermarkSequence++
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := requestWithA9Route()
			ctx, allowed := AuthorizeDelivery(t.Context(), request)
			require.True(t, allowed)

			mutated := request
			route := *request.Subscription.SecureRoute
			snapshot := *route.A9
			route.A9 = &snapshot
			mutated.Subscription.SecureRoute = &route
			test.mutate(mutated.Subscription.SecureRoute.A9)

			require.NotEqual(
				t,
				requestFingerprint(request),
				requestFingerprint(mutated),
			)
			require.False(t, AllowsDelivery(ctx, mutated))
			require.True(t, AllowsDelivery(ctx, request))
		})
	}

	request := requestWithA9Route()
	mutated := request
	route := *request.Subscription.SecureRoute
	route.A9 = nil
	mutated.Subscription.SecureRoute = &route
	require.NotEqual(
		t,
		requestFingerprint(request),
		requestFingerprint(mutated),
	)
}
