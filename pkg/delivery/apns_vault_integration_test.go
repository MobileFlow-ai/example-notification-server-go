package delivery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/pushpolicy"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
	"go.uber.org/zap"
)

const (
	deliveryVaultEnvironment = "development"
	deliveryVaultKeyID       = "delivery-vault-test-key"
)

type deliveryVaultSequenceReader struct {
	next byte
}

func (r *deliveryVaultSequenceReader) Read(destination []byte) (int, error) {
	for index := range destination {
		r.next++
		if r.next == 0 {
			r.next++
		}
		destination[index] = r.next
	}
	return len(destination), nil
}

type deliveryVaultFixture struct {
	store          *vault.Store
	now            *time.Time
	privateKey     ed25519.PrivateKey
	installationID string
	incarnationID  string
	age            authority.AgePolicy
}

func requireDeliveryVaultIntegrationTests(t *testing.T) {
	t.Helper()
	if os.Getenv("VAULT_INTEGRATION_TESTS") != "1" {
		t.Skip("set VAULT_INTEGRATION_TESTS=1 to run database integration coverage")
	}
}

func newDeliveryVaultFixture(
	t *testing.T,
	age authority.AgePolicy,
) *deliveryVaultFixture {
	t.Helper()
	db := testdb.CreateTestDb(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyring, err := vault.NewKeyring(1, map[uint32][]byte{
		1: bytes.Repeat([]byte{0x31}, 32),
	})
	require.NoError(t, err)
	lookup, err := vault.NewLookupKey(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store, err := vault.NewStore(db, vault.StoreOptions{
		Environment:             deliveryVaultEnvironment,
		LeaseTTL:                7 * 24 * time.Hour,
		Encryption:              keyring,
		Lookup:                  lookup,
		AuthorityKeys:           map[string]ed25519.PublicKey{deliveryVaultKeyID: publicKey},
		TeenConversationEnabled: age == authority.AgePolicyTeen,
		Now:                     func() time.Time { return now },
		Random:                  &deliveryVaultSequenceReader{},
	})
	require.NoError(t, err)
	sweeper, err := vault.NewRetentionSweeper(db, vault.RetentionOptions{
		SweepInterval:        15 * time.Minute,
		Environment:          deliveryVaultEnvironment,
		Lookup:               lookup,
		EncryptionKeyVersion: keyring.ActiveVersion(),
		Now:                  func() time.Time { return now },
	})
	require.NoError(t, err)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)
	return &deliveryVaultFixture{
		store:          store,
		now:            &now,
		privateKey:     privateKey,
		installationID: "delivery-installation",
		incarnationID:  "delivery-incarnation",
		age:            age,
	}
}

func (fixture *deliveryVaultFixture) signedControl(
	t *testing.T,
	ttl time.Duration,
) authority.PolicyControlV1 {
	t.Helper()
	control := authority.PolicyControlV1{
		SchemaVersion:        1,
		Environment:          deliveryVaultEnvironment,
		InstallationID:       fixture.installationID,
		AccountIncarnationID: fixture.incarnationID,
		PolicyEpoch:          1,
		State:                authority.PolicyStateActive,
		AgePolicy:            fixture.age,
		IssuedAt:             fixture.now.Format(time.RFC3339Nano),
		ExpiresAt:            fixture.now.Add(ttl).Format(time.RFC3339Nano),
		SigningKeyID:         deliveryVaultKeyID,
		Algorithm:            "Ed25519",
	}
	signingBytes, err := control.SigningBytes()
	require.NoError(t, err)
	control.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(fixture.privateKey, signingBytes),
	)
	return control
}

func (fixture *deliveryVaultFixture) signedSubscription(
	t *testing.T,
	target *topicpkg.Topic,
	routeByte byte,
	period uint32,
	hmacKey []byte,
	mode authority.PushMode,
	ttl time.Duration,
) vault.SubscriptionRefresh {
	t.Helper()
	rawTopic := target.Bytes()
	routeKey := bytes.Repeat([]byte{routeByte}, gate8wrapper.RouteKeySize)
	aliasDay := gate8wrapper.UTCDay(*fixture.now)
	alias, err := gate8wrapper.DeriveRouteAlias(
		routeKey,
		rawTopic,
		gate8wrapper.EnvironmentDevelopment,
		aliasDay,
	)
	require.NoError(t, err)
	topicDigest := sha256.Sum256(rawTopic)
	expectedConversationCommitment := ""
	if target.Kind() == topicpkg.TopicKindWelcomeMessagesV1 {
		commitment, commitmentErr := authority.ExpectedConversationCommitment(
			deliveryVaultEnvironment,
			fixture.installationID,
			fixture.incarnationID,
			"delivery-conversation",
		)
		require.NoError(t, commitmentErr)
		expectedConversationCommitment = hex.EncodeToString(commitment[:])
	}
	capability := authority.ReceiveCapabilityV1{
		SchemaVersion:                  1,
		Environment:                    deliveryVaultEnvironment,
		InstallationID:                 fixture.installationID,
		AccountIncarnationID:           fixture.incarnationID,
		PolicyEpoch:                    1,
		TopicDigest:                    hex.EncodeToString(topicDigest[:]),
		AliasDay:                       aliasDay,
		RouteAlias:                     base64.RawURLEncoding.EncodeToString(alias[:]),
		ConversationGrantVersion:       1,
		RosterVersion:                  1,
		ExpectedConversationCommitment: expectedConversationCommitment,
		PushMode:                       mode,
		IssuedAt:                       fixture.now.Format(time.RFC3339Nano),
		ExpiresAt:                      fixture.now.Add(ttl).Format(time.RFC3339Nano),
		Nonce: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{routeByte + 1}, 16),
		),
		SigningKeyID: deliveryVaultKeyID,
		Algorithm:    "Ed25519",
	}
	signingBytes, err := capability.SigningBytes()
	require.NoError(t, err)
	capability.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(fixture.privateKey, signingBytes),
	)
	subscription := vault.SubscriptionRefresh{
		Topic:         append([]byte(nil), rawTopic...),
		RouteKey:      routeKey,
		RouteKeyEpoch: 1,
		Capability:    capability,
	}
	if target.Kind() == topicpkg.TopicKindGroupMessagesV1 {
		subscription.HMACKeys = []vault.HMACKeyInput{{
			ThirtyDayPeriodsSinceEpoch: period,
			Key:                        append([]byte(nil), hmacKey...),
		}}
	}
	return subscription
}

func (fixture *deliveryVaultFixture) refreshRequest(
	generation uint64,
	control authority.PolicyControlV1,
	subscriptions ...vault.SubscriptionRefresh,
) vault.RefreshRequest {
	return vault.RefreshRequest{
		Environment:          deliveryVaultEnvironment,
		InstallationID:       fixture.installationID,
		AccountIncarnationID: fixture.incarnationID,
		Generation:           generation,
		IdempotencyKey:       "delivery-refresh-" + time.Duration(generation).String(),
		APNSToken:            bytes.Repeat([]byte{0xa1}, 32),
		PayloadSchema:        "hytch_push_wrapper_v1",
		Subscriptions:        subscriptions,
		PolicyControl:        control,
	}
}

func deliveryVaultTopic(kind topicpkg.TopicKind, value byte) *topicpkg.Topic {
	return topicpkg.NewTopic(kind, bytes.Repeat([]byte{value}, 16))
}

func deliveryVaultRequest(
	t *testing.T,
	fixture *deliveryVaultFixture,
	target *topicpkg.Topic,
	period int,
	senderKey []byte,
) interfaces.SendRequest {
	t.Helper()
	subscriptions, err := fixture.store.GetSubscriptions(
		t.Context(),
		target,
		period,
	)
	require.NoError(t, err)
	require.Len(t, subscriptions, 1)
	installations, err := fixture.store.GetInstallations(
		t.Context(),
		[]string{subscriptions[0].InstallationId},
	)
	require.NoError(t, err)
	require.Len(t, installations, 1)
	data := []byte("opaque-message-data")
	hash := hmac.New(sha256.New, senderKey)
	_, _ = hash.Write(data)
	senderHmac := hash.Sum(nil)
	shouldPush := true
	return interfaces.SendRequest{
		IdempotencyKey:   "delivery-source-event",
		Topic:            topics.TopicToString(target),
		EncryptedMessage: []byte("opaque-encrypted-envelope"),
		PayloadFormat:    interfaces.PayloadFormatV3,
		MessageContext: interfaces.MessageContext{
			MessageType: topics.V3Conversation,
			ShouldPush:  &shouldPush,
			HmacInputs:  &data,
			SenderHmac:  &senderHmac,
		},
		Installation: installations[0],
		Subscription: subscriptions[0],
	}
}

func TestSecureVaultHMACListRolloverClosesStalePeriodAndSuppressesSelf(
	t *testing.T,
) {
	requireDeliveryVaultIntegrationTests(t)
	fixture := newDeliveryVaultFixture(t, authority.AgePolicyAdult)
	const period = uint32(688)
	conversation := deliveryVaultTopic(
		topicpkg.TopicKindGroupMessagesV1,
		0x51,
	)
	welcome := deliveryVaultTopic(
		topicpkg.TopicKindWelcomeMessagesV1,
		0x52,
	)
	control := fixture.signedControl(t, 45*time.Second)
	oldKey := bytes.Repeat([]byte{0x61}, sha256.Size)
	newKey := bytes.Repeat([]byte{0x62}, sha256.Size)
	conversationSubscription := fixture.signedSubscription(
		t,
		conversation,
		0x71,
		period,
		oldKey,
		authority.PushModeAlertAllowed,
		45*time.Second,
	)
	welcomeSubscription := fixture.signedSubscription(
		t,
		welcome,
		0x72,
		period,
		nil,
		authority.PushModeSuppressed,
		45*time.Second,
	)
	_, err := fixture.store.Refresh(
		t.Context(),
		fixture.refreshRequest(
			1,
			control,
			conversationSubscription,
			welcomeSubscription,
		),
	)
	require.NoError(t, err)
	initial, err := fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.NoError(t, err)
	require.Len(t, initial, 1)

	rotatedConversation := conversationSubscription
	rotatedConversation.HMACKeys = []vault.HMACKeyInput{{
		ThirtyDayPeriodsSinceEpoch: period + 1,
		Key:                        append([]byte(nil), newKey...),
	}}
	_, err = fixture.store.Refresh(
		t.Context(),
		fixture.refreshRequest(
			2,
			control,
			rotatedConversation,
			welcomeSubscription,
		),
	)
	require.NoError(t, err)

	stale, err := fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.NoError(t, err)
	require.Empty(t, stale)
	current, err := fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period+1),
	)
	require.NoError(t, err)
	require.Len(t, current, 1)
	require.NotNil(t, current[0].HmacKey)
	require.Equal(
		t,
		int(period+1),
		current[0].HmacKey.ThirtyDayPeriodsSinceEpoch,
	)
	require.Equal(t, newKey, current[0].HmacKey.Key)

	request := deliveryVaultRequest(
		t,
		fixture,
		conversation,
		int(period+1),
		newKey,
	)
	client := &recordingApnsClient{}
	service, err := NewApnsDeliveryWithClient(
		zap.NewNop(),
		options.ApnsOptions{
			Mode:  deliveryVaultEnvironment,
			Topic: "com.example.hytch.dev",
		},
		client,
	)
	require.NoError(t, err)
	authorizationContext, allowed := pushpolicy.AuthorizeDelivery(
		t.Context(),
		request,
	)
	require.False(t, allowed)
	require.ErrorIs(
		t,
		service.Send(authorizationContext, request),
		pushpolicy.ErrUnauthorized,
	)
	require.Zero(t, client.pushCount)
}

func TestQueuedAuthorityExactExpiryMakesZeroAPNSCalls(t *testing.T) {
	requireDeliveryVaultIntegrationTests(t)
	tests := []struct {
		name string
		age  authority.AgePolicy
		ttl  time.Duration
	}{
		{
			name: "adult_60_seconds",
			age:  authority.AgePolicyAdult,
			ttl:  time.Minute,
		},
		{
			name: "teen_30_seconds",
			age:  authority.AgePolicyTeen,
			ttl:  30 * time.Second,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeliveryVaultFixture(t, test.age)
			const period = uint32(688)
			conversation := deliveryVaultTopic(
				topicpkg.TopicKindGroupMessagesV1,
				0x53,
			)
			welcome := deliveryVaultTopic(
				topicpkg.TopicKindWelcomeMessagesV1,
				0x54,
			)
			control := fixture.signedControl(t, test.ttl)
			routeHMACKey := bytes.Repeat([]byte{0x63}, sha256.Size)
			_, err := fixture.store.Refresh(
				t.Context(),
				fixture.refreshRequest(
					1,
					control,
					fixture.signedSubscription(
						t,
						conversation,
						0x73,
						period,
						routeHMACKey,
						authority.PushModeAlertAllowed,
						test.ttl,
					),
					fixture.signedSubscription(
						t,
						welcome,
						0x74,
						period,
						nil,
						authority.PushModeSuppressed,
						test.ttl,
					),
				),
			)
			require.NoError(t, err)

			request := deliveryVaultRequest(
				t,
				fixture,
				conversation,
				int(period),
				bytes.Repeat([]byte{0x64}, sha256.Size),
			)
			client := &recordingApnsClient{}
			opts := options.ApnsOptions{
				Topic:                 "com.example.hytch.dev",
				SecureWrapperRequired: true,
				SecureEnvironment:     deliveryVaultEnvironment,
				QueueCapacity:         10,
				RequestTimeoutSeconds: 10,
			}
			reliable := newAPNSReliability(
				zap.NewNop(),
				opts,
				fixture.store,
			)
			clock := &fixedAPNSClock{now: *fixture.now}
			reliable.clock = clock
			reliable.workCtx, reliable.cancel = context.WithCancel(
				context.Background(),
			)
			t.Cleanup(reliable.cancel)
			reliable.started = true
			reliable.accepting = true
			service := &ApnsDelivery{
				apnsClient: client,
				opts:       opts,
				now:        clock.Now,
				random:     bytes.NewReader(bytes.Repeat([]byte{0}, 512)),
				logger:     zap.NewNop(),
				reliable:   reliable,
			}
			authorizationContext, allowed := pushpolicy.AuthorizeDelivery(
				t.Context(),
				request,
			)
			require.True(t, allowed)
			require.NoError(t, service.Send(authorizationContext, request))

			claimed, err := fixture.store.ClaimDeliveryJobs(
				t.Context(),
				1,
				2*time.Second,
			)
			require.NoError(t, err)
			require.Len(t, claimed, 1)
			deadline := fixture.now.Add(test.ttl)
			require.Equal(t, deadline, claimed[0].ExpiresAt)

			*fixture.now = deadline
			clock.now = deadline
			service.processClaimedJob(claimed[0])

			require.Zero(t, client.pushCount)
			remaining, err := fixture.store.ClaimDeliveryJobs(
				t.Context(),
				1,
				2*time.Second,
			)
			require.NoError(t, err)
			require.Empty(t, remaining)
		})
	}
}
