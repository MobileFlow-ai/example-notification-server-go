package vault

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a9api"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

func a9RoutingTestTopic() *topicpkg.Topic {
	return topicpkg.NewTopic(
		topicpkg.TopicKindGroupMessagesV1,
		bytes.Repeat([]byte{0x51}, 32),
	)
}

func a9RoutingDatabaseNow(
	t *testing.T,
	fixture *a9DeliveryTestFixture,
) time.Time {
	t.Helper()
	var now time.Time
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.clock_timestamp()`,
	).Scan(&now))
	now = now.UTC()
	*fixture.runtime.signed.now = now
	return now
}

func a9RoutingTopicBindingLease(
	t *testing.T,
	fixture *a9DeliveryTestFixture,
	now time.Time,
) a9trust.TopicBindingLease {
	t.Helper()
	require.NotNil(t, fixture.job.A9)
	lease, err := fixture.runtime.store.a9Trust.AcquireTopicBindingLease(
		t.Context(),
		now,
		fixture.job.A9.KeysetSequence,
		fixture.job.A9.KeysetHash,
	)
	require.NoError(t, err)
	require.NotNil(t, lease)
	return lease
}

func a9RoutingNonceState(
	t *testing.T,
	fixture *a9DeliveryTestFixture,
) nonceState {
	t.Helper()
	var encrypted []byte
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`SELECT encrypted_nonce_state
		   FROM hytch_push_vault.subscription_leases
		  WHERE lease_id = $1`,
		fixture.leaseID,
	).Scan(&encrypted))
	plaintext, err := fixture.runtime.store.encryption.Open(
		leaseContext(fixture.leaseID, "nonce-state"),
		encrypted,
	)
	require.NoError(t, err)
	defer zero(plaintext)
	state, err := decodeNonceState(plaintext)
	require.NoError(t, err)
	return state
}

func TestA9RoutingWithLeaseReturnsExactSnapshot(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture := newA9DeliveryTestFixture(t)
	require.NotNil(t, fixture.job.A9)
	requestedTopic := a9RoutingTestTopic()
	require.Equal(t, fixture.job.ProviderTopic, requestedTopic.Bytes())
	before := a9RoutingNonceState(t, fixture)
	now := a9RoutingDatabaseNow(t, fixture)
	lease := a9RoutingTopicBindingLease(t, fixture, now)

	subscriptions, err := fixture.runtime.store.getSubscriptionsA9WithLease(
		t.Context(),
		requestedTopic,
		688,
		now,
		fixture.job.A9.KeysetSequence,
		fixture.job.A9.KeysetHash,
		lease,
		[]a9TopicLookupCandidate{{
			topicKeyEpoch: fixture.job.A9.TopicKeyEpoch,
			topicBinding:  fixture.job.A9.TopicBinding,
		}},
	)
	defer wipeA9PreparedSubscriptions(subscriptions)
	require.NoError(t, err)
	require.Len(t, subscriptions, 1)
	secureRoute := subscriptions[0].SecureRoute
	require.NotNil(t, secureRoute)
	require.NotNil(t, secureRoute.A9)
	require.Equal(t, *fixture.job.A9, *secureRoute.A9)
	require.Equal(t, before.Prefix, secureRoute.NoncePrefix)
	require.Equal(t, before.NextSequence, secureRoute.DeliverySequence)

	after := a9RoutingNonceState(t, fixture)
	require.Equal(t, before.Prefix, after.Prefix)
	require.Equal(t, before.NextSequence+1, after.NextSequence)
	acquisitions, evaluations, closes := fixture.trust.counts()
	require.Equal(t, 1, acquisitions)
	require.Equal(t, 1, evaluations)
	require.Equal(t, 1, closes)
}

func TestA9RoutingGetSubscriptionsUsesOneCurrentTrustLease(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	fixture := newA9DeliveryTestFixture(t)
	before := a9RoutingNonceState(t, fixture)
	subscriptions, err := fixture.runtime.store.GetSubscriptions(
		t.Context(),
		a9RoutingTestTopic(),
		688,
	)
	defer wipeA9PreparedSubscriptions(subscriptions)
	require.NoError(t, err)
	require.Len(t, subscriptions, 1)
	require.NotNil(t, subscriptions[0].SecureRoute)
	require.NotNil(t, subscriptions[0].SecureRoute.A9)
	require.Equal(
		t,
		*fixture.job.A9,
		*subscriptions[0].SecureRoute.A9,
	)
	after := a9RoutingNonceState(t, fixture)
	require.Equal(t, before.Prefix, after.Prefix)
	require.Equal(t, before.NextSequence+1, after.NextSequence)
	acquisitions, evaluations, closes := fixture.trust.counts()
	require.Equal(t, 1, acquisitions)
	require.Equal(t, 2, evaluations)
	require.Equal(t, 1, closes)
}

func TestA9RoutingUncertainAuthorityDoesNotAdvanceNonce(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture := newA9DeliveryTestFixture(t)
	require.NotNil(t, fixture.job.A9)
	watermark := fixture.runtime.watermark(
		0x46,
		fixture.installation,
		fixture.epoch,
		2,
		1,
		a9trust.WatermarkStatusUncertain,
	)
	watermark.IssuedAt = fixture.runtime.now
	result, err := fixture.runtime.store.ApplyWatermark(
		t.Context(),
		watermark,
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultStateUncertain, result.State)

	var routeCount int
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_subscription_routes
		  WHERE lease_id = $1`,
		fixture.leaseID,
	).Scan(&routeCount))
	require.Equal(t, 1, routeCount)
	before := a9RoutingNonceState(t, fixture)
	now := a9RoutingDatabaseNow(t, fixture)
	lease := a9RoutingTopicBindingLease(t, fixture, now)

	subscriptions, err := fixture.runtime.store.getSubscriptionsA9WithLease(
		t.Context(),
		a9RoutingTestTopic(),
		688,
		now,
		fixture.job.A9.KeysetSequence,
		fixture.job.A9.KeysetHash,
		lease,
		[]a9TopicLookupCandidate{{
			topicKeyEpoch: fixture.job.A9.TopicKeyEpoch,
			topicBinding:  fixture.job.A9.TopicBinding,
		}},
	)
	defer wipeA9PreparedSubscriptions(subscriptions)
	require.NoError(t, err)
	require.Empty(t, subscriptions)
	require.Equal(t, before, a9RoutingNonceState(t, fixture))
	acquisitions, evaluations, closes := fixture.trust.counts()
	require.Equal(t, 1, acquisitions)
	require.Zero(t, evaluations)
	require.Equal(t, 1, closes)
}
