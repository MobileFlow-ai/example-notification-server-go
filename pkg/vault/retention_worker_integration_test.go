package vault

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

func TestRetentionAdvisoryLockContentionPreservesSharedHealth(t *testing.T) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	lookup, err := NewLookupKey(repeatedBytes(32, 42))
	require.NoError(t, err)
	sweeper, err := NewRetentionSweeper(
		db,
		RetentionOptions{
			SweepInterval:        15 * time.Minute,
			Environment:          "development",
			Lookup:               lookup,
			EncryptionKeyVersion: 1,
			Now:                  func() time.Time { return now },
		},
	)
	require.NoError(t, err)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)

	lockOwner, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer func() {
		_ = lockOwner.Close()
	}()
	var locked bool
	err = lockOwner.QueryRowContext(
		t.Context(),
		`SELECT pg_try_advisory_lock($1)`,
		retentionAdvisoryLockKey(sweeper.environmentID),
	).Scan(&locked)
	require.NoError(t, err)
	require.True(t, locked)
	defer func() {
		_, _ = lockOwner.ExecContext(
			t.Context(),
			`SELECT pg_advisory_unlock($1)`,
			retentionAdvisoryLockKey(sweeper.environmentID),
		)
	}()

	_, err = sweeper.Sweep(t.Context())
	require.ErrorIs(t, err, ErrRetentionBusy)
	require.NoError(t, sweeper.Ready(t.Context()))
	require.NoError(t, sweeper.EnsureReady(t.Context()))
}

func TestGetInstallationsAfterFreshLookupBinding(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, _ := newSignedStoreFixture(t)
	conversation := testTopic(
		t,
		topicpkg.TopicKindGroupMessagesV1,
		0x43,
	)
	welcome := testTopic(
		t,
		topicpkg.TopicKindWelcomeMessagesV1,
		0x45,
	)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	_, err := fixture.store.Refresh(
		t.Context(),
		fixture.refresh(
			t,
			1,
			control,
			fixture.subscription(
				t,
				conversation,
				0x44,
				1,
				688,
				authority.PushModeAlertAllowed,
				1,
			),
			fixture.subscription(
				t,
				welcome,
				0x46,
				1,
				688,
				authority.PushModeSuppressed,
				1,
			),
		),
	)
	require.NoError(t, err)
	routes, err := fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		688,
	)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	installations, err := fixture.store.GetInstallations(
		t.Context(),
		[]string{routes[0].InstallationId},
	)
	require.NoError(t, err)
	require.Len(t, installations, 1)
}

func TestRetentionRejectsLookupRootReplacement(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	wrongLookup, err := NewLookupKey(repeatedBytes(32, 0x7f))
	require.NoError(t, err)
	sweeper, err := NewRetentionSweeper(
		db,
		RetentionOptions{
			SweepInterval:        15 * time.Minute,
			Environment:          fixture.store.environment,
			Lookup:               wrongLookup,
			EncryptionKeyVersion: fixture.store.encryption.ActiveVersion(),
			Now:                  func() time.Time { return *fixture.now },
		},
	)
	require.NoError(t, err)

	_, err = sweeper.Sweep(t.Context())
	require.ErrorIs(t, err, ErrRetentionUnavailable)
	_, err = sweeper.Health(t.Context())
	require.ErrorIs(t, err, ErrRetentionUnavailable)

	var safe bool
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT is_safe
			   FROM hytch_push_vault.retention_state
			  WHERE environment = $1`,
			fixture.store.environmentID,
		).Scan(&safe),
	)
	require.False(t, safe)
}

func TestRetentionTombstonesPreserveErasedEpochAndKeyVersion(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	conversation := testTopic(
		t,
		topicpkg.TopicKindGroupMessagesV1,
		0x53,
	)
	welcome := testTopic(
		t,
		topicpkg.TopicKindWelcomeMessagesV1,
		0x54,
	)
	control := fixture.policy(
		t,
		9,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	_, err := fixture.store.Refresh(
		t.Context(),
		fixture.refresh(
			t,
			1,
			control,
			fixture.subscription(
				t,
				conversation,
				0x55,
				5,
				688,
				authority.PushModeAlertAllowed,
				9,
			),
			fixture.subscription(
				t,
				welcome,
				0x56,
				6,
				688,
				authority.PushModeSuppressed,
				9,
			),
		),
	)
	require.NoError(t, err)

	var installationIdentity []byte
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT installation_identity
			   FROM hytch_push_vault.installation_states`,
		).Scan(&installationIdentity),
	)
	type erasedRoute struct {
		identity   []byte
		fenceEpoch int64
		keyVersion int32
	}
	rows, err := db.QueryContext(
		t.Context(),
		`SELECT route_identity, route_key_epoch,
		        CASE topic_kind WHEN $1 THEN 17 ELSE 18 END
		   FROM hytch_push_vault.subscription_leases`,
		topicConversation,
	)
	require.NoError(t, err)
	var routes []erasedRoute
	for rows.Next() {
		var route erasedRoute
		require.NoError(
			t,
			rows.Scan(
				&route.identity,
				&route.fenceEpoch,
				&route.keyVersion,
			),
		)
		routes = append(routes, route)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.Len(t, routes, 2)

	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.installation_states
		    SET encryption_key_version = 19,
		        expires_at = $1`,
		*fixture.now,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.subscription_leases
		    SET encryption_key_version =
		            CASE topic_kind WHEN $2 THEN 17 ELSE 18 END,
		        expires_at = $1`,
		*fixture.now,
		topicConversation,
	)
	require.NoError(t, err)

	sweeper, err := NewRetentionSweeper(
		db,
		RetentionOptions{
			SweepInterval:        15 * time.Minute,
			Environment:          fixture.store.environment,
			Lookup:               fixture.store.lookup,
			EncryptionKeyVersion: fixture.store.encryption.ActiveVersion(),
			Now:                  func() time.Time { return *fixture.now },
		},
	)
	require.NoError(t, err)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)

	var (
		keyVersion int32
		fenceEpoch int64
	)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT key_version, fence_epoch
			   FROM hytch_push_vault.deletion_tombstones
			  WHERE target_kind = $1
			    AND target_identity = $2`,
			deletionTargetInstallation,
			installationIdentity,
		).Scan(&keyVersion, &fenceEpoch),
	)
	require.Equal(t, int32(19), keyVersion)
	require.Equal(t, int64(9), fenceEpoch)
	for _, route := range routes {
		require.NoError(
			t,
			db.QueryRowContext(
				t.Context(),
				`SELECT key_version, fence_epoch
				   FROM hytch_push_vault.deletion_tombstones
				  WHERE target_kind = $1
				    AND target_identity = $2`,
				deletionTargetRoute,
				route.identity,
			).Scan(&keyVersion, &fenceEpoch),
		)
		require.Equal(t, route.keyVersion, keyVersion)
		require.Equal(t, route.fenceEpoch, fenceEpoch)
	}
}
