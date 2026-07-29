package vault

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

func TestTypedTombstoneReapplyIsInstallationAndRouteScoped(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	tombstoneTime := *fixture.now
	conversation := testTopic(t, topicpkg.TopicKindGroupMessagesV1, 0x71)
	stitchedConversation := testTopic(
		t,
		topicpkg.TopicKindGroupMessagesV1,
		0x72,
	)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	request := fixture.refresh(
		t,
		1,
		control,
		fixture.subscription(
			t,
			conversation,
			0x73,
			1,
			688,
			authority.PushModeAlertAllowed,
			1,
		),
		fixture.subscription(
			t,
			stitchedConversation,
			0x74,
			1,
			688,
			authority.PushModeAlertAllowed,
			1,
		),
	)
	_, err := fixture.store.Refresh(t.Context(), request)
	require.NoError(t, err)

	var (
		installationIdentity []byte
	)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT installation_identity
			   FROM hytch_push_vault.installation_states`,
		).Scan(&installationIdentity),
	)
	conversationIdentity, err := fixture.store.routeHistoryIdentity(
		fixture.installationID,
		conversation.Bytes(),
	)
	require.NoError(t, err)
	stitchedConversationIdentity, err := fixture.store.routeHistoryIdentity(
		fixture.installationID,
		stitchedConversation.Bytes(),
	)
	require.NoError(t, err)
	require.NotEqual(t, conversationIdentity, stitchedConversationIdentity)
	var (
		conversationIdentityCount         int
		stitchedConversationIdentityCount int
	)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FILTER (WHERE route_identity = $1),
			        COUNT(*) FILTER (WHERE route_identity = $2)
			   FROM hytch_push_vault.subscription_leases`,
			conversationIdentity,
			stitchedConversationIdentity,
		).Scan(
			&conversationIdentityCount,
			&stitchedConversationIdentityCount,
		),
	)
	require.Len(t, installationIdentity, 32)
	require.Len(t, conversationIdentity, 32)
	require.Len(t, stitchedConversationIdentity, 32)
	require.Equal(t, 1, conversationIdentityCount)
	require.Equal(t, 1, stitchedConversationIdentityCount)
	require.False(
		t,
		bytes.Contains(
			installationIdentity,
			[]byte(fixture.installationID),
		),
	)
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(
		t,
		upsertDeletionTombstone(
			t.Context(),
			tx,
			fixture.store.environmentID,
			deletionTargetRoute,
			conversationIdentity,
			fixture.store.encryption.ActiveVersion(),
			1,
			*fixture.now,
		),
	)
	require.NoError(t, tx.Commit())
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.subscription_leases
		    SET refreshed_at = $1
		  WHERE route_identity = $2`,
		tombstoneTime.Add(time.Second),
		conversationIdentity,
	)
	require.NoError(t, err)
	require.NoError(
		t,
		fixture.store.ReapplyDeletionTombstones(t.Context()),
	)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FILTER (WHERE route_identity = $1),
			        COUNT(*) FILTER (WHERE route_identity = $2)
			   FROM hytch_push_vault.subscription_leases`,
			conversationIdentity,
			stitchedConversationIdentity,
		).Scan(
			&conversationIdentityCount,
			&stitchedConversationIdentityCount,
		),
	)
	require.Zero(t, conversationIdentityCount)
	require.Equal(t, 1, stitchedConversationIdentityCount)

	tx, err = db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(
		t,
		upsertDeletionTombstone(
			t.Context(),
			tx,
			fixture.store.environmentID,
			deletionTargetInstallation,
			installationIdentity,
			fixture.store.encryption.ActiveVersion(),
			1,
			*fixture.now,
		),
	)
	require.NoError(t, tx.Commit())
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.installation_states
		    SET refreshed_at = $1
		  WHERE installation_identity = $2`,
		tombstoneTime.Add(time.Second),
		installationIdentity,
	)
	require.NoError(t, err)
	require.NoError(
		t,
		fixture.store.ReapplyDeletionTombstones(t.Context()),
	)
	var installationCount int
	var conversationCount int
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*)
			   FROM hytch_push_vault.installation_states`,
		).Scan(&installationCount),
	)
	require.Zero(t, installationCount)

	// A still-valid replay at the erased installation epoch cannot resurrect
	// either the installation or its routes.
	_, err = fixture.store.Refresh(t.Context(), request)
	require.ErrorIs(t, err, ErrRefreshConflict)

	// Raising only the signed installation policy epoch is insufficient: each
	// erased route also requires a strictly higher route-key epoch.
	*fixture.now = fixture.now.Add(time.Second)
	freshControl := fixture.policy(
		t,
		2,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	_, err = fixture.store.Refresh(
		t.Context(),
		fixture.refresh(
			t,
			2,
			freshControl,
			fixture.subscription(
				t,
				conversation,
				0x75,
				1,
				688,
				authority.PushModeAlertAllowed,
				2,
			),
			fixture.subscription(
				t,
				stitchedConversation,
				0x76,
				1,
				688,
				authority.PushModeAlertAllowed,
				2,
			),
		),
	)
	require.ErrorIs(t, err, ErrRefreshConflict)

	// The tombstone is a restore cutoff, not a permanent denylist. A later
	// signed generation with higher installation and route-key epochs must
	// survive subsequent startup reapplication.
	_, err = fixture.store.Refresh(
		t.Context(),
		fixture.refresh(
			t,
			2,
			freshControl,
			fixture.subscription(
				t,
				conversation,
				0x75,
				2,
				688,
				authority.PushModeAlertAllowed,
				2,
			),
			fixture.subscription(
				t,
				stitchedConversation,
				0x76,
				2,
				688,
				authority.PushModeAlertAllowed,
				2,
			),
		),
	)
	require.NoError(t, err)
	staleTimestamp := tombstoneTime.Add(-time.Second)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.installation_states
		    SET refreshed_at = $1,
		        expires_at = $1::timestamptz + INTERVAL '7 days'
		  WHERE installation_identity = $2`,
		staleTimestamp,
		installationIdentity,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.subscription_leases
		    SET refreshed_at = $1,
		        expires_at = $1::timestamptz + INTERVAL '7 days'
		  WHERE installation_lookup = (
		      SELECT installation_lookup
		        FROM hytch_push_vault.installation_states
		       WHERE installation_identity = $2
		  )`,
		staleTimestamp,
		installationIdentity,
	)
	require.NoError(t, err)
	require.NoError(
		t,
		fixture.store.ReapplyDeletionTombstones(t.Context()),
	)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*)
			   FROM hytch_push_vault.installation_states`,
		).Scan(&installationCount),
	)
	require.Equal(t, 1, installationCount)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*)
			   FROM hytch_push_vault.subscription_leases
			  WHERE topic_kind = $1`,
			topicConversation,
		).Scan(&conversationCount),
	)
	require.Equal(t, 2, conversationCount)
}

func TestDeletionTombstoneFenceIsMonotonicAndBlocksStaleAdvance(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	identity := repeatedBytes(32, 0x7a)
	firstCreatedAt := *fixture.now

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(
		t,
		upsertDeletionTombstone(
			t.Context(),
			tx,
			fixture.store.environmentID,
			deletionTargetRoute,
			identity,
			7,
			4,
			firstCreatedAt,
		),
	)
	require.NoError(t, tx.Commit())

	tx, err = db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(
		t,
		upsertDeletionTombstone(
			t.Context(),
			tx,
			fixture.store.environmentID,
			deletionTargetRoute,
			identity,
			8,
			3,
			firstCreatedAt.Add(time.Hour),
		),
	)
	require.NoError(t, tx.Commit())

	var (
		keyVersion int32
		fenceEpoch int64
		createdAt  time.Time
		expiresAt  time.Time
	)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT key_version, fence_epoch, created_at, expires_at
			   FROM hytch_push_vault.deletion_tombstones
			  WHERE target_kind = $1
			    AND target_identity = $2`,
			deletionTargetRoute,
			identity,
		).Scan(
			&keyVersion,
			&fenceEpoch,
			&createdAt,
			&expiresAt,
		),
	)
	require.Equal(t, int32(7), keyVersion)
	require.Equal(t, int64(4), fenceEpoch)
	require.True(t, firstCreatedAt.Equal(createdAt))
	require.True(t, firstCreatedAt.Add(8*24*time.Hour).Equal(expiresAt))

	tx, err = db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.ErrorIs(
		t,
		requireTombstoneAdvance(
			t.Context(),
			tx,
			fixture.store.environmentID,
			deletionTargetRoute,
			identity,
			4,
			firstCreatedAt,
		),
		ErrRefreshConflict,
	)
	require.NoError(t, tx.Rollback())

	tx, err = db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(
		t,
		requireTombstoneAdvance(
			t.Context(),
			tx,
			fixture.store.environmentID,
			deletionTargetRoute,
			identity,
			5,
			firstCreatedAt,
		),
	)
	require.NoError(t, tx.Rollback())

	secondCreatedAt := firstCreatedAt.Add(2 * time.Hour)
	tx, err = db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(
		t,
		upsertDeletionTombstone(
			t.Context(),
			tx,
			fixture.store.environmentID,
			deletionTargetRoute,
			identity,
			9,
			5,
			secondCreatedAt,
		),
	)
	require.NoError(t, tx.Commit())
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT key_version, fence_epoch, created_at, expires_at
			   FROM hytch_push_vault.deletion_tombstones
			  WHERE target_kind = $1
			    AND target_identity = $2`,
			deletionTargetRoute,
			identity,
		).Scan(
			&keyVersion,
			&fenceEpoch,
			&createdAt,
			&expiresAt,
		),
	)
	require.Equal(t, int32(9), keyVersion)
	require.Equal(t, int64(5), fenceEpoch)
	require.True(t, secondCreatedAt.Equal(createdAt))
	require.True(t, secondCreatedAt.Add(8*24*time.Hour).Equal(expiresAt))
}
