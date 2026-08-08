package db_test

import (
	"bytes"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestSecureVaultMigrationUpDownUp(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 6))
	assertQualifiedRelationExists(
		t,
		db,
		"hytch_push_vault.installation_states",
	)

	down, err := os.ReadFile(
		"migrations/00006_secure_routing_vault.down.sql",
	)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), string(down))
	require.NoError(t, err)
	assertQualifiedRelationMissing(
		t,
		db,
		"hytch_push_vault.installation_states",
	)

	up, err := os.ReadFile(
		"migrations/00006_secure_routing_vault.up.sql",
	)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), string(up))
	require.NoError(t, err)
	assertQualifiedRelationExists(
		t,
		db,
		"hytch_push_vault.installation_states",
	)
}

func TestSecureVaultHourChecksUseUTC(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 6))

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() {
		_ = tx.Rollback()
	}()
	_, err = tx.ExecContext(
		t.Context(),
		`SET LOCAL TIME ZONE 'America/Los_Angeles'`,
	)
	require.NoError(t, err)
	var sessionTimeZone string
	require.NoError(
		t,
		tx.QueryRowContext(t.Context(), `SHOW TimeZone`).Scan(&sessionTimeZone),
	)
	require.Equal(t, "America/Los_Angeles", sessionTimeZone)

	coarseHour := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	requestID := bytes.Repeat([]byte{0x21}, 16)
	_, err = tx.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.access_requests (
		     request_id, environment, purpose, data_class, requester_actor,
		     ticket_reference, hypothesis, window_start, window_end,
		     approver_actor, oversight_broadcast_hour, coarse_created_hour,
		     role_expires_at, state
		 ) VALUES ($1,1,1,1,$2,$3,1,$4,$5,$6,$5,$5,$7,2)`,
		requestID,
		"requester:utc-check",
		"incident:utc-check",
		coarseHour.Add(-time.Hour),
		coarseHour,
		"approver:utc-check",
		coarseHour.Add(time.Hour),
	)
	require.NoError(t, err)

	_, err = tx.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.access_audit (
		     event_id, request_id, environment, actor, purpose, data_class,
		     coarse_event_hour, action, result_count_bucket, expires_on
		 ) VALUES ($1,$2,1,$3,1,1,$4,1,0,$5::date)`,
		bytes.Repeat([]byte{0x22}, 16),
		requestID,
		"requester:utc-check",
		coarseHour,
		"2026-07-26",
	)
	require.NoError(t, err)

	// The retention ceiling is also anchored to the UTC day, rather than the
	// session-local date of the stored timestamptz.
	_, err = tx.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.access_audit (
		     event_id, request_id, environment, actor, purpose, data_class,
		     coarse_event_hour, action, result_count_bucket, expires_on
		 ) VALUES ($1,$2,1,$3,1,1,$4,1,0,$5::date)`,
		bytes.Repeat([]byte{0x23}, 16),
		requestID,
		"requester:utc-check",
		coarseHour,
		coarseHour.AddDate(0, 0, 180),
	)
	require.NoError(t, err)
}

func TestSecureVaultEnvironmentKeysAndForeignKeys(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 6))

	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	installationLookup := bytes.Repeat([]byte{0x31}, 32)
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.installation_states (
		     installation_lookup, installation_identity, incarnation_lookup,
		     lookup_key_epoch, generation, idempotency_digest,
		     control_event_digest, encrypted_apns_token, environment,
		     payload_schema, age_policy, policy_epoch, state,
		     encryption_key_version, created_at, refreshed_at, expires_at,
		     control_expires_at, revoked_at
		 ) VALUES (
		     $1,$2,$3,1,1,$4,$5,NULL,1,1,1,1,2,1,$6,$6,$7,$8,NULL
		 )`,
		installationLookup,
		bytes.Repeat([]byte{0x32}, 32),
		bytes.Repeat([]byte{0x33}, 32),
		bytes.Repeat([]byte{0x34}, 32),
		bytes.Repeat([]byte{0x35}, 32),
		now,
		now.Add(24*time.Hour),
		now.Add(30*time.Second),
	)
	require.NoError(t, err)

	leaseID := bytes.Repeat([]byte{0x41}, 16)
	insertLease := func(id []byte, environment int16, topicByte byte) error {
		_, insertErr := db.ExecContext(
			t.Context(),
			`INSERT INTO hytch_push_vault.subscription_leases (
			     lease_id, installation_lookup, route_identity, topic_lookup,
			     lookup_key_epoch, encrypted_topic, encrypted_route_key,
			     encrypted_hmac_keys, encrypted_receive_capability,
			     environment, payload_schema, topic_kind, push_mode, state,
			     generation, policy_epoch, route_key_epoch,
			     encrypted_nonce_state, encryption_key_version, issued_at,
			     refreshed_at, expires_at, control_expires_at, revoked_at
			 ) VALUES (
			     $1,$2,$3,$4,1,$5,$5,$5,$5,$6,1,1,1,2,1,1,1,$5,1,
			     $7,$7,$8,$9,NULL
			 )`,
			id,
			installationLookup,
			bytes.Repeat([]byte{topicByte + 1}, 32),
			bytes.Repeat([]byte{topicByte}, 32),
			[]byte{0x01},
			environment,
			now,
			now.Add(24*time.Hour),
			now.Add(30*time.Second),
		)
		return insertErr
	}
	require.NoError(t, insertLease(leaseID, 1, 0x42))
	require.Error(
		t,
		insertLease(bytes.Repeat([]byte{0x43}, 16), 2, 0x44),
	)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.welcome_authorizations (
		     authorization_id, lease_id, environment, envelope_lookup,
		     encrypted_authorization, policy_epoch, issued_at, expires_at,
		     consumed_at
		 ) VALUES ($1,$2,2,$3,$4,1,$5,$6,NULL)`,
		bytes.Repeat([]byte{0x45}, 16),
		leaseID,
		bytes.Repeat([]byte{0x46}, 32),
		[]byte{0x01},
		now,
		now.Add(time.Minute),
	)
	require.Error(t, err)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.delivery_jobs (
		     job_id, lease_id, encrypted_job, environment, state, attempts,
		     retry_exponent, available_at, expires_at, created_at
		 ) VALUES ($1,$2,$3,2,1,0,0,$4,$5,$4)`,
		bytes.Repeat([]byte{0x51}, 16),
		leaseID,
		[]byte{0x01},
		now,
		now.Add(time.Minute),
	)
	require.Error(t, err)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.delivery_dedupes (
		     lease_id, source_event_lookup, environment, traffic_class,
		     created_at, expires_at
		 ) VALUES ($1,$2,2,1,$3,$4)`,
		leaseID,
		bytes.Repeat([]byte{0x52}, 32),
		now,
		now.Add(time.Minute),
	)
	require.Error(t, err)

	requestID := bytes.Repeat([]byte{0x61}, 16)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.access_requests (
		     request_id, environment, purpose, data_class, requester_actor,
		     ticket_reference, hypothesis, window_start, window_end,
		     coarse_created_hour, state
		 ) VALUES ($1,1,1,1,$2,$3,1,$4,$5,$5,1)`,
		requestID,
		"requester:environment",
		"incident:environment",
		now.Add(-time.Hour),
		now,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.access_audit (
		     event_id, request_id, environment, actor, purpose, data_class,
		     coarse_event_hour, action, result_count_bucket, expires_on
		 ) VALUES ($1,$2,2,$3,1,1,$4,1,0,$5::date)`,
		bytes.Repeat([]byte{0x62}, 16),
		requestID,
		"requester:environment",
		now,
		now.AddDate(0, 0, 180),
	)
	require.Error(t, err)

	sharedDigest := bytes.Repeat([]byte{0x71}, 32)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.welcome_budgets (
		     environment, destination_lookup, minute_window_start,
		     minute_count, hour_window_start, hour_count, updated_at,
		     expires_at
		 ) VALUES
		     (1,$1,$2,0,$2,0,$2,$3),
		     (2,$1,$2,0,$2,0,$2,$3)`,
		sharedDigest,
		now,
		now.Add(time.Hour),
	)
	require.NoError(t, err)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.route_key_history (
		     environment, route_identity, route_key_epoch,
		     route_key_commitment, updated_at, expires_at
		 ) VALUES
		     (1,$1,1,$2,$3,$4),
		     (2,$1,1,$2,$3,$4)`,
		bytes.Repeat([]byte{0x72}, 32),
		bytes.Repeat([]byte{0x73}, 32),
		now,
		now.Add(24*time.Hour),
	)
	require.NoError(t, err)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.deletion_tombstones (
		     environment, target_kind, target_identity, key_version,
		     fence_epoch, created_at, expires_at
		 ) VALUES
		     (1,2,$1,1,1,$2,$3),
		     (2,2,$1,1,1,$2,$3)`,
		bytes.Repeat([]byte{0x74}, 32),
		now,
		now.Add(8*24*time.Hour),
	)
	require.NoError(t, err)

	var retentionEnvironmentCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.retention_state
		  WHERE environment IN (1, 2)`,
	).Scan(&retentionEnvironmentCount))
	require.Equal(t, 2, retentionEnvironmentCount)
}

func assertQualifiedRelationMissing(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(
		t.Context(),
		`SELECT to_regclass($1) IS NOT NULL`,
		name,
	).Scan(&exists)
	require.NoError(t, err)
	require.False(t, exists, name)
}
