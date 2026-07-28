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

func TestDeliveryFinalizationMigrationUpgradesExistingVersionNineRows(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 9))
	jobID, _ := seedVersionNineDeliveryRows(t, db)

	require.NoError(t, database.MigrateUpTo(t.Context(), db, 10))

	var (
		state        int16
		trafficClass sql.NullInt16
		finalReason  sql.NullInt16
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT state, traffic_class, final_reason
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		jobID,
	).Scan(&state, &trafficClass, &finalReason))
	require.Equal(t, int16(1), state)
	require.False(t, trafficClass.Valid)
	require.False(t, finalReason.Valid)

	var aggregateRows int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.operational_aggregates
		  WHERE event_name = 1
		    AND component = 1
		    AND environment = 1
		    AND traffic_class = 0
		    AND outcome = 1
		    AND privacy_version = 1`,
	).Scan(&aggregateRows))
	require.Equal(t, 1, aggregateRows)
}

func TestDeliveryFinalizationMigrationRejectsInvalidFixedShapes(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 10))
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	markerCases := []struct {
		name          string
		encrypted     []byte
		retryExponent int16
		trafficClass  any
		finalReason   any
	}{
		{
			name:         "terminal reason cannot use unknown traffic",
			encrypted:    []byte{0},
			trafficClass: int16(0),
			finalReason:  int16(1),
		},
		{
			name:         "marker cannot retain ciphertext",
			encrypted:    []byte{9, 9},
			trafficClass: int16(1),
			finalReason:  int16(1),
		},
		{
			name:         "marker requires traffic",
			encrypted:    []byte{0},
			trafficClass: nil,
			finalReason:  int16(5),
		},
		{
			name:         "marker requires reason",
			encrypted:    []byte{0},
			trafficClass: int16(1),
			finalReason:  nil,
		},
		{
			name:          "marker cannot carry erasure retry state",
			encrypted:     []byte{0},
			retryExponent: 1,
			trafficClass:  int16(1),
			finalReason:   int16(1),
		},
	}
	for index, testCase := range markerCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := db.ExecContext(
				t.Context(),
				`INSERT INTO hytch_push_vault.delivery_jobs (
				     job_id, encrypted_job, environment, state, attempts,
				     retry_exponent, available_at, expires_at, created_at,
				     traffic_class, final_reason
				 ) VALUES ($1,$2,1,5,0,$3,$4,$5,$4,$6,$7)`,
				bytes.Repeat([]byte{byte(index + 1)}, 16),
				testCase.encrypted,
				testCase.retryExponent,
				now,
				now.Add(10*time.Minute),
				testCase.trafficClass,
				testCase.finalReason,
			)
			requireSQLState(t, err, "23514")
		})
	}

	aggregateCases := []struct {
		name         string
		eventName    int16
		component    int16
		trafficClass int16
		outcome      int16
		sizeBucket   any
		privacy      int16
	}{
		{
			name:         "terminal outcome cannot use unknown traffic",
			eventName:    3,
			component:    1,
			trafficClass: 0,
			outcome:      1,
			sizeBucket:   int16(1),
			privacy:      2,
		},
		{
			name:         "delivery event requires size bucket",
			eventName:    3,
			component:    1,
			trafficClass: 1,
			outcome:      1,
			sizeBucket:   nil,
			privacy:      2,
		},
		{
			name:         "event outcome pairing is fixed",
			eventName:    5,
			component:    1,
			trafficClass: 1,
			outcome:      1,
			sizeBucket:   int16(0),
			privacy:      2,
		},
		{
			name:         "component is fixed",
			eventName:    3,
			component:    2,
			trafficClass: 1,
			outcome:      1,
			sizeBucket:   int16(1),
			privacy:      2,
		},
		{
			name:         "privacy version is allowlisted",
			eventName:    3,
			component:    1,
			trafficClass: 1,
			outcome:      1,
			sizeBucket:   int16(1),
			privacy:      3,
		},
	}
	for index, testCase := range aggregateCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := db.ExecContext(
				t.Context(),
				`INSERT INTO hytch_push_vault.operational_aggregates (
				     bucket_day, bucket_hour, event_name, component,
				     environment, traffic_class, outcome, count_bucket,
				     size_bucket, latency_bucket, privacy_version, expires_on
				 ) VALUES (
				     $1::date,$2,$3,$4,1,$5,$6,1,$7,0,$8,$9::date
				 )`,
				now,
				int16(index),
				testCase.eventName,
				testCase.component,
				testCase.trafficClass,
				testCase.outcome,
				testCase.sizeBucket,
				testCase.privacy,
				now.AddDate(0, 0, 30),
			)
			requireSQLState(t, err, "23514")
		})
	}

	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.operational_aggregates (
		     bucket_day, bucket_hour, event_name, component, environment,
		     traffic_class, outcome, count_bucket, size_bucket,
		     latency_bucket, privacy_version, expires_on
		 ) VALUES ($1::date,12,3,1,1,1,1,1,1,0,2,$2::date)`,
		now,
		now.AddDate(0, 0, 30),
	)
	require.NoError(t, err)
}

func TestDeliveryFinalizationMigrationDownBlocksMarkersThenPreservesRows(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 9))
	normalJobID, _ := seedVersionNineDeliveryRows(t, db)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 10))
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	finalJobID := bytes.Repeat([]byte{0x7f}, 16)
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.delivery_jobs (
		     job_id, encrypted_job, environment, state, attempts,
		     retry_exponent, available_at, expires_at, created_at,
		     traffic_class, final_reason
		 ) VALUES ($1,$2,1,5,1,0,$3,$4,$3,1,1)`,
		finalJobID,
		[]byte{0},
		now,
		now.Add(10*time.Minute),
	)
	require.NoError(t, err)

	down := readDeliveryFinalizationMigration(t, "down")
	_, err = db.ExecContext(t.Context(), down)
	require.Error(t, err)
	assertDeliveryFinalizationColumns(t, db, true)

	_, err = db.ExecContext(
		t.Context(),
		`DELETE FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		finalJobID,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), down)
	require.NoError(t, err)
	assertDeliveryFinalizationColumns(t, db, false)

	var state int16
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT state
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		normalJobID,
	).Scan(&state))
	require.Equal(t, int16(1), state)
}

func seedVersionNineDeliveryRows(
	t *testing.T,
	db *sql.DB,
) ([]byte, []byte) {
	t.Helper()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	installationLookup := bytes.Repeat([]byte{0x11}, 32)
	leaseID := bytes.Repeat([]byte{0x12}, 16)
	jobID := bytes.Repeat([]byte{0x13}, 16)
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.installation_states (
		     installation_lookup, incarnation_lookup, lookup_key_epoch,
		     generation, idempotency_digest, control_event_digest,
		     encrypted_apns_token, environment, payload_schema, age_policy,
		     policy_epoch, state, encryption_key_version, created_at,
		     refreshed_at, expires_at, control_expires_at,
		     installation_identity
		 ) VALUES ($1,$2,1,1,$3,$4,$5,1,1,1,1,2,1,$6,$6,$7,$8,$9)`,
		installationLookup,
		bytes.Repeat([]byte{0x14}, 32),
		bytes.Repeat([]byte{0x15}, 32),
		bytes.Repeat([]byte{0x16}, 32),
		[]byte{2},
		now,
		now.Add(7*24*time.Hour),
		now.Add(time.Minute),
		bytes.Repeat([]byte{0x17}, 32),
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.subscription_leases (
		     lease_id, installation_lookup, topic_lookup, lookup_key_epoch,
		     encrypted_topic, encrypted_route_key, encrypted_hmac_keys,
		     encrypted_receive_capability, environment, payload_schema,
		     topic_kind, push_mode, state, generation, policy_epoch,
		     route_key_epoch, encrypted_nonce_state, encryption_key_version,
		     issued_at, refreshed_at, expires_at, control_expires_at,
		     route_identity
		 ) VALUES (
		     $1,$2,$3,1,$4,$4,$4,$4,1,1,1,2,2,1,1,1,$4,1,
		     $5,$5,$6,$7,$8
		 )`,
		leaseID,
		installationLookup,
		bytes.Repeat([]byte{0x18}, 32),
		[]byte{2},
		now,
		now.Add(7*24*time.Hour),
		now.Add(time.Minute),
		bytes.Repeat([]byte{0x19}, 32),
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.delivery_jobs (
		     job_id, lease_id, encrypted_job, environment, state, attempts,
		     retry_exponent, available_at, expires_at, created_at
		 ) VALUES ($1,$2,$3,1,1,0,0,$4,$5,$4)`,
		jobID,
		leaseID,
		[]byte{3},
		now,
		now.Add(10*time.Minute),
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.operational_aggregates (
		     bucket_day, bucket_hour, event_name, component, environment,
		     traffic_class, outcome, count_bucket, size_bucket,
		     latency_bucket, privacy_version, expires_on
		 ) VALUES ($1::date,12,1,1,1,0,1,1,NULL,0,1,$2::date)`,
		now,
		now.AddDate(0, 0, 30),
	)
	require.NoError(t, err)
	return jobID, leaseID
}

func readDeliveryFinalizationMigration(
	t *testing.T,
	direction string,
) string {
	t.Helper()
	contents, err := os.ReadFile(
		"migrations/00010_delivery_finalization_controls." +
			direction + ".sql",
	)
	require.NoError(t, err)
	return string(contents)
}

func assertDeliveryFinalizationColumns(
	t *testing.T,
	db *sql.DB,
	expected bool,
) {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM information_schema.columns
		  WHERE table_schema = 'hytch_push_vault'
		    AND table_name = 'delivery_jobs'
		    AND column_name IN ('traffic_class', 'final_reason')`,
	).Scan(&count))
	if expected {
		require.Equal(t, 2, count)
		return
	}
	require.Zero(t, count)
}
