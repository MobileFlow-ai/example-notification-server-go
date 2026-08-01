package db_test

import (
	"bytes"
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

var a9TableNames = []string{
	"a9_accepted_keysets",
	"a9_online_key_descriptors",
	"a9_commitment_key_descriptors",
	"a9_keyset_state",
	"a9_service_jti_receipts",
	"a9_idempotency_receipts",
	"a9_installation_authority",
	"a9_watermarks",
	"a9_installation_gate6_bindings",
	"a9_control_events",
	"a9_assertions",
	"a9_bindings",
	"a9_binding_tombstones",
	"a9_subscription_routes",
}

func TestA9MigrationUpgradesVersionElevenFailClosed(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 11))
	require.Error(t, database.RequireCurrentSchema(t.Context(), db))

	var a9Absent bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.to_regclass(
		     'hytch_push_vault.a9_installation_authority'
		 ) IS NULL`,
	).Scan(&a9Absent))
	require.True(t, a9Absent)

	insertLegacyFinalDeliveryJob(t, db, "19")
	require.NoError(t, database.Migrate(t.Context(), db))
	require.NoError(t, database.RequireCurrentSchema(t.Context(), db))

	var (
		version int
		dirty   bool
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT version, dirty FROM public.schema_migrations`,
	).Scan(&version, &dirty))
	require.Equal(t, 12, version)
	require.False(t, dirty)

	for _, tableName := range a9TableNames {
		var rowCount int
		require.NoError(t, db.QueryRowContext(
			t.Context(),
			fmt.Sprintf(
				"SELECT COUNT(*) FROM hytch_push_vault.%s",
				tableName,
			),
		).Scan(&rowCount))
		require.Zero(t, rowCount, tableName)
	}

	var legacyJobsWithA9State int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.delivery_jobs
		  WHERE a9_installation_binding_id IS NOT NULL
		     OR a9_sequencer_epoch IS NOT NULL
		     OR a9_subscription_generation IS NOT NULL
		     OR a9_binding_id IS NOT NULL
		     OR a9_binding_version IS NOT NULL
		     OR a9_assertion_hash IS NOT NULL
		     OR a9_assertion_stream_sequence IS NOT NULL
		     OR a9_topic_key_epoch IS NOT NULL
		     OR a9_topic_binding IS NOT NULL
		     OR a9_route_key_epoch IS NOT NULL
		     OR a9_keyset_sequence IS NOT NULL
		     OR a9_keyset_hash IS NOT NULL
		     OR a9_watermark_sequence IS NOT NULL`,
	).Scan(&legacyJobsWithA9State))
	require.Zero(t, legacyJobsWithA9State)

	var eligibleLegacyJobs int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.delivery_jobs AS jobs
		   JOIN hytch_push_vault.a9_subscription_routes AS routes
		     ON routes.lease_id = jobs.lease_id
		    AND routes.environment = jobs.environment`,
	).Scan(&eligibleLegacyJobs))
	require.Zero(t, eligibleLegacyJobs)
}

func TestA9MigrationEmptyStateRoundTripsToVersionEleven(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 11))

	var (
		version   int
		dirty     bool
		a9Missing bool
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT version, dirty FROM public.schema_migrations`,
	).Scan(&version, &dirty))
	require.Equal(t, 11, version)
	require.False(t, dirty)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.to_regclass(
		     'hytch_push_vault.a9_accepted_keysets'
		 ) IS NULL`,
	).Scan(&a9Missing))
	require.True(t, a9Missing)

	require.NoError(t, database.Migrate(t.Context(), db))
	require.NoError(t, database.RequireCurrentSchema(t.Context(), db))
}

func TestA9MigrationDowngradeRefusesAuthorityState(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	insertA9AcceptedKeyset(t, db)

	err := database.MigrateUpTo(t.Context(), db, 11)
	require.Error(t, err)
	require.Contains(t, err.Error(), "SQLSTATE 55000")

	var keysetStillPresent bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.a9_accepted_keysets
		 )`,
	).Scan(&keysetStillPresent))
	require.True(t, keysetStillPresent)
}

func TestA9MigrationDowngradeRefusesGate6BindingState(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	insertValidA9AuthorityGraph(t, db)

	err := database.MigrateUpTo(t.Context(), db, 11)
	require.Error(t, err)
	require.Contains(t, err.Error(), "SQLSTATE 55000")

	var mappingStillPresent bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.a9_installation_gate6_bindings
		      WHERE environment = 1
		        AND installation_binding_id =
		                decode(repeat('aa', 16), 'hex')
		        AND installation_identity =
		                decode(repeat('11', 32), 'hex')
		 )`,
	).Scan(&mappingStillPresent))
	require.True(t, mappingStillPresent)
}

func TestA9MigrationStableIdentitySurvivesLookupEpochRotation(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	insertValidA9AuthorityGraph(t, db)

	_, err := db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.installation_states
		    SET installation_lookup = decode(repeat('20', 32), 'hex'),
		        lookup_key_epoch = 2
		  WHERE environment = 1
		    AND installation_identity =
		            decode(repeat('11', 32), 'hex')`,
	)
	require.NoError(t, err)

	var (
		leaseLookup     []byte
		leaseIdentity   []byte
		mappingIdentity []byte
		routeIdentity   []byte
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT lease.installation_lookup,
		        lease.installation_identity,
		        mapping.installation_identity,
		        route.installation_identity
		   FROM hytch_push_vault.subscription_leases AS lease
		   JOIN hytch_push_vault.a9_subscription_routes AS route
		     ON route.lease_id = lease.lease_id
		    AND route.environment = lease.environment
		    AND route.installation_identity =
		        lease.installation_identity
		   JOIN hytch_push_vault.a9_installation_gate6_bindings AS mapping
		     ON mapping.environment = route.environment
		    AND mapping.installation_binding_id =
		        route.installation_binding_id
		    AND mapping.installation_identity =
		        route.installation_identity
		  WHERE lease.lease_id = decode(repeat('17', 16), 'hex')`,
	).Scan(
		&leaseLookup,
		&leaseIdentity,
		&mappingIdentity,
		&routeIdentity,
	))
	require.Equal(t, bytes.Repeat([]byte{0x20}, 32), leaseLookup)
	for _, identity := range [][]byte{
		leaseIdentity,
		mappingIdentity,
		routeIdentity,
	} {
		require.Equal(t, bytes.Repeat([]byte{0x11}, 32), identity)
	}
}

func TestA9MigrationRejectsPrivateAndOutOfDomainState(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))

	rows, err := db.QueryContext(
		t.Context(),
		`SELECT table_name, column_name
		   FROM information_schema.columns
		  WHERE table_schema = 'hytch_push_vault'
		    AND (
		        table_name LIKE 'a9\_%' ESCAPE '\' OR
		        (
		            table_name = 'delivery_jobs' AND
		            column_name LIKE 'a9\_%' ESCAPE '\'
		        )
		    )`,
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, rows.Close())
	}()

	columns := make(map[string]struct{})
	for rows.Next() {
		var tableName string
		var columnName string
		require.NoError(t, rows.Scan(&tableName, &columnName))
		columns[tableName+"."+columnName] = struct{}{}
	}
	require.NoError(t, rows.Err())

	for _, prohibited := range []string{
		"a9_assertions.signature_base64url",
		"a9_assertions.signed_assertion_jcs",
		"a9_assertions.roster_digest",
		"a9_assertions.account_incarnation_id",
		"a9_assertions.conversation_id",
		"a9_assertions.transport_conversation_id",
		"a9_installation_gate6_bindings.legacy_installation_id",
		"a9_installation_gate6_bindings.installation_id",
		"a9_installation_gate6_bindings.account_incarnation_id",
		"a9_subscription_routes.topic_base64url",
		"a9_subscription_routes.legacy_installation_id",
		"a9_subscription_routes.apns_token_base64url",
		"a9_subscription_routes.route_key_base64url",
		"a9_subscription_routes.hmac_keys",
		"a9_subscription_routes.receive_capability_base64url",
	} {
		_, exists := columns[prohibited]
		require.False(t, exists, prohibited)
	}

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_accepted_keysets (
		     environment,
		     keyset_sequence,
		     signed_keyset_hash,
		     signed_keyset_jcs,
		     root_signing_key_id,
		     issued_at,
		     expires_at
		 ) VALUES (
		     1,
		     1,
		     decode(repeat('01', 31), 'hex'),
		     decode('7b7d', 'hex'),
		     decode(repeat('02', 32), 'hex'),
		     TIMESTAMPTZ '2026-07-29 00:00:00Z',
		     TIMESTAMPTZ '2026-07-29 23:00:00Z'
		 )`,
	)
	requireSQLState(t, err, "23514")

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_accepted_keysets (
		     environment,
		     keyset_sequence,
		     signed_keyset_hash,
		     signed_keyset_jcs,
		     root_signing_key_id,
		     issued_at,
		     expires_at
		 ) VALUES (
		     1,
		     9007199254740992,
		     decode(repeat('01', 32), 'hex'),
		     decode('7b7d', 'hex'),
		     decode(repeat('02', 32), 'hex'),
		     TIMESTAMPTZ '2026-07-29 00:00:00Z',
		     TIMESTAMPTZ '2026-07-29 23:00:00Z'
		 )`,
	)
	requireSQLState(t, err, "23514")

	insertA9AcceptedKeyset(t, db)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_online_key_descriptors (
		     environment,
		     keyset_sequence,
		     key_use,
		     key_state,
		     key_id,
		     public_key,
		     not_before,
		     not_after
		 ) VALUES
		     (
		         1,
		         1,
		         1,
		         1,
		         decode(repeat('03', 32), 'hex'),
		         decode(repeat('08', 32), 'hex'),
		         TIMESTAMPTZ '2026-07-28 23:00:00Z',
		         TIMESTAMPTZ '2026-07-29 23:00:00Z'
		     ),
		     (
		         1,
		         1,
		         1,
		         1,
		         decode(repeat('04', 32), 'hex'),
		         decode(repeat('09', 32), 'hex'),
		         TIMESTAMPTZ '2026-07-28 23:00:00Z',
		         TIMESTAMPTZ '2026-07-29 23:00:00Z'
		     )`,
	)
	requireSQLState(t, err, "23505")

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_commitment_key_descriptors (
		     environment,
		     keyset_sequence,
		     purpose,
		     key_id,
		     topic_key_epoch,
		     not_before,
		     not_after
		 ) VALUES (
		     1,
		     1,
		     3,
		     decode(repeat('07', 32), 'hex'),
		     NULL,
		     TIMESTAMPTZ '2026-07-28 23:00:00Z',
		     TIMESTAMPTZ '2026-07-29 23:00:00Z'
		 )`,
	)
	requireSQLState(t, err, "23514")

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_keyset_state (
		     environment,
		     keyset_sequence,
		     signed_keyset_hash,
		     state,
		     uncertainty_reason,
		     expires_at,
		     refreshed_at
		 ) VALUES (
		     2,
		     0,
		     NULL,
		     2,
		     1,
		     NULL,
		     TIMESTAMPTZ '2026-07-29 00:00:00Z'
		 )`,
	)
	require.NoError(t, err)

	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.a9_keyset_state
		    SET state = 1,
		        uncertainty_reason = 0
		  WHERE environment = 2`,
	)
	requireSQLState(t, err, "23514")

	insertLegacyFinalDeliveryJob(t, db, "1a")
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.delivery_jobs
		    SET a9_installation_binding_id =
		            decode(repeat('aa', 16), 'hex')
		  WHERE job_id = decode(repeat('1a', 16), 'hex')`,
	)
	requireSQLState(t, err, "23514")
}

func TestA9MigrationAppendOnlyAndJTIExpiryGuards(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))

	for _, tableName := range []string{
		"a9_accepted_keysets",
		"a9_online_key_descriptors",
		"a9_commitment_key_descriptors",
		"a9_watermarks",
		"a9_installation_gate6_bindings",
		"a9_idempotency_receipts",
		"a9_control_events",
		"a9_assertions",
		"a9_binding_tombstones",
	} {
		_, err := db.ExecContext(
			t.Context(),
			fmt.Sprintf(
				"UPDATE hytch_push_vault.%s "+
					"SET environment = environment WHERE FALSE",
				tableName,
			),
		)
		requireSQLState(t, err, "55000")

		_, err = db.ExecContext(
			t.Context(),
			fmt.Sprintf(
				"DELETE FROM hytch_push_vault.%s WHERE FALSE",
				tableName,
			),
		)
		requireSQLState(t, err, "55000")

		_, err = db.ExecContext(
			t.Context(),
			fmt.Sprintf(
				"TRUNCATE hytch_push_vault.%s CASCADE",
				tableName,
			),
		)
		requireSQLState(t, err, "55000")
	}

	_, err := db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.a9_service_jti_receipts
		    SET environment = environment
		  WHERE FALSE`,
	)
	requireSQLState(t, err, "55000")
	_, err = db.ExecContext(
		t.Context(),
		`TRUNCATE hytch_push_vault.a9_service_jti_receipts`,
	)
	requireSQLState(t, err, "55000")

	_, err = db.ExecContext(
		t.Context(),
		`WITH receipt_time AS (
		     SELECT pg_catalog.clock_timestamp() AS now
		 )
		 INSERT INTO hytch_push_vault.a9_service_jti_receipts (
		     environment,
		     jti,
		     jwt_expires_at,
		     delete_after,
		     consumed_at
		 )
		 SELECT
		     1,
		     '11111111-1111-4111-8111-111111111111',
		     receipt_time.now + INTERVAL '60 seconds',
		     receipt_time.now + INTERVAL '65 seconds',
		     receipt_time.now
		 FROM receipt_time`,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`DELETE FROM hytch_push_vault.a9_service_jti_receipts
		  WHERE environment = 1
		    AND jti = '11111111-1111-4111-8111-111111111111'`,
	)
	requireSQLState(t, err, "55000")

	_, err = db.ExecContext(
		t.Context(),
		`WITH receipt_time AS (
		     SELECT pg_catalog.clock_timestamp() AS now
		 )
		 INSERT INTO hytch_push_vault.a9_service_jti_receipts (
		     environment,
		     jti,
		     jwt_expires_at,
		     delete_after,
		     consumed_at
		 )
		 SELECT
		     1,
		     '22222222-2222-4222-8222-222222222222',
		     receipt_time.now - INTERVAL '10 seconds',
		     receipt_time.now - INTERVAL '5 seconds',
		     receipt_time.now - INTERVAL '20 seconds'
		 FROM receipt_time`,
	)
	require.NoError(t, err)
	result, err := db.ExecContext(
		t.Context(),
		`DELETE FROM hytch_push_vault.a9_service_jti_receipts
		  WHERE environment = 1
		    AND jti = '22222222-2222-4222-8222-222222222222'`,
	)
	require.NoError(t, err)
	deleted, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted)
}

func TestA9MigrationCrossBindsRoutesJobsAndGapRevokes(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	insertValidA9AuthorityGraph(t, db)

	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_installation_authority (
		     environment,
		     installation_binding_id,
		     sequencer_epoch,
		     contiguous_stream_sequence,
		     subscription_generation,
		     state,
		     uncertainty_reason,
		     created_at,
		     updated_at
		 ) VALUES (
		     1,
		     decode(repeat('ab', 16), 'hex'),
		     decode(repeat('bc', 16), 'hex'),
		     0,
		     0,
		     3,
		     1,
		     TIMESTAMPTZ '2026-07-29 00:00:00Z',
		     TIMESTAMPTZ '2026-07-29 00:00:00Z'
		 )`,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_installation_gate6_bindings (
		     environment,
		     installation_binding_id,
		     installation_identity
		 ) VALUES (
		     1,
		     decode(repeat('ab', 16), 'hex'),
		     decode(repeat('11', 32), 'hex')
		 )`,
	)
	// One keyed Gate-6 installation cannot be paired to two A9 installation
	// bindings, even if both A9 authority rows otherwise exist.
	requireSQLState(t, err, "23505")

	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.a9_subscription_routes
		    SET installation_binding_id =
		            decode(repeat('ab', 16), 'hex')
		  WHERE lease_id = decode(repeat('17', 16), 'hex')`,
	)
	requireSQLState(t, err, "23503")

	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.a9_subscription_routes
		    SET installation_identity =
		            decode(repeat('12', 32), 'hex')
		  WHERE lease_id = decode(repeat('17', 16), 'hex')`,
	)
	// The route must match both the append-only A9/Gate-6 mapping and the
	// stable installation identity on the exact Gate-6 lease.
	requireSQLState(t, err, "23503")

	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.a9_subscription_routes
		    SET replacement_idempotency_key =
		            '11111111-1111-4111-8111-111111111111'
		  WHERE lease_id = decode(repeat('17', 16), 'hex')`,
	)
	// A CONTROL receipt cannot be reused as ACTIVE/APPLIED replacement
	// provenance even when installation, epoch, and generation match.
	requireSQLState(t, err, "23503")

	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.delivery_jobs
		    SET a9_topic_binding = decode(repeat('ff', 32), 'hex')
		  WHERE job_id = decode(repeat('18', 16), 'hex')`,
	)
	requireSQLState(t, err, "23503")

	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.delivery_jobs
		    SET state = 5
		  WHERE job_id = decode(repeat('18', 16), 'hex')`,
	)
	requireSQLState(t, err, "23514")

	insertA9ControlReceipt(
		t,
		db,
		"33333333-3333-4333-8333-333333333333",
		"21",
		4,
		2,
	)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_control_events (
		     environment,
		     installation_binding_id,
		     sequencer_epoch,
		     stream_sequence,
		     expected_previous_sequence,
		     binding_id,
		     binding_version,
		     expected_binding_version,
		     action,
		     assertion_hash,
		     reason_code,
		     idempotency_key,
		     signed_event_hash,
		     stream_is_contiguous,
		     issued_at,
		     expires_at,
		     signing_key_id,
		     keyset_sequence,
		     keyset_hash
		 ) VALUES (
		     1,
		     decode(repeat('aa', 16), 'hex'),
		     decode(repeat('bb', 16), 'hex'),
		     3,
		     2,
		     decode(repeat('cc', 16), 'hex'),
		     2,
		     1,
		     2,
		     decode(repeat('20', 32), 'hex'),
		     1,
		     '33333333-3333-4333-8333-333333333333',
		     decode(repeat('21', 32), 'hex'),
		     FALSE,
		     TIMESTAMPTZ '2026-07-29 00:00:00Z',
		     TIMESTAMPTZ '2026-07-29 00:00:30Z',
		     decode(repeat('03', 32), 'hex'),
		     1,
		     decode(repeat('01', 32), 'hex')
		 )`,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_binding_tombstones (
		     environment,
		     installation_binding_id,
		     binding_id,
		     binding_version,
		     assertion_hash,
		     sequencer_epoch,
		     control_stream_sequence,
		     reason_code,
		     revoked_at
		 ) VALUES (
		     1,
		     decode(repeat('aa', 16), 'hex'),
		     decode(repeat('cc', 16), 'hex'),
		     2,
		     decode(repeat('20', 32), 'hex'),
		     decode(repeat('bb', 16), 'hex'),
		     3,
		     1,
		     TIMESTAMPTZ '2026-07-29 00:00:00Z'
		 )`,
	)
	require.NoError(t, err)

	_, err = db.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_assertions (
		    environment,
		    assertion_hash,
		    installation_binding_id,
		    sequencer_epoch,
		    assertion_stream_sequence,
		    binding_id,
		    binding_version,
		    lease_id,
		    tuple_commitment,
		    tuple_commitment_key_id,
		    roster_commitment,
		    roster_commitment_key_id,
		    topic_binding,
		    topic_key_epoch,
		    topic_commitment_key_id,
		    conversation_generation,
		    roster_version,
		    issued_at,
		    expires_at,
		    signing_key_id,
		    keyset_sequence,
		    keyset_hash
		)
		SELECT
		    environment,
		    decode(repeat('20', 32), 'hex'),
		    installation_binding_id,
		    sequencer_epoch,
		    3,
		    binding_id,
		    2,
		    lease_id,
		    tuple_commitment,
		    tuple_commitment_key_id,
		    roster_commitment,
		    roster_commitment_key_id,
		    topic_binding,
		    topic_key_epoch,
		    topic_commitment_key_id,
		    conversation_generation,
		    roster_version,
		    issued_at,
		    expires_at,
		    signing_key_id,
		    keyset_sequence,
		    keyset_hash
		  FROM hytch_push_vault.a9_assertions
		 WHERE environment = 1
		   AND assertion_hash = decode(repeat('dd', 32), 'hex')
	`)
	// An assertion's generated UPSERT discriminator cannot attach it to the
	// exact REVOKE event used by the tombstone.
	requireSQLState(t, err, "23503")

	var contiguousSequence int64
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT contiguous_stream_sequence
		   FROM hytch_push_vault.a9_installation_authority
		  WHERE environment = 1
		    AND installation_binding_id =
		            decode(repeat('aa', 16), 'hex')`,
	).Scan(&contiguousSequence))
	require.Equal(t, int64(1), contiguousSequence)

	insertA9ControlReceipt(
		t,
		db,
		"44444444-4444-4444-8444-444444444444",
		"23",
		4,
		3,
	)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_control_events (
		     environment,
		     installation_binding_id,
		     sequencer_epoch,
		     stream_sequence,
		     expected_previous_sequence,
		     binding_id,
		     binding_version,
		     expected_binding_version,
		     action,
		     assertion_hash,
		     reason_code,
		     idempotency_key,
		     signed_event_hash,
		     stream_is_contiguous,
		     issued_at,
		     expires_at,
		     signing_key_id,
		     keyset_sequence,
		     keyset_hash
		 ) VALUES (
		     1,
		     decode(repeat('aa', 16), 'hex'),
		     decode(repeat('bb', 16), 'hex'),
		     2,
		     1,
		     decode(repeat('cc', 16), 'hex'),
		     2,
		     1,
		     1,
		     decode(repeat('22', 32), 'hex'),
		     0,
		     '44444444-4444-4444-8444-444444444444',
		     decode(repeat('23', 32), 'hex'),
		     FALSE,
		     TIMESTAMPTZ '2026-07-29 00:00:00Z',
		     TIMESTAMPTZ '2026-07-29 00:00:30Z',
		     decode(repeat('03', 32), 'hex'),
		     1,
		     decode(repeat('01', 32), 'hex')
		 )`,
	)
	requireSQLState(t, err, "23514")
}

func TestA9MigrationSeparatesSignerUseAndCommitmentPurpose(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	insertValidA9AuthorityGraph(t, db)

	insertA9ControlReceipt(
		t,
		db,
		"88888888-8888-4888-8888-888888888888",
		"30",
		1,
		1,
	)
	err := insertA9UpsertControl(
		t,
		db,
		"88888888-8888-4888-8888-888888888888",
		2,
		1,
		2,
		1,
		"30",
		"31",
		"03",
	)
	// The receipt is for different signed bytes. Exact hash provenance is a
	// database invariant, not an application-layer convention.
	requireSQLState(t, err, "23503")

	insertA9ControlReceipt(
		t,
		db,
		"55555555-5555-4555-8555-555555555555",
		"25",
		1,
		1,
	)
	err = insertA9UpsertControl(
		t,
		db,
		"55555555-5555-4555-8555-555555555555",
		2,
		1,
		2,
		1,
		"24",
		"25",
		"04",
	)
	// Key 0x04 is a SERVICE_AUTH signer. The generated A9_CONTROL use
	// discriminator prevents it from signing a control artifact.
	requireSQLState(t, err, "23503")

	insertA9ControlReceipt(
		t,
		db,
		"66666666-6666-4666-8666-666666666666",
		"27",
		1,
		1,
	)
	err = insertA9UpsertControl(
		t,
		db,
		"66666666-6666-4666-8666-666666666666",
		2,
		1,
		2,
		1,
		"26",
		"27",
		"03",
	)
	require.NoError(t, err)

	_, err = db.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_assertions (
		    environment,
		    assertion_hash,
		    installation_binding_id,
		    sequencer_epoch,
		    assertion_stream_sequence,
		    binding_id,
		    binding_version,
		    lease_id,
		    tuple_commitment,
		    tuple_commitment_key_id,
		    roster_commitment,
		    roster_commitment_key_id,
		    topic_binding,
		    topic_key_epoch,
		    topic_commitment_key_id,
		    conversation_generation,
		    roster_version,
		    issued_at,
		    expires_at,
		    signing_key_id,
		    keyset_sequence,
		    keyset_hash
		)
		SELECT
		    environment,
		    decode(repeat('26', 32), 'hex'),
		    installation_binding_id,
		    sequencer_epoch,
		    2,
		    binding_id,
		    2,
		    lease_id,
		    tuple_commitment,
		    -- 0x06 is the ROSTER key and cannot occupy the generated
		    -- TUPLE-purpose foreign-key slot.
		    decode(repeat('06', 32), 'hex'),
		    roster_commitment,
		    roster_commitment_key_id,
		    topic_binding,
		    topic_key_epoch,
		    topic_commitment_key_id,
		    conversation_generation,
		    roster_version,
		    issued_at,
		    expires_at,
		    signing_key_id,
		    keyset_sequence,
		    keyset_hash
		  FROM hytch_push_vault.a9_assertions
		 WHERE environment = 1
		   AND assertion_hash = decode(repeat('dd', 32), 'hex')
	`)
	requireSQLState(t, err, "23503")

	insertA9ControlReceipt(
		t,
		db,
		"77777777-7777-4777-8777-777777777777",
		"29",
		1,
		1,
	)
	err = insertA9UpsertControl(
		t,
		db,
		"77777777-7777-4777-8777-777777777777",
		3,
		2,
		3,
		2,
		"28",
		"29",
		"03",
	)
	require.NoError(t, err)

	_, err = db.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_assertions (
		    environment,
		    assertion_hash,
		    installation_binding_id,
		    sequencer_epoch,
		    assertion_stream_sequence,
		    binding_id,
		    binding_version,
		    lease_id,
		    tuple_commitment,
		    tuple_commitment_key_id,
		    roster_commitment,
		    roster_commitment_key_id,
		    topic_binding,
		    topic_key_epoch,
		    topic_commitment_key_id,
		    conversation_generation,
		    roster_version,
		    issued_at,
		    expires_at,
		    signing_key_id,
		    keyset_sequence,
		    keyset_hash
		)
		SELECT
		    environment,
		    decode(repeat('28', 32), 'hex'),
		    installation_binding_id,
		    sequencer_epoch,
		    3,
		    binding_id,
		    3,
		    lease_id,
		    tuple_commitment,
		    tuple_commitment_key_id,
		    roster_commitment,
		    roster_commitment_key_id,
		    topic_binding,
		    655,
		    topic_commitment_key_id,
		    conversation_generation,
		    roster_version,
		    issued_at,
		    expires_at,
		    signing_key_id,
		    keyset_sequence,
		    keyset_hash
		  FROM hytch_push_vault.a9_assertions
		 WHERE environment = 1
		   AND assertion_hash = decode(repeat('dd', 32), 'hex')
	`)
	// TOPIC key 0x07 is bound to epoch 654 and cannot verify epoch 655.
	requireSQLState(t, err, "23503")
}

func insertA9AcceptedKeyset(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_accepted_keysets (
		     environment,
		     keyset_sequence,
		     signed_keyset_hash,
		     signed_keyset_jcs,
		     root_signing_key_id,
		     issued_at,
		     expires_at
		 ) VALUES (
		     1,
		     1,
		     decode(repeat('01', 32), 'hex'),
		     decode('7b7d', 'hex'),
		     decode(repeat('02', 32), 'hex'),
		     TIMESTAMPTZ '2026-07-29 00:00:00Z',
		     TIMESTAMPTZ '2026-07-29 23:00:00Z'
		 )`,
	)
	require.NoError(t, err)
}

func insertLegacyFinalDeliveryJob(
	t *testing.T,
	db *sql.DB,
	jobByte string,
) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.delivery_jobs (
		     job_id,
		     encrypted_job,
		     environment,
		     state,
		     attempts,
		     retry_exponent,
		     available_at,
		     expires_at,
		     created_at,
		     traffic_class,
		     final_reason
		 ) VALUES (
		     decode(repeat($1, 16), 'hex'),
		     decode('00', 'hex'),
		     1,
		     5,
		     0,
		     0,
		     TIMESTAMPTZ '2026-07-29 00:00:00Z',
		     TIMESTAMPTZ '2026-07-29 00:05:00Z',
		     TIMESTAMPTZ '2026-07-29 00:00:00Z',
		     1,
		     1
		 )`,
		jobByte,
	)
	require.NoError(t, err)
}

func insertA9ControlReceipt(
	t *testing.T,
	db *sql.DB,
	idempotencyKey string,
	hashByte string,
	outcome int,
	state int,
) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_idempotency_receipts (
		     environment,
		     idempotency_key,
		     operation_kind,
		     installation_binding_id,
		     sequencer_epoch,
		     signed_request_hash,
		     result_outcome,
		     result_state,
		     subscription_generation,
		     accepted_stream_sequence,
		     created_at
		 ) VALUES (
		     1,
		     $1,
		     1,
		     decode(repeat('aa', 16), 'hex'),
		     decode(repeat('bb', 16), 'hex'),
		     decode(repeat($2, 32), 'hex'),
		     $3,
		     $4,
		     1,
		     1,
		     TIMESTAMPTZ '2026-07-29 00:00:00Z'
		 )`,
		idempotencyKey,
		hashByte,
		outcome,
		state,
	)
	require.NoError(t, err)
}

func insertA9ReplacementReceipt(
	t *testing.T,
	db *sql.DB,
	idempotencyKey string,
	hashByte string,
	generation int,
) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_idempotency_receipts (
		     environment,
		     idempotency_key,
		     operation_kind,
		     installation_binding_id,
		     sequencer_epoch,
		     signed_request_hash,
		     result_outcome,
		     result_state,
		     subscription_generation,
		     accepted_stream_sequence,
		     created_at
		 ) VALUES (
		     1,
		     $1,
		     2,
		     decode(repeat('aa', 16), 'hex'),
		     decode(repeat('bb', 16), 'hex'),
		     decode(repeat($2, 32), 'hex'),
		     1,
		     1,
		     $3,
		     1,
		     TIMESTAMPTZ '2026-07-29 00:00:00Z'
		 )`,
		idempotencyKey,
		hashByte,
		generation,
	)
	require.NoError(t, err)
}

func insertA9UpsertControl(
	t *testing.T,
	db *sql.DB,
	idempotencyKey string,
	streamSequence int,
	expectedStreamSequence int,
	bindingVersion int,
	expectedBindingVersion int,
	assertionHashByte string,
	eventHashByte string,
	signingKeyByte string,
) error {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_control_events (
		     environment,
		     installation_binding_id,
		     sequencer_epoch,
		     stream_sequence,
		     expected_previous_sequence,
		     binding_id,
		     binding_version,
		     expected_binding_version,
		     action,
		     assertion_hash,
		     reason_code,
		     idempotency_key,
		     signed_event_hash,
		     stream_is_contiguous,
		     issued_at,
		     expires_at,
		     signing_key_id,
		     keyset_sequence,
		     keyset_hash
		 ) VALUES (
		     1,
		     decode(repeat('aa', 16), 'hex'),
		     decode(repeat('bb', 16), 'hex'),
		     $1,
		     $2,
		     decode(repeat('cc', 16), 'hex'),
		     $3,
		     $4,
		     1,
		     decode(repeat($5, 32), 'hex'),
		     0,
		     $6,
		     decode(repeat($7, 32), 'hex'),
		     TRUE,
		     TIMESTAMPTZ '2026-07-29 00:00:00Z',
		     TIMESTAMPTZ '2026-07-29 00:00:30Z',
		     decode(repeat($8, 32), 'hex'),
		     1,
		     decode(repeat('01', 32), 'hex')
		 )`,
		streamSequence,
		expectedStreamSequence,
		bindingVersion,
		expectedBindingVersion,
		assertionHashByte,
		idempotencyKey,
		eventHashByte,
		signingKeyByte,
	)
	return err
}

func insertValidA9AuthorityGraph(t *testing.T, db *sql.DB) {
	t.Helper()
	insertA9AcceptedKeyset(t, db)

	_, err := db.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_online_key_descriptors (
		    environment,
		    keyset_sequence,
		    key_use,
		    key_state,
		    key_id,
		    public_key,
		    not_before,
		    not_after
		) VALUES
		    (
		        1,
		        1,
		        1,
		        1,
		        decode(repeat('03', 32), 'hex'),
		        decode(repeat('08', 32), 'hex'),
		        TIMESTAMPTZ '2026-07-28 23:00:00Z',
		        TIMESTAMPTZ '2026-07-29 23:00:00Z'
		    ),
		    (
		        1,
		        1,
		        2,
		        1,
		        decode(repeat('04', 32), 'hex'),
		        decode(repeat('09', 32), 'hex'),
		        TIMESTAMPTZ '2026-07-28 23:00:00Z',
		        TIMESTAMPTZ '2026-07-29 23:00:00Z'
		    );

		INSERT INTO hytch_push_vault.a9_commitment_key_descriptors (
		    environment,
		    keyset_sequence,
		    purpose,
		    key_id,
		    topic_key_epoch,
		    not_before,
		    not_after
		) VALUES
		    (
		        1,
		        1,
		        1,
		        decode(repeat('06', 32), 'hex'),
		        NULL,
		        TIMESTAMPTZ '2026-07-28 23:00:00Z',
		        TIMESTAMPTZ '2026-07-29 23:00:00Z'
		    ),
		    (
		        1,
		        1,
		        2,
		        decode(repeat('05', 32), 'hex'),
		        NULL,
		        TIMESTAMPTZ '2026-07-28 23:00:00Z',
		        TIMESTAMPTZ '2026-07-29 23:00:00Z'
		    ),
		    (
		        1,
		        1,
		        3,
		        decode(repeat('07', 32), 'hex'),
		        654,
		        TIMESTAMPTZ '2026-07-28 23:00:00Z',
		        TIMESTAMPTZ '2026-07-29 23:00:00Z'
		    );

		INSERT INTO hytch_push_vault.a9_keyset_state (
		    environment,
		    keyset_sequence,
		    signed_keyset_hash,
		    state,
		    uncertainty_reason,
		    expires_at,
		    refreshed_at
		) VALUES (
		    1,
		    1,
		    decode(repeat('01', 32), 'hex'),
		    1,
		    0,
		    TIMESTAMPTZ '2026-07-29 23:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:00Z'
		);

		INSERT INTO hytch_push_vault.installation_states (
		    installation_lookup,
		    installation_identity,
		    incarnation_lookup,
		    lookup_key_epoch,
		    generation,
		    idempotency_digest,
		    control_event_digest,
		    encrypted_apns_token,
		    environment,
		    payload_schema,
		    age_policy,
		    policy_epoch,
		    state,
		    encryption_key_version,
		    refreshed_at,
		    expires_at,
		    control_expires_at
		) VALUES (
		    decode(repeat('10', 32), 'hex'),
		    decode(repeat('11', 32), 'hex'),
		    decode(repeat('12', 32), 'hex'),
		    1,
		    1,
		    decode(repeat('13', 32), 'hex'),
		    decode(repeat('14', 32), 'hex'),
		    decode('01', 'hex'),
		    1,
		    1,
		    1,
		    1,
		    2,
		    1,
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    TIMESTAMPTZ '2026-07-30 00:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:30Z'
		);

		INSERT INTO hytch_push_vault.subscription_leases (
		    lease_id,
		    installation_lookup,
		    installation_identity,
		    route_identity,
		    topic_lookup,
		    lookup_key_epoch,
		    encrypted_topic,
		    encrypted_route_key,
		    encrypted_hmac_keys,
		    encrypted_receive_capability,
		    environment,
		    payload_schema,
		    topic_kind,
		    push_mode,
		    state,
		    generation,
		    policy_epoch,
		    route_key_epoch,
		    encrypted_nonce_state,
		    encryption_key_version,
		    issued_at,
		    refreshed_at,
		    expires_at,
		    control_expires_at
		) VALUES (
		    decode(repeat('17', 16), 'hex'),
		    decode(repeat('10', 32), 'hex'),
		    decode(repeat('11', 32), 'hex'),
		    decode(repeat('15', 32), 'hex'),
		    decode(repeat('16', 32), 'hex'),
		    1,
		    decode('01', 'hex'),
		    decode('02', 'hex'),
		    decode('03', 'hex'),
		    decode('04', 'hex'),
		    1,
		    1,
		    1,
		    1,
		    2,
		    1,
		    1,
		    2,
		    decode('05', 'hex'),
		    1,
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    TIMESTAMPTZ '2026-07-30 00:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:30Z'
		);
	`)
	require.NoError(t, err)

	insertA9ControlReceipt(
		t,
		db,
		"11111111-1111-4111-8111-111111111111",
		"0e",
		1,
		1,
	)
	insertA9ReplacementReceipt(
		t,
		db,
		"99999999-9999-4999-8999-999999999999",
		"1c",
		1,
	)

	_, err = db.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_watermarks (
		    environment,
		    installation_binding_id,
		    sequencer_epoch,
		    watermark_sequence,
		    signed_watermark_hash,
		    committed_through_stream_sequence,
		    status,
		    uncertainty_reason,
		    issued_at,
		    expires_at,
		    signing_key_id,
		    keyset_sequence,
		    keyset_hash
		) VALUES (
		    1,
		    decode(repeat('aa', 16), 'hex'),
		    decode(repeat('bb', 16), 'hex'),
		    1,
		    decode(repeat('0f', 32), 'hex'),
		    1,
		    1,
		    0,
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:30Z',
		    decode(repeat('03', 32), 'hex'),
		    1,
		    decode(repeat('01', 32), 'hex')
		);

		INSERT INTO hytch_push_vault.a9_installation_authority (
		    environment,
		    installation_binding_id,
		    sequencer_epoch,
		    contiguous_stream_sequence,
		    subscription_generation,
		    state,
		    uncertainty_reason,
		    watermark_sequence,
		    watermark_signed_hash,
		    watermark_committed_through,
		    watermark_status,
		    watermark_uncertainty_reason,
		    watermark_issued_at,
		    watermark_expires_at,
		    watermark_signing_key_id,
		    watermark_keyset_sequence,
		    watermark_keyset_hash,
		    created_at,
		    updated_at
		) VALUES (
		    1,
		    decode(repeat('aa', 16), 'hex'),
		    decode(repeat('bb', 16), 'hex'),
		    1,
		    1,
		    1,
		    0,
		    1,
		    decode(repeat('0f', 32), 'hex'),
		    1,
		    1,
		    0,
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:30Z',
		    decode(repeat('03', 32), 'hex'),
		    1,
		    decode(repeat('01', 32), 'hex'),
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:00Z'
		);

		INSERT INTO hytch_push_vault.a9_installation_gate6_bindings (
		    environment,
		    installation_binding_id,
		    installation_identity,
		    created_at
		) VALUES (
		    1,
		    decode(repeat('aa', 16), 'hex'),
		    decode(repeat('11', 32), 'hex'),
		    TIMESTAMPTZ '2026-07-29 00:00:00Z'
		);

		INSERT INTO hytch_push_vault.a9_control_events (
		    environment,
		    installation_binding_id,
		    sequencer_epoch,
		    stream_sequence,
		    expected_previous_sequence,
		    binding_id,
		    binding_version,
		    expected_binding_version,
		    action,
		    assertion_hash,
		    reason_code,
		    idempotency_key,
		    signed_event_hash,
		    stream_is_contiguous,
		    issued_at,
		    expires_at,
		    signing_key_id,
		    keyset_sequence,
		    keyset_hash
		) VALUES (
		    1,
		    decode(repeat('aa', 16), 'hex'),
		    decode(repeat('bb', 16), 'hex'),
		    1,
		    0,
		    decode(repeat('cc', 16), 'hex'),
		    1,
		    0,
		    1,
		    decode(repeat('dd', 32), 'hex'),
		    0,
		    '11111111-1111-4111-8111-111111111111',
		    decode(repeat('0e', 32), 'hex'),
		    TRUE,
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:30Z',
		    decode(repeat('03', 32), 'hex'),
		    1,
		    decode(repeat('01', 32), 'hex')
		);

		INSERT INTO hytch_push_vault.a9_assertions (
		    environment,
		    assertion_hash,
		    installation_binding_id,
		    sequencer_epoch,
		    assertion_stream_sequence,
		    binding_id,
		    binding_version,
		    lease_id,
		    tuple_commitment,
		    tuple_commitment_key_id,
		    roster_commitment,
		    roster_commitment_key_id,
		    topic_binding,
		    topic_key_epoch,
		    topic_commitment_key_id,
		    conversation_generation,
		    roster_version,
		    issued_at,
		    expires_at,
		    signing_key_id,
		    keyset_sequence,
		    keyset_hash
		) VALUES (
		    1,
		    decode(repeat('dd', 32), 'hex'),
		    decode(repeat('aa', 16), 'hex'),
		    decode(repeat('bb', 16), 'hex'),
		    1,
		    decode(repeat('cc', 16), 'hex'),
		    1,
		    decode(repeat('0d', 16), 'hex'),
		    decode(repeat('0b', 32), 'hex'),
		    decode(repeat('05', 32), 'hex'),
		    decode(repeat('0c', 32), 'hex'),
		    decode(repeat('06', 32), 'hex'),
		    decode(repeat('0a', 32), 'hex'),
		    654,
		    decode(repeat('07', 32), 'hex'),
		    1,
		    1,
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:30Z',
		    decode(repeat('03', 32), 'hex'),
		    1,
		    decode(repeat('01', 32), 'hex')
		);

		INSERT INTO hytch_push_vault.a9_bindings (
		    environment,
		    installation_binding_id,
		    binding_id,
		    sequencer_epoch,
		    binding_version,
		    state,
		    active_assertion_hash,
		    active_assertion_stream_sequence,
		    active_topic_key_epoch,
		    active_topic_binding,
		    active_keyset_sequence,
		    active_keyset_hash,
		    updated_at
		) VALUES (
		    1,
		    decode(repeat('aa', 16), 'hex'),
		    decode(repeat('cc', 16), 'hex'),
		    decode(repeat('bb', 16), 'hex'),
		    1,
		    1,
		    decode(repeat('dd', 32), 'hex'),
		    1,
		    654,
		    decode(repeat('0a', 32), 'hex'),
		    1,
		    decode(repeat('01', 32), 'hex'),
		    TIMESTAMPTZ '2026-07-29 00:00:00Z'
		);

		INSERT INTO hytch_push_vault.a9_subscription_routes (
		    lease_id,
		    environment,
		    installation_binding_id,
		    installation_identity,
		    sequencer_epoch,
		    subscription_generation,
		    replacement_idempotency_key,
		    binding_id,
		    binding_version,
		    assertion_hash,
		    assertion_stream_sequence,
		    topic_key_epoch,
		    topic_binding,
		    route_key_epoch,
		    keyset_sequence,
		    keyset_hash,
		    watermark_sequence,
		    created_at,
		    refreshed_at
		) VALUES (
		    decode(repeat('17', 16), 'hex'),
		    1,
		    decode(repeat('aa', 16), 'hex'),
		    decode(repeat('11', 32), 'hex'),
		    decode(repeat('bb', 16), 'hex'),
		    1,
		    '99999999-9999-4999-8999-999999999999',
		    decode(repeat('cc', 16), 'hex'),
		    1,
		    decode(repeat('dd', 32), 'hex'),
		    1,
		    654,
		    decode(repeat('0a', 32), 'hex'),
		    2,
		    1,
		    decode(repeat('01', 32), 'hex'),
		    1,
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:00Z'
		);

		INSERT INTO hytch_push_vault.delivery_jobs (
		    job_id,
		    lease_id,
		    encrypted_job,
		    environment,
		    state,
		    attempts,
		    retry_exponent,
		    available_at,
		    expires_at,
		    created_at,
		    traffic_class,
		    a9_installation_binding_id,
		    a9_sequencer_epoch,
		    a9_subscription_generation,
		    a9_binding_id,
		    a9_binding_version,
		    a9_assertion_hash,
		    a9_assertion_stream_sequence,
		    a9_topic_key_epoch,
		    a9_topic_binding,
		    a9_route_key_epoch,
		    a9_keyset_sequence,
		    a9_keyset_hash,
		    a9_watermark_sequence
		) VALUES (
		    decode(repeat('18', 16), 'hex'),
		    decode(repeat('17', 16), 'hex'),
		    decode('01', 'hex'),
		    1,
		    1,
		    0,
		    0,
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    TIMESTAMPTZ '2026-07-29 00:05:00Z',
		    TIMESTAMPTZ '2026-07-29 00:00:00Z',
		    1,
		    decode(repeat('aa', 16), 'hex'),
		    decode(repeat('bb', 16), 'hex'),
		    1,
		    decode(repeat('cc', 16), 'hex'),
		    1,
		    decode(repeat('dd', 32), 'hex'),
		    1,
		    654,
		    decode(repeat('0a', 32), 'hex'),
		    2,
		    1,
		    decode(repeat('01', 32), 'hex'),
		    1
		);
	`)
	require.NoError(t, err)
}
