package db_test

import (
	"database/sql"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	"github.com/xmtp/example-notification-server-go/pkg/db/migrations"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestSecureActivationSQLObjectsRoundTripWhileDormant(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 8))
	assertLegacyActivationMigration(t, db, true, 0, true)

	down := readActivationMigration(t, "down")
	_, err := db.ExecContext(t.Context(), down)
	require.NoError(t, err)
	assertLegacyActivationMigration(t, db, false, 0, true)

	up := readActivationMigration(t, "up")
	_, err = db.ExecContext(t.Context(), up)
	require.NoError(t, err)
	assertLegacyActivationMigration(t, db, true, 0, true)
}

func TestSecureActivationDownRefusesRetirementAfterMarkerTampering(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 8))
	activateLegacyRoutingRetirement(t, db)
	assertLegacyActivationMigration(t, db, true, 1, false)

	_, err := db.ExecContext(
		t.Context(),
		`ALTER TABLE hytch_push_vault.legacy_routing_activation
		     DISABLE TRIGGER hytch_legacy_activation_dml_guard;
		 DELETE FROM hytch_push_vault.legacy_routing_activation;
		 ALTER TABLE hytch_push_vault.legacy_routing_activation
		     ENABLE ALWAYS TRIGGER hytch_legacy_activation_dml_guard`,
	)
	require.NoError(t, err)
	assertLegacyActivationMigration(t, db, true, 0, false)

	_, err = db.ExecContext(t.Context(), readActivationMigration(t, "down"))
	requireSQLState(t, err, "55000")
	assertLegacyActivationMigration(t, db, true, 0, false)
}

func TestMigrationRefusesEnabledEventTriggerBeforeAnyDDL(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	_, err := db.ExecContext(
		t.Context(),
		`CREATE FUNCTION public.hytch_test_event_trigger()
		 RETURNS event_trigger
		 LANGUAGE plpgsql
		 AS $function$
		 BEGIN
		     NULL;
		 END;
		 $function$;
		 CREATE EVENT TRIGGER hytch_test_enabled_event_trigger
		 ON ddl_command_start
		 EXECUTE FUNCTION public.hytch_test_event_trigger()`,
	)
	require.NoError(t, err)

	err = database.Migrate(t.Context(), db)
	require.ErrorIs(t, err, migrations.ErrEnabledEventTrigger)

	var migrationStateAbsent bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
		     to_regclass('public.schema_migrations') IS NULL AND
		     to_regclass('public.installations') IS NULL AND
		     to_regnamespace('hytch_push_vault') IS NULL`,
	).Scan(&migrationStateAbsent))
	require.True(t, migrationStateAbsent)
}

func readActivationMigration(t *testing.T, direction string) string {
	t.Helper()
	contents, err := os.ReadFile(
		"migrations/00008_disable_legacy_plaintext_routing." +
			direction + ".sql",
	)
	require.NoError(t, err)
	return string(contents)
}

func activateLegacyRoutingRetirement(t *testing.T, db *sql.DB) {
	t.Helper()
	var databaseName string
	require.NoError(
		t,
		db.QueryRowContext(t.Context(), `SELECT current_database()`).
			Scan(&databaseName),
	)
	_, err := db.ExecContext(
		t.Context(),
		`SELECT hytch_push_vault.activate_legacy_routing_retirement($1)`,
		"RETIRE LEGACY PLAINTEXT ROUTING FROM "+databaseName,
	)
	require.NoError(t, err)
}

func assertLegacyActivationMigration(
	t *testing.T,
	db *sql.DB,
	installed bool,
	expectedMarkerRows int,
	legacyObjectsPresent bool,
) {
	t.Helper()
	var markerExists bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT to_regclass(
		     'hytch_push_vault.legacy_routing_activation'
		 ) IS NOT NULL`,
	).Scan(&markerExists))
	require.Equal(t, installed, markerExists)

	if markerExists {
		var markerRows int
		require.NoError(t, db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*)
			   FROM hytch_push_vault.legacy_routing_activation
			  WHERE singleton`,
		).Scan(&markerRows))
		require.Equal(t, expectedMarkerRows, markerRows)
	} else {
		require.Zero(t, expectedMarkerRows)
	}

	var markerTriggerCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM pg_catalog.pg_trigger AS trigger
		   JOIN pg_catalog.pg_class AS relation
		     ON relation.oid = trigger.tgrelid
		   JOIN pg_catalog.pg_namespace AS namespace
		     ON namespace.oid = relation.relnamespace
		  WHERE namespace.nspname = 'hytch_push_vault'
		    AND relation.relname = 'legacy_routing_activation'
		    AND trigger.tgname IN (
		        'hytch_legacy_activation_insert_guard',
		        'hytch_legacy_activation_dml_guard',
		        'hytch_legacy_activation_truncate_guard'
		    )
		    AND trigger.tgenabled = 'A'
		    AND NOT trigger.tgisinternal`,
	).Scan(&markerTriggerCount))

	var legacyRelationCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM (
		       VALUES
		           ('public.installations'),
		           ('public.device_delivery_mechanisms'),
		           ('public.subscriptions'),
		           ('public.subscription_hmac_keys')
		   ) AS expected(name)
		  WHERE to_regclass(expected.name) IS NOT NULL`,
	).Scan(&legacyRelationCount))

	var ownedSequenceCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM (
		       VALUES
		           ('public.device_delivery_mechanisms_id_seq'),
		           ('public.subscriptions_id_seq')
		   ) AS expected(name)
		  WHERE to_regclass(expected.name) IS NOT NULL`,
	).Scan(&ownedSequenceCount))

	var legacyUserTriggerCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM pg_catalog.pg_trigger AS trigger
		   JOIN pg_catalog.pg_class AS relation
		     ON relation.oid = trigger.tgrelid
		   JOIN pg_catalog.pg_namespace AS namespace
		     ON namespace.oid = relation.relnamespace
		  WHERE namespace.nspname = 'public'
		    AND relation.relname IN (
		        'installations',
		        'device_delivery_mechanisms',
		        'subscriptions',
		        'subscription_hmac_keys'
		    )
		    AND NOT trigger.tgisinternal`,
	).Scan(&legacyUserTriggerCount))

	var hardenedFunctionCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM pg_catalog.pg_proc AS routine
		   JOIN pg_catalog.pg_namespace AS namespace
		     ON namespace.oid = routine.pronamespace
		  WHERE namespace.nspname = 'hytch_push_vault'
		    AND routine.proname IN (
		        'reject_legacy_routing_mutation',
		        'activate_legacy_routing_retirement'
		    )
		    AND routine.prosecdef
		    AND routine.proconfig = ARRAY[
		        'search_path=pg_catalog'
		    ]::TEXT[]
		    AND NOT EXISTS (
		        SELECT 1
		          FROM pg_catalog.aclexplode(
		              COALESCE(
		                  routine.proacl,
		                  pg_catalog.acldefault(
		                      'f',
		                      routine.proowner
		                  )
		              )
		          ) AS privilege
		         WHERE privilege.grantee <> routine.proowner
		           AND privilege.privilege_type = 'EXECUTE'
		    )`,
	).Scan(&hardenedFunctionCount))

	var secureVaultStillExists bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT to_regclass(
		     'hytch_push_vault.vault_key_bindings'
		 ) IS NOT NULL`,
	).Scan(&secureVaultStillExists))
	require.True(t, secureVaultStillExists)

	if installed {
		require.Equal(t, 3, markerTriggerCount)
		require.Equal(t, 2, hardenedFunctionCount)
	} else {
		require.Zero(t, markerTriggerCount)
		require.Zero(t, hardenedFunctionCount)
	}
	require.Zero(t, legacyUserTriggerCount)
	if legacyObjectsPresent {
		require.Equal(t, 4, legacyRelationCount)
		require.Equal(t, 2, ownedSequenceCount)
	} else {
		require.Zero(t, legacyRelationCount)
		require.Zero(t, ownedSequenceCount)
	}
}

func requireSQLState(t *testing.T, err error, expected string) {
	t.Helper()
	require.Error(t, err)
	var pgError *pgconn.PgError
	require.ErrorAs(t, err, &pgError)
	require.Equal(t, expected, pgError.Code)
}
