package db_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestA10MigrationEmptyStateRoundTripsToVersionTwelve(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 12))
	var missing bool
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT pg_catalog.to_regclass('hytch_push_vault.a10_registration_replays') IS NULL`).Scan(&missing))
	require.True(t, missing)
	require.NoError(t, database.Migrate(t.Context(), db))
	require.NoError(t, database.RequireCurrentSchema(t.Context(), db))
}

func TestA10MigrationDowngradeRefusesDurableState(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	_, err := db.ExecContext(t.Context(), `WITH instant AS (SELECT pg_catalog.clock_timestamp() AS now) INSERT INTO hytch_push_vault.a10_registration_replays (environment, jti, jwt_expires_at, delete_after, consumed_at) SELECT 1, '00000000-0000-4000-8000-000000000099', now + INTERVAL '55 seconds', now + INTERVAL '60 seconds', now FROM instant`)
	require.NoError(t, err)
	err = database.MigrateUpTo(t.Context(), db, 12)
	require.Error(t, err)
	require.Contains(t, err.Error(), "SQLSTATE 55000")
	var retained bool
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT EXISTS (SELECT 1 FROM hytch_push_vault.a10_registration_replays)`).Scan(&retained))
	require.True(t, retained)
}

func TestA10MigrationDowngradeLocksBeforeCheckingDormantState(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))

	blocker, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback() }()
	_, err = blocker.ExecContext(
		t.Context(),
		`LOCK TABLE hytch_push_vault.a10_registration_replays
		 IN ROW EXCLUSIVE MODE`,
	)
	require.NoError(t, err)

	migrationDone := make(chan error, 1)
	go func() {
		migrationDone <- database.MigrateUpTo(t.Context(), db, 12)
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		queryErr := db.QueryRowContext(
			t.Context(),
			`SELECT EXISTS (
			     SELECT 1
			       FROM pg_catalog.pg_locks AS lock
			      WHERE lock.relation =
			            'hytch_push_vault.a10_registration_replays'
			                ::pg_catalog.regclass
			        AND lock.mode = 'AccessExclusiveLock'
			        AND NOT lock.granted
			 )`,
		).Scan(&waiting)
		return queryErr == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)

	_, err = blocker.ExecContext(
		t.Context(),
		`WITH instant AS (
		     SELECT pg_catalog.clock_timestamp() AS now
		 )
		 INSERT INTO hytch_push_vault.a10_registration_replays
		 (environment, jti, jwt_expires_at, delete_after, consumed_at)
		 SELECT 1,
		        '00000000-0000-4000-8000-000000000098',
		        now + INTERVAL '55 seconds',
		        now + INTERVAL '60 seconds',
		        now
		   FROM instant`,
	)
	require.NoError(t, err)
	require.NoError(t, blocker.Commit())

	select {
	case migrationErr := <-migrationDone:
		require.Error(t, migrationErr)
		require.Contains(t, migrationErr.Error(), "SQLSTATE 55000")
	case <-time.After(5 * time.Second):
		t.Fatal("downgrade did not resume after the concurrent writer committed")
	}

	var retained bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.a10_registration_replays
		      WHERE jti = '00000000-0000-4000-8000-000000000098'
		 )`,
	).Scan(&retained))
	require.True(t, retained)
}

func TestA10MigrationRevokesPublicTriggerFunctionExecution(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))

	var publicExecutionAbsent bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT NOT EXISTS (
		     SELECT 1
		       FROM pg_catalog.pg_proc AS routine
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = routine.pronamespace
		       CROSS JOIN LATERAL pg_catalog.aclexplode(
		           COALESCE(
		               routine.proacl,
		               pg_catalog.acldefault('f', routine.proowner)
		           )
		       ) AS privilege
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND routine.proname IN (
		            'reject_a10_immutable_mutation',
		            'guard_a10_replay_delete'
		        )
		        AND privilege.grantee = 0
		        AND privilege.privilege_type = 'EXECUTE'
		 )`,
	).Scan(&publicExecutionAbsent))
	require.True(t, publicExecutionAbsent)
}
