package db_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestAccessAuditBarrierMigrationRoundTrip(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 9))
	assertAccessAuditBarrierObjects(t, db, true)

	_, err := db.ExecContext(
		t.Context(),
		readAccessAuditBarrierMigration(t, "down"),
	)
	require.NoError(t, err)
	assertAccessAuditBarrierObjects(t, db, false)
	assertAccessAuditBarrierRowCount(t, db, 0)

	_, err = db.ExecContext(
		t.Context(),
		readAccessAuditBarrierMigration(t, "up"),
	)
	require.NoError(t, err)
	assertAccessAuditBarrierObjects(t, db, true)
	assertAccessAuditBarrierRowCount(t, db, 0)
}

func TestAccessAuditBarrierDownRefusesExistingHistory(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 9))
	seedAccessAuditBarrierRows(t, db)

	_, err := db.ExecContext(
		t.Context(),
		readAccessAuditBarrierMigration(t, "down"),
	)
	require.Error(t, err)
	assertAccessAuditBarrierObjects(t, db, true)
	assertAccessAuditBarrierRowCount(t, db, 3)
}

func TestAccessAuditBarrierRejectsMutationAndPurgesOnlyExpiredEnvironment(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 9))
	seedAccessAuditBarrierRows(t, db)

	mutations := []string{
		`UPDATE hytch_push_vault.access_audit
		    SET actor = actor
		  WHERE environment = 1`,
		`DELETE FROM hytch_push_vault.access_audit
		  WHERE environment = 1`,
		`TRUNCATE TABLE hytch_push_vault.access_audit`,
	}
	for _, statement := range mutations {
		_, err := db.ExecContext(t.Context(), statement)
		requireSQLState(t, err, "55000")
	}
	assertAccessAuditBarrierRowCount(t, db, 3)

	_, err := db.ExecContext(
		t.Context(),
		`SET session_replication_role = replica`,
	)
	require.NoError(t, err)
	for _, statement := range mutations {
		_, err = db.ExecContext(t.Context(), statement)
		requireSQLState(t, err, "55000")
	}
	_, err = db.ExecContext(
		t.Context(),
		`RESET session_replication_role`,
	)
	require.NoError(t, err)
	assertAccessAuditBarrierRowCount(t, db, 3)

	var deleted int64
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
		     hytch_push_vault.
		         purge_expired_access_audit_development()`,
	).Scan(&deleted))
	require.Equal(t, int64(1), deleted)

	var (
		expiredDevelopmentRows int
		futureDevelopmentRows  int
		expiredProductionRows  int
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
		     COUNT(*) FILTER (
		         WHERE event_id = $1
		     ),
		     COUNT(*) FILTER (
		         WHERE event_id = $2
		     ),
		     COUNT(*) FILTER (
		         WHERE event_id = $3
		     )
		   FROM hytch_push_vault.access_audit`,
		bytes.Repeat([]byte{0x21}, 16),
		bytes.Repeat([]byte{0x22}, 16),
		bytes.Repeat([]byte{0x23}, 16),
	).Scan(
		&expiredDevelopmentRows,
		&futureDevelopmentRows,
		&expiredProductionRows,
	))
	require.Zero(t, expiredDevelopmentRows)
	require.Equal(t, 1, futureDevelopmentRows)
	require.Equal(t, 1, expiredProductionRows)

	_, err = db.ExecContext(
		t.Context(),
		`DELETE FROM hytch_push_vault.access_audit
		  WHERE event_id = $1`,
		bytes.Repeat([]byte{0x22}, 16),
	)
	requireSQLState(t, err, "55000")

	var publicExecuteGrants int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
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
		        'purge_expired_access_audit_development',
		        'purge_expired_access_audit_production'
		    )
		    AND privilege.grantee = 0
		    AND privilege.privilege_type = 'EXECUTE'`,
	).Scan(&publicExecuteGrants))
	require.Zero(t, publicExecuteGrants)
}

func TestAccessAuditPurgeRoleCannotInvokeOtherEnvironment(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 9))
	seedAccessAuditBarrierRows(t, db)

	role := fmt.Sprintf(
		"hytch_audit_development_%d",
		time.Now().UnixNano(),
	)
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(`CREATE ROLE %s NOLOGIN`, role),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(
			context.Background(),
			fmt.Sprintf(`DROP OWNED BY %s`, role),
		)
		_, _ = db.ExecContext(
			context.Background(),
			fmt.Sprintf(`DROP ROLE IF EXISTS %s`, role),
		)
	})
	_, err = db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`GRANT USAGE
			     ON SCHEMA hytch_push_vault
			   TO %[1]s;
			 GRANT SELECT, INSERT
			     ON TABLE hytch_push_vault.access_audit
			   TO %[1]s;
			 GRANT EXECUTE
			     ON FUNCTION
			         hytch_push_vault.
			             purge_expired_access_audit_development()
			   TO %[1]s`,
			role,
		),
	)
	require.NoError(t, err)

	runtimeConnection, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer func() { _ = runtimeConnection.Close() }()
	_, err = runtimeConnection.ExecContext(
		t.Context(),
		fmt.Sprintf(`SET ROLE %s`, role),
	)
	require.NoError(t, err)

	var deleted int64
	err = runtimeConnection.QueryRowContext(
		t.Context(),
		`SELECT
		     hytch_push_vault.
		         purge_expired_access_audit_production()`,
	).Scan(&deleted)
	requireSQLState(t, err, "42501")

	require.NoError(t, runtimeConnection.QueryRowContext(
		t.Context(),
		`SELECT
		     hytch_push_vault.
		         purge_expired_access_audit_development()`,
	).Scan(&deleted))
	require.Equal(t, int64(1), deleted)
	_, err = runtimeConnection.ExecContext(t.Context(), `RESET ROLE`)
	require.NoError(t, err)

	var (
		expiredDevelopmentRows int
		expiredProductionRows  int
	)
	require.NoError(t, runtimeConnection.QueryRowContext(
		t.Context(),
		`SELECT
		     COUNT(*) FILTER (WHERE event_id = $1),
		     COUNT(*) FILTER (WHERE event_id = $2)
		   FROM hytch_push_vault.access_audit`,
		bytes.Repeat([]byte{0x21}, 16),
		bytes.Repeat([]byte{0x23}, 16),
	).Scan(
		&expiredDevelopmentRows,
		&expiredProductionRows,
	))
	require.Zero(t, expiredDevelopmentRows)
	require.Equal(t, 1, expiredProductionRows)
}

func TestAccessAuditPurgeExceptionRollsBackDeleteGuardState(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 9))
	seedAccessAuditBarrierRows(t, db)

	_, err := db.ExecContext(
		t.Context(),
		`CREATE FUNCTION hytch_push_vault.test_access_audit_delete_failure()
		 RETURNS TRIGGER
		 LANGUAGE plpgsql
		 AS $function$
		 BEGIN
		     RAISE EXCEPTION USING
		         ERRCODE = '55000',
		         MESSAGE = 'synthetic access audit delete failure';
		 END;
		 $function$;
		 CREATE TRIGGER zz_test_access_audit_delete_failure
		 BEFORE DELETE
		 ON hytch_push_vault.access_audit
		 FOR EACH STATEMENT
		 EXECUTE FUNCTION
		     hytch_push_vault.test_access_audit_delete_failure()`,
	)
	require.NoError(t, err)

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(t.Context(), `SAVEPOINT before_audit_purge`)
	require.NoError(t, err)

	var deleted int64
	err = tx.QueryRowContext(
		t.Context(),
		`SELECT
		     hytch_push_vault.
		         purge_expired_access_audit_development()`,
	).Scan(&deleted)
	requireSQLState(t, err, "55000")
	_, err = tx.ExecContext(
		t.Context(),
		`ROLLBACK TO SAVEPOINT before_audit_purge`,
	)
	require.NoError(t, err)

	var enabled string
	require.NoError(t, tx.QueryRowContext(
		t.Context(),
		`SELECT trigger.tgenabled
		   FROM pg_catalog.pg_trigger AS trigger
		  WHERE trigger.tgrelid =
		        'hytch_push_vault.access_audit'::pg_catalog.regclass
		    AND trigger.tgname =
		        'hytch_access_audit_delete_guard'`,
	).Scan(&enabled))
	require.Equal(t, "A", enabled)
	require.NoError(t, tx.Commit())

	_, err = db.ExecContext(
		t.Context(),
		`DELETE FROM hytch_push_vault.access_audit
		  WHERE environment = 1`,
	)
	requireSQLState(t, err, "55000")
	assertAccessAuditBarrierRowCount(t, db, 3)
}

func TestAccessAuditPurgeBlocksConcurrentDeleteWhileGuardDisabled(
	t *testing.T,
) {
	const advisoryLockKey int64 = 4_701_000_000_009

	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 9))
	seedAccessAuditBarrierRows(t, db)

	_, err := db.ExecContext(
		t.Context(),
		`CREATE FUNCTION hytch_push_vault.test_access_audit_delete_block()
		 RETURNS TRIGGER
		 LANGUAGE plpgsql
		 AS $function$
		 BEGIN
		     PERFORM pg_catalog.pg_advisory_lock(
		         TG_ARGV[0]::BIGINT
		     );
		     PERFORM pg_catalog.pg_advisory_unlock(
		         TG_ARGV[0]::BIGINT
		     );
		     RETURN NULL;
		 END;
		 $function$;
		 CREATE TRIGGER zz_test_access_audit_delete_block
		 BEFORE DELETE
		 ON hytch_push_vault.access_audit
		 FOR EACH STATEMENT
		 EXECUTE FUNCTION
		     hytch_push_vault.test_access_audit_delete_block(
		         '4701000000009'
		     )`,
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	blocker, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = blocker.Close() }()
	_, err = blocker.ExecContext(
		ctx,
		`SELECT pg_catalog.pg_advisory_lock($1)`,
		advisoryLockKey,
	)
	require.NoError(t, err)
	lockHeld := true
	defer func() {
		if lockHeld {
			_, _ = blocker.ExecContext(
				context.Background(),
				`SELECT pg_catalog.pg_advisory_unlock($1)`,
				advisoryLockKey,
			)
		}
	}()

	purgeConnection, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = purgeConnection.Close() }()
	var purgeBackendPID int
	require.NoError(t, purgeConnection.QueryRowContext(
		ctx,
		`SELECT pg_catalog.pg_backend_pid()`,
	).Scan(&purgeBackendPID))

	type purgeResult struct {
		deleted int64
		err     error
	}
	purgeDone := make(chan purgeResult, 1)
	go func() {
		var deleted int64
		purgeErr := purgeConnection.QueryRowContext(
			ctx,
			`SELECT
			     hytch_push_vault.
			         purge_expired_access_audit_development()`,
		).Scan(&deleted)
		purgeDone <- purgeResult{deleted: deleted, err: purgeErr}
	}()

	require.Eventually(t, func() bool {
		var waiting bool
		queryErr := db.QueryRowContext(
			ctx,
			`SELECT EXISTS (
			     SELECT 1
			       FROM pg_catalog.pg_locks AS lock
			      WHERE lock.pid = $1
			        AND lock.locktype = 'advisory'
			        AND NOT lock.granted
			 )`,
			purgeBackendPID,
		).Scan(&waiting)
		return queryErr == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)

	concurrent, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = concurrent.Close() }()
	_, err = concurrent.ExecContext(
		ctx,
		`SET lock_timeout = '250ms'`,
	)
	require.NoError(t, err)
	_, err = concurrent.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.access_audit
		  WHERE event_id = $1`,
		bytes.Repeat([]byte{0x22}, 16),
	)
	requireSQLState(t, err, "55P03")

	_, err = blocker.ExecContext(
		ctx,
		`SELECT pg_catalog.pg_advisory_unlock($1)`,
		advisoryLockKey,
	)
	require.NoError(t, err)
	lockHeld = false

	select {
	case result := <-purgeDone:
		require.NoError(t, result.err)
		require.Equal(t, int64(1), result.deleted)
	case <-ctx.Done():
		require.Fail(t, "purge did not complete after advisory lock release")
	}

	var enabled string
	require.NoError(t, db.QueryRowContext(
		ctx,
		`SELECT trigger.tgenabled
		   FROM pg_catalog.pg_trigger AS trigger
		  WHERE trigger.tgrelid =
		        'hytch_push_vault.access_audit'::pg_catalog.regclass
		    AND trigger.tgname =
		        'hytch_access_audit_delete_guard'`,
	).Scan(&enabled))
	require.Equal(t, "A", enabled)
}

func seedAccessAuditBarrierRows(t *testing.T, db *sql.DB) {
	t.Helper()
	requests := []struct {
		id          []byte
		environment int16
	}{
		{bytes.Repeat([]byte{0x11}, 16), 1},
		{bytes.Repeat([]byte{0x12}, 16), 1},
		{bytes.Repeat([]byte{0x13}, 16), 2},
	}
	for _, request := range requests {
		_, err := db.ExecContext(
			t.Context(),
			`WITH utc_clock AS (
			     SELECT
			         date_trunc(
			             'hour',
			             clock_timestamp() AT TIME ZONE 'UTC'
			         ) AT TIME ZONE 'UTC' AS coarse_hour
			 )
			 INSERT INTO hytch_push_vault.access_requests (
			     request_id,
			     environment,
			     purpose,
			     data_class,
			     requester_actor,
			     ticket_reference,
			     hypothesis,
			     window_start,
			     window_end,
			     coarse_created_hour,
			     state
			 )
			 SELECT
			     $1,
			     $2,
			     1,
			     1,
			     'requester:append-only-test',
			     'incident:append-only-test',
			     1,
			     coarse_hour - INTERVAL '1 hour',
			     coarse_hour,
			     coarse_hour,
			     4
			   FROM utc_clock`,
			request.id,
			request.environment,
		)
		require.NoError(t, err)
	}

	audits := []struct {
		eventID     []byte
		requestID   []byte
		environment int16
		days        int
	}{
		{
			bytes.Repeat([]byte{0x21}, 16),
			bytes.Repeat([]byte{0x11}, 16),
			1,
			0,
		},
		{
			bytes.Repeat([]byte{0x22}, 16),
			bytes.Repeat([]byte{0x12}, 16),
			1,
			1,
		},
		{
			bytes.Repeat([]byte{0x23}, 16),
			bytes.Repeat([]byte{0x13}, 16),
			2,
			0,
		},
	}
	for _, audit := range audits {
		_, err := db.ExecContext(
			t.Context(),
			`WITH utc_clock AS (
			     SELECT
			         date_trunc(
			             'hour',
			             clock_timestamp() AT TIME ZONE 'UTC'
			         ) AT TIME ZONE 'UTC' AS coarse_hour,
			         (
			             clock_timestamp() AT TIME ZONE 'UTC'
			         )::DATE AS cutoff_date
			 )
			 INSERT INTO hytch_push_vault.access_audit (
			     event_id,
			     request_id,
			     environment,
			     actor,
			     purpose,
			     data_class,
			     coarse_event_hour,
			     action,
			     result_count_bucket,
			     expires_on
			 )
			 SELECT
			     $1,
			     $2,
			     $3,
			     'requester:append-only-test',
			     1,
			     1,
			     coarse_hour,
			     1,
			     0,
			     cutoff_date + $4::INTEGER
			   FROM utc_clock`,
			audit.eventID,
			audit.requestID,
			audit.environment,
			audit.days,
		)
		require.NoError(t, err)
	}
}

func assertAccessAuditBarrierObjects(
	t *testing.T,
	db *sql.DB,
	installed bool,
) {
	t.Helper()
	var triggerCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM pg_catalog.pg_trigger AS trigger
		   JOIN pg_catalog.pg_class AS relation
		     ON relation.oid = trigger.tgrelid
		   JOIN pg_catalog.pg_namespace AS namespace
		     ON namespace.oid = relation.relnamespace
		  WHERE namespace.nspname = 'hytch_push_vault'
		    AND relation.relname = 'access_audit'
		    AND trigger.tgname IN (
		        'hytch_access_audit_update_guard',
		        'hytch_access_audit_delete_guard',
		        'hytch_access_audit_truncate_guard'
		    )
		    AND trigger.tgenabled = 'A'
		    AND NOT trigger.tgisinternal`,
	).Scan(&triggerCount))

	var functionCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM pg_catalog.pg_proc AS routine
		   JOIN pg_catalog.pg_namespace AS namespace
		     ON namespace.oid = routine.pronamespace
		  WHERE namespace.nspname = 'hytch_push_vault'
		    AND routine.proname IN (
		        'reject_access_audit_mutation',
		        'purge_expired_access_audit_development',
		        'purge_expired_access_audit_production'
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
		         WHERE privilege.grantee = 0
		           AND privilege.privilege_type = 'EXECUTE'
		    )`,
	).Scan(&functionCount))

	if installed {
		require.Equal(t, 3, triggerCount)
		require.Equal(t, 3, functionCount)
	} else {
		require.Zero(t, triggerCount)
		require.Zero(t, functionCount)
	}
}

func assertAccessAuditBarrierRowCount(
	t *testing.T,
	db *sql.DB,
	expected int,
) {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*) FROM hytch_push_vault.access_audit`,
	).Scan(&count))
	require.Equal(t, expected, count)
}

func readAccessAuditBarrierMigration(
	t *testing.T,
	direction string,
) string {
	t.Helper()
	contents, err := os.ReadFile(
		"migrations/00009_append_only_access_audit." +
			direction + ".sql",
	)
	require.NoError(t, err)
	return string(contents)
}
