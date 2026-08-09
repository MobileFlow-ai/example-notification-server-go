package vault

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestAccessAuditBarrierRequiresRestrictedRuntimeRole(t *testing.T) {
	requireVaultIntegrationTests(t)
	for _, environmentID := range []int16{
		environmentDevelopment,
		environmentProduction,
	} {
		t.Run(fmt.Sprintf("environment-%d", environmentID), func(t *testing.T) {
			db := testdb.CreateTestDb(t)
			store := &Store{db: db, environmentID: environmentID}

			require.ErrorIs(
				t,
				store.RequireAccessAuditBarrier(t.Context()),
				ErrAccessAuditBarrierInvalid,
			)

			role := createAccessAuditRuntimeRole(t, db, environmentID)
			require.NoError(
				t,
				runAccessAuditBarrierAsRole(t, db, store, role),
			)
		})
	}
}

func TestAccessAuditBarrierPinsCatalogSearchPath(t *testing.T) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	role := createAccessAuditRuntimeRole(
		t,
		db,
		environmentDevelopment,
	)
	execAccessAuditTamperSQL(
		t,
		db,
		`CREATE SCHEMA barrier_shadow;
		 CREATE FUNCTION barrier_shadow.octet_length(BYTEA)
		 RETURNS INTEGER
		 LANGUAGE SQL
		 IMMUTABLE
		 STRICT
		 AS $function$
		     SELECT 16
		 $function$;
		 SET search_path = barrier_shadow, pg_catalog`,
	)
	store := &Store{
		db:            db,
		environmentID: environmentDevelopment,
	}
	require.NoError(
		t,
		runAccessAuditBarrierAsRole(t, db, store, role),
	)
}

func TestAccessAuditBarrierAcceptsEquivalentPG18NotNullNames(t *testing.T) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	var serverVersion int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.current_setting(
		             'server_version_num'
		         )::pg_catalog.int4`,
	).Scan(&serverVersion))
	if serverVersion < 180000 || serverVersion >= 190000 {
		t.Skip("PostgreSQL 18 named NOT NULL catalog case")
	}
	role := createAccessAuditRuntimeRole(
		t,
		db,
		environmentDevelopment,
	)
	execAccessAuditTamperSQL(
		t,
		db,
		`ALTER TABLE hytch_push_vault.access_audit
		     RENAME CONSTRAINT access_audit_actor_not_null
		     TO restored_actor_not_null`,
	)
	store := &Store{
		db:            db,
		environmentID: environmentDevelopment,
	}
	require.NoError(
		t,
		runAccessAuditBarrierAsRole(t, db, store, role),
	)
}

func TestAccessAuditBarrierRejectsRuntimeACLDrift(t *testing.T) {
	requireVaultIntegrationTests(t)
	testCases := []struct {
		name   string
		tamper func(*testing.T, *sql.DB, string)
	}{
		{
			name: "missing select",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`REVOKE SELECT
					     ON TABLE hytch_push_vault.access_audit
					   FROM %s`,
				)
			},
		},
		{
			name: "missing insert",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`REVOKE INSERT
					     ON TABLE hytch_push_vault.access_audit
					   FROM %s`,
				)
			},
		},
		{
			name: "missing purge execute",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`REVOKE EXECUTE
					     ON FUNCTION
					         hytch_push_vault.
					             purge_expired_access_audit_development()
					   FROM %s`,
				)
			},
		},
		{
			name: "update privilege",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`GRANT UPDATE
					     ON TABLE hytch_push_vault.access_audit
					   TO %s`,
				)
			},
		},
		{
			name: "column update privilege",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`GRANT UPDATE (actor)
					     ON TABLE hytch_push_vault.access_audit
					   TO %s`,
				)
			},
		},
		{
			name: "delete privilege",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`GRANT DELETE
					     ON TABLE hytch_push_vault.access_audit
					   TO %s`,
				)
			},
		},
		{
			name: "truncate privilege",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`GRANT TRUNCATE
					     ON TABLE hytch_push_vault.access_audit
					   TO %s`,
				)
			},
		},
		{
			name: "guard execute privilege",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`GRANT EXECUTE
					     ON FUNCTION
					         hytch_push_vault.reject_access_audit_mutation()
					   TO %s`,
				)
			},
		},
		{
			name: "purge grant option",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`GRANT EXECUTE
					     ON FUNCTION
					         hytch_push_vault.
					             purge_expired_access_audit_development()
					   TO %s
					   WITH GRANT OPTION`,
				)
			},
		},
		{
			name: "cross environment purge privilege",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`GRANT EXECUTE
					     ON FUNCTION
					         hytch_push_vault.
					             purge_expired_access_audit_production()
					   TO %s`,
				)
			},
		},
		{
			name: "schema create privilege",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`GRANT CREATE
					     ON SCHEMA hytch_push_vault
					   TO %s`,
				)
			},
		},
		{
			name: "table ownership",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				execAccessAuditRoleSQL(
					t,
					db,
					role,
					`ALTER TABLE hytch_push_vault.access_audit
					     OWNER TO %s`,
				)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			db := testdb.CreateTestDb(t)
			role := createAccessAuditRuntimeRole(
				t,
				db,
				environmentDevelopment,
			)
			store := &Store{
				db:            db,
				environmentID: environmentDevelopment,
			}
			require.NoError(
				t,
				runAccessAuditBarrierAsRole(t, db, store, role),
			)

			testCase.tamper(t, db, role)
			require.ErrorIs(
				t,
				runAccessAuditBarrierAsRole(t, db, store, role),
				ErrAccessAuditBarrierInvalid,
			)
		})
	}
}

func TestAccessAuditBarrierRejectsCatalogTampering(t *testing.T) {
	requireVaultIntegrationTests(t)
	testCases := []struct {
		name   string
		tamper func(*testing.T, *sql.DB)
	}{
		{
			name: "disabled delete trigger",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`ALTER TABLE hytch_push_vault.access_audit
					     DISABLE TRIGGER
					         hytch_access_audit_delete_guard`,
				)
			},
		},
		{
			name: "conditional row trigger",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`DROP TRIGGER hytch_access_audit_update_guard
					     ON hytch_push_vault.access_audit;
					 CREATE TRIGGER hytch_access_audit_update_guard
					 BEFORE UPDATE
					 ON hytch_push_vault.access_audit
					 FOR EACH ROW
					 WHEN (FALSE)
					 EXECUTE FUNCTION
					     hytch_push_vault.reject_access_audit_mutation();
					 ALTER TABLE hytch_push_vault.access_audit
					     ENABLE ALWAYS TRIGGER
					         hytch_access_audit_update_guard`,
				)
			},
		},
		{
			name: "redirected truncate trigger",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`CREATE FUNCTION
					     hytch_push_vault.test_access_audit_noop()
					 RETURNS TRIGGER
					 LANGUAGE plpgsql
					 AS $function$
					 BEGIN
					     RETURN NULL;
					 END;
					 $function$;
					 DROP TRIGGER hytch_access_audit_truncate_guard
					     ON hytch_push_vault.access_audit;
					 CREATE TRIGGER hytch_access_audit_truncate_guard
					 BEFORE TRUNCATE
					 ON hytch_push_vault.access_audit
					 FOR EACH STATEMENT
					 EXECUTE FUNCTION
					     hytch_push_vault.test_access_audit_noop();
					 ALTER TABLE hytch_push_vault.access_audit
					     ENABLE ALWAYS TRIGGER
					         hytch_access_audit_truncate_guard`,
				)
			},
		},
		{
			name: "reject function source",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`CREATE OR REPLACE FUNCTION
					     hytch_push_vault.reject_access_audit_mutation()
					 RETURNS TRIGGER
					 LANGUAGE plpgsql
					 SECURITY DEFINER
					 SET search_path = pg_catalog
					 AS $function$
					 BEGIN
					     RETURN NULL;
					 END;
					 $function$`,
				)
			},
		},
		{
			name: "development purge function source",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`CREATE OR REPLACE FUNCTION
					     hytch_push_vault.
					         purge_expired_access_audit_development()
					 RETURNS BIGINT
					 LANGUAGE plpgsql
					 SECURITY DEFINER
					 SET search_path = pg_catalog
					 AS $function$
					 BEGIN
					     RETURN 0;
					 END;
					 $function$`,
				)
			},
		},
		{
			name: "production purge function source",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`CREATE OR REPLACE FUNCTION
					     hytch_push_vault.
					         purge_expired_access_audit_production()
					 RETURNS BIGINT
					 LANGUAGE plpgsql
					 SECURITY DEFINER
					 SET search_path = pg_catalog
					 AS $function$
					 BEGIN
					     RETURN 0;
					 END;
					 $function$`,
				)
			},
		},
		{
			name: "public purge execute",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`GRANT EXECUTE
					     ON FUNCTION
					         hytch_push_vault.
					             purge_expired_access_audit_development()
					   TO PUBLIC`,
				)
			},
		},
		{
			name: "row level security",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`ALTER TABLE hytch_push_vault.access_audit
					     ENABLE ROW LEVEL SECURITY`,
				)
			},
		},
		{
			name: "rewrite rule",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`CREATE RULE hytch_access_audit_update_noop
					 AS ON UPDATE
					 TO hytch_push_vault.access_audit
					 DO INSTEAD NOTHING`,
				)
			},
		},
		{
			name: "extra column",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`ALTER TABLE hytch_push_vault.access_audit
					     ADD COLUMN test_extra BOOLEAN NOT NULL
					     DEFAULT FALSE`,
				)
			},
		},
		{
			name: "extra index",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`CREATE INDEX hytch_access_audit_test_index
					     ON hytch_push_vault.access_audit (actor)`,
				)
			},
		},
		{
			name: "weakened environment constraint",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`ALTER TABLE hytch_push_vault.access_audit
					     DROP CONSTRAINT
					         access_audit_environment_check;
					 ALTER TABLE hytch_push_vault.access_audit
					     ADD CONSTRAINT
					         access_audit_environment_check
					     CHECK (environment IN (1, 2, 3))`,
				)
			},
		},
		{
			name: "weakened event identifier constraint",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`ALTER TABLE hytch_push_vault.access_audit
					     DROP CONSTRAINT
					         access_audit_event_id_check;
					 ALTER TABLE hytch_push_vault.access_audit
					     ADD CONSTRAINT access_audit_event_id_check
					     CHECK (octet_length(event_id) > 0)`,
				)
			},
		},
		{
			name: "unenforced event identifier constraint",
			tamper: func(t *testing.T, db *sql.DB) {
				var serverVersion int
				require.NoError(t, db.QueryRowContext(
					t.Context(),
					`SELECT pg_catalog.current_setting(
					             'server_version_num'
					         )::pg_catalog.int4`,
				).Scan(&serverVersion))
				if serverVersion < 180000 || serverVersion >= 190000 {
					t.Skip("PostgreSQL 18 NOT ENFORCED catalog case")
				}
				execAccessAuditTamperSQL(
					t,
					db,
					`ALTER TABLE hytch_push_vault.access_audit
					     DROP CONSTRAINT access_audit_event_id_check;
					 ALTER TABLE hytch_push_vault.access_audit
					     ADD CONSTRAINT access_audit_event_id_check
					     CHECK (octet_length(event_id) = 16)
					     NOT ENFORCED`,
				)
			},
		},
		{
			name: "shadowed event identifier function",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`CREATE SCHEMA barrier_shadow;
					 CREATE FUNCTION barrier_shadow.octet_length(BYTEA)
					 RETURNS INTEGER
					 LANGUAGE SQL
					 IMMUTABLE
					 STRICT
					 AS $function$
					     SELECT 16
					 $function$;
					 SET search_path = barrier_shadow, pg_catalog;
					 ALTER TABLE hytch_push_vault.access_audit
					     DROP CONSTRAINT access_audit_event_id_check;
					 ALTER TABLE hytch_push_vault.access_audit
					     ADD CONSTRAINT access_audit_event_id_check
					     CHECK (octet_length(event_id) = 16)`,
				)
			},
		},
		{
			name: "weakened coarse hour constraint",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`ALTER TABLE hytch_push_vault.access_audit
					     DROP CONSTRAINT
					         access_audit_coarse_event_hour_check;
					 ALTER TABLE hytch_push_vault.access_audit
					     ADD CONSTRAINT
					         access_audit_coarse_event_hour_check
					     CHECK (TRUE)`,
				)
			},
		},
		{
			name: "weakened expiry constraint",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`ALTER TABLE hytch_push_vault.access_audit
					     DROP CONSTRAINT access_audit_check;
					 ALTER TABLE hytch_push_vault.access_audit
					     ADD CONSTRAINT access_audit_check
					     CHECK (
					         expires_on <=
					             (
					                 coarse_event_hour
					                     AT TIME ZONE 'UTC'
					             )::date + 365
					     )`,
				)
			},
		},
		{
			name: "unvalidated named not null constraint",
			tamper: func(t *testing.T, db *sql.DB) {
				var serverVersion int
				require.NoError(t, db.QueryRowContext(
					t.Context(),
					`SELECT pg_catalog.current_setting(
					             'server_version_num'
					         )::pg_catalog.int4`,
				).Scan(&serverVersion))
				if serverVersion < 180000 || serverVersion >= 190000 {
					t.Skip("PostgreSQL 18 named NOT NULL catalog case")
				}
				execAccessAuditTamperSQL(
					t,
					db,
					`ALTER TABLE hytch_push_vault.access_audit
					     ALTER COLUMN actor DROP NOT NULL;
					 WITH utc_clock AS (
					     SELECT date_trunc(
					                'hour',
					                pg_catalog.clock_timestamp()
					                    AT TIME ZONE 'UTC'
					            ) AT TIME ZONE 'UTC' AS coarse_hour
					 ), request_row AS (
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
					     SELECT decode(
					                '11111111111111111111111111111111',
					                'hex'
					            ),
					            1,
					            1,
					            1,
					            'requester:not-null-test',
					            'incident:not-null-test',
					            1,
					            coarse_hour - INTERVAL '1 hour',
					            coarse_hour,
					            coarse_hour,
					            4
					       FROM utc_clock
					     RETURNING request_id, environment
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
					 SELECT decode(
					            '22222222222222222222222222222222',
					            'hex'
					        ),
					        request_row.request_id,
					        request_row.environment,
					        NULL,
					        1,
					        1,
					        utc_clock.coarse_hour,
					        1,
					        0,
					        (
					            utc_clock.coarse_hour AT TIME ZONE 'UTC'
					        )::DATE + 180
					   FROM request_row
					   CROSS JOIN utc_clock;
					 ALTER TABLE hytch_push_vault.access_audit
					     ADD CONSTRAINT access_audit_actor_not_null
					     NOT NULL actor NOT VALID`,
				)
			},
		},
		{
			name: "unlogged relation",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`ALTER TABLE hytch_push_vault.access_audit
					     SET UNLOGGED`,
				)
			},
		},
		{
			name: "inherited child relation",
			tamper: func(t *testing.T, db *sql.DB) {
				execAccessAuditTamperSQL(
					t,
					db,
					`CREATE TABLE
					     hytch_push_vault.test_access_audit_child ()
					 INHERITS (hytch_push_vault.access_audit)`,
				)
			},
		},
		{
			name: "enabled event trigger",
			tamper: func(t *testing.T, db *sql.DB) {
				installNoopEventTrigger(t, db)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			db := testdb.CreateTestDb(t)
			role := createAccessAuditRuntimeRole(
				t,
				db,
				environmentDevelopment,
			)
			store := &Store{
				db:            db,
				environmentID: environmentDevelopment,
			}
			require.NoError(
				t,
				runAccessAuditBarrierAsRole(t, db, store, role),
			)

			testCase.tamper(t, db)
			require.ErrorIs(
				t,
				runAccessAuditBarrierAsRole(t, db, store, role),
				ErrAccessAuditBarrierInvalid,
			)
		})
	}
}

func createAccessAuditRuntimeRole(
	t *testing.T,
	db *sql.DB,
	environmentID int16,
) string {
	t.Helper()
	var purgeRoutine string
	switch environmentID {
	case environmentDevelopment:
		purgeRoutine = "hytch_push_vault." +
			"purge_expired_access_audit_development()"
	case environmentProduction:
		purgeRoutine = "hytch_push_vault." +
			"purge_expired_access_audit_production()"
	default:
		t.Fatal("invalid test environment")
	}
	role := fmt.Sprintf(
		"hytch_access_audit_%d",
		time.Now().UnixNano(),
	)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`CREATE ROLE %s NOLOGIN`,
			quotePostgresIdentifier(role),
		),
	)
	require.NoError(t, err)
	execAccessAuditRoleSQL(
		t,
		db,
		role,
		fmt.Sprintf(
			`GRANT USAGE
			     ON SCHEMA hytch_push_vault
			   TO %%[1]s;
			 GRANT SELECT, INSERT
			     ON TABLE hytch_push_vault.access_audit
			   TO %%[1]s;
			 GRANT EXECUTE
			     ON FUNCTION %s
			   TO %%[1]s`,
			purgeRoutine,
		),
	)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `RESET ROLE`)
		_, _ = db.ExecContext(
			context.Background(),
			fmt.Sprintf(
				`DROP OWNED BY %s`,
				quotePostgresIdentifier(role),
			),
		)
		_, _ = db.ExecContext(
			context.Background(),
			fmt.Sprintf(
				`DROP ROLE IF EXISTS %s`,
				quotePostgresIdentifier(role),
			),
		)
	})
	return role
}

func runAccessAuditBarrierAsRole(
	t *testing.T,
	db *sql.DB,
	store *Store,
	role string,
) error {
	t.Helper()
	setRole(t, db, role)
	err := store.RequireAccessAuditBarrier(t.Context())
	resetRole(t, db)
	return err
}

func execAccessAuditRoleSQL(
	t *testing.T,
	db *sql.DB,
	role string,
	statement string,
) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			statement,
			quotePostgresIdentifier(role),
		),
	)
	require.NoError(t, err)
}

func execAccessAuditTamperSQL(
	t *testing.T,
	db *sql.DB,
	statement string,
) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), statement)
	require.NoError(t, err)
}
