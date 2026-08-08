package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	"github.com/xmtp/example-notification-server-go/pkg/db/migrations"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestMigratePinsBookkeepingAndObjectsToIntendedSchemas(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	_, err := db.ExecContext(t.Context(), `
		CREATE SCHEMA shadow_schema;
		CREATE TABLE shadow_schema.schema_migrations (
			version BIGINT NOT NULL PRIMARY KEY,
			dirty BOOLEAN NOT NULL,
			marker TEXT NOT NULL
		);
		INSERT INTO shadow_schema.schema_migrations (
			version,
			dirty,
			marker
		) VALUES (424242, TRUE, 'shadow sentinel');
		SET search_path TO shadow_schema, public;
	`)
	require.NoError(t, err)

	require.NoError(t, database.Migrate(t.Context(), db))
	require.NoError(t, database.RequireCurrentSchema(t.Context(), db))

	latest, err := database.LatestMigrationVersion()
	require.NoError(t, err)

	var version int
	var dirty bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT version, dirty
		   FROM public.schema_migrations`,
	).Scan(&version, &dirty))
	require.Equal(t, latest, version)
	require.False(t, dirty)

	var shadowVersion int
	var shadowDirty bool
	var marker string
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT version, dirty, marker
		   FROM shadow_schema.schema_migrations`,
	).Scan(&shadowVersion, &shadowDirty, &marker))
	require.Equal(t, 424242, shadowVersion)
	require.True(t, shadowDirty)
	require.Equal(t, "shadow sentinel", marker)

	for _, relation := range []string{
		"public.installations",
		"public.device_delivery_mechanisms",
		"public.subscriptions",
		"public.subscription_hmac_keys",
		"hytch_push_vault.vault_key_bindings",
		"hytch_push_vault.installation_states",
		"hytch_push_vault.route_key_history",
		"hytch_push_vault.subscription_leases",
		"hytch_push_vault.welcome_authorizations",
		"hytch_push_vault.welcome_budgets",
		"hytch_push_vault.welcome_global_circuit",
		"hytch_push_vault.delivery_jobs",
		"hytch_push_vault.delivery_dedupes",
		"hytch_push_vault.deletion_tombstones",
		"hytch_push_vault.operational_aggregates",
		"hytch_push_vault.access_requests",
		"hytch_push_vault.access_audit",
		"hytch_push_vault.retention_state",
		"hytch_push_vault.legacy_routing_activation",
	} {
		assertQualifiedRelationExists(t, db, relation)
	}

	var unexpectedShadowRelations int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM pg_catalog.pg_class AS relation
		   JOIN pg_catalog.pg_namespace AS namespace
		     ON namespace.oid = relation.relnamespace
		  WHERE namespace.nspname = 'shadow_schema'
		    AND relation.relname <> 'schema_migrations'
		    AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')`,
	).Scan(&unexpectedShadowRelations))
	require.Zero(t, unexpectedShadowRelations)
}

func TestMigrateRejectsEnabledEventTriggerBeforeReconciliationOrDDL(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	createLegacyBunSchemaForMigrationPreflight(t, db)

	const eventTriggerName = "hytch_test_migration_event_trigger"
	const eventFunctionName = "hytch_test_migration_event_trigger"
	_, err := db.ExecContext(t.Context(), fmt.Sprintf(`
		CREATE FUNCTION public.%[1]s()
		RETURNS event_trigger
		LANGUAGE plpgsql
		AS $function$
		BEGIN
			NULL;
		END;
		$function$;
		CREATE EVENT TRIGGER %[2]s
			ON ddl_command_start
			EXECUTE FUNCTION public.%[1]s();
	`, eventFunctionName, eventTriggerName))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(
			context.Background(),
			"DROP EVENT TRIGGER IF EXISTS "+eventTriggerName,
		)
		_, _ = db.ExecContext(
			context.Background(),
			"DROP FUNCTION IF EXISTS public."+eventFunctionName+"()",
		)
	})

	err = database.Migrate(t.Context(), db)
	require.ErrorIs(t, err, migrations.ErrEnabledEventTrigger)
	assertQualifiedRelationMissing(t, db, "public.schema_migrations")
	assertQualifiedRelationMissing(
		t,
		db,
		"public.device_delivery_mechanisms_latest_idx",
	)

	var secureSchemaExists bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT to_regnamespace('hytch_push_vault') IS NOT NULL`,
	).Scan(&secureSchemaExists))
	require.False(t, secureSchemaExists)

	_, err = db.ExecContext(
		t.Context(),
		"ALTER EVENT TRIGGER "+eventTriggerName+" DISABLE",
	)
	require.NoError(t, err)
	require.NoError(t, database.Migrate(t.Context(), db))
	require.NoError(t, database.RequireCurrentSchema(t.Context(), db))
	assertQualifiedRelationExists(t, db, "public.schema_migrations")
	assertQualifiedRelationExists(
		t,
		db,
		"hytch_push_vault.installation_states",
	)
}

func TestRequireCurrentSchemaRequiresExactBookkeepingRelation(
	t *testing.T,
) {
	t.Run("exact migrated relation", func(t *testing.T) {
		db := testdb.CreateTestDb(t)
		require.NoError(t, database.RequireCurrentSchema(t.Context(), db))
	})

	latest, err := database.LatestMigrationVersion()
	require.NoError(t, err)
	tests := []struct {
		name       string
		statements string
	}{
		{
			name: "view instead of ordinary table",
			statements: fmt.Sprintf(`
				DROP TABLE public.schema_migrations;
				CREATE VIEW public.schema_migrations AS
				SELECT %d::BIGINT AS version, FALSE::BOOLEAN AS dirty;
			`, latest),
		},
		{
			name: "table outside public schema",
			statements: fmt.Sprintf(`
				DROP TABLE public.schema_migrations;
				CREATE SCHEMA shadow_bookkeeping;
				CREATE TABLE shadow_bookkeeping.schema_migrations (
					version BIGINT NOT NULL PRIMARY KEY,
					dirty BOOLEAN NOT NULL
				);
				INSERT INTO shadow_bookkeeping.schema_migrations (
					version,
					dirty
				) VALUES (%d, FALSE);
				SET search_path TO shadow_bookkeeping, public;
			`, latest),
		},
		{
			name:       "unlogged table",
			statements: `ALTER TABLE public.schema_migrations SET UNLOGGED`,
		},
		{
			name: "row level security",
			statements: `
				ALTER TABLE public.schema_migrations
					ENABLE ROW LEVEL SECURITY
			`,
		},
		{
			name: "forced row level security",
			statements: `
				ALTER TABLE public.schema_migrations
					ENABLE ROW LEVEL SECURITY;
				ALTER TABLE public.schema_migrations
					FORCE ROW LEVEL SECURITY;
			`,
		},
		{
			name: "user policy",
			statements: `
				CREATE POLICY schema_migrations_user_policy
					ON public.schema_migrations
					USING (TRUE)
					WITH CHECK (TRUE)
			`,
		},
		{
			name: "user rule",
			statements: `
				CREATE RULE schema_migrations_user_rule
					AS ON UPDATE TO public.schema_migrations
					DO ALSO NOTHING
			`,
		},
		{
			name: "unexpected column",
			statements: `
				ALTER TABLE public.schema_migrations
					ADD COLUMN unexpected BOOLEAN NOT NULL DEFAULT FALSE
			`,
		},
		{
			name: "missing version primary key",
			statements: `
				ALTER TABLE public.schema_migrations
					DROP CONSTRAINT schema_migrations_pkey
			`,
		},
		{
			name: "user trigger",
			statements: `
				CREATE FUNCTION public.schema_migrations_user_trigger()
				RETURNS TRIGGER
				LANGUAGE plpgsql
				AS $function$
				BEGIN
					RETURN NEW;
				END;
				$function$;
				CREATE TRIGGER schema_migrations_user_trigger
					BEFORE UPDATE ON public.schema_migrations
					FOR EACH ROW
					EXECUTE FUNCTION
						public.schema_migrations_user_trigger()
			`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := testdb.CreateTestDb(t)
			_, mutationErr := db.ExecContext(
				t.Context(),
				test.statements,
			)
			require.NoError(t, mutationErr)
			require.ErrorIs(
				t,
				database.RequireCurrentSchema(t.Context(), db),
				migrations.ErrSchemaNotCurrent,
			)
		})
	}
}

func createLegacyBunSchemaForMigrationPreflight(
	t *testing.T,
	db *sql.DB,
) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `
		CREATE TABLE public.installations (
			id TEXT PRIMARY KEY,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted_at TIMESTAMPTZ
		);
		CREATE TABLE public.device_delivery_mechanisms (
			id BIGSERIAL PRIMARY KEY,
			installation_id TEXT NOT NULL
				REFERENCES public.installations(id),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			kind TEXT NOT NULL,
			token TEXT NOT NULL,
			UNIQUE (installation_id, kind, token)
		);
		CREATE TABLE public.subscriptions (
			id BIGSERIAL PRIMARY KEY,
			installation_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			topic TEXT NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT FALSE,
			is_silent BOOLEAN NOT NULL DEFAULT FALSE
		);
		CREATE INDEX subscriptions_topic_is_active_idx
			ON public.subscriptions (topic, is_active);
		CREATE UNIQUE INDEX subscriptions_installation_id_topic_idx
			ON public.subscriptions (installation_id, topic);
		CREATE INDEX device_delivery_mechanisms_installation_id_idx
			ON public.device_delivery_mechanisms (installation_id);
		CREATE TABLE public.subscription_hmac_keys (
			subscription_id BIGINT NOT NULL
				REFERENCES public.subscriptions(id) ON DELETE CASCADE,
			thirty_day_periods_since_epoch INTEGER NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			key BYTEA NOT NULL,
			PRIMARY KEY (
				subscription_id,
				thirty_day_periods_since_epoch
			)
		);
	`)
	require.NoError(t, err)
}
