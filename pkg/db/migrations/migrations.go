package migrations

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed *.sql
var migrationFS embed.FS

// Legacy Bun deployments are considered equivalent to the first two golang-migrate
// migrations:
//  1. init schema
//  2. add subscription_hmac_keys + is_silent + unique subscription index
//
// Reconciliation must stay pinned to that handoff point so future golang-migrate-only
// migrations are still applied normally after older deployments upgrade.
const legacyBunBaselineVersion = 2

var ErrSchemaNotCurrent = errors.New("database schema is not current")
var ErrEnabledEventTrigger = errors.New(
	"enabled database event trigger blocks migration",
)

// LatestVersion returns the highest migration version found in the embedded
// migration files. This is useful for tests that need to assert the current
// schema version without hardcoding a number.
func LatestVersion() (int, error) {
	entries, err := migrationFS.ReadDir(".")
	if err != nil {
		return 0, err
	}
	max := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) < 5 {
			continue
		}
		seq, err := strconv.Atoi(name[:5])
		if err != nil {
			continue
		}
		if seq > max {
			max = seq
		}
	}
	return max, nil
}

// Migrate always uses golang-migrate's schema_migrations table as the source of truth.
// For databases that were previously bootstrapped by Bun, we first "reconcile" by
// recording the fixed Bun-equivalent golang-migrate version in schema_migrations
// without replaying those baseline migrations. That handoff lets already-initialized
// deployments keep their existing application tables while still allowing future
// golang-migrate-only migrations to run normally after upgrade.
func Migrate(ctx context.Context, db *sql.DB) error {
	if err := RequireNoEnabledEventTriggers(ctx, db); err != nil {
		return err
	}
	return withMigrator(ctx, db, func(m *migrate.Migrate) error {
		return m.Up()
	})
}

// MigrateUpTo runs migrations up to (and including) the given version.
func MigrateUpTo(ctx context.Context, db *sql.DB, version uint) error {
	if err := RequireNoEnabledEventTriggers(ctx, db); err != nil {
		return err
	}
	return withMigrator(ctx, db, func(m *migrate.Migrate) error {
		return m.Migrate(version)
	})
}

// RequireNoEnabledEventTriggers is a read-only preflight that must run before
// any migration DDL. An enabled event trigger can observe DDL while legacy
// plaintext rows still exist, so migration refuses every enabled mode,
// including ENABLE REPLICA and ENABLE ALWAYS.
func RequireNoEnabledEventTriggers(
	ctx context.Context,
	db *sql.DB,
) error {
	if db == nil {
		return ErrEnabledEventTrigger
	}
	var enabled bool
	if err := db.QueryRowContext(
		ctx,
		`SELECT EXISTS (
		     SELECT 1
		       FROM pg_catalog.pg_event_trigger AS event_trigger
		      WHERE event_trigger.evtenabled <> 'D'
		 )`,
	).Scan(&enabled); err != nil {
		return ErrEnabledEventTrigger
	}
	if enabled {
		return ErrEnabledEventTrigger
	}
	return nil
}

// RequireCurrent is a read-only runtime gate. Secure services use it instead
// of applying owner-level migrations during process startup.
func RequireCurrent(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return ErrSchemaNotCurrent
	}
	latest, err := LatestVersion()
	if err != nil {
		return ErrSchemaNotCurrent
	}
	var tableExists bool
	if err = db.QueryRowContext(
		ctx,
		`SELECT pg_catalog.to_regclass(
		     'public.schema_migrations'
		 ) IS NOT NULL`,
	).Scan(&tableExists); err != nil || !tableExists {
		return ErrSchemaNotCurrent
	}
	var relationValid bool
	if err = db.QueryRowContext(
		ctx,
		`WITH migration_relation AS (
		     SELECT relation.*
		       FROM pg_catalog.pg_class AS relation
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = relation.relnamespace
		      WHERE namespace.nspname = 'public'
		        AND relation.relname = 'schema_migrations'
		 )
		 SELECT COALESCE((
		     SELECT
		         relation.relkind = 'r' AND
		         relation.relpersistence = 'p' AND
		         NOT relation.relispartition AND
		         NOT relation.relhassubclass AND
		         NOT relation.relrowsecurity AND
		         NOT relation.relforcerowsecurity AND
		         NOT relation.relhastriggers AND
		         NOT relation.relhasrules AND
		         (
		             SELECT pg_catalog.count(*) = 2 AND
		                    COALESCE(pg_catalog.bool_and(
		                        attribute.attnotnull AND
		                        attribute.attidentity = '' AND
		                        attribute.attgenerated = '' AND
		                        NOT attribute.atthasdef AND
		                        attribute.attacl IS NULL AND
		                        attribute.attoptions IS NULL AND
		                        attribute.attcollation = 0 AND
		                        (
		                            (
		                                attribute.attnum = 1 AND
		                                attribute.attname = 'version' AND
		                                attribute.atttypid =
		                                    'pg_catalog.int8'
		                                        ::pg_catalog.regtype
		                            ) OR (
		                                attribute.attnum = 2 AND
		                                attribute.attname = 'dirty' AND
		                                attribute.atttypid =
		                                    'pg_catalog.bool'
		                                        ::pg_catalog.regtype
		                            )
		                        )
		                    ), FALSE)
		               FROM pg_catalog.pg_attribute AS attribute
		              WHERE attribute.attrelid = relation.oid
		                AND attribute.attnum > 0
		                AND NOT attribute.attisdropped
		         ) AND
		         (
		             SELECT (
		                        (
		                            pg_catalog.current_setting(
		                                'server_version_num'
		                            )::pg_catalog.int4 >= 130000 AND
		                            pg_catalog.current_setting(
		                                'server_version_num'
		                            )::pg_catalog.int4 < 140000 AND
		                            pg_catalog.count(*) = 1 AND
		                            pg_catalog.count(*) FILTER (
		                                WHERE constraint_record.contype = 'n'
		                            ) = 0
		                        ) OR (
		                            pg_catalog.current_setting(
		                                'server_version_num'
		                            )::pg_catalog.int4 >= 180000 AND
		                            pg_catalog.current_setting(
		                                'server_version_num'
		                            )::pg_catalog.int4 < 190000 AND
		                            pg_catalog.count(*) = 3 AND
		                            pg_catalog.count(*) FILTER (
		                                WHERE constraint_record.contype = 'n'
		                            ) = 2
		                        )
		                    ) AND
		                    pg_catalog.count(*) FILTER (
		                        WHERE constraint_record.contype <> 'n'
		                    ) = 1 AND
		                    pg_catalog.count(*) FILTER (
		                        WHERE constraint_record.contype = 'p' AND
		                              constraint_record.conkey = ARRAY[
		                                  (
		                                      SELECT attribute.attnum
		                                        FROM pg_catalog.pg_attribute AS
		                                             attribute
		                                       WHERE attribute.attrelid = relation.oid
		                                         AND attribute.attname = 'version'
		                                         AND NOT attribute.attisdropped
		                                  )
		                              ]::pg_catalog.int2[]
		                              AND constraint_record.convalidated
		                              AND NOT constraint_record.condeferrable
		                              AND NOT constraint_record.condeferred
		                              AND constraint_record.conislocal
		                              AND constraint_record.coninhcount = 0
		                              AND constraint_record.connoinherit
		                    ) = 1
		               FROM pg_catalog.pg_constraint AS constraint_record
		              WHERE constraint_record.conrelid = relation.oid
		         ) AND
		         NOT EXISTS (
		             SELECT 1
		               FROM pg_catalog.pg_inherits AS inheritance
		              WHERE inheritance.inhrelid = relation.oid OR
		                    inheritance.inhparent = relation.oid
		         ) AND
		         NOT EXISTS (
		             SELECT 1
		               FROM pg_catalog.pg_policy AS policy
		              WHERE policy.polrelid = relation.oid
		         ) AND
		         NOT EXISTS (
		             SELECT 1
		               FROM pg_catalog.pg_rewrite AS rewrite_rule
		              WHERE rewrite_rule.ev_class = relation.oid
		         ) AND
		         NOT EXISTS (
		             SELECT 1
		               FROM pg_catalog.pg_trigger AS trigger
		              WHERE trigger.tgrelid = relation.oid
		         )
		       FROM migration_relation AS relation
		 ), FALSE)`,
	).Scan(&relationValid); err != nil || !relationValid {
		return ErrSchemaNotCurrent
	}
	var rowCount int
	var version int
	var dirty bool
	if err = db.QueryRowContext(
		ctx,
		`SELECT
		     pg_catalog.count(*),
		     COALESCE(pg_catalog.max(version), 0),
		     COALESCE(pg_catalog.bool_or(dirty), TRUE)
		   FROM public.schema_migrations`,
	).Scan(&rowCount, &version, &dirty); err != nil {
		return ErrSchemaNotCurrent
	}
	if rowCount != 1 || version != latest || dirty {
		return ErrSchemaNotCurrent
	}
	return nil
}

func withMigrator(ctx context.Context, db *sql.DB, fn func(*migrate.Migrate) error) error {
	sourceDriver, err := iofs.New(migrationFS, ".")
	if err != nil {
		return err
	}
	defer func() {
		_ = sourceDriver.Close()
	}()

	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()

	if _, err = conn.ExecContext(
		ctx,
		`SELECT pg_catalog.set_config(
		     'search_path',
		     'public',
		     FALSE
		 )`,
	); err != nil {
		return err
	}
	if err = reconcileExistingBunSchema(ctx, conn); err != nil {
		return err
	}

	driver, err := postgres.WithConnection(
		ctx,
		conn,
		&postgres.Config{SchemaName: "public"},
	)
	if err != nil {
		return err
	}
	defer func() {
		_ = driver.Close()
	}()

	migrator, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", driver)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = migrator.Close()
	}()

	if err := fn(migrator); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	return nil
}

// reconcileExistingBunSchema bridges databases that already have the legacy Bun-era
// application schema but do not yet have golang-migrate bookkeeping.
//
// Before reconciliation:
//   - the application tables already exist (installations, device_delivery_mechanisms,
//     subscriptions, subscription_hmac_keys, plus the legacy indexes/columns)
//   - schema_migrations is missing or empty
//
// After reconciliation:
//   - the application tables are unchanged
//   - schema_migrations exists and contains the fixed Bun-equivalent baseline version
//
// We intentionally do not translate Bun's bun_migrations metadata into golang-migrate
// rows. The application data tables are what matter for boot compatibility, so we detect
// the fully-initialized legacy schema directly and mark the new migration runner at the
// Bun handoff version rather than at whatever the latest embedded migration happens to be.
type databaseConnection interface {
	ExecContext(
		ctx context.Context,
		query string,
		args ...any,
	) (sql.Result, error)
	QueryRowContext(
		ctx context.Context,
		query string,
		args ...any,
	) *sql.Row
}

func reconcileExistingBunSchema(
	ctx context.Context,
	db databaseConnection,
) error {
	alreadyTracked, err := hasSchemaMigrationState(ctx, db)
	if err != nil {
		return err
	}
	if alreadyTracked {
		return nil
	}

	exists, err := hasLegacySchema(ctx, db)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS public.schema_migrations (
			version bigint NOT NULL PRIMARY KEY,
			dirty boolean NOT NULL
		)`); err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO public.schema_migrations (version, dirty)
		VALUES ($1, FALSE)
		ON CONFLICT (version) DO UPDATE SET dirty = EXCLUDED.dirty
	`, legacyBunBaselineVersion)
	return err
}

func hasSchemaMigrationState(
	ctx context.Context,
	db databaseConnection,
) (bool, error) {
	var tableExists bool
	if err := db.QueryRowContext(
		ctx,
		`SELECT pg_catalog.to_regclass(
		     'public.schema_migrations'
		 ) IS NOT NULL`,
	).Scan(&tableExists); err != nil {
		return false, err
	}
	if !tableExists {
		return false, nil
	}

	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT pg_catalog.count(*)
		   FROM public.schema_migrations`,
	).Scan(&count); err != nil {
		return false, err
	}

	return count > 0, nil
}

func hasLegacySchema(
	ctx context.Context,
	db databaseConnection,
) (bool, error) {
	checks := []string{
		`SELECT pg_catalog.to_regclass(
		     'public.installations'
		 ) IS NOT NULL`,
		`SELECT pg_catalog.to_regclass(
		     'public.device_delivery_mechanisms'
		 ) IS NOT NULL`,
		`SELECT pg_catalog.to_regclass(
		     'public.subscriptions'
		 ) IS NOT NULL`,
		`SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name = 'subscriptions'
			  AND column_name = 'is_silent'
		)`,
		`SELECT pg_catalog.to_regclass(
		     'public.subscriptions_installation_id_topic_idx'
		 ) IS NOT NULL`,
		`SELECT pg_catalog.to_regclass(
		     'public.subscription_hmac_keys'
		 ) IS NOT NULL`,
	}

	for _, query := range checks {
		var ok bool
		if err := db.QueryRowContext(ctx, query).Scan(&ok); err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}

	return true, nil
}
