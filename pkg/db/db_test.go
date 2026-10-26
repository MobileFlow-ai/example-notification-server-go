package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestMigrateFreshDatabase(t *testing.T) {
	db := createRawDB(t)
	resetSchema(t, db)

	require.NoError(t, database.Migrate(t.Context(), db))
	require.NoError(t, database.Migrate(t.Context(), db))

	assertRelationExists(t, db, "installations")
	assertRelationExists(t, db, "device_delivery_mechanisms")
	assertRelationExists(t, db, "subscriptions")
	assertRelationExists(t, db, "subscription_hmac_keys")
	assertRelationExists(t, db, "subscriptions_installation_id_topic_idx")
	assertRelationExists(t, db, "device_delivery_mechanisms_latest_idx")
	assertQualifiedRelationExists(t, db, "hytch_push_vault.installation_states")
	assertQualifiedRelationExists(t, db, "hytch_push_vault.subscription_leases")
	assertQualifiedRelationExists(t, db, "hytch_push_vault.delivery_jobs")
	assertQualifiedRelationExists(t, db, "hytch_push_vault.delivery_dedupes")
	assertQualifiedRelationExists(t, db, "notification_queue.notification_envelopes")
	assertQualifiedRelationExists(t, db, "notification_queue.notification_recipient_receipts")
}

func TestMigrateExistingLegacySchema(t *testing.T) {
	db := createRawDB(t)
	resetSchema(t, db)

	legacyStatements := []string{
		`CREATE TABLE installations (
			id TEXT PRIMARY KEY,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted_at TIMESTAMPTZ
		)`,
		`CREATE TABLE device_delivery_mechanisms (
			id BIGSERIAL PRIMARY KEY,
			installation_id TEXT NOT NULL REFERENCES installations(id),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			kind TEXT NOT NULL,
			token TEXT NOT NULL,
			UNIQUE (installation_id, kind, token)
		)`,
		`CREATE TABLE subscriptions (
			id BIGSERIAL PRIMARY KEY,
			installation_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			topic TEXT NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT FALSE,
			is_silent BOOLEAN NOT NULL DEFAULT FALSE
		)`,
		`CREATE INDEX subscriptions_topic_is_active_idx ON subscriptions (topic, is_active)`,
		`CREATE INDEX device_delivery_mechanisms_installation_id_idx ON device_delivery_mechanisms (installation_id)`,
		`CREATE UNIQUE INDEX subscriptions_installation_id_topic_idx ON subscriptions (installation_id, topic)`,
		`CREATE TABLE subscription_hmac_keys (
			subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
			thirty_day_periods_since_epoch INTEGER NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			key BYTEA NOT NULL,
			PRIMARY KEY (subscription_id, thirty_day_periods_since_epoch)
		)`,
	}
	for _, statement := range legacyStatements {
		_, err := db.ExecContext(t.Context(), statement)
		require.NoError(t, err)
	}

	require.NoError(t, database.Migrate(t.Context(), db))

	var version int
	err := db.QueryRowContext(t.Context(), `SELECT version FROM schema_migrations`).Scan(&version)
	require.NoError(t, err)

	latest, latestErr := database.LatestMigrationVersion()
	require.NoError(t, latestErr)
	require.Equal(t, latest, version)
}

func TestRequireCurrentSchemaIsReadOnlyAndExact(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)

	require.Error(t, database.RequireCurrentSchema(t.Context(), db))
	var schemaTableExists bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT to_regclass('public.schema_migrations') IS NOT NULL`,
	).Scan(&schemaTableExists))
	require.False(t, schemaTableExists)

	latest, err := database.LatestMigrationVersion()
	require.NoError(t, err)
	require.Greater(t, latest, 1)
	require.NoError(
		t,
		database.MigrateUpTo(t.Context(), db, uint(latest-1)),
	)
	require.Error(t, database.RequireCurrentSchema(t.Context(), db))

	var version int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT version FROM public.schema_migrations`,
	).Scan(&version))
	require.Equal(t, latest-1, version)

	require.NoError(t, database.Migrate(t.Context(), db))
	require.NoError(t, database.RequireCurrentSchema(t.Context(), db))

	_, err = db.ExecContext(
		t.Context(),
		`UPDATE public.schema_migrations SET dirty = TRUE`,
	)
	require.NoError(t, err)
	require.Error(t, database.RequireCurrentSchema(t.Context(), db))
}

func TestMigration_BinaryTopics_DataConversion(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)

	// Run migrations up through 00003 (db_perf_improvements, pre-binary schema)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 3))

	// Seed rows: conforming group, conforming welcome, non-conforming, duplicate (case diff)
	_, err := db.ExecContext(t.Context(), `
		INSERT INTO installations (id) VALUES ('inst1');
		INSERT INTO subscriptions (installation_id, topic, is_active) VALUES
			('inst1', '/xmtp/mls/1/g-24ce39d660600b3a98adff3075b6d1f4/proto', TRUE),
			('inst1', '/xmtp/mls/1/w-f3ac64eba2272334/proto', TRUE),
			('inst1', '/xmtp/mls/1/w-test_installation/proto', TRUE),
			('inst1', '/xmtp/mls/1/g-24CE39D660600B3A98ADFF3075B6D1F4/proto', TRUE);
	`)
	require.NoError(t, err)

	// Run migration 00004 (binary conversion + drop legacy column)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 4))

	rows, err := db.QueryContext(t.Context(),
		"SELECT topic FROM subscriptions WHERE installation_id = 'inst1' ORDER BY topic",
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, rows.Close())
	}()

	var actualTopics [][]byte
	for rows.Next() {
		var topicBytes []byte
		require.NoError(t, rows.Scan(&topicBytes))
		actualTopics = append(actualTopics, topicBytes)
	}
	require.NoError(t, rows.Err())

	expectedGroup := testdb.MustParseTopicBytes(t, "/xmtp/mls/1/g-24ce39d660600b3a98adff3075b6d1f4/proto")
	expectedWelcome := testdb.MustParseTopicBytes(t, "/xmtp/mls/1/w-f3ac64eba2272334/proto")

	// Verify: non-conforming row deleted, duplicate collapsed, and valid rows converted exactly.
	require.ElementsMatch(t, [][]byte{expectedGroup, expectedWelcome}, actualTopics)

	// Verify topic_legacy column does not exist
	var count int
	err = db.QueryRowContext(t.Context(),
		"SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'subscriptions' AND column_name = 'topic_legacy'",
	).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 0, count)
}

func createRawDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := database.CreateDB(testdb.TEST_DSN, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func resetSchema(t *testing.T, db *sql.DB) {
	t.Helper()

	statements := []string{
		"DROP SCHEMA IF EXISTS hytch_push_vault CASCADE",
		"DROP SCHEMA IF EXISTS notification_queue CASCADE",
		"DROP TABLE IF EXISTS schema_migrations",
		"DROP TABLE IF EXISTS bun_migrations",
		"DROP TABLE IF EXISTS subscription_hmac_keys",
		"DROP TABLE IF EXISTS subscriptions",
		"DROP TABLE IF EXISTS device_delivery_mechanisms",
		"DROP TABLE IF EXISTS installations",
	}
	for _, statement := range statements {
		_, err := db.ExecContext(t.Context(), statement)
		require.NoError(t, err)
	}
}

func assertRelationExists(t *testing.T, db *sql.DB, name string) {
	t.Helper()

	var exists bool
	err := db.QueryRowContext(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, "public."+name).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, name)
}

func assertQualifiedRelationExists(t *testing.T, db *sql.DB, name string) {
	t.Helper()

	var exists bool
	err := db.QueryRowContext(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, name)
}

func assertRelationAbsent(t *testing.T, db *sql.DB, name string) {
	t.Helper()

	var absent bool
	err := db.QueryRowContext(t.Context(), `SELECT to_regclass($1) IS NULL`, "public."+name).Scan(&absent)
	require.NoError(t, err)
	require.True(t, absent, name)
}

func assertNotificationQueueAbsent(t *testing.T, db *sql.DB) {
	t.Helper()

	var absent bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT to_regnamespace('notification_queue') IS NULL`,
	).Scan(&absent))
	require.True(t, absent, "notification_queue schema")
}

func assertSchemaVersion(t *testing.T, db *sql.DB, expected int) {
	t.Helper()

	var version int
	var dirty bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT version, dirty FROM public.schema_migrations`,
	).Scan(&version, &dirty))
	require.Equal(t, expected, version)
	require.False(t, dirty)
}

func assertDeliveryTokenVersionColumns(t *testing.T, db *sql.DB, expected int) {
	t.Helper()

	var count int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*) FROM information_schema.columns
		  WHERE table_schema = 'public'
		    AND table_name = 'device_delivery_mechanisms'
		    AND column_name IN ('invalidated_at', 'registration_version')`,
	).Scan(&count))
	require.Equal(t, expected, count)
}

// Migration 00015 lands on top of the secure schema at 00014. Existing
// plaintext token rows keep their value and start at registration version 1.
func TestNotificationDurability_UpgradesExistingV14(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 14))
	assertSchemaVersion(t, db, 14)
	_, err := db.ExecContext(t.Context(), "INSERT INTO installations(id) VALUES ('existing'); INSERT INTO device_delivery_mechanisms(installation_id,kind,token) VALUES ('existing','apns','kept-token')")
	require.NoError(t, err)
	require.NoError(t, database.Migrate(t.Context(), db))
	assertSchemaVersion(t, db, 15)
	require.NoError(t, database.RequireCurrentSchema(t.Context(), db))
	var token string
	var version int64
	var invalidated sql.NullTime
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT token,registration_version,invalidated_at FROM device_delivery_mechanisms WHERE installation_id='existing'").Scan(&token, &version, &invalidated))
	require.Equal(t, "kept-token", token)
	require.Equal(t, int64(1), version)
	require.False(t, invalidated.Valid)
	assertQualifiedRelationExists(t, db, "notification_queue.notification_envelopes")
	assertQualifiedRelationExists(t, db, "notification_queue.notification_recipient_receipts")
	assertQualifiedRelationExists(t, db, "notification_queue.notification_envelopes_terminal_created_idx")
	require.NoError(t, database.Migrate(t.Context(), db))

	// Down reverts exactly to 00014 and keeps the legacy row; up reapplies.
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 14))
	assertSchemaVersion(t, db, 14)
	assertNotificationQueueAbsent(t, db)
	assertDeliveryTokenVersionColumns(t, db, 0)
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT token FROM device_delivery_mechanisms WHERE installation_id='existing'").Scan(&token))
	require.Equal(t, "kept-token", token)
	require.NoError(t, database.Migrate(t.Context(), db))
	assertSchemaVersion(t, db, 15)
	assertDeliveryTokenVersionColumns(t, db, 2)
}

// A secure-vault database has dropped the four legacy routing relations.
// 00015 must still apply and revert there, or the migration job would leave
// the schema dirty and the secure runtime's schema gate would never pass.
func TestNotificationDurability_AppliesAndRevertsAfterLegacyRetirement(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 14))
	activateLegacyRoutingRetirement(t, db)
	assertRelationAbsent(t, db, "device_delivery_mechanisms")

	require.NoError(t, database.Migrate(t.Context(), db))
	assertSchemaVersion(t, db, 15)
	require.NoError(t, database.RequireCurrentSchema(t.Context(), db))
	assertQualifiedRelationExists(t, db, "notification_queue.notification_envelopes")
	assertQualifiedRelationExists(t, db, "notification_queue.notification_recipient_receipts")
	assertRelationAbsent(t, db, "device_delivery_mechanisms")

	require.NoError(t, database.MigrateUpTo(t.Context(), db, 14))
	assertSchemaVersion(t, db, 14)
	assertNotificationQueueAbsent(t, db)
	assertRelationAbsent(t, db, "device_delivery_mechanisms")

	require.NoError(t, database.Migrate(t.Context(), db))
	assertSchemaVersion(t, db, 15)
	require.NoError(t, database.RequireCurrentSchema(t.Context(), db))
}

// The production shape: a dedicated, non-superuser migration owner that is
// not the owner of schema public. Retirement leaves it without CREATE on
// public, so 00015 must not need that privilege.
func TestNotificationDurability_NonSuperuserOwnerAfterLegacyRetirement(t *testing.T) {
	admin, err := database.CreateDB(testdb.TEST_DSN, 5*time.Second)
	require.NoError(t, err)
	role := fmt.Sprintf("migrator_%d", time.Now().UnixNano())
	_, err = admin.ExecContext(t.Context(), `CREATE ROLE "`+role+`" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD 'migrator'`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP ROLE IF EXISTS "`+role+`"`)
		_ = admin.Close()
	})

	superuserDB := testdb.CreateEmptyTestDb(t)
	var databaseName string
	require.NoError(t, superuserDB.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&databaseName))
	_, err = superuserDB.ExecContext(t.Context(), `GRANT CREATE, CONNECT ON DATABASE "`+databaseName+`" TO "`+role+`"; GRANT USAGE, CREATE ON SCHEMA public TO "`+role+`"`)
	require.NoError(t, err)

	migratorDSN, err := url.Parse(testdb.TEST_DSN)
	require.NoError(t, err)
	migratorDSN.User = url.UserPassword(role, "migrator")
	migratorDSN.Path = "/" + databaseName
	migrator, err := database.CreateDB(migratorDSN.String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = migrator.Close() })

	require.NoError(t, database.MigrateUpTo(t.Context(), migrator, 14))
	// Runbook retirement step: revoke every named non-owner CREATE on public.
	_, err = superuserDB.ExecContext(t.Context(), `REVOKE CREATE ON SCHEMA public FROM "`+role+`"`)
	require.NoError(t, err)
	activateLegacyRoutingRetirement(t, migrator)
	var canCreateInPublic bool
	require.NoError(t, migrator.QueryRowContext(t.Context(), `SELECT has_schema_privilege(current_user, 'public', 'CREATE')`).Scan(&canCreateInPublic))
	require.False(t, canCreateInPublic)

	require.NoError(t, database.Migrate(t.Context(), migrator))
	assertSchemaVersion(t, migrator, 15)
	require.NoError(t, database.RequireCurrentSchema(t.Context(), migrator))
	assertQualifiedRelationExists(t, migrator, "notification_queue.notification_envelopes")

	require.NoError(t, database.MigrateUpTo(t.Context(), migrator, 14))
	assertSchemaVersion(t, migrator, 14)
	assertNotificationQueueAbsent(t, migrator)
	require.NoError(t, database.Migrate(t.Context(), migrator))
	assertSchemaVersion(t, migrator, 15)
}
