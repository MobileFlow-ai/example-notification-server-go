package db_test

import (
	"testing"

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
