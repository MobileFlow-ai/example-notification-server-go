package db_test

import (
	"database/sql"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestWelcomeEnvelopeLookupIndexMigrationUpDownUp(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 7))
	assertWelcomeEnvelopeLookupIndex(t, db, true)

	down, err := os.ReadFile(
		"migrations/00007_index_welcome_envelope_lookup.down.sql",
	)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), string(down))
	require.NoError(t, err)
	assertWelcomeEnvelopeLookupIndex(t, db, false)

	up, err := os.ReadFile(
		"migrations/00007_index_welcome_envelope_lookup.up.sql",
	)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), string(up))
	require.NoError(t, err)
	assertWelcomeEnvelopeLookupIndex(t, db, true)
}

func assertWelcomeEnvelopeLookupIndex(
	t *testing.T,
	db *sql.DB,
	expected bool,
) {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(
		t.Context(),
		`SELECT to_regclass(
		    'hytch_push_vault.welcome_authorizations_envelope_lookup_idx'
		 ) IS NOT NULL`,
	).Scan(&exists)
	require.NoError(t, err)
	require.Equal(t, expected, exists)
}
