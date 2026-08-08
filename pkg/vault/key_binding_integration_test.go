package vault

import (
	"bytes"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestLookupRootBindingIsEnvironmentScoped(t *testing.T) {
	db := testdb.CreateTestDb(t)
	developmentLookup, err := NewLookupKey(bytes.Repeat([]byte{0x31}, 32))
	require.NoError(t, err)
	productionLookup, err := NewLookupKey(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)

	bindLookupRootForTest(
		t,
		db,
		developmentLookup,
		environmentDevelopment,
	)
	bindLookupRootForTest(
		t,
		db,
		productionLookup,
		environmentProduction,
	)
	bindLookupRootForTest(
		t,
		db,
		developmentLookup,
		environmentDevelopment,
	)

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	require.ErrorIs(
		t,
		requireLookupKeyBoundTx(
			t.Context(),
			tx,
			developmentLookup,
			environmentProduction,
		),
		ErrLookupUnavailable,
	)
	require.NoError(t, tx.Rollback())

	var bindingCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.vault_key_bindings`,
	).Scan(&bindingCount))
	require.Equal(t, 2, bindingCount)
}

func TestLookupRootBindingRejectsUnknownEnvironment(t *testing.T) {
	db := testdb.CreateTestDb(t)
	lookup, err := NewLookupKey(bytes.Repeat([]byte{0x53}, 32))
	require.NoError(t, err)
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	require.ErrorIs(
		t,
		requireLookupKeyBoundTx(t.Context(), tx, lookup, 0),
		ErrLookupUnavailable,
	)
}

func bindLookupRootForTest(
	t *testing.T,
	db *sql.DB,
	lookup *LookupKey,
	environmentID int16,
) {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	require.NoError(t, requireLookupKeyBoundTx(
		t.Context(),
		tx,
		lookup,
		environmentID,
	))
	require.NoError(t, tx.Commit())
}
