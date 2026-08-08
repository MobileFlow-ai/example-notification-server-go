package vault

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRetentionUnsafeTransitionWaitsForAuthorizedTransaction(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)

	authorizedTx, err := db.BeginTx(
		t.Context(),
		&sql.TxOptions{Isolation: sql.LevelSerializable},
	)
	require.NoError(t, err)
	require.NoError(
		t,
		fixture.store.requireRetentionSafeTx(t.Context(), authorizedTx),
	)

	competing, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer func() { _ = competing.Close() }()
	_, err = competing.ExecContext(
		t.Context(),
		`SET lock_timeout = '100ms'`,
	)
	require.NoError(t, err)
	_, err = competing.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.retention_state
		    SET is_safe = FALSE, fixed_outcome = $1
		  WHERE environment = $2`,
		retentionOutcomeUnsafe,
		fixture.store.environmentID,
	)
	require.Error(t, err)

	require.NoError(t, authorizedTx.Rollback())
	_, err = competing.ExecContext(
		context.Background(),
		`SET lock_timeout = 0`,
	)
	require.NoError(t, err)
	_, err = competing.ExecContext(
		context.Background(),
		`UPDATE hytch_push_vault.retention_state
		    SET is_safe = FALSE, fixed_outcome = $1
		  WHERE environment = $2`,
		retentionOutcomeUnsafe,
		fixture.store.environmentID,
	)
	require.NoError(t, err)

	rejectedTx, err := db.BeginTx(
		t.Context(),
		&sql.TxOptions{Isolation: sql.LevelSerializable},
	)
	require.NoError(t, err)
	defer func() { _ = rejectedTx.Rollback() }()
	require.ErrorIs(
		t,
		fixture.store.requireRetentionSafeTx(t.Context(), rejectedTx),
		ErrRetentionUnsafe,
	)
}
