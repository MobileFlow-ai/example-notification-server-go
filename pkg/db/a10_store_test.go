package db_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a10registration"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

var (
	_ a10registration.KeysetStore = database.NewA10KeysetStore(nil)
	_ a10registration.ReplayStore = database.NewA10ReplayStore(nil)
)

func a10Candidate(sequence uint64, marker byte) a10registration.AcceptedKeyset {
	canonical := []byte{marker, marker + 1, marker + 2}
	digest := sha256.Sum256(canonical)
	issued := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	return a10registration.AcceptedKeyset{
		Environment:           "dev",
		Sequence:              sequence,
		ObjectHash:            hex.EncodeToString(digest[:]),
		CanonicalSignedObject: canonical,
		IssuedAt:              issued,
		ExpiresAt:             issued.Add(time.Hour),
	}
}

func TestA10PostgresKeysetStoreAcceptsAndLatchesConflicts(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	store := database.NewA10KeysetStore(db)
	first := a10Candidate(1, 0x31)

	state, err := store.AcceptA10Keyset(t.Context(), first)
	require.NoError(t, err)
	require.Equal(t, first.Environment, state.Environment)
	require.Equal(t, first.Sequence, state.Sequence)
	require.Equal(t, first.ObjectHash, state.ObjectHash)
	require.False(t, state.Uncertain)

	replayed, err := store.AcceptA10Keyset(t.Context(), first)
	require.NoError(t, err)
	require.Equal(t, state, replayed)

	conflict := a10Candidate(1, 0x41)
	latched, err := store.AcceptA10Keyset(t.Context(), conflict)
	require.ErrorIs(t, err, a10registration.ErrKeysetRejected)
	require.True(t, latched.Uncertain)

	current, err := store.CurrentA10KeysetState(t.Context(), "dev")
	require.NoError(t, err)
	require.True(t, current.Uncertain)
	_, err = store.AcceptA10Keyset(t.Context(), a10Candidate(2, 0x51))
	require.ErrorIs(t, err, a10registration.ErrKeysetRejected)
}

func TestA10PostgresReplayStoreConsumesOnceAndPurgesAfterDeadline(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	store := database.NewA10ReplayStore(db)
	var databaseNow time.Time
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT pg_catalog.clock_timestamp()`).Scan(&databaseNow))
	jti := "00000000-0000-4000-8000-000000000010"
	deadline := databaseNow.UTC().Add(10 * time.Second)

	consumed, err := store.ConsumeA10Registration(t.Context(), "dev", jti, deadline, databaseNow.UTC())
	require.NoError(t, err)
	require.True(t, consumed)
	consumed, err = store.ConsumeA10Registration(t.Context(), "dev", jti, deadline, databaseNow.UTC())
	require.NoError(t, err)
	require.False(t, consumed)

	_, err = db.ExecContext(t.Context(), `DELETE FROM hytch_push_vault.a10_registration_replays WHERE environment = 1 AND jti = $1`, jti)
	require.Error(t, err)
	_, err = db.ExecContext(t.Context(), `UPDATE hytch_push_vault.a10_registration_replays SET delete_after = pg_catalog.clock_timestamp() - INTERVAL '1 second' WHERE environment = 1 AND jti = $1`, jti)
	require.Error(t, err)

	_, err = db.ExecContext(t.Context(), `WITH instant AS (SELECT pg_catalog.clock_timestamp() AS now) INSERT INTO hytch_push_vault.a10_registration_replays (environment, jti, jwt_expires_at, delete_after, consumed_at) SELECT 1, '00000000-0000-4000-8000-000000000011', now - INTERVAL '6 seconds', now - INTERVAL '1 second', now - INTERVAL '7 seconds' FROM instant`)
	require.NoError(t, err)
	purged, err := store.PurgeExpired(t.Context())
	require.NoError(t, err)
	require.Equal(t, int64(1), purged)
}

func TestA10StoresRejectInvalidInputsWithoutDatabaseAccess(t *testing.T) {
	_, err := database.NewA10KeysetStore(nil).AcceptA10Keyset(context.Background(), a10Candidate(0, 0x61))
	require.ErrorIs(t, err, a10registration.ErrKeysetRejected)
	_, err = database.NewA10KeysetStore(nil).CurrentA10KeysetState(context.Background(), "unknown")
	require.ErrorIs(t, err, a10registration.ErrKeysetUnavailable)
	consumed, err := database.NewA10ReplayStore(nil).ConsumeA10Registration(context.Background(), "dev", "not-a-uuid", time.Now().Add(time.Minute), time.Now())
	require.False(t, consumed)
	require.True(t, errors.Is(err, a10registration.ErrUnavailable))
}
