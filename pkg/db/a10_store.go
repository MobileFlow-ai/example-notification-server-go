package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xmtp/example-notification-server-go/pkg/a10registration"
)

const a10KeysetLockClass = 0x413130

// A10KeysetStore durably fences the independently rooted A10 keyset stream.
// A rollback or equal-sequence conflict latches uncertainty until an operator
// performs a separately authorized recovery.
type A10KeysetStore struct{ db *sql.DB }

func NewA10KeysetStore(db *sql.DB) *A10KeysetStore { return &A10KeysetStore{db: db} }

type A10ReplayStore struct{ db *sql.DB }

func NewA10ReplayStore(db *sql.DB) *A10ReplayStore { return &A10ReplayStore{db: db} }

func (store *A10KeysetStore) AcceptA10Keyset(ctx context.Context, candidate a10registration.AcceptedKeyset) (a10registration.KeysetState, error) {
	environmentID, hash, ok := validateA10Candidate(candidate)
	if !ok {
		return a10registration.KeysetState{}, a10registration.ErrKeysetRejected
	}
	if !validA9StoreContext(ctx) || store == nil || store.db == nil {
		return a10registration.KeysetState{}, a10registration.ErrKeysetUnavailable
	}
	for attempt := 0; attempt < a9SerializableAttempts; attempt++ {
		state, err := store.acceptA10KeysetOnce(ctx, candidate, environmentID, hash)
		if err == nil || errors.Is(err, a10registration.ErrKeysetRejected) {
			return state, err
		}
		if !isA10SerializationFailure(err) || attempt+1 == a9SerializableAttempts {
			return a10registration.KeysetState{}, a10registration.ErrKeysetUnavailable
		}
	}
	return a10registration.KeysetState{}, a10registration.ErrKeysetUnavailable
}

func (store *A10KeysetStore) acceptA10KeysetOnce(ctx context.Context, candidate a10registration.AcceptedKeyset, environmentID int16, hash []byte) (a10registration.KeysetState, error) {
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return a10registration.KeysetState{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `SELECT pg_catalog.pg_advisory_xact_lock($1, $2)`, a10KeysetLockClass, environmentID); err != nil {
		return a10registration.KeysetState{}, err
	}
	current, err := scanA10KeysetState(tx.QueryRowContext(ctx, `
		SELECT keyset_sequence, signed_keyset_hash, state, expires_at
		  FROM hytch_push_vault.a10_keyset_state
		 WHERE environment = $1
		 FOR UPDATE`, environmentID), candidate.Environment)
	hasCurrent := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return a10registration.KeysetState{}, err
	}
	if hasCurrent && current.Uncertain {
		return current, a10registration.ErrKeysetRejected
	}
	if hasCurrent && (candidate.Sequence < current.Sequence ||
		(candidate.Sequence == current.Sequence && (candidate.ObjectHash != current.ObjectHash || !candidate.ExpiresAt.Equal(current.ExpiresAt)))) {
		result, updateErr := tx.ExecContext(ctx, `UPDATE hytch_push_vault.a10_keyset_state SET state = 2, uncertainty_reason = 1, refreshed_at = pg_catalog.clock_timestamp() WHERE environment = $1 AND state = 1`, environmentID)
		if updateErr != nil {
			return a10registration.KeysetState{}, updateErr
		}
		if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
			return a10registration.KeysetState{}, a10registration.ErrKeysetUnavailable
		}
		current.Uncertain = true
		if err = tx.Commit(); err != nil {
			return a10registration.KeysetState{}, err
		}
		return current, a10registration.ErrKeysetRejected
	}
	if hasCurrent && candidate.Sequence == current.Sequence {
		if _, err = tx.ExecContext(ctx, `UPDATE hytch_push_vault.a10_keyset_state SET refreshed_at = pg_catalog.clock_timestamp() WHERE environment = $1 AND state = 1`, environmentID); err != nil {
			return a10registration.KeysetState{}, err
		}
		if err = tx.Commit(); err != nil {
			return a10registration.KeysetState{}, err
		}
		return current, nil
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO hytch_push_vault.a10_accepted_keysets
		(environment, keyset_sequence, signed_keyset_hash, signed_keyset_jcs, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, environmentID, int64(candidate.Sequence), hash, candidate.CanonicalSignedObject, candidate.IssuedAt.UTC(), candidate.ExpiresAt.UTC()); err != nil {
		return a10registration.KeysetState{}, err
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO hytch_push_vault.a10_keyset_state
		(environment, keyset_sequence, signed_keyset_hash, state, uncertainty_reason, expires_at, refreshed_at)
		VALUES ($1, $2, $3, 1, 0, $4, pg_catalog.clock_timestamp())
		ON CONFLICT (environment) DO UPDATE SET
		keyset_sequence = EXCLUDED.keyset_sequence,
		signed_keyset_hash = EXCLUDED.signed_keyset_hash,
		expires_at = EXCLUDED.expires_at,
		refreshed_at = EXCLUDED.refreshed_at
		WHERE hytch_push_vault.a10_keyset_state.state = 1`, environmentID, int64(candidate.Sequence), hash, candidate.ExpiresAt.UTC())
	if err != nil {
		return a10registration.KeysetState{}, err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return a10registration.KeysetState{}, a10registration.ErrKeysetUnavailable
	}
	if err = tx.Commit(); err != nil {
		return a10registration.KeysetState{}, err
	}
	return a10registration.KeysetState{Environment: candidate.Environment, Sequence: candidate.Sequence, ObjectHash: candidate.ObjectHash, ExpiresAt: candidate.ExpiresAt.UTC()}, nil
}

func (store *A10KeysetStore) CurrentA10KeysetState(ctx context.Context, environment string) (a10registration.KeysetState, error) {
	environmentID, ok := a9EnvironmentID(environment)
	if !ok || !validA9StoreContext(ctx) || store == nil || store.db == nil {
		return a10registration.KeysetState{}, a10registration.ErrKeysetUnavailable
	}
	state, err := scanA10KeysetState(store.db.QueryRowContext(ctx, `SELECT keyset_sequence, signed_keyset_hash, state, expires_at FROM hytch_push_vault.a10_keyset_state WHERE environment = $1`, environmentID), environment)
	if err != nil {
		return a10registration.KeysetState{}, a10registration.ErrKeysetUnavailable
	}
	return state, nil
}

type a10RowScanner interface{ Scan(...any) error }

func scanA10KeysetState(row a10RowScanner, environment string) (a10registration.KeysetState, error) {
	var sequence int64
	var hash []byte
	var state int16
	var expires time.Time
	if err := row.Scan(&sequence, &hash, &state, &expires); err != nil {
		return a10registration.KeysetState{}, err
	}
	if sequence < 1 || uint64(sequence) > a9SafeIntegerMaximum || len(hash) != sha256.Size || (state != 1 && state != 2) {
		return a10registration.KeysetState{}, a10registration.ErrKeysetUnavailable
	}
	return a10registration.KeysetState{Environment: environment, Sequence: uint64(sequence), ObjectHash: hex.EncodeToString(hash), ExpiresAt: expires.UTC(), Uncertain: state == 2}, nil
}

func validateA10Candidate(candidate a10registration.AcceptedKeyset) (int16, []byte, bool) {
	environmentID, ok := a9EnvironmentID(candidate.Environment)
	if !ok || candidate.Sequence == 0 || candidate.Sequence > a9SafeIntegerMaximum || len(candidate.CanonicalSignedObject) == 0 || candidate.IssuedAt.IsZero() || !candidate.ExpiresAt.After(candidate.IssuedAt) {
		return 0, nil, false
	}
	hash, err := hex.DecodeString(candidate.ObjectHash)
	computed := sha256.Sum256(candidate.CanonicalSignedObject)
	if err != nil || len(hash) != sha256.Size || hex.EncodeToString(hash) != candidate.ObjectHash || !equalA10Hash(hash, computed[:]) {
		return 0, nil, false
	}
	return environmentID, hash, true
}

func equalA10Hash(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}

func isA10SerializationFailure(err error) bool {
	if isA9SerializationFailure(err) {
		return true
	}
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505" &&
		(postgresError.ConstraintName == "a10_accepted_keysets_pkey" ||
			postgresError.ConstraintName == "a10_keyset_state_pkey")
}

func (store *A10ReplayStore) ConsumeA10Registration(ctx context.Context, environment, jti string, retainUntil, now time.Time) (bool, error) {
	environmentID, ok := a9EnvironmentID(environment)
	if !ok || !validCanonicalA9UUID(jti) || !validA9StoreContext(ctx) || store == nil || store.db == nil || retainUntil.IsZero() || now.IsZero() || now.UTC().After(retainUntil.UTC()) {
		return false, a10registration.ErrUnavailable
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return false, a10registration.ErrUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	var databaseNow time.Time
	if err = tx.QueryRowContext(ctx, `SELECT pg_catalog.clock_timestamp()`).Scan(&databaseNow); err != nil || databaseNow.UTC().After(retainUntil.UTC()) {
		return false, a10registration.ErrUnavailable
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO hytch_push_vault.a10_registration_replays (environment, jti, jwt_expires_at, delete_after, consumed_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (environment, jti) DO NOTHING`, environmentID, jti, retainUntil.UTC().Add(-5*time.Second), retainUntil.UTC(), databaseNow.UTC())
	if err != nil {
		return false, a10registration.ErrUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil || (rows != 0 && rows != 1) {
		return false, a10registration.ErrUnavailable
	}
	if rows == 1 {
		var commitClock time.Time
		if err = tx.QueryRowContext(ctx, `SELECT pg_catalog.clock_timestamp()`).Scan(&commitClock); err != nil || commitClock.UTC().After(retainUntil.UTC()) {
			return false, a10registration.ErrUnavailable
		}
	}
	if err = tx.Commit(); err != nil {
		return false, a10registration.ErrUnavailable
	}
	return rows == 1, nil
}

func (store *A10ReplayStore) PurgeExpired(ctx context.Context) (int64, error) {
	if !validA9StoreContext(ctx) || store == nil || store.db == nil {
		return 0, a10registration.ErrUnavailable
	}
	result, err := store.db.ExecContext(ctx, `DELETE FROM hytch_push_vault.a10_registration_replays WHERE delete_after < pg_catalog.clock_timestamp()`)
	if err != nil {
		return 0, a10registration.ErrUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, a10registration.ErrUnavailable
	}
	return rows, nil
}
