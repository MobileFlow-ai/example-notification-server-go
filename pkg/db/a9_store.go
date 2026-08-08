package db

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

const (
	a9SafeIntegerMaximum   uint64 = 9007199254740991
	a9KeysetLockClass             = 0x4139
	a9SerializableAttempts        = 5

	a9KeysetStateCurrent   int16 = 1
	a9KeysetStateUncertain int16 = 2

	a9UncertaintyKeyState int16 = 1
	a9UncertaintyRollback int16 = 2
	a9UncertaintyRotation int16 = 3
)

var errA9DatabaseUnavailable = errors.New(
	"a9 database store unavailable",
)

// A9KeysetStore is the PostgreSQL implementation of a9trust.KeysetStore.
// Accepted public keysets and their descriptors are append-only; the one
// mutable high-water row is serialized across replicas by an advisory
// transaction lock and a SERIALIZABLE transaction.
type A9KeysetStore struct {
	db *sql.DB
}

func NewA9KeysetStore(db *sql.DB) *A9KeysetStore {
	return &A9KeysetStore{db: db}
}

// A9ReplayStore is the PostgreSQL implementation of a9auth.ReplayStore.
// Consume returns success only after the unique receipt insert commits.
type A9ReplayStore struct {
	db *sql.DB
}

func NewA9ReplayStore(db *sql.DB) *A9ReplayStore {
	return &A9ReplayStore{db: db}
}

type a9ValidatedOnlineKey struct {
	use       int16
	state     int16
	keyID     []byte
	publicKey []byte
	notBefore time.Time
	notAfter  time.Time
}

type a9ValidatedCommitmentKey struct {
	purpose       int16
	keyID         []byte
	topicKeyEpoch *int64
	notBefore     time.Time
	notAfter      time.Time
}

type a9ValidatedCandidate struct {
	environmentID int16
	objectHash    []byte
	rootKeyID     []byte
	object        map[string]any
	online        []a9ValidatedOnlineKey
	commitments   []a9ValidatedCommitmentKey
}

func (store *A9KeysetStore) AcceptKeyset(
	ctx context.Context,
	candidate a9trust.AcceptedKeyset,
) (a9trust.KeysetState, error) {
	validated, err := validateA9AcceptedKeyset(candidate)
	if err != nil {
		if _, ok := a9EnvironmentID(candidate.Environment); ok {
			if latchErr := store.LatchKeysetUncertainty(
				ctx,
				candidate.Environment,
				"KEY_STATE",
			); latchErr != nil {
				return a9trust.KeysetState{}, errA9DatabaseUnavailable
			}
		}
		return a9trust.KeysetState{}, a9trust.ErrKeysetRejected
	}
	if !validA9StoreContext(ctx) || store == nil || store.db == nil {
		return a9trust.KeysetState{}, errA9DatabaseUnavailable
	}

	for attempt := 0; attempt < a9SerializableAttempts; attempt++ {
		state, acceptErr := store.acceptKeysetOnce(
			ctx,
			candidate,
			validated,
		)
		switch {
		case acceptErr == nil,
			errors.Is(acceptErr, a9trust.ErrKeysetRejected):
			return state, acceptErr
		case isA9SerializationFailure(acceptErr) &&
			attempt+1 < a9SerializableAttempts:
			continue
		default:
			return a9trust.KeysetState{}, errA9DatabaseUnavailable
		}
	}
	return a9trust.KeysetState{}, errA9DatabaseUnavailable
}

func (store *A9KeysetStore) acceptKeysetOnce(
	ctx context.Context,
	candidate a9trust.AcceptedKeyset,
	validated a9ValidatedCandidate,
) (a9trust.KeysetState, error) {
	tx, err := store.db.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelSerializable},
	)
	if err != nil {
		return a9trust.KeysetState{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err = lockA9KeysetEnvironment(
		ctx,
		tx,
		validated.environmentID,
	); err != nil {
		return a9trust.KeysetState{}, err
	}

	current, previousCanonical, err := readA9KeysetStateForUpdate(
		ctx,
		tx,
		candidate.Environment,
		validated.environmentID,
	)
	hasCurrent := true
	if errors.Is(err, sql.ErrNoRows) {
		hasCurrent = false
		current = a9trust.KeysetState{
			Environment: candidate.Environment,
		}
	} else if err != nil {
		return a9trust.KeysetState{}, err
	}

	if hasCurrent && current.Uncertain {
		if err = tx.Commit(); err != nil {
			return a9trust.KeysetState{}, err
		}
		committed = true
		return current, a9trust.ErrKeysetRejected
	}

	if hasCurrent &&
		(candidate.Sequence < current.Sequence ||
			(candidate.Sequence == current.Sequence &&
				candidate.ObjectHash != current.ObjectHash)) {
		current, err = latchA9KeysetStateTx(
			ctx,
			tx,
			current,
			validated.environmentID,
			a9UncertaintyRollback,
		)
		if err != nil {
			return a9trust.KeysetState{}, err
		}
		if err = tx.Commit(); err != nil {
			return a9trust.KeysetState{}, err
		}
		committed = true
		return current, a9trust.ErrKeysetRejected
	}

	if hasCurrent && candidate.Sequence == current.Sequence {
		if !candidate.ExpiresAt.Equal(current.ExpiresAt) {
			current, err = latchA9KeysetStateTx(
				ctx,
				tx,
				current,
				validated.environmentID,
				a9UncertaintyRollback,
			)
			if err != nil {
				return a9trust.KeysetState{}, err
			}
			if err = tx.Commit(); err != nil {
				return a9trust.KeysetState{}, err
			}
			committed = true
			return current, a9trust.ErrKeysetRejected
		}
		if err = refreshA9KeysetStateTx(
			ctx,
			tx,
			current,
			validated.environmentID,
		); err != nil {
			return a9trust.KeysetState{}, err
		}
		if err = tx.Commit(); err != nil {
			return a9trust.KeysetState{}, err
		}
		committed = true
		return current, nil
	}

	if hasCurrent {
		previous, parseErr := parseA9CanonicalObject(previousCanonical)
		rotation := a9trust.ValidateOnlineRotation(
			previous,
			validated.object,
		)
		if parseErr != nil || !rotation.IsEligible() {
			current, err = latchA9KeysetStateTx(
				ctx,
				tx,
				current,
				validated.environmentID,
				a9UncertaintyRotation,
			)
			if err != nil {
				return a9trust.KeysetState{}, err
			}
			if err = tx.Commit(); err != nil {
				return a9trust.KeysetState{}, err
			}
			committed = true
			return current, a9trust.ErrKeysetRejected
		}
	}

	if err = appendA9KeysetTx(
		ctx,
		tx,
		candidate,
		validated,
		current,
		hasCurrent,
	); err != nil {
		return a9trust.KeysetState{}, err
	}
	result := a9trust.KeysetState{
		Environment: candidate.Environment,
		Sequence:    candidate.Sequence,
		ObjectHash:  candidate.ObjectHash,
		ExpiresAt:   candidate.ExpiresAt.UTC(),
		Uncertain:   false,
	}
	if err = tx.Commit(); err != nil {
		return a9trust.KeysetState{}, err
	}
	committed = true
	return result, nil
}

func (store *A9KeysetStore) CurrentKeysetState(
	ctx context.Context,
	environment string,
) (a9trust.KeysetState, error) {
	environmentID, ok := a9EnvironmentID(environment)
	if !ok ||
		!validA9StoreContext(ctx) ||
		store == nil ||
		store.db == nil {
		return a9trust.KeysetState{}, errA9DatabaseUnavailable
	}
	state, _, err := scanA9KeysetState(
		store.db.QueryRowContext(
			ctx,
			`SELECT
			     state_row.keyset_sequence,
			     state_row.signed_keyset_hash,
			     state_row.state,
			     state_row.expires_at,
			     accepted.signed_keyset_jcs
			   FROM hytch_push_vault.a9_keyset_state AS state_row
			   LEFT JOIN hytch_push_vault.a9_accepted_keysets AS accepted
			     ON accepted.environment = state_row.environment
			    AND accepted.keyset_sequence =
			            state_row.keyset_sequence
			    AND accepted.signed_keyset_hash =
			            state_row.signed_keyset_hash
			  WHERE state_row.environment = $1`,
			environmentID,
		),
		environment,
	)
	if err != nil {
		return a9trust.KeysetState{}, errA9DatabaseUnavailable
	}
	return state, nil
}

func (store *A9KeysetStore) LatchKeysetUncertainty(
	ctx context.Context,
	environment string,
	reason string,
) error {
	environmentID, ok := a9EnvironmentID(environment)
	if !ok ||
		!validA9StoreContext(ctx) ||
		store == nil ||
		store.db == nil {
		return errA9DatabaseUnavailable
	}
	for attempt := 0; attempt < a9SerializableAttempts; attempt++ {
		latchErr := store.latchKeysetUncertaintyOnce(
			ctx,
			environment,
			environmentID,
			a9UncertaintyReason(reason),
		)
		switch {
		case latchErr == nil:
			return nil
		case isA9SerializationFailure(latchErr) &&
			attempt+1 < a9SerializableAttempts:
			continue
		default:
			return errA9DatabaseUnavailable
		}
	}
	return errA9DatabaseUnavailable
}

func (store *A9KeysetStore) latchKeysetUncertaintyOnce(
	ctx context.Context,
	environment string,
	environmentID int16,
	reason int16,
) error {
	tx, err := store.db.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelSerializable},
	)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err = lockA9KeysetEnvironment(
		ctx,
		tx,
		environmentID,
	); err != nil {
		return err
	}
	state, _, err := readA9KeysetStateForUpdate(
		ctx,
		tx,
		environment,
		environmentID,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.ExecContext(
			ctx,
			`INSERT INTO hytch_push_vault.a9_keyset_state (
			     environment,
			     keyset_sequence,
			     signed_keyset_hash,
			     state,
			     uncertainty_reason,
			     expires_at,
			     refreshed_at
			 ) VALUES (
			     $1,
			     0,
			     NULL,
			     2,
			     $2,
			     NULL,
			     pg_catalog.clock_timestamp()
			)`,
			environmentID,
			reason,
		)
		if err != nil {
			return err
		}
	case err != nil:
		return err
	case state.Uncertain:
		// The first durable uncertainty reason wins. Repeated latches are a
		// true no-op rather than an observable write.
	default:
		if _, err = latchA9KeysetStateTx(
			ctx,
			tx,
			state,
			environmentID,
			reason,
		); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (store *A9ReplayStore) Consume(
	ctx context.Context,
	environment string,
	jti string,
	retainUntil time.Time,
	now time.Time,
) (bool, error) {
	environmentID, ok := a9EnvironmentID(environment)
	if !ok ||
		!validCanonicalA9UUID(jti) ||
		!validA9StoreContext(ctx) ||
		store == nil ||
		store.db == nil ||
		retainUntil.IsZero() ||
		now.IsZero() {
		return false, errA9DatabaseUnavailable
	}
	retainUntil = retainUntil.UTC()
	now = now.UTC()
	if now.After(retainUntil) {
		return false, errA9DatabaseUnavailable
	}
	jwtExpiresAt := retainUntil.Add(-5 * time.Second)

	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return false, errA9DatabaseUnavailable
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	var databaseNow time.Time
	if err = tx.QueryRowContext(
		ctx,
		`SELECT pg_catalog.clock_timestamp()`,
	).Scan(&databaseNow); err != nil {
		return false, errA9DatabaseUnavailable
	}
	databaseNow = databaseNow.UTC()
	// PostgreSQL owns replay-retention expiry because purge and the v12
	// deletion guard use that same clock. A caller clock that lags the
	// database must never be able to recreate a JTI after its receipt became
	// purgeable. The exact exp+5 boundary remains valid, matching JWT skew
	// verification and the contract's inclusive boundary.
	if databaseNow.After(retainUntil) {
		return false, errA9DatabaseUnavailable
	}
	result, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_service_jti_receipts (
		     environment,
		     jti,
		     jwt_expires_at,
		     delete_after,
		     consumed_at
		 ) VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (environment, jti) DO NOTHING`,
		environmentID,
		jti,
		jwtExpiresAt,
		retainUntil,
		databaseNow,
	)
	if err != nil {
		return false, errA9DatabaseUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil || (rows != 0 && rows != 1) {
		return false, errA9DatabaseUnavailable
	}
	if rows == 1 {
		var commitClock time.Time
		if err = tx.QueryRowContext(
			ctx,
			`SELECT pg_catalog.clock_timestamp()`,
		).Scan(&commitClock); err != nil ||
			commitClock.UTC().After(retainUntil) {
			// This second sample closes the boundary race in which the insert
			// waits behind a concurrent purge of an older receipt. A request
			// that cannot commit its new fence by the retention deadline is
			// denied rather than recreating a replayable JTI.
			return false, errA9DatabaseUnavailable
		}
	}
	if err = tx.Commit(); err != nil {
		return false, errA9DatabaseUnavailable
	}
	committed = true
	return rows == 1, nil
}

// PurgeExpired removes only replay receipts whose server-clock retention
// deadline has elapsed. The v12 trigger independently rejects an early delete.
func (store *A9ReplayStore) PurgeExpired(
	ctx context.Context,
) (int64, error) {
	if !validA9StoreContext(ctx) || store == nil || store.db == nil {
		return 0, errA9DatabaseUnavailable
	}
	result, err := store.db.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.a9_service_jti_receipts
		  WHERE delete_after < pg_catalog.clock_timestamp()`,
	)
	if err != nil {
		return 0, errA9DatabaseUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, errA9DatabaseUnavailable
	}
	return rows, nil
}

func appendA9KeysetTx(
	ctx context.Context,
	tx *sql.Tx,
	candidate a9trust.AcceptedKeyset,
	validated a9ValidatedCandidate,
	current a9trust.KeysetState,
	hasCurrent bool,
) error {
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_accepted_keysets (
		     environment,
		     keyset_sequence,
		     signed_keyset_hash,
		     signed_keyset_jcs,
		     root_signing_key_id,
		     issued_at,
		     expires_at
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		validated.environmentID,
		int64(candidate.Sequence),
		validated.objectHash,
		candidate.CanonicalSignedObject,
		validated.rootKeyID,
		candidate.IssuedAt.UTC(),
		candidate.ExpiresAt.UTC(),
	); err != nil {
		return err
	}
	for _, key := range validated.online {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO hytch_push_vault.a9_online_key_descriptors (
			     environment,
			     keyset_sequence,
			     key_use,
			     key_state,
			     key_id,
			     public_key,
			     not_before,
			     not_after
			 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			validated.environmentID,
			int64(candidate.Sequence),
			key.use,
			key.state,
			key.keyID,
			key.publicKey,
			key.notBefore.UTC(),
			key.notAfter.UTC(),
		); err != nil {
			return err
		}
	}
	for _, key := range validated.commitments {
		var topicKeyEpoch any
		if key.topicKeyEpoch != nil {
			topicKeyEpoch = *key.topicKeyEpoch
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO
			     hytch_push_vault.a9_commitment_key_descriptors (
			         environment,
			         keyset_sequence,
			         purpose,
			         key_id,
			         topic_key_epoch,
			         not_before,
			         not_after
			     ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			validated.environmentID,
			int64(candidate.Sequence),
			key.purpose,
			key.keyID,
			topicKeyEpoch,
			key.notBefore.UTC(),
			key.notAfter.UTC(),
		); err != nil {
			return err
		}
	}

	if !hasCurrent {
		_, err := tx.ExecContext(
			ctx,
			`INSERT INTO hytch_push_vault.a9_keyset_state (
			     environment,
			     keyset_sequence,
			     signed_keyset_hash,
			     state,
			     uncertainty_reason,
			     expires_at,
			     refreshed_at
			 ) VALUES (
			     $1,
			     $2,
			     $3,
			     1,
			     0,
			     $4,
			     pg_catalog.clock_timestamp()
			 )`,
			validated.environmentID,
			int64(candidate.Sequence),
			validated.objectHash,
			candidate.ExpiresAt.UTC(),
		)
		return err
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.a9_keyset_state
		    SET keyset_sequence = $2,
		        signed_keyset_hash = $3,
		        state = 1,
		        uncertainty_reason = 0,
		        expires_at = $4,
		        refreshed_at = pg_catalog.clock_timestamp()
		  WHERE environment = $1
		    AND keyset_sequence = $5
		    AND signed_keyset_hash = $6
		    AND state = 1`,
		validated.environmentID,
		int64(candidate.Sequence),
		validated.objectHash,
		candidate.ExpiresAt.UTC(),
		int64(current.Sequence),
		decodeA9BareHash(current.ObjectHash),
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errA9DatabaseUnavailable
	}
	return nil
}

func latchA9KeysetStateTx(
	ctx context.Context,
	tx *sql.Tx,
	current a9trust.KeysetState,
	environmentID int16,
	reason int16,
) (a9trust.KeysetState, error) {
	result, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.a9_keyset_state
		    SET state = 2,
		        uncertainty_reason = $2,
		        refreshed_at = pg_catalog.clock_timestamp()
		  WHERE environment = $1
		    AND state = 1`,
		environmentID,
		reason,
	)
	if err != nil {
		return a9trust.KeysetState{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return a9trust.KeysetState{}, errA9DatabaseUnavailable
	}
	current.Uncertain = true
	return current, nil
}

func refreshA9KeysetStateTx(
	ctx context.Context,
	tx *sql.Tx,
	current a9trust.KeysetState,
	environmentID int16,
) error {
	result, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.a9_keyset_state
		    SET refreshed_at = pg_catalog.clock_timestamp()
		  WHERE environment = $1
		    AND keyset_sequence = $2
		    AND signed_keyset_hash = $3
		    AND state = 1`,
		environmentID,
		int64(current.Sequence),
		decodeA9BareHash(current.ObjectHash),
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errA9DatabaseUnavailable
	}
	return nil
}

func lockA9KeysetEnvironment(
	ctx context.Context,
	tx *sql.Tx,
	environmentID int16,
) error {
	_, err := tx.ExecContext(
		ctx,
		`SELECT pg_catalog.pg_advisory_xact_lock($1, $2)`,
		a9KeysetLockClass,
		environmentID,
	)
	return err
}

func readA9KeysetStateForUpdate(
	ctx context.Context,
	tx *sql.Tx,
	environment string,
	environmentID int16,
) (a9trust.KeysetState, []byte, error) {
	return scanA9KeysetState(
		tx.QueryRowContext(
			ctx,
			`SELECT
			     state_row.keyset_sequence,
			     state_row.signed_keyset_hash,
			     state_row.state,
			     state_row.expires_at,
			     accepted.signed_keyset_jcs
			   FROM hytch_push_vault.a9_keyset_state AS state_row
			   LEFT JOIN hytch_push_vault.a9_accepted_keysets AS accepted
			     ON accepted.environment = state_row.environment
			    AND accepted.keyset_sequence =
			            state_row.keyset_sequence
			    AND accepted.signed_keyset_hash =
			            state_row.signed_keyset_hash
			  WHERE state_row.environment = $1
			  FOR UPDATE OF state_row`,
			environmentID,
		),
		environment,
	)
}

type a9RowScanner interface {
	Scan(dest ...any) error
}

func scanA9KeysetState(
	row a9RowScanner,
	environment string,
) (a9trust.KeysetState, []byte, error) {
	var (
		sequence  int64
		hash      []byte
		stateCode int16
		expiresAt sql.NullTime
		canonical []byte
	)
	if err := row.Scan(
		&sequence,
		&hash,
		&stateCode,
		&expiresAt,
		&canonical,
	); err != nil {
		return a9trust.KeysetState{}, nil, err
	}
	if sequence < 0 ||
		uint64(sequence) > a9SafeIntegerMaximum ||
		(stateCode != a9KeysetStateCurrent &&
			stateCode != a9KeysetStateUncertain) {
		return a9trust.KeysetState{}, nil, errA9DatabaseUnavailable
	}
	result := a9trust.KeysetState{
		Environment: environment,
		Sequence:    uint64(sequence),
		Uncertain:   stateCode == a9KeysetStateUncertain,
	}
	if sequence == 0 {
		if stateCode != a9KeysetStateUncertain ||
			len(hash) != 0 ||
			expiresAt.Valid ||
			len(canonical) != 0 {
			return a9trust.KeysetState{}, nil, errA9DatabaseUnavailable
		}
		return result, nil, nil
	}
	if len(hash) != 32 || !expiresAt.Valid || len(canonical) == 0 {
		return a9trust.KeysetState{}, nil, errA9DatabaseUnavailable
	}
	result.ObjectHash = hex.EncodeToString(hash)
	result.ExpiresAt = expiresAt.Time.UTC()
	return result, append([]byte(nil), canonical...), nil
}

func validateA9AcceptedKeyset(
	candidate a9trust.AcceptedKeyset,
) (a9ValidatedCandidate, error) {
	environmentID, ok := a9EnvironmentID(candidate.Environment)
	if !ok ||
		candidate.Sequence == 0 ||
		candidate.Sequence > a9SafeIntegerMaximum ||
		candidate.IssuedAt.IsZero() ||
		candidate.ExpiresAt.IsZero() ||
		!candidate.ExpiresAt.After(candidate.IssuedAt) ||
		candidate.ExpiresAt.Sub(candidate.IssuedAt) > 24*time.Hour ||
		len(candidate.CanonicalSignedObject) == 0 ||
		len(candidate.CanonicalSignedObject) > 262144 {
		return a9ValidatedCandidate{}, a9trust.ErrKeysetRejected
	}
	object, err := parseA9CanonicalObject(
		candidate.CanonicalSignedObject,
	)
	if err != nil ||
		a9trust.SHA256LowerHex(candidate.CanonicalSignedObject) !=
			candidate.ObjectHash ||
		a9ObjectString(object, "environment") != candidate.Environment ||
		a9ObjectUint(object, "keyset_sequence") != candidate.Sequence ||
		a9ObjectString(object, "root_signing_key_id") !=
			candidate.RootKeyID {
		return a9ValidatedCandidate{}, a9trust.ErrKeysetRejected
	}
	issuedAt, ok := parseA9WireTime(
		a9ObjectString(object, "issued_at"),
	)
	if !ok || !issuedAt.Equal(candidate.IssuedAt) {
		return a9ValidatedCandidate{}, a9trust.ErrKeysetRejected
	}
	expiresAt, ok := parseA9WireTime(
		a9ObjectString(object, "expires_at"),
	)
	if !ok || !expiresAt.Equal(candidate.ExpiresAt) {
		return a9ValidatedCandidate{}, a9trust.ErrKeysetRejected
	}
	objectHash, ok := decodeA9LowerHex(candidate.ObjectHash, "")
	if !ok {
		return a9ValidatedCandidate{}, a9trust.ErrKeysetRejected
	}
	rootKeyID, ok := decodeA9LowerHex(
		candidate.RootKeyID,
		"ed25519-sha256:",
	)
	if !ok {
		return a9ValidatedCandidate{}, a9trust.ErrKeysetRejected
	}
	online, ok := validateA9OnlineKeys(
		object["keys"],
		candidate.OnlineKeys,
	)
	if !ok {
		return a9ValidatedCandidate{}, a9trust.ErrKeysetRejected
	}
	commitments, ok := validateA9CommitmentKeys(
		object["commitment_keys"],
		candidate.CommitmentKeys,
	)
	if !ok {
		return a9ValidatedCandidate{}, a9trust.ErrKeysetRejected
	}
	return a9ValidatedCandidate{
		environmentID: environmentID,
		objectHash:    objectHash,
		rootKeyID:     rootKeyID,
		object:        object,
		online:        online,
		commitments:   commitments,
	}, nil
}

func parseA9CanonicalObject(raw []byte) (map[string]any, error) {
	value, err := a9trust.ParseStrictJSON(raw)
	if err != nil {
		return nil, err
	}
	canonical, err := a9trust.Canonicalize(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, a9trust.ErrKeysetRejected
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, a9trust.ErrKeysetRejected
	}
	return object, nil
}

func validateA9OnlineKeys(
	raw any,
	expected []a9trust.OnlineKey,
) ([]a9ValidatedOnlineKey, bool) {
	items, ok := raw.([]any)
	if !ok || len(items) != len(expected) {
		return nil, false
	}
	validated := make([]a9ValidatedOnlineKey, len(items))
	seen := make(map[string]struct{}, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		keyID := a9ObjectString(object, "key_id")
		use := a9ObjectString(object, "use")
		state := a9ObjectString(object, "state")
		publicKeyText := a9ObjectString(
			object,
			"public_key_base64url",
		)
		publicKey, ok := decodeA9Base64URL(publicKeyText, 32)
		if !ok {
			return nil, false
		}
		notBefore, ok := parseA9WireTime(
			a9ObjectString(object, "not_before"),
		)
		if !ok {
			return nil, false
		}
		notAfter, ok := parseA9WireTime(
			a9ObjectString(object, "not_after"),
		)
		if !ok || !notAfter.After(notBefore) {
			return nil, false
		}
		keyIDBytes, ok := decodeA9LowerHex(
			keyID,
			"ed25519-sha256:",
		)
		if !ok {
			return nil, false
		}
		recomputed, err := a9trust.Ed25519KeyID(publicKey)
		if err != nil || recomputed != keyID {
			return nil, false
		}
		useCode, ok := a9OnlineUseCode(use)
		if !ok {
			return nil, false
		}
		stateCode, ok := a9OnlineStateCode(state)
		if !ok {
			return nil, false
		}
		if _, duplicate := seen[keyID]; duplicate {
			return nil, false
		}
		seen[keyID] = struct{}{}
		expectedKey := expected[index]
		if expectedKey.KeyID != keyID ||
			expectedKey.Use != use ||
			expectedKey.State != state ||
			!bytes.Equal(expectedKey.PublicKey, publicKey) ||
			!expectedKey.NotBefore.Equal(notBefore) ||
			!expectedKey.NotAfter.Equal(notAfter) {
			return nil, false
		}
		validated[index] = a9ValidatedOnlineKey{
			use:       useCode,
			state:     stateCode,
			keyID:     keyIDBytes,
			publicKey: append([]byte(nil), publicKey...),
			notBefore: notBefore,
			notAfter:  notAfter,
		}
	}
	return validated, true
}

func validateA9CommitmentKeys(
	raw any,
	expected []a9trust.CommitmentKey,
) ([]a9ValidatedCommitmentKey, bool) {
	items, ok := raw.([]any)
	if !ok || len(items) != len(expected) {
		return nil, false
	}
	validated := make([]a9ValidatedCommitmentKey, len(items))
	seen := make(map[string]struct{}, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		purpose := a9ObjectString(object, "purpose")
		keyID := a9ObjectString(object, "key_id")
		keyIDBytes, ok := decodeA9LowerHex(
			keyID,
			"hmac-sha256:",
		)
		if !ok {
			return nil, false
		}
		purposeCode, ok := a9CommitmentPurposeCode(purpose)
		if !ok {
			return nil, false
		}
		var topicKeyEpoch *int64
		var expectedEpoch *uint32
		switch value := object["topic_key_epoch"].(type) {
		case nil:
		case json.Number:
			parsed, err := strconv.ParseUint(string(value), 10, 32)
			if err != nil || parsed == 0 {
				return nil, false
			}
			epoch := int64(parsed)
			topicKeyEpoch = &epoch
			expectedValue := uint32(parsed)
			expectedEpoch = &expectedValue
		default:
			return nil, false
		}
		if (purpose == "TOPIC") != (topicKeyEpoch != nil) {
			return nil, false
		}
		notBefore, ok := parseA9WireTime(
			a9ObjectString(object, "not_before"),
		)
		if !ok {
			return nil, false
		}
		notAfter, ok := parseA9WireTime(
			a9ObjectString(object, "not_after"),
		)
		if !ok || !notAfter.After(notBefore) {
			return nil, false
		}
		if _, duplicate := seen[keyID]; duplicate {
			return nil, false
		}
		seen[keyID] = struct{}{}
		expectedKey := expected[index]
		if expectedKey.KeyID != keyID ||
			expectedKey.Purpose != purpose ||
			!sameA9TopicEpoch(
				expectedKey.TopicKeyEpoch,
				expectedEpoch,
			) ||
			!expectedKey.NotBefore.Equal(notBefore) ||
			!expectedKey.NotAfter.Equal(notAfter) {
			return nil, false
		}
		validated[index] = a9ValidatedCommitmentKey{
			purpose:       purposeCode,
			keyID:         keyIDBytes,
			topicKeyEpoch: topicKeyEpoch,
			notBefore:     notBefore,
			notAfter:      notAfter,
		}
	}
	return validated, true
}

func a9EnvironmentID(environment string) (int16, bool) {
	switch environment {
	case "dev":
		return 1, true
	case "production":
		return 2, true
	default:
		return 0, false
	}
}

func a9OnlineUseCode(use string) (int16, bool) {
	switch use {
	case "A9_CONTROL":
		return 1, true
	case "SERVICE_AUTH":
		return 2, true
	default:
		return 0, false
	}
}

func a9OnlineStateCode(state string) (int16, bool) {
	switch state {
	case "SIGN":
		return 1, true
	case "VERIFY_ONLY":
		return 2, true
	default:
		return 0, false
	}
}

func a9CommitmentPurposeCode(purpose string) (int16, bool) {
	switch purpose {
	case "ROSTER":
		return 1, true
	case "TUPLE":
		return 2, true
	case "TOPIC":
		return 3, true
	default:
		return 0, false
	}
}

func a9UncertaintyReason(reason string) int16 {
	switch reason {
	case "KEYSET_ROLLBACK":
		return a9UncertaintyRollback
	case "ONLINE_ROTATION":
		return a9UncertaintyRotation
	default:
		return a9UncertaintyKeyState
	}
}

func a9ObjectString(object map[string]any, field string) string {
	value, _ := object[field].(string)
	return value
}

func a9ObjectUint(object map[string]any, field string) uint64 {
	number, ok := object[field].(json.Number)
	if !ok {
		return 0
	}
	parsed, err := strconv.ParseUint(string(number), 10, 64)
	if err != nil || parsed > a9SafeIntegerMaximum {
		return 0
	}
	return parsed
}

func parseA9WireTime(value string) (time.Time, bool) {
	const layout = "2006-01-02T15:04:05.000Z"
	if len(value) != len(layout) {
		return time.Time{}, false
	}
	parsed, err := time.Parse(layout, value)
	if err != nil || parsed.Format(layout) != value {
		return time.Time{}, false
	}
	return parsed, true
}

func decodeA9Base64URL(value string, size int) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil ||
		len(decoded) != size ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}

func decodeA9LowerHex(
	value string,
	prefix string,
) ([]byte, bool) {
	if !strings.HasPrefix(value, prefix) {
		return nil, false
	}
	raw := strings.TrimPrefix(value, prefix)
	if len(raw) != 64 || strings.ToLower(raw) != raw {
		return nil, false
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil ||
		len(decoded) != 32 ||
		hex.EncodeToString(decoded) != raw {
		return nil, false
	}
	return decoded, true
}

func decodeA9BareHash(value string) []byte {
	decoded, ok := decodeA9LowerHex(value, "")
	if !ok {
		return nil
	}
	return decoded
}

func validCanonicalA9UUID(value string) bool {
	if len(value) != 36 ||
		value[8] != '-' ||
		value[13] != '-' ||
		value[18] != '-' ||
		value[23] != '-' ||
		strings.ToLower(value) != value {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func sameA9TopicEpoch(left, right *uint32) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func isA9SerializationFailure(err error) bool {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return false
	}
	if postgresError.Code == "40001" || postgresError.Code == "40P01" {
		return true
	}
	if postgresError.Code != "23505" {
		return false
	}
	// PostgreSQL can report a unique violation, rather than 40001, when the
	// first statement in a SERIALIZABLE transaction waits on the advisory
	// lock and the stale snapshot then races a first-row insert. Only the two
	// first-acceptance keys are retryable; every other uniqueness violation
	// remains a fixed fail-closed storage error.
	return postgresError.ConstraintName == "a9_accepted_keysets_pkey" ||
		postgresError.ConstraintName == "a9_keyset_state_pkey"
}

func validA9StoreContext(ctx context.Context) bool {
	return ctx != nil && ctx.Err() == nil
}
