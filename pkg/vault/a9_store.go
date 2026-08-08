package vault

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9api"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

const (
	a9MaxSafeInteger = uint64(1<<53 - 1)

	a9OperationControl int16 = 1
	a9OperationReplace int16 = 2

	a9OutcomeApplied      int16 = 1
	a9OutcomeReplay       int16 = 2
	a9OutcomeStale        int16 = 3
	a9OutcomeGap          int16 = 4
	a9OutcomeConflict     int16 = 5
	a9OutcomeInconclusive int16 = 6

	a9ResultActive    int16 = 1
	a9ResultRevoked   int16 = 2
	a9ResultUncertain int16 = 3

	a9AuthorityActive    int16 = 1
	a9AuthorityUncertain int16 = 3

	a9BindingActive  int16 = 1
	a9BindingRevoked int16 = 2

	a9UncertaintyControlGap         int16 = 1
	a9UncertaintyIdempotency        int16 = 2
	a9UncertaintyControlRegression  int16 = 3
	a9UncertaintyEpoch              int16 = 4
	a9UncertaintyWatermarkGap       int16 = 5
	a9UncertaintyWatermarkRollback  int16 = 6
	a9UncertaintyArtifactExpired    int16 = 7
	a9UncertaintySignedWatermark    int16 = 8
	a9UncertaintyBindingConflict    int16 = 9
	a9UncertaintyAuthorityReference int16 = 10

	a9TransactionAttempts = 4
)

type a9AuthorityRow struct {
	epoch                 [16]byte
	contiguous            uint64
	generation            uint64
	state                 int16
	uncertaintyReason     int16
	watermarkSequence     sql.NullInt64
	watermarkHash         []byte
	watermarkCommitted    sql.NullInt64
	watermarkStatus       sql.NullInt64
	watermarkReason       sql.NullInt64
	watermarkIssuedAt     sql.NullTime
	watermarkExpiresAt    sql.NullTime
	watermarkSigningKeyID []byte
	watermarkKeysetSeq    sql.NullInt64
	watermarkKeysetHash   []byte
}

type a9ReceiptRow struct {
	operation  int16
	bindingID  []byte
	epoch      []byte
	hash       []byte
	outcome    int16
	state      int16
	generation uint64
	sequence   uint64
}

type a9BindingRow struct {
	version       uint64
	state         int16
	assertionHash []byte
}

// ApplyControl implements the A9 control stream as a retry-bounded
// SERIALIZABLE transaction. A retry is attempted only when PostgreSQL proves
// that the transaction did not commit.
func (s *Store) ApplyControl(
	ctx context.Context,
	event a9trust.VerifiedControl,
) (a9api.Result, error) {
	if !s.validA9Control(event) {
		return a9api.Result{}, ErrStoreUnavailable
	}
	for attempt := 0; attempt < a9TransactionAttempts; attempt++ {
		result, err := s.applyA9ControlOnce(ctx, event)
		if err == nil {
			return result, nil
		}
		if !isSerializationFailure(err) {
			return a9api.Result{}, ErrStoreUnavailable
		}
	}
	return a9api.Result{}, ErrStoreUnavailable
}

func (s *Store) applyA9ControlOnce(
	ctx context.Context,
	event a9trust.VerifiedControl,
) (a9api.Result, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return a9api.Result{}, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()

	dbNow, err := s.requireA9KeysetTx(
		ctx,
		tx,
		event.KeysetSequence,
		event.KeysetHash,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return a9api.Result{}, storeDatabaseError(err)
	}

	authority, err := s.loadA9AuthorityTx(
		ctx,
		tx,
		event.InstallationBindingID,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	if authority == nil {
		initialState := a9AuthorityActive
		initialReason := int16(0)
		if event.StreamSequence != 1 {
			initialState = a9AuthorityUncertain
			initialReason = a9UncertaintyControlGap
		}
		if err = s.insertA9AuthorityTx(
			ctx,
			tx,
			event.InstallationBindingID,
			event.SequencerEpoch,
			initialState,
			initialReason,
			dbNow,
		); err != nil {
			return a9api.Result{}, err
		}
		authority = &a9AuthorityRow{
			epoch:             event.SequencerEpoch,
			state:             initialState,
			uncertaintyReason: initialReason,
		}
	}

	if replay, found, receiptErr := s.a9ReceiptResultTx(
		ctx,
		tx,
		event.IdempotencyKey,
		a9OperationControl,
		event.InstallationBindingID,
		event.SequencerEpoch,
		event.SignedObjectHash,
		authority,
		dbNow,
	); receiptErr != nil {
		return a9api.Result{}, receiptErr
	} else if found {
		if replay.Outcome == a9api.ResultOutcomeReplay &&
			(!dbNow.Before(event.ExpiresAt.UTC()) ||
				(event.Assertion != nil &&
					!dbNow.Before(event.Assertion.ExpiresAt.UTC()))) {
			return a9api.Result{}, ErrStoreUnavailable
		}
		return commitA9Result(tx, replay)
	}

	if authority.epoch != event.SequencerEpoch {
		if event.StreamSequence != 1 ||
			event.ExpectedPreviousSequence != 0 {
			if err = s.latchA9UncertaintyTx(
				ctx,
				tx,
				event.InstallationBindingID,
				a9UncertaintyEpoch,
				dbNow,
			); err != nil {
				return a9api.Result{}, err
			}
			result := s.a9Result(
				event.InstallationBindingID,
				event.SequencerEpoch,
				authority.generation,
				a9ResultUncertain,
				a9OutcomeInconclusive,
				authority.contiguous,
			)
			if err = s.insertA9ReceiptTx(
				ctx, tx, event.IdempotencyKey, a9OperationControl,
				event.InstallationBindingID, event.SequencerEpoch,
				event.SignedObjectHash, result,
			); err != nil {
				return a9api.Result{}, err
			}
			return commitA9Result(tx, result)
		}
		previouslyObserved, observedErr := s.a9EpochPreviouslyObservedTx(
			ctx,
			tx,
			event.InstallationBindingID,
			event.SequencerEpoch,
		)
		if observedErr != nil {
			return a9api.Result{}, observedErr
		}
		if previouslyObserved {
			if err = s.latchA9UncertaintyTx(
				ctx,
				tx,
				event.InstallationBindingID,
				a9UncertaintyEpoch,
				dbNow,
			); err != nil {
				return a9api.Result{}, err
			}
			result := s.a9Result(
				event.InstallationBindingID,
				event.SequencerEpoch,
				authority.generation,
				a9ResultUncertain,
				a9OutcomeConflict,
				authority.contiguous,
			)
			if err = s.insertA9ReceiptTx(
				ctx, tx, event.IdempotencyKey, a9OperationControl,
				event.InstallationBindingID, event.SequencerEpoch,
				event.SignedObjectHash, result,
			); err != nil {
				return a9api.Result{}, err
			}
			return commitA9Result(tx, result)
		}
		if err = s.resetA9EpochTx(
			ctx,
			tx,
			event.InstallationBindingID,
			event.SequencerEpoch,
			dbNow,
		); err != nil {
			return a9api.Result{}, err
		}
		authority.epoch = event.SequencerEpoch
		authority.contiguous = 0
		authority.state = a9AuthorityUncertain
		authority.uncertaintyReason = a9UncertaintyEpoch
		authority.watermarkSequence = sql.NullInt64{}
		authority.watermarkHash = nil
	}

	if !dbNow.Before(event.ExpiresAt.UTC()) ||
		(event.Assertion != nil &&
			!dbNow.Before(event.Assertion.ExpiresAt.UTC())) {
		if err = s.latchA9UncertaintyTx(
			ctx, tx, event.InstallationBindingID,
			a9UncertaintyArtifactExpired, dbNow,
		); err != nil {
			return a9api.Result{}, err
		}
		result := s.a9Result(
			event.InstallationBindingID, event.SequencerEpoch,
			authority.generation, a9ResultUncertain,
			a9OutcomeInconclusive, authority.contiguous,
		)
		if err = s.insertA9ReceiptTx(
			ctx, tx, event.IdempotencyKey, a9OperationControl,
			event.InstallationBindingID, event.SequencerEpoch,
			event.SignedObjectHash, result,
		); err != nil {
			return a9api.Result{}, err
		}
		return commitA9Result(tx, result)
	}

	binding, err := s.loadA9BindingTx(
		ctx,
		tx,
		event.InstallationBindingID,
		event.BindingID,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	highestVersion := uint64(0)
	if binding != nil {
		highestVersion = binding.version
	}
	tombstoneVersion, err := s.highestA9TombstoneVersionTx(
		ctx,
		tx,
		event.InstallationBindingID,
		event.BindingID,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	if tombstoneVersion > highestVersion {
		highestVersion = tombstoneVersion
	}

	// A terminal denial cannot be reversed by an equal or older UPSERT.
	if event.Action == a9trust.ControlActionUpsert &&
		tombstoneVersion >= event.BindingVersion {
		result := s.a9Result(
			event.InstallationBindingID, event.SequencerEpoch,
			authority.generation, a9ResultRevoked,
			a9OutcomeStale, authority.contiguous,
		)
		if err = s.insertA9ReceiptTx(
			ctx, tx, event.IdempotencyKey, a9OperationControl,
			event.InstallationBindingID, event.SequencerEpoch,
			event.SignedObjectHash, result,
		); err != nil {
			return a9api.Result{}, err
		}
		return commitA9Result(tx, result)
	}

	switch {
	case event.StreamSequence <= authority.contiguous:
		if err = s.latchA9UncertaintyTx(
			ctx, tx, event.InstallationBindingID,
			a9UncertaintyControlRegression, dbNow,
		); err != nil {
			return a9api.Result{}, err
		}
		result := s.a9Result(
			event.InstallationBindingID, event.SequencerEpoch,
			authority.generation, a9ResultUncertain,
			a9OutcomeConflict, authority.contiguous,
		)
		if err = s.insertA9ReceiptTx(
			ctx, tx, event.IdempotencyKey, a9OperationControl,
			event.InstallationBindingID, event.SequencerEpoch,
			event.SignedObjectHash, result,
		); err != nil {
			return a9api.Result{}, err
		}
		return commitA9Result(tx, result)

	case event.StreamSequence > authority.contiguous+1:
		if err = s.latchA9UncertaintyTx(
			ctx, tx, event.InstallationBindingID,
			a9UncertaintyControlGap, dbNow,
		); err != nil {
			return a9api.Result{}, err
		}
		if event.Action == a9trust.ControlActionRevoke &&
			event.BindingVersion > highestVersion {
			result := s.a9Result(
				event.InstallationBindingID, event.SequencerEpoch,
				authority.generation, a9ResultUncertain,
				a9OutcomeApplied, authority.contiguous,
			)
			if err = s.insertA9ReceiptTx(
				ctx, tx, event.IdempotencyKey, a9OperationControl,
				event.InstallationBindingID, event.SequencerEpoch,
				event.SignedObjectHash, result,
			); err != nil {
				return a9api.Result{}, err
			}
			if err = s.persistA9RevokeTx(
				ctx, tx, event, false, dbNow,
			); err != nil {
				return a9api.Result{}, err
			}
			return commitA9Result(tx, result)
		}
		result := s.a9Result(
			event.InstallationBindingID, event.SequencerEpoch,
			authority.generation, a9ResultUncertain,
			a9OutcomeGap, authority.contiguous,
		)
		if err = s.insertA9ReceiptTx(
			ctx, tx, event.IdempotencyKey, a9OperationControl,
			event.InstallationBindingID, event.SequencerEpoch,
			event.SignedObjectHash, result,
		); err != nil {
			return a9api.Result{}, err
		}
		return commitA9Result(tx, result)

	case event.ExpectedPreviousSequence != authority.contiguous ||
		event.ExpectedBindingVersion != highestVersion:
		if err = s.latchA9UncertaintyTx(
			ctx, tx, event.InstallationBindingID,
			a9UncertaintyBindingConflict, dbNow,
		); err != nil {
			return a9api.Result{}, err
		}
		result := s.a9Result(
			event.InstallationBindingID, event.SequencerEpoch,
			authority.generation, a9ResultUncertain,
			a9OutcomeGap, authority.contiguous,
		)
		if err = s.insertA9ReceiptTx(
			ctx, tx, event.IdempotencyKey, a9OperationControl,
			event.InstallationBindingID, event.SequencerEpoch,
			event.SignedObjectHash, result,
		); err != nil {
			return a9api.Result{}, err
		}
		return commitA9Result(tx, result)
	}

	resultState := a9ResultActive
	if event.Action == a9trust.ControlActionRevoke {
		resultState = a9ResultRevoked
	}
	if authority.state == a9AuthorityUncertain {
		resultState = a9ResultUncertain
	}
	result := s.a9Result(
		event.InstallationBindingID, event.SequencerEpoch,
		authority.generation, resultState,
		a9OutcomeApplied, event.StreamSequence,
	)
	if err = s.insertA9ReceiptTx(
		ctx, tx, event.IdempotencyKey, a9OperationControl,
		event.InstallationBindingID, event.SequencerEpoch,
		event.SignedObjectHash, result,
	); err != nil {
		return a9api.Result{}, err
	}
	if event.Action == a9trust.ControlActionUpsert {
		err = s.persistA9UpsertTx(ctx, tx, event, dbNow)
	} else {
		err = s.persistA9RevokeTx(ctx, tx, event, true, dbNow)
	}
	if err != nil {
		return a9api.Result{}, err
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.a9_installation_authority
		    SET contiguous_stream_sequence = $3,
		        updated_at = $4
		  WHERE environment = $1
		    AND installation_binding_id = $2`,
		s.environmentID,
		event.InstallationBindingID[:],
		int64(event.StreamSequence),
		dbNow,
	); err != nil {
		return a9api.Result{}, storeDatabaseError(err)
	}
	return commitA9Result(tx, result)
}

// ApplyWatermark enforces exact sequence continuity and persists accepted
// watermarks only in append-only history. A signed UNCERTAIN watermark is a
// committed denial latch, never positive authority.
func (s *Store) ApplyWatermark(
	ctx context.Context,
	watermark a9trust.VerifiedWatermark,
) (a9api.Result, error) {
	if !s.validA9Watermark(watermark) {
		return a9api.Result{}, ErrStoreUnavailable
	}
	for attempt := 0; attempt < a9TransactionAttempts; attempt++ {
		result, err := s.applyA9WatermarkOnce(ctx, watermark)
		if err == nil {
			return result, nil
		}
		if !isSerializationFailure(err) {
			return a9api.Result{}, ErrStoreUnavailable
		}
	}
	return a9api.Result{}, ErrStoreUnavailable
}

func (s *Store) applyA9WatermarkOnce(
	ctx context.Context,
	watermark a9trust.VerifiedWatermark,
) (a9api.Result, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return a9api.Result{}, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()

	dbNow, err := s.requireA9KeysetTx(
		ctx, tx, watermark.KeysetSequence, watermark.KeysetHash,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return a9api.Result{}, storeDatabaseError(err)
	}
	authority, err := s.loadA9AuthorityTx(
		ctx, tx, watermark.InstallationBindingID,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	if authority == nil {
		if err = s.insertA9AuthorityTx(
			ctx, tx, watermark.InstallationBindingID,
			watermark.SequencerEpoch, a9AuthorityUncertain,
			a9UncertaintyWatermarkGap, dbNow,
		); err != nil {
			return a9api.Result{}, err
		}
		authority = &a9AuthorityRow{
			epoch:             watermark.SequencerEpoch,
			state:             a9AuthorityUncertain,
			uncertaintyReason: a9UncertaintyWatermarkGap,
		}
	}

	resultFor := func(
		state int16,
		outcome int16,
	) a9api.Result {
		return s.a9Result(
			watermark.InstallationBindingID,
			watermark.SequencerEpoch,
			authority.generation,
			state,
			outcome,
			authority.contiguous,
		)
	}
	latch := func(reason int16, outcome int16) (a9api.Result, error) {
		if latchErr := s.latchA9UncertaintyTx(
			ctx, tx, watermark.InstallationBindingID, reason, dbNow,
		); latchErr != nil {
			return a9api.Result{}, latchErr
		}
		return commitA9Result(
			tx,
			resultFor(a9ResultUncertain, outcome),
		)
	}

	replayed, err := s.a9WatermarkAlreadyAcceptedTx(
		ctx,
		tx,
		watermark,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	if replayed {
		if !dbNow.Before(watermark.ExpiresAt.UTC()) {
			return a9api.Result{}, ErrStoreUnavailable
		}
		if authority.state == a9AuthorityUncertain {
			return commitA9Result(
				tx,
				resultFor(a9ResultUncertain, a9OutcomeInconclusive),
			)
		}
		return commitA9Result(
			tx,
			resultFor(a9ResultActive, a9OutcomeReplay),
		)
	}
	if authority.epoch != watermark.SequencerEpoch {
		return latch(a9UncertaintyEpoch, a9OutcomeInconclusive)
	}
	if !dbNow.Before(watermark.ExpiresAt.UTC()) {
		return latch(a9UncertaintyArtifactExpired, a9OutcomeInconclusive)
	}

	currentSequence := uint64(0)
	if authority.watermarkSequence.Valid {
		if authority.watermarkSequence.Int64 <= 0 {
			return a9api.Result{}, ErrStoreUnavailable
		}
		currentSequence = uint64(authority.watermarkSequence.Int64)
	}
	switch {
	case watermark.WatermarkSequence <= currentSequence:
		return latch(a9UncertaintyWatermarkRollback, a9OutcomeConflict)
	case currentSequence == 0 && watermark.WatermarkSequence != 1:
		return latch(a9UncertaintyWatermarkGap, a9OutcomeGap)
	case currentSequence != 0 &&
		watermark.WatermarkSequence != currentSequence+1:
		return latch(a9UncertaintyWatermarkGap, a9OutcomeGap)
	case watermark.Status == a9trust.WatermarkStatusCurrent &&
		watermark.CommittedThroughStreamSequence > authority.contiguous:
		return latch(a9UncertaintyWatermarkGap, a9OutcomeGap)
	case watermark.Status == a9trust.WatermarkStatusCurrent &&
		authority.state == a9AuthorityUncertain &&
		authority.uncertaintyReason != a9UncertaintyEpoch:
		return commitA9Result(
			tx,
			resultFor(a9ResultUncertain, a9OutcomeInconclusive),
		)
	}

	if err = s.appendA9WatermarkTx(ctx, tx, watermark); err != nil {
		return a9api.Result{}, err
	}
	state := authority.state
	reason := authority.uncertaintyReason
	resultState := a9ResultActive
	resultOutcome := a9OutcomeApplied
	if watermark.Status == a9trust.WatermarkStatusUncertain {
		state = a9AuthorityUncertain
		reason = a9UncertaintySignedWatermark
		resultState = a9ResultUncertain
		resultOutcome = a9OutcomeInconclusive
	} else if authority.state == a9AuthorityUncertain {
		// This is a recovery candidate, not an egress-opening transition.
		// Replace must still validate the complete fresh-epoch route set and
		// clear the installation latch in the same vault CAS.
		state = a9AuthorityUncertain
		reason = authority.uncertaintyReason
		resultState = a9ResultUncertain
		resultOutcome = a9OutcomeInconclusive
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.a9_installation_authority
		    SET state = $3,
		        uncertainty_reason = $4,
		        watermark_sequence = $5,
		        watermark_signed_hash = $6,
		        watermark_committed_through = $7,
		        watermark_status = $8,
		        watermark_uncertainty_reason = $9,
		        watermark_issued_at = $10,
		        watermark_expires_at = $11,
		        watermark_signing_key_id = $12,
		        watermark_keyset_sequence = $13,
		        watermark_keyset_hash = $14,
		        updated_at = $15
		  WHERE environment = $1
		    AND installation_binding_id = $2`,
		s.environmentID,
		watermark.InstallationBindingID[:],
		state,
		reason,
		int64(watermark.WatermarkSequence),
		watermark.SignedObjectHash[:],
		int64(watermark.CommittedThroughStreamSequence),
		int16(watermark.Status),
		int16(watermark.UncertaintyReason),
		watermark.IssuedAt.UTC(),
		watermark.ExpiresAt.UTC(),
		watermark.SigningKeyID[:],
		int64(watermark.KeysetSequence),
		watermark.KeysetHash[:],
		dbNow,
	); err != nil {
		return a9api.Result{}, storeDatabaseError(err)
	}
	return commitA9Result(
		tx,
		resultFor(resultState, resultOutcome),
	)
}

func (s *Store) requireA9KeysetTx(
	ctx context.Context,
	tx *sql.Tx,
	sequence uint64,
	hash [32]byte,
) (time.Time, error) {
	if s == nil || tx == nil || sequence == 0 ||
		sequence > a9MaxSafeInteger {
		return time.Time{}, ErrStoreUnavailable
	}
	var (
		dbNow          time.Time
		storedSequence uint64
		storedHash     []byte
		state          int16
		uncertainty    int16
		expiresAt      sql.NullTime
		refreshedAt    time.Time
	)
	err := tx.QueryRowContext(
		ctx,
		`SELECT pg_catalog.clock_timestamp(),
		        keyset_sequence, signed_keyset_hash, state,
		        uncertainty_reason, expires_at, refreshed_at
		   FROM hytch_push_vault.a9_keyset_state
		  WHERE environment = $1
		  FOR UPDATE`,
		s.environmentID,
	).Scan(
		&dbNow,
		&storedSequence,
		&storedHash,
		&state,
		&uncertainty,
		&expiresAt,
		&refreshedAt,
	)
	if err != nil {
		return time.Time{}, storeDatabaseError(err)
	}
	dbNow = dbNow.UTC()
	if storedSequence != sequence ||
		!bytes.Equal(storedHash, hash[:]) ||
		state != 1 ||
		uncertainty != 0 ||
		!expiresAt.Valid ||
		!dbNow.Before(expiresAt.Time.UTC()) ||
		!refreshedAt.UTC().After(dbNow.Add(-6*time.Hour)) {
		return time.Time{}, ErrStoreUnavailable
	}
	return dbNow, nil
}

func (s *Store) loadA9AuthorityTx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
) (*a9AuthorityRow, error) {
	row := &a9AuthorityRow{}
	var epoch []byte
	err := tx.QueryRowContext(
		ctx,
		`SELECT sequencer_epoch, contiguous_stream_sequence,
		        subscription_generation, state, uncertainty_reason,
		        watermark_sequence, watermark_signed_hash,
		        watermark_committed_through, watermark_status,
		        watermark_uncertainty_reason, watermark_issued_at,
		        watermark_expires_at, watermark_signing_key_id,
		        watermark_keyset_sequence, watermark_keyset_hash
		   FROM hytch_push_vault.a9_installation_authority
		  WHERE environment = $1
		    AND installation_binding_id = $2
		  FOR UPDATE`,
		s.environmentID,
		installationBindingID[:],
	).Scan(
		&epoch,
		&row.contiguous,
		&row.generation,
		&row.state,
		&row.uncertaintyReason,
		&row.watermarkSequence,
		&row.watermarkHash,
		&row.watermarkCommitted,
		&row.watermarkStatus,
		&row.watermarkReason,
		&row.watermarkIssuedAt,
		&row.watermarkExpiresAt,
		&row.watermarkSigningKeyID,
		&row.watermarkKeysetSeq,
		&row.watermarkKeysetHash,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil || len(epoch) != len(row.epoch) {
		return nil, storeDatabaseError(err)
	}
	copy(row.epoch[:], epoch)
	return row, nil
}

func (s *Store) insertA9AuthorityTx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
	epoch [16]byte,
	state int16,
	reason int16,
	now time.Time,
) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_installation_authority (
		     environment, installation_binding_id, sequencer_epoch,
		     contiguous_stream_sequence, subscription_generation,
		     state, uncertainty_reason, created_at, updated_at
		 ) VALUES ($1,$2,$3,0,0,$4,$5,$6,$6)`,
		s.environmentID,
		installationBindingID[:],
		epoch[:],
		state,
		reason,
		now,
	)
	return storeDatabaseError(err)
}

func (s *Store) latchA9UncertaintyTx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
	reason int16,
	now time.Time,
) error {
	result, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.a9_installation_authority
		    SET state = $3,
		        uncertainty_reason = $4,
		        watermark_sequence = NULL,
		        watermark_signed_hash = NULL,
		        watermark_committed_through = NULL,
		        watermark_status = NULL,
		        watermark_uncertainty_reason = NULL,
		        watermark_issued_at = NULL,
		        watermark_expires_at = NULL,
		        watermark_signing_key_id = NULL,
		        watermark_keyset_sequence = NULL,
		        watermark_keyset_hash = NULL,
		        updated_at = $5
		  WHERE environment = $1
		    AND installation_binding_id = $2`,
		s.environmentID,
		installationBindingID[:],
		a9AuthorityUncertain,
		reason,
		now,
	)
	if err != nil {
		return storeDatabaseError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *Store) a9EpochPreviouslyObservedTx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
	epoch [16]byte,
) (bool, error) {
	var observed bool
	if err := tx.QueryRowContext(
		ctx,
		`SELECT EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.a9_control_events
		      WHERE environment = $1
		        AND installation_binding_id = $2
		        AND sequencer_epoch = $3
		     UNION ALL
		     SELECT 1
		       FROM hytch_push_vault.a9_watermarks
		      WHERE environment = $1
		        AND installation_binding_id = $2
		        AND sequencer_epoch = $3
		     UNION ALL
		     SELECT 1
		       FROM hytch_push_vault.a9_idempotency_receipts
		      WHERE environment = $1
		        AND installation_binding_id = $2
		        AND sequencer_epoch = $3
		 )`,
		s.environmentID,
		installationBindingID[:],
		epoch[:],
	).Scan(&observed); err != nil {
		return false, storeDatabaseError(err)
	}
	return observed, nil
}

func (s *Store) resetA9EpochTx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
	epoch [16]byte,
	now time.Time,
) error {
	if err := s.cancelA9RoutesTx(
		ctx, tx, installationBindingID, nil, now,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.a9_subscription_routes
		  WHERE environment = $1
		    AND installation_binding_id = $2`,
		s.environmentID,
		installationBindingID[:],
	); err != nil {
		return storeDatabaseError(err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.a9_bindings
		  WHERE environment = $1
		    AND installation_binding_id = $2`,
		s.environmentID,
		installationBindingID[:],
	); err != nil {
		return storeDatabaseError(err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.a9_installation_authority
		    SET sequencer_epoch = $3,
		        contiguous_stream_sequence = 0,
		        state = $4,
		        uncertainty_reason = $5,
		        watermark_sequence = NULL,
		        watermark_signed_hash = NULL,
		        watermark_committed_through = NULL,
		        watermark_status = NULL,
		        watermark_uncertainty_reason = NULL,
		        watermark_issued_at = NULL,
		        watermark_expires_at = NULL,
		        watermark_signing_key_id = NULL,
		        watermark_keyset_sequence = NULL,
		        watermark_keyset_hash = NULL,
		        updated_at = $6
		  WHERE environment = $1
		    AND installation_binding_id = $2`,
		s.environmentID,
		installationBindingID[:],
		epoch[:],
		a9AuthorityUncertain,
		a9UncertaintyEpoch,
		now,
	); err != nil {
		return storeDatabaseError(err)
	}
	return nil
}

func (s *Store) a9ReceiptResultTx(
	ctx context.Context,
	tx *sql.Tx,
	idempotencyKey string,
	operation int16,
	installationBindingID [16]byte,
	epoch [16]byte,
	hash [32]byte,
	authority *a9AuthorityRow,
	now time.Time,
) (a9api.Result, bool, error) {
	var receipt a9ReceiptRow
	err := tx.QueryRowContext(
		ctx,
		`SELECT operation_kind, installation_binding_id,
		        sequencer_epoch, signed_request_hash,
		        result_outcome, result_state,
		        subscription_generation, accepted_stream_sequence
		   FROM hytch_push_vault.a9_idempotency_receipts
		  WHERE environment = $1
		    AND idempotency_key = $2
		  FOR UPDATE`,
		s.environmentID,
		idempotencyKey,
	).Scan(
		&receipt.operation,
		&receipt.bindingID,
		&receipt.epoch,
		&receipt.hash,
		&receipt.outcome,
		&receipt.state,
		&receipt.generation,
		&receipt.sequence,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return a9api.Result{}, false, nil
	}
	if err != nil {
		return a9api.Result{}, false, storeDatabaseError(err)
	}
	if receipt.operation == operation &&
		bytes.Equal(receipt.bindingID, installationBindingID[:]) &&
		bytes.Equal(receipt.epoch, epoch[:]) &&
		bytes.Equal(receipt.hash, hash[:]) {
		return s.a9Result(
			installationBindingID,
			epoch,
			receipt.generation,
			receipt.state,
			a9OutcomeReplay,
			receipt.sequence,
		), true, nil
	}
	if err = s.latchA9UncertaintyTx(
		ctx, tx, installationBindingID,
		a9UncertaintyIdempotency, now,
	); err != nil {
		return a9api.Result{}, false, err
	}
	return s.a9Result(
		installationBindingID,
		epoch,
		authority.generation,
		a9ResultUncertain,
		a9OutcomeConflict,
		authority.contiguous,
	), true, nil
}

func (s *Store) insertA9ReceiptTx(
	ctx context.Context,
	tx *sql.Tx,
	idempotencyKey string,
	operation int16,
	installationBindingID [16]byte,
	epoch [16]byte,
	hash [32]byte,
	result a9api.Result,
) error {
	outcome, state, ok := encodeA9Result(result)
	if !ok {
		return ErrStoreUnavailable
	}
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_idempotency_receipts (
		     environment, idempotency_key, operation_kind,
		     installation_binding_id, sequencer_epoch,
		     signed_request_hash, result_outcome, result_state,
		     subscription_generation, accepted_stream_sequence
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		s.environmentID,
		idempotencyKey,
		operation,
		installationBindingID[:],
		epoch[:],
		hash[:],
		outcome,
		state,
		int64(result.SubscriptionGeneration),
		int64(result.AcceptedStreamSequence),
	)
	return storeDatabaseError(err)
}

func (s *Store) loadA9BindingTx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
	bindingID [16]byte,
) (*a9BindingRow, error) {
	row := &a9BindingRow{}
	err := tx.QueryRowContext(
		ctx,
		`SELECT binding_version, state, active_assertion_hash
		   FROM hytch_push_vault.a9_bindings
		  WHERE environment = $1
		    AND installation_binding_id = $2
		    AND binding_id = $3
		  FOR UPDATE`,
		s.environmentID,
		installationBindingID[:],
		bindingID[:],
	).Scan(&row.version, &row.state, &row.assertionHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, storeDatabaseError(err)
	}
	return row, nil
}

func (s *Store) highestA9TombstoneVersionTx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
	bindingID [16]byte,
) (uint64, error) {
	var version sql.NullInt64
	err := tx.QueryRowContext(
		ctx,
		`SELECT MAX(binding_version)
		   FROM hytch_push_vault.a9_binding_tombstones
		  WHERE environment = $1
		    AND installation_binding_id = $2
		    AND binding_id = $3`,
		s.environmentID,
		installationBindingID[:],
		bindingID[:],
	).Scan(&version)
	if err != nil {
		return 0, storeDatabaseError(err)
	}
	if !version.Valid {
		return 0, nil
	}
	if version.Int64 <= 0 {
		return 0, ErrStoreUnavailable
	}
	return uint64(version.Int64), nil
}

func (s *Store) persistA9UpsertTx(
	ctx context.Context,
	tx *sql.Tx,
	event a9trust.VerifiedControl,
	now time.Time,
) error {
	assertion := event.Assertion
	if assertion == nil {
		return ErrStoreUnavailable
	}
	if err := s.insertA9ControlEventTx(ctx, tx, event, true); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_assertions (
		     environment, assertion_hash, installation_binding_id,
		     sequencer_epoch, assertion_stream_sequence,
		     binding_id, binding_version, lease_id,
		     tuple_commitment, tuple_commitment_key_id,
		     roster_commitment, roster_commitment_key_id,
		     topic_binding, topic_key_epoch, topic_commitment_key_id,
		     conversation_generation, roster_version,
		     issued_at, expires_at, signing_key_id,
		     keyset_sequence, keyset_hash
		 ) VALUES (
		     $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
		     $16,$17,$18,$19,$20,$21,$22
		 )`,
		s.environmentID,
		assertion.Hash[:],
		assertion.InstallationBindingID[:],
		assertion.SequencerEpoch[:],
		int64(assertion.StreamSequence),
		assertion.BindingID[:],
		int64(assertion.BindingVersion),
		assertion.LeaseID[:],
		assertion.TupleCommitment[:],
		assertion.TupleCommitmentKeyID[:],
		assertion.RosterCommitment[:],
		assertion.RosterCommitmentKeyID[:],
		assertion.TopicBinding[:],
		int64(assertion.TopicKeyEpoch),
		assertion.TopicCommitmentKeyID[:],
		int64(assertion.ConversationGeneration),
		int64(assertion.RosterVersion),
		assertion.IssuedAt.UTC(),
		assertion.ExpiresAt.UTC(),
		assertion.SigningKeyID[:],
		int64(assertion.KeysetSequence),
		assertion.KeysetHash[:],
	); err != nil {
		return storeDatabaseError(err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_bindings (
		     environment, installation_binding_id, binding_id,
		     sequencer_epoch, binding_version, state,
		     active_assertion_hash, active_assertion_stream_sequence,
		     active_topic_key_epoch, active_topic_binding,
		     active_keyset_sequence, active_keyset_hash, updated_at
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		 ON CONFLICT (
		   environment, installation_binding_id, binding_id
		 ) DO UPDATE SET
		     sequencer_epoch = EXCLUDED.sequencer_epoch,
		     binding_version = EXCLUDED.binding_version,
		     state = EXCLUDED.state,
		     active_assertion_hash = EXCLUDED.active_assertion_hash,
		     active_assertion_stream_sequence =
		         EXCLUDED.active_assertion_stream_sequence,
		     active_topic_key_epoch = EXCLUDED.active_topic_key_epoch,
		     active_topic_binding = EXCLUDED.active_topic_binding,
		     active_keyset_sequence = EXCLUDED.active_keyset_sequence,
		     active_keyset_hash = EXCLUDED.active_keyset_hash,
		     updated_at = EXCLUDED.updated_at`,
		s.environmentID,
		event.InstallationBindingID[:],
		event.BindingID[:],
		event.SequencerEpoch[:],
		int64(event.BindingVersion),
		a9BindingActive,
		assertion.Hash[:],
		int64(assertion.StreamSequence),
		int64(assertion.TopicKeyEpoch),
		assertion.TopicBinding[:],
		int64(assertion.KeysetSequence),
		assertion.KeysetHash[:],
		now,
	); err != nil {
		return storeDatabaseError(err)
	}
	return nil
}

func (s *Store) persistA9RevokeTx(
	ctx context.Context,
	tx *sql.Tx,
	event a9trust.VerifiedControl,
	contiguous bool,
	now time.Time,
) error {
	if err := s.insertA9ControlEventTx(
		ctx, tx, event, contiguous,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_binding_tombstones (
		     environment, installation_binding_id, binding_id,
		     binding_version, assertion_hash, sequencer_epoch,
		     control_stream_sequence, reason_code, revoked_at
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		s.environmentID,
		event.InstallationBindingID[:],
		event.BindingID[:],
		int64(event.BindingVersion),
		event.AssertionHash[:],
		event.SequencerEpoch[:],
		int64(event.StreamSequence),
		int16(event.Reason),
		now,
	); err != nil {
		return storeDatabaseError(err)
	}
	if err := s.cancelA9RoutesTx(
		ctx, tx, event.InstallationBindingID, event.BindingID[:], now,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.a9_subscription_routes
		  WHERE environment = $1
		    AND installation_binding_id = $2
		    AND binding_id = $3`,
		s.environmentID,
		event.InstallationBindingID[:],
		event.BindingID[:],
	); err != nil {
		return storeDatabaseError(err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_bindings (
		     environment, installation_binding_id, binding_id,
		     sequencer_epoch, binding_version, state, updated_at
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (
		   environment, installation_binding_id, binding_id
		 ) DO UPDATE SET
		     sequencer_epoch = EXCLUDED.sequencer_epoch,
		     binding_version = EXCLUDED.binding_version,
		     state = EXCLUDED.state,
		     active_assertion_hash = NULL,
		     active_assertion_stream_sequence = NULL,
		     active_topic_key_epoch = NULL,
		     active_topic_binding = NULL,
		     active_keyset_sequence = NULL,
		     active_keyset_hash = NULL,
		     updated_at = EXCLUDED.updated_at`,
		s.environmentID,
		event.InstallationBindingID[:],
		event.BindingID[:],
		event.SequencerEpoch[:],
		int64(event.BindingVersion),
		a9BindingRevoked,
		now,
	); err != nil {
		return storeDatabaseError(err)
	}
	return nil
}

func (s *Store) insertA9ControlEventTx(
	ctx context.Context,
	tx *sql.Tx,
	event a9trust.VerifiedControl,
	contiguous bool,
) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_control_events (
		     environment, installation_binding_id, sequencer_epoch,
		     stream_sequence, expected_previous_sequence,
		     binding_id, binding_version, expected_binding_version,
		     action, assertion_hash, reason_code, idempotency_key,
		     signed_event_hash, stream_is_contiguous,
		     issued_at, expires_at, signing_key_id,
		     keyset_sequence, keyset_hash
		 ) VALUES (
		     $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
		     $15,$16,$17,$18,$19
		 )`,
		s.environmentID,
		event.InstallationBindingID[:],
		event.SequencerEpoch[:],
		int64(event.StreamSequence),
		int64(event.ExpectedPreviousSequence),
		event.BindingID[:],
		int64(event.BindingVersion),
		int64(event.ExpectedBindingVersion),
		int16(event.Action),
		event.AssertionHash[:],
		int16(event.Reason),
		event.IdempotencyKey,
		event.SignedObjectHash[:],
		contiguous,
		event.IssuedAt.UTC(),
		event.ExpiresAt.UTC(),
		event.SigningKeyID[:],
		int64(event.KeysetSequence),
		event.KeysetHash[:],
	)
	return storeDatabaseError(err)
}

func (s *Store) appendA9WatermarkTx(
	ctx context.Context,
	tx *sql.Tx,
	watermark a9trust.VerifiedWatermark,
) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_watermarks (
		     environment, installation_binding_id, sequencer_epoch,
		     watermark_sequence, signed_watermark_hash,
		     committed_through_stream_sequence, status,
		     uncertainty_reason, issued_at, expires_at,
		     signing_key_id, keyset_sequence, keyset_hash
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		s.environmentID,
		watermark.InstallationBindingID[:],
		watermark.SequencerEpoch[:],
		int64(watermark.WatermarkSequence),
		watermark.SignedObjectHash[:],
		int64(watermark.CommittedThroughStreamSequence),
		int16(watermark.Status),
		int16(watermark.UncertaintyReason),
		watermark.IssuedAt.UTC(),
		watermark.ExpiresAt.UTC(),
		watermark.SigningKeyID[:],
		int64(watermark.KeysetSequence),
		watermark.KeysetHash[:],
	)
	return storeDatabaseError(err)
}

func (s *Store) a9WatermarkAlreadyAcceptedTx(
	ctx context.Context,
	tx *sql.Tx,
	watermark a9trust.VerifiedWatermark,
) (bool, error) {
	var (
		installation []byte
		epoch        []byte
		sequence     uint64
	)
	err := tx.QueryRowContext(
		ctx,
		`SELECT installation_binding_id, sequencer_epoch,
		        watermark_sequence
		   FROM hytch_push_vault.a9_watermarks
		  WHERE environment = $1
		    AND signed_watermark_hash = $2`,
		s.environmentID,
		watermark.SignedObjectHash[:],
	).Scan(&installation, &epoch, &sequence)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, storeDatabaseError(err)
	}
	if !bytes.Equal(installation, watermark.InstallationBindingID[:]) ||
		!bytes.Equal(epoch, watermark.SequencerEpoch[:]) ||
		sequence != watermark.WatermarkSequence {
		return false, ErrStoreUnavailable
	}
	return true, nil
}

func (s *Store) cancelA9RoutesTx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
	bindingID []byte,
	now time.Time,
) error {
	if s == nil || tx == nil || now.IsZero() ||
		(len(bindingID) != 0 && len(bindingID) != 16) {
		return ErrStoreUnavailable
	}
	routeQuery := `
		SELECT lease_id
		  FROM hytch_push_vault.a9_subscription_routes
		 WHERE environment = $1
		   AND installation_binding_id = $2`
	routeArgs := []any{
		s.environmentID,
		installationBindingID[:],
	}
	if len(bindingID) != 0 {
		routeQuery += ` AND binding_id = $3`
		routeArgs = append(routeArgs, bindingID)
	}
	routeQuery += `
		 ORDER BY topic_key_epoch, topic_binding, lease_id
		 FOR UPDATE`
	routeRows, err := tx.QueryContext(ctx, routeQuery, routeArgs...)
	if err != nil {
		return storeDatabaseError(err)
	}
	for routeRows.Next() {
		var leaseID []byte
		if err = routeRows.Scan(&leaseID); err != nil {
			_ = routeRows.Close()
			return storeDatabaseError(err)
		}
	}
	if err = routeRows.Err(); err != nil {
		_ = routeRows.Close()
		return storeDatabaseError(err)
	}
	if err = routeRows.Close(); err != nil {
		return storeDatabaseError(err)
	}

	jobQuery := `
		SELECT job_id
		  FROM hytch_push_vault.delivery_jobs
		 WHERE environment = $1
		   AND a9_installation_binding_id = $2
		   AND state IN ($3,$4)`
	jobArgs := []any{
		s.environmentID,
		installationBindingID[:],
		deliveryJobPending,
		deliveryJobClaimed,
	}
	if len(bindingID) != 0 {
		jobQuery += ` AND a9_binding_id = $5`
		jobArgs = append(jobArgs, bindingID)
	}
	jobQuery += `
		 ORDER BY job_id
		 FOR UPDATE`
	jobRows, err := tx.QueryContext(ctx, jobQuery, jobArgs...)
	if err != nil {
		return storeDatabaseError(err)
	}
	for jobRows.Next() {
		var jobID []byte
		if err = jobRows.Scan(&jobID); err != nil {
			_ = jobRows.Close()
			return storeDatabaseError(err)
		}
	}
	if err = jobRows.Err(); err != nil {
		_ = jobRows.Close()
		return storeDatabaseError(err)
	}
	if err = jobRows.Close(); err != nil {
		return storeDatabaseError(err)
	}

	query := `
		UPDATE hytch_push_vault.delivery_jobs
		   SET lease_id = NULL,
		       installation_lookup = NULL,
		       encrypted_job = $1,
		       state = $2,
		       retry_exponent = 0,
		       available_at = $3,
		       traffic_class = COALESCE(traffic_class, $4),
		       final_reason = $5,
		       a9_installation_binding_id = NULL,
		       a9_sequencer_epoch = NULL,
		       a9_subscription_generation = NULL,
		       a9_binding_id = NULL,
		       a9_binding_version = NULL,
		       a9_assertion_hash = NULL,
		       a9_assertion_stream_sequence = NULL,
		       a9_topic_key_epoch = NULL,
		       a9_topic_binding = NULL,
		       a9_route_key_epoch = NULL,
		       a9_keyset_sequence = NULL,
		       a9_keyset_hash = NULL,
		       a9_watermark_sequence = NULL
		 WHERE environment = $6
		   AND a9_installation_binding_id = $7
		   AND state IN ($8,$9)`
	args := []any{
		[]byte{0},
		deliveryJobFinal,
		now,
		int16(DeliveryTrafficUnknown),
		int16(DeliveryFinalSafetyInvalidated),
		s.environmentID,
		installationBindingID[:],
		deliveryJobPending,
		deliveryJobClaimed,
	}
	if len(bindingID) != 0 {
		query += ` AND a9_binding_id = $10`
		args = append(args, bindingID)
	}
	if _, err = tx.ExecContext(ctx, query, args...); err != nil {
		return storeDatabaseError(err)
	}
	return nil
}

func (s *Store) validA9Control(event a9trust.VerifiedControl) bool {
	if s == nil || s.db == nil ||
		event.Environment != s.environment ||
		event.StreamSequence == 0 ||
		event.StreamSequence > a9MaxSafeInteger ||
		event.ExpectedPreviousSequence > a9MaxSafeInteger ||
		event.StreamSequence != event.ExpectedPreviousSequence+1 ||
		event.BindingVersion == 0 ||
		event.BindingVersion > a9MaxSafeInteger ||
		event.ExpectedBindingVersion > a9MaxSafeInteger ||
		event.BindingVersion != event.ExpectedBindingVersion+1 ||
		event.KeysetSequence == 0 ||
		event.KeysetSequence > a9MaxSafeInteger ||
		event.IdempotencyKey == "" ||
		event.ExpiresAt.IsZero() ||
		!event.ExpiresAt.After(event.IssuedAt) ||
		event.ExpiresAt.Sub(event.IssuedAt) > 30*time.Second {
		return false
	}
	switch event.Action {
	case a9trust.ControlActionUpsert:
		if event.Reason != a9trust.ControlReasonNone ||
			event.Assertion == nil {
			return false
		}
		assertion := event.Assertion
		return assertion.Hash == event.AssertionHash &&
			assertion.InstallationBindingID ==
				event.InstallationBindingID &&
			assertion.SequencerEpoch == event.SequencerEpoch &&
			assertion.StreamSequence == event.StreamSequence &&
			assertion.BindingID == event.BindingID &&
			assertion.BindingVersion == event.BindingVersion &&
			assertion.KeysetSequence == event.KeysetSequence &&
			assertion.KeysetHash == event.KeysetHash &&
			assertion.ExpiresAt.After(assertion.IssuedAt) &&
			assertion.ExpiresAt.Sub(assertion.IssuedAt) <=
				30*time.Second
	case a9trust.ControlActionRevoke:
		return event.Assertion == nil &&
			event.Reason >= a9trust.ControlReasonAuthorityRevoked &&
			event.Reason <= a9trust.ControlReasonAuthorityReplaced
	default:
		return false
	}
}

func (s *Store) validA9Watermark(
	watermark a9trust.VerifiedWatermark,
) bool {
	if s == nil || s.db == nil ||
		watermark.Environment != s.environment ||
		watermark.WatermarkSequence == 0 ||
		watermark.WatermarkSequence > a9MaxSafeInteger ||
		watermark.CommittedThroughStreamSequence > a9MaxSafeInteger ||
		watermark.KeysetSequence == 0 ||
		watermark.KeysetSequence > a9MaxSafeInteger ||
		watermark.ExpiresAt.IsZero() ||
		!watermark.ExpiresAt.After(watermark.IssuedAt) ||
		watermark.ExpiresAt.Sub(watermark.IssuedAt) > 30*time.Second {
		return false
	}
	switch watermark.Status {
	case a9trust.WatermarkStatusCurrent:
		return watermark.UncertaintyReason ==
			a9trust.WatermarkUncertaintyNone
	case a9trust.WatermarkStatusUncertain:
		return watermark.UncertaintyReason >=
			a9trust.WatermarkUncertaintySourceUnavailable &&
			watermark.UncertaintyReason <=
				a9trust.WatermarkUncertaintyClock
	default:
		return false
	}
}

func (s *Store) a9Result(
	installationBindingID [16]byte,
	epoch [16]byte,
	generation uint64,
	state int16,
	outcome int16,
	sequence uint64,
) a9api.Result {
	return a9api.Result{
		Environment:            s.environment,
		InstallationBindingID:  installationBindingID,
		SequencerEpoch:         epoch,
		SubscriptionGeneration: generation,
		State:                  decodeA9ResultState(state),
		Outcome:                decodeA9ResultOutcome(outcome),
		AcceptedStreamSequence: sequence,
	}
}

func encodeA9Result(result a9api.Result) (int16, int16, bool) {
	var outcome int16
	switch result.Outcome {
	case a9api.ResultOutcomeApplied:
		outcome = a9OutcomeApplied
	case a9api.ResultOutcomeReplay:
		outcome = a9OutcomeReplay
	case a9api.ResultOutcomeStale:
		outcome = a9OutcomeStale
	case a9api.ResultOutcomeGap:
		outcome = a9OutcomeGap
	case a9api.ResultOutcomeConflict:
		outcome = a9OutcomeConflict
	case a9api.ResultOutcomeInconclusive:
		outcome = a9OutcomeInconclusive
	default:
		return 0, 0, false
	}
	var state int16
	switch result.State {
	case a9api.ResultStateActive:
		state = a9ResultActive
	case a9api.ResultStateRevoked:
		state = a9ResultRevoked
	case a9api.ResultStateUncertain:
		state = a9ResultUncertain
	default:
		return 0, 0, false
	}
	return outcome, state, true
}

func decodeA9ResultState(value int16) a9api.ResultState {
	switch value {
	case a9ResultActive:
		return a9api.ResultStateActive
	case a9ResultRevoked:
		return a9api.ResultStateRevoked
	case a9ResultUncertain:
		return a9api.ResultStateUncertain
	default:
		return ""
	}
}

func decodeA9ResultOutcome(value int16) a9api.ResultOutcome {
	switch value {
	case a9OutcomeApplied:
		return a9api.ResultOutcomeApplied
	case a9OutcomeReplay:
		return a9api.ResultOutcomeReplay
	case a9OutcomeStale:
		return a9api.ResultOutcomeStale
	case a9OutcomeGap:
		return a9api.ResultOutcomeGap
	case a9OutcomeConflict:
		return a9api.ResultOutcomeConflict
	case a9OutcomeInconclusive:
		return a9api.ResultOutcomeInconclusive
	default:
		return ""
	}
}

func commitA9Result(
	tx *sql.Tx,
	result a9api.Result,
) (a9api.Result, error) {
	if tx == nil {
		return a9api.Result{}, ErrStoreUnavailable
	}
	if err := tx.Commit(); err != nil {
		return a9api.Result{}, storeDatabaseError(err)
	}
	return result, nil
}

func canonicalA9UUID(value [16]byte) string {
	encoded := hex.EncodeToString(value[:])
	return fmt.Sprintf(
		"%s-%s-%s-%s-%s",
		encoded[0:8],
		encoded[8:12],
		encoded[12:16],
		encoded[16:20],
		encoded[20:32],
	)
}
