package vault

import (
	"context"
	"database/sql"
)

// RequireRetentionSafe is the common fail-closed gate for registration,
// routing, and durable job creation. Revocation paths intentionally do not use
// it, because deletion authority must remain available during a privacy-control
// incident.
func (s *Store) RequireRetentionSafe(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrRetentionUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrRetentionUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrRetentionUnavailable
	}
	return nil
}

// requireRetentionSafeTx holds a shared lock on this environment's retention
// row until the caller commits or rolls back. The sweep's unsafe transition
// requires the conflicting row lock, so a route mutation either completes while
// shared state is still safe or observes the unsafe state and fails closed.
func (s *Store) requireRetentionSafeTx(
	ctx context.Context,
	tx *sql.Tx,
) error {
	if s == nil || tx == nil {
		return ErrRetentionUnavailable
	}
	if err := requireLookupKeyBoundTx(
		ctx,
		tx,
		s.lookup,
		s.environmentID,
	); err != nil {
		return ErrRetentionUnavailable
	}
	return s.requireRetentionSafeRow(
		tx.QueryRowContext(
			ctx,
			`SELECT last_started_at, last_completed_at, next_deadline_at,
			        is_safe, fixed_outcome
				   FROM hytch_push_vault.retention_state
				  WHERE environment = $1
				  FOR SHARE`,
			s.environmentID,
		),
	)
}

type retentionStateRow interface {
	Scan(dest ...any) error
}

func (s *Store) requireRetentionSafeRow(row retentionStateRow) error {
	if s == nil || row == nil {
		return ErrRetentionUnavailable
	}
	var (
		lastStarted   sql.NullTime
		lastCompleted sql.NullTime
		nextDeadline  sql.NullTime
		storedSafe    bool
		fixedOutcome  int16
	)
	if err := row.Scan(
		&lastStarted,
		&lastCompleted,
		&nextDeadline,
		&storedSafe,
		&fixedOutcome,
	); err != nil {
		return ErrRetentionUnavailable
	}
	health := retentionHealthFromState(
		s.now().UTC(),
		lastStarted,
		lastCompleted,
		nextDeadline,
		storedSafe,
		fixedOutcome,
	)
	if !health.Safe {
		return ErrRetentionUnsafe
	}
	return nil
}
