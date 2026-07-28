package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"time"
)

const (
	defaultRetentionSweepInterval = 15 * time.Minute
	maxRetentionSweepInterval     = time.Hour
	defaultRetentionRetryInitial  = 250 * time.Millisecond
	defaultRetentionRetryMaximum  = 30 * time.Second
	retentionDeadlineMargin       = 30 * time.Second
	retentionAdvisoryLockKeyBase  = int64(0x4859544348524500)

	retentionOutcomeUnsafe   int16 = 1
	retentionOutcomeComplete int16 = 2
)

var (
	ErrRetentionInvalid     = errors.New("retention configuration invalid")
	ErrRetentionUnavailable = errors.New("retention control unavailable")
	ErrRetentionBusy        = errors.New("retention sweep unavailable")
	ErrRetentionUnsafe      = errors.New("retention health unsafe")
)

type RetentionOptions struct {
	SweepInterval        time.Duration
	Environment          string
	Lookup               *LookupKey
	EncryptionKeyVersion uint32
	Now                  func() time.Time
}

type RetentionSweeper struct {
	db             *sql.DB
	sweepInterval  time.Duration
	environmentID  int16
	lookup         *LookupKey
	keyVersion     uint32
	now            func() time.Time
	retryInitial   time.Duration
	retryMaximum   time.Duration
	wait           func(context.Context, time.Duration) bool
	sweepOverride  func(context.Context) (*RetentionResult, error)
	healthOverride func(context.Context) (*RetentionHealth, error)
}

type RetentionResult struct {
	CompletedAt time.Time
	NextDueAt   time.Time
}

type RetentionHealth struct {
	Safe            bool
	LastStartedAt   *time.Time
	LastCompletedAt *time.Time
	NextDeadlineAt  *time.Time
	FixedOutcome    int16
}

func NewRetentionSweeper(
	db *sql.DB,
	options RetentionOptions,
) (*RetentionSweeper, error) {
	environmentID, environmentErr := encodeEnvironment(options.Environment)
	if db == nil || options.Lookup == nil ||
		options.EncryptionKeyVersion == 0 || environmentErr != nil {
		return nil, ErrRetentionInvalid
	}
	interval := options.SweepInterval
	if interval == 0 {
		interval = defaultRetentionSweepInterval
	}
	if interval < time.Minute || interval > maxRetentionSweepInterval {
		return nil, ErrRetentionInvalid
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &RetentionSweeper{
		db:            db,
		sweepInterval: interval,
		environmentID: environmentID,
		lookup:        options.Lookup,
		keyVersion:    options.EncryptionKeyVersion,
		now:           now,
		retryInitial:  defaultRetentionRetryInitial,
		retryMaximum:  defaultRetentionRetryMaximum,
		wait:          waitForRetentionAttempt,
	}, nil
}

// EnsureReady waits for either this replica or another lock-holding replica to
// establish a current safe retention deadline. The caller should bound ctx so a
// startup dependency failure becomes a visible process failure.
func (s *RetentionSweeper) EnsureReady(
	ctx context.Context,
) (readyErr error) {
	defer func() {
		if recover() != nil {
			readyErr = ErrRetentionUnavailable
		}
	}()
	if s == nil || s.db == nil {
		return ErrRetentionUnavailable
	}
	retryDelay := s.initialRetryDelay()
	for {
		if _, healthy := s.sharedHealthyDelay(ctx); healthy {
			return nil
		}
		if _, err := s.runSweep(ctx); err == nil {
			return nil
		} else if errors.Is(err, ErrRetentionBusy) {
			// Advisory-lock contention is normal during rolling deploys. The
			// lock owner is authoritative only after it publishes a current
			// safe deadline, so keep waiting while shared state is unsafe.
			if _, healthy := s.sharedHealthyDelay(ctx); healthy {
				return nil
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !s.waitForAttempt(ctx, retryDelay) {
			if err := ctx.Err(); err != nil {
				return err
			}
			return ErrRetentionUnavailable
		}
		retryDelay = nextRetentionRetry(
			retryDelay,
			s.maximumRetryDelay(),
		)
	}
}

// Run keeps the retention deadline current. Transient database failures and
// advisory-lock contention never silently stop the worker. Failed or overdue
// sweeps remain visible through Ready while this loop retries with capped
// backoff.
func (s *RetentionSweeper) Run(
	ctx context.Context,
) (runErr error) {
	defer func() {
		if recover() != nil {
			runErr = ErrRetentionUnavailable
		}
	}()
	if s == nil || s.db == nil {
		return ErrRetentionUnavailable
	}
	delay, healthy := s.sharedHealthyDelay(ctx)
	if !healthy {
		delay = 0
	}
	retryDelay := s.initialRetryDelay()
	for {
		if !s.waitForAttempt(ctx, delay) {
			return nil
		}
		// A contending replica may have completed while this worker backed
		// off. Honor its newly published deadline instead of immediately
		// performing a redundant second sweep.
		if sharedDelay, sharedHealthy := s.sharedHealthyDelay(ctx); sharedHealthy &&
			sharedDelay > 0 {
			retryDelay = s.initialRetryDelay()
			delay = sharedDelay
			continue
		}
		result, err := s.runSweep(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			retryDelay = s.initialRetryDelay()
			delay = s.delayUntilNextSweep(result.NextDueAt)
			continue
		}
		if errors.Is(err, ErrRetentionBusy) {
			if sharedDelay, sharedHealthy := s.sharedHealthyDelay(ctx); sharedHealthy {
				if sharedDelay > 0 {
					retryDelay = s.initialRetryDelay()
					delay = sharedDelay
				} else {
					delay = retryDelay
					retryDelay = nextRetentionRetry(
						retryDelay,
						s.maximumRetryDelay(),
					)
				}
				continue
			}
		}
		delay = retryDelay
		retryDelay = nextRetentionRetry(
			retryDelay,
			s.maximumRetryDelay(),
		)
	}
}

func (s *RetentionSweeper) runSweep(
	ctx context.Context,
) (*RetentionResult, error) {
	if s.sweepOverride != nil {
		return s.sweepOverride(ctx)
	}
	return s.Sweep(ctx)
}

func (s *RetentionSweeper) runHealth(
	ctx context.Context,
) (*RetentionHealth, error) {
	if s.healthOverride != nil {
		return s.healthOverride(ctx)
	}
	return s.Health(ctx)
}

func (s *RetentionSweeper) sharedHealthyDelay(
	ctx context.Context,
) (time.Duration, bool) {
	health, err := s.runHealth(ctx)
	if err != nil || !health.Safe || health.NextDeadlineAt == nil {
		return 0, false
	}
	return s.delayUntilNextSweep(*health.NextDeadlineAt), true
}

func (s *RetentionSweeper) delayUntilNextSweep(
	deadline time.Time,
) time.Duration {
	margin := retentionDeadlineMargin
	if maximumMargin := s.sweepInterval / 2; margin > maximumMargin {
		margin = maximumMargin
	}
	delay := deadline.Sub(s.now().UTC()) - margin
	if delay < 0 {
		return 0
	}
	return delay
}

func (s *RetentionSweeper) initialRetryDelay() time.Duration {
	if s.retryInitial <= 0 {
		return defaultRetentionRetryInitial
	}
	return s.retryInitial
}

func (s *RetentionSweeper) maximumRetryDelay() time.Duration {
	if s.retryMaximum < s.initialRetryDelay() {
		return s.initialRetryDelay()
	}
	return s.retryMaximum
}

func (s *RetentionSweeper) waitForAttempt(
	ctx context.Context,
	delay time.Duration,
) bool {
	if s.wait != nil {
		return s.wait(ctx, delay)
	}
	return waitForRetentionAttempt(ctx, delay)
}

func waitForRetentionAttempt(
	ctx context.Context,
	delay time.Duration,
) bool {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextRetentionRetry(
	current time.Duration,
	maximum time.Duration,
) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func retentionAdvisoryLockKey(environmentID int16) int64 {
	return retentionAdvisoryLockKeyBase + int64(environmentID)
}

// Sweep physically removes expired ciphertext and privacy records. It marks
// retention unsafe before any destructive work, so a partial or failed sweep
// cannot leave the service reporting a stale healthy state.
func (s *RetentionSweeper) Sweep(ctx context.Context) (*RetentionResult, error) {
	if s == nil || s.db == nil {
		return nil, ErrRetentionUnavailable
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, ErrRetentionUnavailable
	}
	defer func() {
		_ = conn.Close()
	}()

	var locked bool
	if err = conn.QueryRowContext(
		ctx,
		`SELECT pg_try_advisory_lock($1)`,
		retentionAdvisoryLockKey(s.environmentID),
	).Scan(&locked); err != nil {
		return nil, ErrRetentionUnavailable
	}
	if !locked {
		return nil, ErrRetentionBusy
	}
	defer func() {
		unlockContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = conn.ExecContext(
			unlockContext,
			`SELECT pg_advisory_unlock($1)`,
			retentionAdvisoryLockKey(s.environmentID),
		)
	}()

	startedAt := s.now().UTC()
	result, err := conn.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.retention_state
			 SET last_started_at = $2,
			     is_safe = FALSE,
			     fixed_outcome = $3
			 WHERE environment = $1`,
		s.environmentID,
		startedAt,
		retentionOutcomeUnsafe,
	)
	if err != nil {
		return nil, ErrRetentionUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return nil, ErrRetentionUnavailable
	}

	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, ErrRetentionUnavailable
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err = requireLookupKeyBoundTx(
		ctx,
		tx,
		s.lookup,
		s.environmentID,
	); err != nil {
		return nil, ErrRetentionUnavailable
	}
	if err = s.deleteExpiredVaultRows(ctx, tx, startedAt); err != nil {
		return nil, err
	}

	completedAt := s.now().UTC()
	nextDeadlineAt := completedAt.Add(s.sweepInterval)
	var overdueErasure bool
	if err = tx.QueryRowContext(
		ctx,
		`SELECT EXISTS (
		   SELECT 1
		     FROM hytch_push_vault.delivery_jobs
			    WHERE state IN ($1, $2)
			      AND created_at + INTERVAL '15 minutes' <= $3
			      AND environment = $4
			 )`,
		erasureJobPending,
		erasureJobClaimed,
		completedAt,
		s.environmentID,
	).Scan(&overdueErasure); err != nil {
		return nil, ErrRetentionUnavailable
	}
	if overdueErasure {
		result, err = tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.retention_state
				 SET last_completed_at = $2,
				     next_deadline_at = $3,
				     is_safe = FALSE,
				     fixed_outcome = $4
				 WHERE environment = $1`,
			s.environmentID,
			completedAt,
			nextDeadlineAt,
			retentionOutcomeUnsafe,
		)
		if err != nil {
			return nil, ErrRetentionUnavailable
		}
		affected, err = result.RowsAffected()
		if err != nil || affected != 1 {
			return nil, ErrRetentionUnavailable
		}
		if err = tx.Commit(); err != nil {
			return nil, ErrRetentionUnavailable
		}
		return nil, ErrRetentionUnsafe
	}
	result, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.retention_state
			 SET last_completed_at = $2,
			     next_deadline_at = $3,
			     is_safe = TRUE,
			     fixed_outcome = $4
			 WHERE environment = $1`,
		s.environmentID,
		completedAt,
		nextDeadlineAt,
		retentionOutcomeComplete,
	)
	if err != nil {
		return nil, ErrRetentionUnavailable
	}
	affected, err = result.RowsAffected()
	if err != nil || affected != 1 {
		return nil, ErrRetentionUnavailable
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrRetentionUnavailable
	}
	return &RetentionResult{
		CompletedAt: completedAt,
		NextDueAt:   nextDeadlineAt,
	}, nil
}

func (s *RetentionSweeper) deleteExpiredVaultRows(
	ctx context.Context,
	tx *sql.Tx,
	now time.Time,
) error {
	if err := s.tombstoneExpiredLeases(ctx, tx, now); err != nil {
		return err
	}
	if err := s.tombstoneExpiredInstallations(ctx, tx, now); err != nil {
		return err
	}
	finalizer := &Store{
		db:              s.db,
		environmentID:   s.environmentID,
		now:             s.now,
		aggregateRandom: rand.Reader,
	}
	if err := finalizer.markExpiredDeliveryJobsTx(
		ctx,
		tx,
		now,
	); err != nil {
		return ErrRetentionUnavailable
	}
	if err := s.markExpiringAuthorityDeliveryJobs(
		ctx,
		tx,
		now,
		finalizer,
	); err != nil {
		return err
	}
	if err := finalizer.completeDeliveryMarkersTx(ctx, tx); err != nil {
		return ErrRetentionUnavailable
	}
	statements := []string{
		`DELETE FROM hytch_push_vault.delivery_dedupes
		 WHERE expires_at <= $1
		   AND environment = $2`,
		`DELETE FROM hytch_push_vault.route_key_history
		 WHERE expires_at <= $1
		   AND environment = $2`,
		`DELETE FROM hytch_push_vault.welcome_authorizations
		 WHERE expires_at <= $1
		   AND environment = $2`,
		`DELETE FROM hytch_push_vault.welcome_budgets
		 WHERE expires_at <= $1
		   AND environment = $2`,
		`DELETE FROM hytch_push_vault.subscription_leases
		 WHERE expires_at <= $1
		   AND environment = $2`,
		`DELETE FROM hytch_push_vault.installation_states
		 WHERE expires_at <= $1
		   AND environment = $2`,
		`DELETE FROM hytch_push_vault.deletion_tombstones
		 WHERE expires_at <= $1
		   AND environment = $2`,
		`DELETE FROM hytch_push_vault.operational_aggregates
		 WHERE environment = $2
		   AND (
		     expires_on <= $1::date
		     OR bucket_day <= ($1::date - 30)
		   )`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(
			ctx,
			statement,
			now,
			s.environmentID,
		); err != nil {
			return ErrRetentionUnavailable
		}
	}
	var accessAuditPurgeQuery string
	switch s.environmentID {
	case environmentDevelopment:
		accessAuditPurgeQuery =
			`SELECT hytch_push_vault.` +
				`purge_expired_access_audit_development()`
	case environmentProduction:
		accessAuditPurgeQuery =
			`SELECT hytch_push_vault.` +
				`purge_expired_access_audit_production()`
	default:
		return ErrRetentionUnavailable
	}
	var purgedAccessAuditRows int64
	if err := tx.QueryRowContext(
		ctx,
		accessAuditPurgeQuery,
	).Scan(&purgedAccessAuditRows); err != nil ||
		purgedAccessAuditRows < 0 {
		return ErrRetentionUnavailable
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.access_requests AS request
		 WHERE request.coarse_created_hour <=
		       ($1::timestamptz - INTERVAL '180 days')
		   AND request.environment = $2
		   AND NOT EXISTS (
		       SELECT 1
		       FROM hytch_push_vault.access_audit AS audit
		       WHERE audit.request_id = request.request_id
		         AND audit.environment = $2
		   )`,
		now,
		s.environmentID,
	); err != nil {
		return ErrRetentionUnavailable
	}
	return nil
}

func (s *RetentionSweeper) markExpiringAuthorityDeliveryJobs(
	ctx context.Context,
	tx *sql.Tx,
	now time.Time,
	finalizer *Store,
) error {
	rows, err := tx.QueryContext(
		ctx,
		`SELECT lease_id
		   FROM hytch_push_vault.subscription_leases
		  WHERE expires_at <= $1
		    AND environment = $2
		  FOR UPDATE`,
		now,
		s.environmentID,
	)
	if err != nil {
		return ErrRetentionUnavailable
	}
	var leaseIDs [][]byte
	for rows.Next() {
		var leaseID []byte
		if err = rows.Scan(&leaseID); err != nil {
			_ = rows.Close()
			return ErrRetentionUnavailable
		}
		leaseIDs = append(leaseIDs, leaseID)
	}
	if err = rows.Close(); err != nil {
		return ErrRetentionUnavailable
	}
	if err = rows.Err(); err != nil {
		return ErrRetentionUnavailable
	}
	for _, leaseID := range leaseIDs {
		if err = finalizer.markDeliveryJobsSafetyForLeaseTx(
			ctx,
			tx,
			leaseID,
		); err != nil {
			return ErrRetentionUnavailable
		}
	}

	rows, err = tx.QueryContext(
		ctx,
		`SELECT installation_lookup
		   FROM hytch_push_vault.installation_states
		  WHERE expires_at <= $1
		    AND environment = $2
		  FOR UPDATE`,
		now,
		s.environmentID,
	)
	if err != nil {
		return ErrRetentionUnavailable
	}
	var installationLookups [][]byte
	for rows.Next() {
		var installationLookup []byte
		if err = rows.Scan(&installationLookup); err != nil {
			_ = rows.Close()
			return ErrRetentionUnavailable
		}
		installationLookups = append(
			installationLookups,
			installationLookup,
		)
	}
	if err = rows.Close(); err != nil {
		return ErrRetentionUnavailable
	}
	if err = rows.Err(); err != nil {
		return ErrRetentionUnavailable
	}
	for _, installationLookup := range installationLookups {
		if err = finalizer.markDeliveryJobsSafetyForInstallationTx(
			ctx,
			tx,
			installationLookup,
			nil,
		); err != nil {
			return ErrRetentionUnavailable
		}
	}
	return nil
}

func (s *RetentionSweeper) tombstoneExpiredLeases(
	ctx context.Context,
	tx *sql.Tx,
	now time.Time,
) error {
	rows, err := tx.QueryContext(
		ctx,
		`SELECT route_identity, route_key_epoch, encryption_key_version
			 FROM hytch_push_vault.subscription_leases
			 WHERE expires_at <= $1
			   AND environment = $2
			 FOR UPDATE`,
		now,
		s.environmentID,
	)
	if err != nil {
		return ErrRetentionUnavailable
	}
	type expiredLease struct {
		routeIdentity        []byte
		routeKeyEpoch        int64
		encryptionKeyVersion int64
	}
	var leases []expiredLease
	for rows.Next() {
		var lease expiredLease
		if err = rows.Scan(
			&lease.routeIdentity,
			&lease.routeKeyEpoch,
			&lease.encryptionKeyVersion,
		); err != nil {
			_ = rows.Close()
			return ErrRetentionUnavailable
		}
		leases = append(leases, lease)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return ErrRetentionUnavailable
	}
	if err = rows.Close(); err != nil {
		return ErrRetentionUnavailable
	}
	for _, lease := range leases {
		if len(lease.routeIdentity) != 32 ||
			lease.routeKeyEpoch <= 0 ||
			lease.routeKeyEpoch > maxRouteKeyEpoch ||
			lease.encryptionKeyVersion <= 0 ||
			lease.encryptionKeyVersion >
				int64(maxDeletionTombstoneKeyVersion) {
			return ErrRetentionUnavailable
		}
		if err = retireRouteKeyHistory(
			ctx,
			tx,
			s.environmentID,
			lease.routeIdentity,
			uint32(lease.routeKeyEpoch),
			now,
		); err != nil {
			return ErrRetentionUnavailable
		}
		if err = upsertDeletionTombstone(
			ctx,
			tx,
			s.environmentID,
			deletionTargetRoute,
			lease.routeIdentity,
			uint32(lease.encryptionKeyVersion),
			uint64(lease.routeKeyEpoch),
			now,
		); err != nil {
			return ErrRetentionUnavailable
		}
	}
	return nil
}

func (s *RetentionSweeper) tombstoneExpiredInstallations(
	ctx context.Context,
	tx *sql.Tx,
	now time.Time,
) error {
	rows, err := tx.QueryContext(
		ctx,
		`SELECT installation_identity, policy_epoch, encryption_key_version
			   FROM hytch_push_vault.installation_states
			  WHERE expires_at <= $1
			    AND environment = $2
			  FOR UPDATE`,
		now,
		s.environmentID,
	)
	if err != nil {
		return ErrRetentionUnavailable
	}
	type expiredInstallation struct {
		identity             []byte
		policyEpoch          int64
		encryptionKeyVersion int64
	}
	var installations []expiredInstallation
	for rows.Next() {
		var installation expiredInstallation
		if err = rows.Scan(
			&installation.identity,
			&installation.policyEpoch,
			&installation.encryptionKeyVersion,
		); err != nil {
			_ = rows.Close()
			return ErrRetentionUnavailable
		}
		installations = append(installations, installation)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return ErrRetentionUnavailable
	}
	if err = rows.Close(); err != nil {
		return ErrRetentionUnavailable
	}
	for _, installation := range installations {
		if len(installation.identity) != 32 ||
			installation.policyEpoch <= 0 ||
			uint64(installation.policyEpoch) >
				maxInstallationTombstoneFenceEpoch ||
			installation.encryptionKeyVersion <= 0 ||
			installation.encryptionKeyVersion >
				int64(maxDeletionTombstoneKeyVersion) {
			return ErrRetentionUnavailable
		}
		if err = upsertDeletionTombstone(
			ctx,
			tx,
			s.environmentID,
			deletionTargetInstallation,
			installation.identity,
			uint32(installation.encryptionKeyVersion),
			uint64(installation.policyEpoch),
			now,
		); err != nil {
			return ErrRetentionUnavailable
		}
	}
	return nil
}

func (s *RetentionSweeper) Health(ctx context.Context) (*RetentionHealth, error) {
	if s == nil || s.db == nil {
		return nil, ErrRetentionUnavailable
	}
	tx, err := s.db.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelReadCommitted},
	)
	if err != nil {
		return nil, ErrRetentionUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if err = requireLookupKeyBoundTx(
		ctx,
		tx,
		s.lookup,
		s.environmentID,
	); err != nil {
		return nil, ErrRetentionUnavailable
	}
	var (
		lastStarted   sql.NullTime
		lastCompleted sql.NullTime
		nextDeadline  sql.NullTime
		storedSafe    bool
		fixedOutcome  int16
	)
	err = tx.QueryRowContext(
		ctx,
		`SELECT last_started_at, last_completed_at, next_deadline_at,
			        is_safe, fixed_outcome
			 FROM hytch_push_vault.retention_state
			 WHERE environment = $1`,
		s.environmentID,
	).Scan(
		&lastStarted,
		&lastCompleted,
		&nextDeadline,
		&storedSafe,
		&fixedOutcome,
	)
	if err != nil {
		return nil, ErrRetentionUnavailable
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrRetentionUnavailable
	}
	health := retentionHealthFromState(
		s.now().UTC(),
		lastStarted,
		lastCompleted,
		nextDeadline,
		storedSafe,
		fixedOutcome,
	)
	return &health, nil
}

func (s *RetentionSweeper) Ready(ctx context.Context) error {
	health, err := s.Health(ctx)
	if err != nil {
		return err
	}
	if !health.Safe {
		return ErrRetentionUnsafe
	}
	return nil
}

func retentionHealthFromState(
	now time.Time,
	lastStarted sql.NullTime,
	lastCompleted sql.NullTime,
	nextDeadline sql.NullTime,
	storedSafe bool,
	fixedOutcome int16,
) RetentionHealth {
	health := RetentionHealth{
		Safe:         storedSafe,
		FixedOutcome: fixedOutcome,
	}
	if lastStarted.Valid {
		value := lastStarted.Time.UTC()
		health.LastStartedAt = &value
	}
	if lastCompleted.Valid {
		value := lastCompleted.Time.UTC()
		health.LastCompletedAt = &value
	}
	if nextDeadline.Valid {
		value := nextDeadline.Time.UTC()
		health.NextDeadlineAt = &value
	}
	if !lastCompleted.Valid ||
		!nextDeadline.Valid ||
		!now.Before(nextDeadline.Time) ||
		(lastStarted.Valid && lastStarted.Time.After(lastCompleted.Time)) ||
		fixedOutcome != retentionOutcomeComplete {
		health.Safe = false
	}
	return health
}
