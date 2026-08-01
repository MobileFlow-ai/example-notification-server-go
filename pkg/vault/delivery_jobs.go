package vault

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
)

const (
	MaxDeliveryAttempts = 3

	deliveryJobPending int16 = 1
	deliveryJobClaimed int16 = 2
	erasureJobPending  int16 = 3
	erasureJobClaimed  int16 = 4
	deliveryJobFinal   int16 = 5

	maxDeliveryJobLifetime                 = 15 * time.Minute
	deliveryQueueLockID                    = int64(0x48595443484a4f42)
	maxErasureRetryExponent                = 16
	retentionDeliveryFinalizationBatchSize = 128
)

var (
	ErrDeliveryJobInvalid          = errors.New("delivery job invalid")
	ErrDeliveryQueueFull           = errors.New("delivery queue full")
	ErrDeliveryQueueUnavailable    = errors.New("delivery queue unavailable")
	ErrDeliveryFinalizationPending = errors.New(
		"delivery finalization pending",
	)
)

// SerializedDeliveryJob is the exact APNS request material persisted for
// bounded retry. The implementation encrypts the entire value before it
// reaches PostgreSQL; callers must never log or otherwise serialize it.
type SerializedDeliveryJob struct {
	DeviceToken            string               `json:"device_token"`
	Topic                  string               `json:"topic"`
	ProviderTopic          []byte               `json:"provider_topic,omitempty"`
	Payload                []byte               `json:"payload"`
	PushType               string               `json:"push_type"`
	Priority               int                  `json:"priority"`
	Expiration             time.Time            `json:"expiration"`
	TrafficClass           DeliveryTrafficClass `json:"traffic_class"`
	PolicyEpoch            uint64               `json:"policy_epoch"`
	RouteKeyEpoch          uint32               `json:"route_key_epoch"`
	NoncePrefix            uint32               `json:"nonce_prefix"`
	DeliverySequence       uint64               `json:"delivery_sequence"`
	AliasDay               string               `json:"alias_day"`
	RouteAlias             []byte               `json:"route_alias"`
	WelcomeAuthorizationID []byte                      `json:"welcome_authorization_id,omitempty"`
	WelcomeEnvelopeDigest  []byte                      `json:"welcome_envelope_digest,omitempty"`
	A9                     *interfaces.A9RouteSnapshot `json:"a9,omitempty"`
	EraseOnly              bool                        `json:"erase_only,omitempty"`
}

type DeliveryTrafficClass uint8

const (
	DeliveryTrafficUnknown DeliveryTrafficClass = iota
	DeliveryTrafficConversation
	DeliveryTrafficWelcome DeliveryTrafficClass = 2
)

// DeliveryFinalReason is persisted as a fixed enum before delivery material is
// removed. It is deliberately incapable of carrying APNS provider text,
// identifiers, or any other free-form value.
type DeliveryFinalReason uint8

const (
	DeliveryFinalTerminalRejected DeliveryFinalReason = iota + 1
	DeliveryFinalRetryExhausted
	DeliveryFinalTTLExpired
	DeliveryFinalSafetyInvalidated
	DeliveryFinalMaterialInvalid
)

type ClaimedDeliveryJob struct {
	JobID              []byte
	LeaseID            []byte
	InstallationLookup []byte
	Job                SerializedDeliveryJob
	Attempts           int
	RetryExponent      int
	ExpiresAt          time.Time
}

type a9DeliverySnapshotRow struct {
	installationBindingID  []byte
	sequencerEpoch         []byte
	subscriptionGeneration sql.NullInt64
	bindingID               []byte
	bindingVersion          sql.NullInt64
	assertionHash           []byte
	assertionStreamSequence sql.NullInt64
	topicKeyEpoch           sql.NullInt64
	topicBinding            []byte
	routeKeyEpoch           sql.NullInt64
	keysetSequence          sql.NullInt64
	keysetHash              []byte
	watermarkSequence       sql.NullInt64
}

func (row *a9DeliverySnapshotRow) scanDestinations() []any {
	return []any{
		&row.installationBindingID,
		&row.sequencerEpoch,
		&row.subscriptionGeneration,
		&row.bindingID,
		&row.bindingVersion,
		&row.assertionHash,
		&row.assertionStreamSequence,
		&row.topicKeyEpoch,
		&row.topicBinding,
		&row.routeKeyEpoch,
		&row.keysetSequence,
		&row.keysetHash,
		&row.watermarkSequence,
	}
}

func (row a9DeliverySnapshotRow) empty() bool {
	return len(row.installationBindingID) == 0 &&
		len(row.sequencerEpoch) == 0 &&
		!row.subscriptionGeneration.Valid &&
		len(row.bindingID) == 0 &&
		!row.bindingVersion.Valid &&
		len(row.assertionHash) == 0 &&
		!row.assertionStreamSequence.Valid &&
		!row.topicKeyEpoch.Valid &&
		len(row.topicBinding) == 0 &&
		!row.routeKeyEpoch.Valid &&
		!row.keysetSequence.Valid &&
		len(row.keysetHash) == 0 &&
		!row.watermarkSequence.Valid
}

func (row a9DeliverySnapshotRow) complete() bool {
	return len(row.installationBindingID) == 16 &&
		len(row.sequencerEpoch) == 16 &&
		row.subscriptionGeneration.Valid &&
		row.subscriptionGeneration.Int64 > 0 &&
		uint64(row.subscriptionGeneration.Int64) <= a9MaxSafeInteger &&
		len(row.bindingID) == 16 &&
		row.bindingVersion.Valid &&
		row.bindingVersion.Int64 > 0 &&
		uint64(row.bindingVersion.Int64) <= a9MaxSafeInteger &&
		len(row.assertionHash) == 32 &&
		row.assertionStreamSequence.Valid &&
		row.assertionStreamSequence.Int64 > 0 &&
		uint64(row.assertionStreamSequence.Int64) <= a9MaxSafeInteger &&
		row.topicKeyEpoch.Valid &&
		row.topicKeyEpoch.Int64 > 0 &&
		uint64(row.topicKeyEpoch.Int64) <= uint64(^uint32(0)) &&
		len(row.topicBinding) == 32 &&
		row.routeKeyEpoch.Valid &&
		row.routeKeyEpoch.Int64 > 0 &&
		uint64(row.routeKeyEpoch.Int64) <= uint64(^uint32(0)) &&
		row.keysetSequence.Valid &&
		row.keysetSequence.Int64 > 0 &&
		uint64(row.keysetSequence.Int64) <= a9MaxSafeInteger &&
		len(row.keysetHash) == 32 &&
		row.watermarkSequence.Valid &&
		row.watermarkSequence.Int64 > 0 &&
		uint64(row.watermarkSequence.Int64) <= a9MaxSafeInteger
}

func (row a9DeliverySnapshotRow) matches(
	snapshot *interfaces.A9RouteSnapshot,
) bool {
	return snapshot != nil &&
		row.complete() &&
		subtle.ConstantTimeCompare(
			row.installationBindingID,
			snapshot.InstallationBindingID[:],
		) == 1 &&
		subtle.ConstantTimeCompare(
			row.sequencerEpoch,
			snapshot.SequencerEpoch[:],
		) == 1 &&
		uint64(row.subscriptionGeneration.Int64) ==
			snapshot.SubscriptionGeneration &&
		subtle.ConstantTimeCompare(
			row.bindingID,
			snapshot.BindingID[:],
		) == 1 &&
		uint64(row.bindingVersion.Int64) == snapshot.BindingVersion &&
		subtle.ConstantTimeCompare(
			row.assertionHash,
			snapshot.AssertionHash[:],
		) == 1 &&
		uint64(row.assertionStreamSequence.Int64) ==
			snapshot.AssertionStreamSequence &&
		uint64(row.topicKeyEpoch.Int64) == uint64(snapshot.TopicKeyEpoch) &&
		subtle.ConstantTimeCompare(
			row.topicBinding,
			snapshot.TopicBinding[:],
		) == 1 &&
		uint64(row.routeKeyEpoch.Int64) == uint64(snapshot.RouteKeyEpoch) &&
		uint64(row.keysetSequence.Int64) == snapshot.KeysetSequence &&
		subtle.ConstantTimeCompare(
			row.keysetHash,
			snapshot.KeysetHash[:],
		) == 1 &&
		uint64(row.watermarkSequence.Int64) == snapshot.WatermarkSequence
}

type DeliveryAttemptOutcome uint8

const (
	DeliveryAttemptSent DeliveryAttemptOutcome = iota + 1
	DeliveryAttemptTransient
	DeliveryAttemptInvalidToken
	DeliveryAttemptRejected
)

type DeliveryAttemptResult struct {
	Outcome DeliveryAttemptOutcome
	RetryAt time.Time
}

// DeliveryAttemptGuard holds the retention, job, route-authority, and
// installation-token locks acquired immediately before APNS egress. The
// worker records the attempt only after it has invoked APNS; Release rolls the
// reservation back without spending an attempt.
type DeliveryAttemptGuard interface {
	Complete(
		ctx context.Context,
		result DeliveryAttemptResult,
	) error
	RecordAttempt(ctx context.Context) error
	Release() error
}

// DeliveryJobStore is deliberately narrow so the APNS worker can be tested
// without receiving access to any other vault data.
type DeliveryJobStore interface {
	EnqueueDeliveryJob(
		ctx context.Context,
		leaseID []byte,
		job SerializedDeliveryJob,
		sourceEventID string,
		maxQueued int,
	) ([]byte, error)
	RecoverDeliveryJobs(ctx context.Context) error
	ClaimDeliveryJobs(
		ctx context.Context,
		limit int,
		claimTTL time.Duration,
	) ([]ClaimedDeliveryJob, error)
	AcquireDeliveryAttempt(
		ctx context.Context,
		job ClaimedDeliveryJob,
	) (DeliveryAttemptGuard, bool, error)
	ValidateDeliveryClaim(
		ctx context.Context,
		job ClaimedDeliveryJob,
	) (bool, error)
	RescheduleDeliveryJob(
		ctx context.Context,
		jobID []byte,
		attempts int,
		availableAt time.Time,
	) error
	ConvertInvalidTokenToErasure(
		ctx context.Context,
		jobID []byte,
		failedDeviceToken string,
		trafficClass DeliveryTrafficClass,
		availableAt time.Time,
	) ([]byte, error)
	FinalizeDeliveryJob(
		ctx context.Context,
		jobID []byte,
		reason DeliveryFinalReason,
	) error
	ReleaseDeliveryJob(ctx context.Context, jobID []byte) error
}

// InvalidTokenErasureStore is independent of APNS egress. Its deletion-only
// worker must remain available while retention is unsafe and when APNS is
// disabled.
type InvalidTokenErasureStore interface {
	RecoverInvalidTokenErasures(ctx context.Context) error
	ClaimErasureJobs(
		ctx context.Context,
		limit int,
		claimTTL time.Duration,
	) ([]ClaimedDeliveryJob, error)
	RescheduleInvalidTokenErasure(
		ctx context.Context,
		jobID []byte,
		availableAt time.Time,
	) error
	ReleaseDeliveryJob(ctx context.Context, jobID []byte) error
	DeleteErasureJob(ctx context.Context, jobID []byte) error
}

type InvalidAPNSTokenEraser interface {
	EraseInvalidAPNSToken(
		ctx context.Context,
		installationLookup []byte,
		failedDeviceToken string,
	) error
}

func (s *Store) EnqueueDeliveryJob(
	ctx context.Context,
	leaseID []byte,
	job SerializedDeliveryJob,
	sourceEventID string,
	maxQueued int,
) ([]byte, error) {
	const maxSerializationAttempts = 3
	for attempt := 0; attempt < maxSerializationAttempts; attempt++ {
		jobID, err := s.enqueueDeliveryJobOnce(
			ctx,
			leaseID,
			job,
			sourceEventID,
			maxQueued,
		)
		if err == nil || !isSerializationFailure(err) {
			return jobID, err
		}
		if attempt+1 == maxSerializationAttempts {
			break
		}
		delay := time.Duration(attempt+1) * 10 * time.Millisecond
		select {
		case <-ctx.Done():
			return nil, ErrDeliveryQueueUnavailable
		case <-time.After(delay):
		}
	}
	return nil, ErrDeliveryQueueUnavailable
}

func (s *Store) enqueueDeliveryJobOnce(
	ctx context.Context,
	leaseID []byte,
	job SerializedDeliveryJob,
	sourceEventID string,
	maxQueued int,
) ([]byte, error) {
	if s == nil || s.db == nil || s.encryption == nil || s.lookup == nil ||
		len(leaseID) != 16 || len(sourceEventID) == 0 ||
		len(sourceEventID) > 512 || maxQueued <= 0 {
		return nil, ErrDeliveryJobInvalid
	}
	now := s.now().UTC()
	if err := validateSerializedDeliveryJob(job, now); err != nil {
		return nil, err
	}
	if s.a9Enabled != (job.A9 != nil) {
		return nil, ErrDeliveryJobInvalid
	}
	if err := s.RequireRetentionSafe(ctx); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if err := s.RecoverDeliveryJobs(ctx); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	var topicBindingLease a9trust.TopicBindingLease
	if s.a9Enabled {
		if s.a9Trust == nil {
			return nil, ErrDeliveryQueueUnavailable
		}
		var acquireErr error
		topicBindingLease, acquireErr =
			s.a9Trust.AcquireTopicBindingLease(
				ctx,
				now,
				job.A9.KeysetSequence,
				job.A9.KeysetHash,
			)
		if acquireErr != nil || topicBindingLease == nil {
			return nil, ErrDeliveryQueueUnavailable
		}
		defer func() {
			if topicBindingLease != nil {
				topicBindingLease.Close()
			}
		}()
	}
	expiresAt := job.Expiration.UTC()
	if maximum := now.Add(maxDeliveryJobLifetime); expiresAt.After(maximum) {
		expiresAt = maximum
		job.Expiration = maximum
	}
	jobID := make([]byte, 16)
	if _, err := io.ReadFull(s.random, jobID); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, deliveryQueueDatabaseError(err)
	}
	defer func() { _ = tx.Rollback() }()
	var currentA9Route a9CurrentRouteState
	if s.a9Enabled {
		var current bool
		currentA9Route, current, err = s.requireA9CurrentRouteTx(
			ctx,
			tx,
			leaseID,
			job.A9,
		)
		if err != nil {
			return nil, ErrDeliveryQueueUnavailable
		}
		if !current {
			return nil, ErrDeliveryJobInvalid
		}
		if !a9TrustClockAligned(now, currentA9Route.databaseNow) {
			return nil, ErrDeliveryQueueUnavailable
		}
		recomputed, verdict := topicBindingLease.TopicBindingForEpoch(
			ctx,
			job.ProviderTopic,
			job.A9.TopicKeyEpoch,
			now,
			job.A9.AssertionExpiresAt,
			true,
		)
		if !verdict.IsEligible() ||
			!a9trust.EqualBinding(recomputed, job.A9.TopicBinding[:]) {
			clear(recomputed)
			return nil, ErrDeliveryJobInvalid
		}
		clear(recomputed)
		topicBindingLease.Close()
		topicBindingLease = nil
		defer zero(currentA9Route.installationIdentity)
	} else if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`SELECT pg_advisory_xact_lock($1)`,
		deliveryQueueLockID+int64(s.environmentID),
	); err != nil {
		return nil, deliveryQueueDatabaseError(err)
	}
	var expectedTopicKind int16
	var expectedPushMode int16
	var expectedLeaseState int16
	switch job.TrafficClass {
	case DeliveryTrafficConversation:
		expectedTopicKind = topicConversation
		expectedPushMode = pushAlert
		expectedLeaseState = stateActive
	case DeliveryTrafficWelcome:
		if !s.welcomeEnabled {
			return nil, ErrDeliveryQueueUnavailable
		}
		expectedTopicKind = topicWelcome
		expectedPushMode = pushSuppressed
		expectedLeaseState = stateSuppressed
	default:
		return nil, ErrDeliveryJobInvalid
	}
	var (
		authorityExpiresAt    time.Time
		currentRouteKeyEpoch  int64
		currentPolicyEpoch    int64
		encryptedNonceState   []byte
		encryptedTopic        []byte
		installationLookup    []byte
		installationIdentity  []byte
		encryptedCurrentToken []byte
	)
	err = tx.QueryRowContext(
		ctx,
		`SELECT LEAST(
		     leases.expires_at,
		     leases.control_expires_at,
		     states.expires_at,
		     states.control_expires_at
		 ),
		 leases.route_key_epoch,
		 leases.policy_epoch,
		 leases.encrypted_nonce_state,
		 leases.encrypted_topic,
		 leases.installation_lookup,
		 leases.installation_identity,
		 states.encrypted_apns_token
		   FROM hytch_push_vault.subscription_leases AS leases
		   JOIN hytch_push_vault.installation_states AS states
		     ON states.installation_lookup = leases.installation_lookup
			  WHERE leases.lease_id = $1
			    AND states.state = $2
			    AND states.encrypted_apns_token IS NOT NULL
			    AND states.policy_epoch = leases.policy_epoch
			    AND leases.topic_kind = $3
			    AND leases.push_mode = $4
			    AND leases.state = $5
			    AND leases.environment = $6
			    AND states.environment = $6
			  FOR SHARE OF leases, states`,
		leaseID,
		stateActive,
		expectedTopicKind,
		expectedPushMode,
		expectedLeaseState,
		s.environmentID,
	).Scan(
		&authorityExpiresAt,
		&currentRouteKeyEpoch,
		&currentPolicyEpoch,
		&encryptedNonceState,
		&encryptedTopic,
		&installationLookup,
		&installationIdentity,
		&encryptedCurrentToken,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDeliveryJobInvalid
	}
	if err != nil {
		return nil, deliveryQueueDatabaseError(err)
	}
	authorityMatches, err := s.deliveryAuthorityMatches(
		job,
		leaseID,
		installationLookup,
		encryptedCurrentToken,
		encryptedNonceState,
		currentPolicyEpoch,
		currentRouteKeyEpoch,
	)
	if err != nil {
		return nil, err
	}
	if !authorityMatches {
		return nil, ErrDeliveryJobInvalid
	}
	if s.a9Enabled &&
		subtle.ConstantTimeCompare(
			installationIdentity,
			currentA9Route.installationIdentity,
		) != 1 {
		return nil, ErrDeliveryJobInvalid
	}
	if s.a9Enabled {
		currentTopic, openErr := s.encryption.Open(
			leaseContext(leaseID, "topic"),
			encryptedTopic,
		)
		if openErr != nil {
			return nil, ErrDeliveryQueueUnavailable
		}
		topicMatches := subtle.ConstantTimeCompare(
			currentTopic,
			job.ProviderTopic,
		) == 1
		zero(currentTopic)
		if !topicMatches {
			return nil, ErrDeliveryJobInvalid
		}
	}
	if authorityExpiresAt.UTC().Before(expiresAt) {
		expiresAt = authorityExpiresAt.UTC()
		job.Expiration = expiresAt
	}
	if s.a9Enabled {
		a9ExpiresAt := currentA9Route.authorityExpiresAt()
		if a9ExpiresAt.Before(expiresAt) {
			expiresAt = a9ExpiresAt
			job.Expiration = expiresAt
		}
	}
	expiryReference := now
	if s.a9Enabled && currentA9Route.databaseNow.After(expiryReference) {
		expiryReference = currentA9Route.databaseNow
	}
	if !expiresAt.After(expiryReference) {
		return nil, ErrDeliveryJobInvalid
	}
	sourceEventLookup, err := s.deliverySourceEventLookup(
		leaseID,
		job.TrafficClass,
		sourceEventID,
	)
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.delivery_dedupes
			  WHERE expires_at <= $1
			    AND environment = $2`,
		now,
		s.environmentID,
	); err != nil {
		return nil, deliveryQueueDatabaseError(err)
	}
	result, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.delivery_dedupes (
			     lease_id, source_event_lookup, environment,
			     traffic_class, created_at, expires_at
			 ) VALUES ($1,$2,$3,$4,$5,$6)
			 ON CONFLICT (
			   environment, lease_id, source_event_lookup, traffic_class
			 ) DO NOTHING`,
		leaseID,
		sourceEventLookup,
		s.environmentID,
		int16(job.TrafficClass),
		now,
		now.Add(maxDeliveryJobLifetime),
	)
	if err != nil {
		return nil, deliveryQueueDatabaseError(err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return nil, deliveryQueueDatabaseError(err)
	}
	if inserted == 0 {
		if err = tx.Commit(); err != nil {
			return nil, deliveryQueueDatabaseError(err)
		}
		return nil, nil
	}
	if job.TrafficClass == DeliveryTrafficWelcome {
		var welcomeAllowed bool
		welcomeAllowed, err = s.finalizeWelcomeEnqueue(
			ctx,
			tx,
			leaseID,
			job,
			now,
		)
		if err != nil {
			return nil, err
		}
		if !welcomeAllowed {
			if err = tx.Commit(); err != nil {
				return nil, deliveryQueueDatabaseError(err)
			}
			return nil, nil
		}
	}
	plaintext, err := json.Marshal(job)
	if err != nil {
		return nil, ErrDeliveryJobInvalid
	}
	defer zero(plaintext)
	encrypted, err := s.encryption.Seal(deliveryJobContext(jobID), plaintext)
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	var queued int
	if err = tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
			   FROM hytch_push_vault.delivery_jobs
			  WHERE environment = $1`,
		s.environmentID,
	).Scan(&queued); err != nil {
		return nil, deliveryQueueDatabaseError(err)
	}
	if queued >= maxQueued {
		// Roll back the source-event dedupe, Welcome reservation, and budget
		// before recording queue pressure in an independent transaction.
		// Committing an aggregate must never consume delivery authority.
		_ = tx.Rollback()
		_ = s.RecordDeliveryObservation(
			ctx,
			DeliveryObservation{
				Event:           DeliveryObservationQueue,
				Outcome:         DeliveryOutcomeQueueBackpressure,
				TrafficClass:    job.TrafficClass,
				ThresholdBucket: DeliveryBucketCritical,
				LatencyBucket:   DeliveryBucketMinimal,
			},
		)
		return nil, ErrDeliveryQueueFull
	}
	if s.a9Enabled {
		var finalDatabaseNow time.Time
		if err = tx.QueryRowContext(
			ctx,
			`SELECT pg_catalog.clock_timestamp()`,
		).Scan(&finalDatabaseNow); err != nil {
			return nil, ErrDeliveryQueueUnavailable
		}
		reference, stillCurrent := a9RouteStillCurrentAt(
			now,
			s.now().UTC(),
			finalDatabaseNow.UTC(),
			currentA9Route,
			job.A9,
		)
		if !stillCurrent ||
			!reference.Before(expiresAt) ||
			!reference.Before(authorityExpiresAt.UTC()) {
			return nil, ErrDeliveryQueueUnavailable
		}
	}
	queueBucket := deliveryQueueUtilizationBucket(queued+1, maxQueued)
	var (
		a9InstallationBindingID  any
		a9SequencerEpoch         any
		a9SubscriptionGeneration any
		a9BindingID               any
		a9BindingVersion          any
		a9AssertionHash           any
		a9AssertionStreamSequence any
		a9TopicKeyEpoch           any
		a9TopicBinding            any
		a9RouteKeyEpoch           any
		a9KeysetSequence          any
		a9KeysetHash              any
		a9WatermarkSequence       any
	)
	if job.A9 != nil {
		a9InstallationBindingID = job.A9.InstallationBindingID[:]
		a9SequencerEpoch = job.A9.SequencerEpoch[:]
		a9SubscriptionGeneration = int64(job.A9.SubscriptionGeneration)
		a9BindingID = job.A9.BindingID[:]
		a9BindingVersion = int64(job.A9.BindingVersion)
		a9AssertionHash = job.A9.AssertionHash[:]
		a9AssertionStreamSequence = int64(
			job.A9.AssertionStreamSequence,
		)
		a9TopicKeyEpoch = int64(job.A9.TopicKeyEpoch)
		a9TopicBinding = job.A9.TopicBinding[:]
		a9RouteKeyEpoch = int64(job.A9.RouteKeyEpoch)
		a9KeysetSequence = int64(job.A9.KeysetSequence)
		a9KeysetHash = job.A9.KeysetHash[:]
		a9WatermarkSequence = int64(job.A9.WatermarkSequence)
	}
	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.delivery_jobs (
			     job_id, lease_id, encrypted_job, environment,
			     state, attempts, available_at, expires_at, created_at,
			     traffic_class, a9_installation_binding_id,
			     a9_sequencer_epoch, a9_subscription_generation,
			     a9_binding_id, a9_binding_version, a9_assertion_hash,
			     a9_assertion_stream_sequence, a9_topic_key_epoch,
			     a9_topic_binding, a9_route_key_epoch,
			     a9_keyset_sequence, a9_keyset_hash,
			     a9_watermark_sequence
			 ) VALUES (
			     $1,$2,$3,$4,$5,0,$6,$7,$6,$8,$9,$10,$11,$12,$13,
			     $14,$15,$16,$17,$18,$19,$20,$21
			 )`,
		jobID,
		leaseID,
		encrypted,
		s.environmentID,
		deliveryJobPending,
		now,
		expiresAt,
		int16(job.TrafficClass),
		a9InstallationBindingID,
		a9SequencerEpoch,
		a9SubscriptionGeneration,
		a9BindingID,
		a9BindingVersion,
		a9AssertionHash,
		a9AssertionStreamSequence,
		a9TopicKeyEpoch,
		a9TopicBinding,
		a9RouteKeyEpoch,
		a9KeysetSequence,
		a9KeysetHash,
		a9WatermarkSequence,
	); err != nil {
		return nil, deliveryQueueDatabaseError(err)
	}
	if err = tx.Commit(); err != nil {
		return nil, deliveryQueueDatabaseError(err)
	}
	_ = s.RecordDeliveryObservation(
		ctx,
		DeliveryObservation{
			Event:           DeliveryObservationQueue,
			Outcome:         DeliveryOutcomeQueueAccepted,
			TrafficClass:    job.TrafficClass,
			ThresholdBucket: queueBucket,
			LatencyBucket:   DeliveryBucketMinimal,
		},
	)
	return append([]byte(nil), jobID...), nil
}

func deliveryQueueDatabaseError(err error) error {
	if isSerializationFailure(err) {
		return err
	}
	return ErrDeliveryQueueUnavailable
}

func deliveryAttemptBucket(attempt int) DeliveryObservationBucket {
	switch attempt {
	case 1:
		return DeliveryBucketLow
	case 2:
		return DeliveryBucketModerate
	default:
		return DeliveryBucketHigh
	}
}

func deliveryQueueUtilizationBucket(
	queued int,
	capacity int,
) DeliveryObservationBucket {
	if queued <= 0 || capacity <= 0 {
		return DeliveryBucketMinimal
	}
	switch {
	case queued >= capacity:
		return DeliveryBucketCritical
	case queued*4 < capacity:
		return DeliveryBucketMinimal
	case queued*2 < capacity:
		return DeliveryBucketLow
	case queued*4 < capacity*3:
		return DeliveryBucketModerate
	case queued*10 < capacity*9:
		return DeliveryBucketHigh
	default:
		return DeliveryBucketCritical
	}
}

func deliveryRemainingLifetimeBucket(
	now time.Time,
	expiration time.Time,
) DeliveryObservationBucket {
	remaining := expiration.UTC().Sub(now.UTC())
	switch {
	case remaining <= 0:
		return DeliveryBucketMinimal
	case remaining <= 30*time.Second:
		return DeliveryBucketLow
	case remaining <= time.Minute:
		return DeliveryBucketModerate
	case remaining <= 5*time.Minute:
		return DeliveryBucketHigh
	default:
		return DeliveryBucketCritical
	}
}

func validDeliveryFinalReason(reason DeliveryFinalReason) bool {
	return reason >= DeliveryFinalTerminalRejected &&
		reason <= DeliveryFinalMaterialInvalid
}

func deliveryFinalOutcome(
	reason DeliveryFinalReason,
) (DeliveryObservationOutcome, bool) {
	switch reason {
	case DeliveryFinalTerminalRejected:
		return DeliveryOutcomeTerminalRejected, true
	case DeliveryFinalRetryExhausted:
		return DeliveryOutcomeRetryExhausted, true
	case DeliveryFinalTTLExpired:
		return DeliveryOutcomeTTLExpired, true
	case DeliveryFinalSafetyInvalidated:
		return DeliveryOutcomeSafetyInvalidated, true
	case DeliveryFinalMaterialInvalid:
		return DeliveryOutcomeMaterialInvalid, true
	default:
		return 0, false
	}
}

// markDeliveryJobFinalTx makes normal delivery work permanently non-sendable
// before its aggregate is written. The marker contains only fixed enums,
// bounded counters, retention timestamps, and a one-byte tombstone; APNS
// material and authority foreign keys are removed in this transaction.
func (s *Store) markDeliveryJobFinalTx(
	ctx context.Context,
	tx *sql.Tx,
	jobID []byte,
	reason DeliveryFinalReason,
) (bool, error) {
	if s == nil || tx == nil || len(jobID) != 16 ||
		!validDeliveryFinalReason(reason) {
		return false, ErrDeliveryJobInvalid
	}
	var (
		state          int16
		encrypted      []byte
		persistedClass sql.NullInt16
	)
	err := tx.QueryRowContext(
		ctx,
		`SELECT state, encrypted_job, traffic_class
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1
		    AND environment = $2
		  FOR UPDATE`,
		jobID,
		s.environmentID,
	).Scan(&state, &encrypted, &persistedClass)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, ErrDeliveryQueueUnavailable
	}
	if state == deliveryJobFinal {
		return true, nil
	}
	if state != deliveryJobPending && state != deliveryJobClaimed {
		// Invalid-token erasure markers are intentionally independent and must
		// never be consumed by normal delivery finalization.
		return false, nil
	}

	trafficClass := DeliveryTrafficUnknown
	if persistedClass.Valid &&
		(persistedClass.Int16 == int16(DeliveryTrafficConversation) ||
			persistedClass.Int16 == int16(DeliveryTrafficWelcome)) {
		trafficClass = DeliveryTrafficClass(persistedClass.Int16)
	} else if plaintext, openErr := s.encryption.Open(
		deliveryJobContext(jobID),
		encrypted,
	); openErr == nil {
		var job SerializedDeliveryJob
		decodeErr := json.Unmarshal(plaintext, &job)
		zero(plaintext)
		if decodeErr == nil &&
			(job.TrafficClass == DeliveryTrafficConversation ||
				job.TrafficClass == DeliveryTrafficWelcome) {
			trafficClass = job.TrafficClass
		}
	}
	if trafficClass == DeliveryTrafficUnknown &&
		reason != DeliveryFinalSafetyInvalidated &&
		reason != DeliveryFinalMaterialInvalid {
		reason = DeliveryFinalMaterialInvalid
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
		    SET lease_id = NULL,
		        installation_lookup = NULL,
		        encrypted_job = $1,
		        state = $2,
		        retry_exponent = 0,
		        available_at = $3,
		        traffic_class = $4,
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
		  WHERE job_id = $6
		    AND state IN ($7, $8)
		    AND environment = $9`,
		[]byte{0},
		deliveryJobFinal,
		s.now().UTC(),
		int16(trafficClass),
		int16(reason),
		jobID,
		deliveryJobPending,
		deliveryJobClaimed,
		s.environmentID,
	)
	if err != nil {
		return false, ErrDeliveryQueueUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return false, ErrDeliveryQueueUnavailable
	}
	return true, nil
}

func (s *Store) markDeliveryJobsSafetyForLeaseTx(
	ctx context.Context,
	tx *sql.Tx,
	leaseID []byte,
) error {
	if s == nil || tx == nil || len(leaseID) != 16 {
		return ErrDeliveryJobInvalid
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
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
		  WHERE lease_id = $6
		    AND state IN ($7, $8)
		    AND environment = $9`,
		[]byte{0},
		deliveryJobFinal,
		s.now().UTC(),
		int16(DeliveryTrafficUnknown),
		int16(DeliveryFinalSafetyInvalidated),
		leaseID,
		deliveryJobPending,
		deliveryJobClaimed,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}

func (s *Store) markDeliveryJobsSafetyForInstallationTx(
	ctx context.Context,
	tx *sql.Tx,
	installationLookup []byte,
	exceptJobID []byte,
) error {
	if s == nil || tx == nil || len(installationLookup) != 32 ||
		(len(exceptJobID) != 0 && len(exceptJobID) != 16) {
		return ErrDeliveryJobInvalid
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs AS jobs
		    SET lease_id = NULL,
		        installation_lookup = NULL,
		        encrypted_job = $1,
		        state = $2,
		        retry_exponent = 0,
		        available_at = $3,
		        traffic_class = COALESCE(jobs.traffic_class, $4),
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
		   FROM hytch_push_vault.subscription_leases AS leases
		  WHERE jobs.lease_id = leases.lease_id
		    AND leases.installation_lookup = $6
		    AND (
		      $7::BYTEA IS NULL OR
		      jobs.job_id <> $7
		    )
		    AND jobs.state IN ($8, $9)
		    AND jobs.environment = $10
		    AND leases.environment = $10`,
		[]byte{0},
		deliveryJobFinal,
		s.now().UTC(),
		int16(DeliveryTrafficUnknown),
		int16(DeliveryFinalSafetyInvalidated),
		installationLookup,
		nullableBytes(exceptJobID),
		deliveryJobPending,
		deliveryJobClaimed,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}

func (s *Store) markExpiredDeliveryJobsTx(
	ctx context.Context,
	tx *sql.Tx,
	now time.Time,
) error {
	if s == nil || tx == nil || now.IsZero() {
		return ErrDeliveryJobInvalid
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
		    SET lease_id = NULL,
		        installation_lookup = NULL,
		        encrypted_job = $1,
		        state = $2,
		        retry_exponent = 0,
		        available_at = $3,
		        traffic_class = COALESCE(traffic_class, $4),
		        final_reason = CASE
		          WHEN traffic_class IN ($5, $6) THEN $7::SMALLINT
		          ELSE $8::SMALLINT
		        END,
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
		  WHERE state IN ($9, $10)
		    AND expires_at <= $3
		    AND environment = $11`,
		[]byte{0},
		deliveryJobFinal,
		now.UTC(),
		int16(DeliveryTrafficUnknown),
		int16(DeliveryTrafficConversation),
		int16(DeliveryTrafficWelcome),
		int16(DeliveryFinalTTLExpired),
		int16(DeliveryFinalMaterialInvalid),
		deliveryJobPending,
		deliveryJobClaimed,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

// FinalizeDeliveryJob first commits a payload-free, non-sendable marker and
// then atomically records its fixed aggregate and deletes the marker. Failure
// in the second transaction leaves the safe marker for recovery.
func (s *Store) FinalizeDeliveryJob(
	ctx context.Context,
	jobID []byte,
	reason DeliveryFinalReason,
) error {
	if s == nil || s.db == nil || s.encryption == nil ||
		len(jobID) != 16 || !validDeliveryFinalReason(reason) {
		return ErrDeliveryJobInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	marked, err := s.markDeliveryJobFinalTx(ctx, tx, jobID, reason)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if !marked {
		return nil
	}
	return s.completeDeliveryFinalization(ctx, jobID)
}

func (s *Store) completeDeliveryFinalization(
	ctx context.Context,
	jobID []byte,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	completed, err := s.completeDeliveryFinalizationTx(ctx, tx, jobID)
	if err != nil {
		return err
	}
	if !completed {
		return nil
	}
	if err = tx.Commit(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}

func (s *Store) completeDeliveryFinalizationTx(
	ctx context.Context,
	tx *sql.Tx,
	jobID []byte,
) (bool, error) {
	if s == nil || tx == nil || len(jobID) != 16 {
		return false, ErrDeliveryJobInvalid
	}
	var (
		trafficClass int16
		reason       int16
		attempts     int16
		expiresAt    time.Time
	)
	err := tx.QueryRowContext(
		ctx,
		`SELECT traffic_class, final_reason, attempts, expires_at
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1
		    AND state = $2
		    AND environment = $3
		  FOR UPDATE`,
		jobID,
		deliveryJobFinal,
		s.environmentID,
	).Scan(&trafficClass, &reason, &attempts, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, ErrDeliveryQueueUnavailable
	}
	finalReason := DeliveryFinalReason(reason)
	outcome, valid := deliveryFinalOutcome(finalReason)
	if !valid ||
		trafficClass < int16(DeliveryTrafficUnknown) ||
		trafficClass > int16(DeliveryTrafficWelcome) ||
		(trafficClass == int16(DeliveryTrafficUnknown) &&
			finalReason != DeliveryFinalSafetyInvalidated &&
			finalReason != DeliveryFinalMaterialInvalid) {
		return false, ErrDeliveryQueueUnavailable
	}
	attempt := int(attempts)
	if attempt < 1 {
		attempt = 1
	}
	now := s.now().UTC()
	if err = s.recordDeliveryObservationTx(
		ctx,
		tx,
		DeliveryObservation{
			Event:           DeliveryObservationTerminal,
			Outcome:         outcome,
			TrafficClass:    DeliveryTrafficClass(trafficClass),
			ThresholdBucket: deliveryAttemptBucket(attempt),
			LatencyBucket: deliveryRemainingLifetimeBucket(
				now,
				expiresAt,
			),
		},
		now,
	); err != nil {
		return false, ErrDeliveryQueueUnavailable
	}
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1
		    AND state = $2
		    AND final_reason = $3
		    AND environment = $4`,
		jobID,
		deliveryJobFinal,
		reason,
		s.environmentID,
	)
	if err != nil {
		return false, ErrDeliveryQueueUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return false, ErrDeliveryQueueUnavailable
	}
	return true, nil
}

func (s *Store) finalizeDeliveryMarkers(ctx context.Context) error {
	for {
		rows, err := s.db.QueryContext(
			ctx,
			`SELECT job_id
			   FROM hytch_push_vault.delivery_jobs
			  WHERE state = $1
			    AND environment = $2
			  ORDER BY created_at
			  LIMIT 128`,
			deliveryJobFinal,
			s.environmentID,
		)
		if err != nil {
			return ErrDeliveryQueueUnavailable
		}
		var jobIDs [][]byte
		for rows.Next() {
			var jobID []byte
			if err = rows.Scan(&jobID); err != nil {
				_ = rows.Close()
				return ErrDeliveryQueueUnavailable
			}
			jobIDs = append(jobIDs, append([]byte(nil), jobID...))
		}
		if err = rows.Close(); err != nil {
			return ErrDeliveryQueueUnavailable
		}
		if err = rows.Err(); err != nil {
			return ErrDeliveryQueueUnavailable
		}
		if len(jobIDs) == 0 {
			return nil
		}
		for _, jobID := range jobIDs {
			if err = s.completeDeliveryFinalization(ctx, jobID); err != nil {
				return err
			}
		}
	}
}

func (s *Store) completeDeliveryMarkersTx(
	ctx context.Context,
	tx *sql.Tx,
) error {
	if s == nil || tx == nil {
		return ErrDeliveryQueueUnavailable
	}
	rows, err := tx.QueryContext(
		ctx,
		`SELECT job_id
		   FROM hytch_push_vault.delivery_jobs
		  WHERE state = $1
		    AND environment = $2
		  ORDER BY created_at
		  LIMIT $3
		  FOR UPDATE`,
		deliveryJobFinal,
		s.environmentID,
		retentionDeliveryFinalizationBatchSize,
	)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	var jobIDs [][]byte
	for rows.Next() {
		var jobID []byte
		if err = rows.Scan(&jobID); err != nil {
			_ = rows.Close()
			return ErrDeliveryQueueUnavailable
		}
		jobIDs = append(jobIDs, jobID)
	}
	if err = rows.Close(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if err = rows.Err(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	for _, jobID := range jobIDs {
		if _, err = s.completeDeliveryFinalizationTx(
			ctx,
			tx,
			jobID,
		); err != nil {
			return err
		}
	}
	return nil
}

// RecoverDeliveryJobs returns non-exhausted APNS claims whose claim lease
// elapsed to pending without lowering their persisted attempt count. Terminal
// rows are first converted to payload-free markers; aggregate persistence must
// complete before recovery permits another claim.
func (s *Store) RecoverDeliveryJobs(ctx context.Context) error {
	if s == nil || s.db == nil || s.encryption == nil {
		return ErrDeliveryQueueUnavailable
	}
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(
		ctx,
		`SELECT jobs.job_id,
		        CASE
		          WHEN jobs.attempts >= $2 THEN $3::SMALLINT
		          WHEN jobs.expires_at <= $1 THEN $4::SMALLINT
		          ELSE $5::SMALLINT
		        END
		   FROM hytch_push_vault.delivery_jobs AS jobs
		  WHERE jobs.environment = $6
		    AND jobs.state IN ($7, $8)
		    AND (
		      jobs.expires_at <= $1
		      OR (
		        jobs.state = $8
		        AND jobs.available_at <= $1
		        AND jobs.attempts >= $2
		      )
		      OR NOT EXISTS (
		        SELECT 1
		          FROM hytch_push_vault.subscription_leases AS leases
		         WHERE leases.lease_id = jobs.lease_id
		           AND leases.environment = $6
		      )
		    )
		  FOR UPDATE OF jobs`,
		now,
		MaxDeliveryAttempts,
		DeliveryFinalRetryExhausted,
		DeliveryFinalTTLExpired,
		DeliveryFinalSafetyInvalidated,
		s.environmentID,
		deliveryJobPending,
		deliveryJobClaimed,
	)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	type finalCandidate struct {
		jobID  []byte
		reason int16
	}
	var finalCandidates []finalCandidate
	for rows.Next() {
		var candidate finalCandidate
		if err = rows.Scan(&candidate.jobID, &candidate.reason); err != nil {
			_ = rows.Close()
			return ErrDeliveryQueueUnavailable
		}
		finalCandidates = append(finalCandidates, candidate)
	}
	if err = rows.Close(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if err = rows.Err(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	for _, candidate := range finalCandidates {
		if _, err = s.markDeliveryJobFinalTx(
			ctx,
			tx,
			candidate.jobID,
			DeliveryFinalReason(candidate.reason),
		); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
		    SET state = $1, available_at = $2
			  WHERE state = $3
			    AND available_at <= $2
			    AND attempts < $4
			    AND expires_at > $2
			    AND environment = $5`,
		deliveryJobPending,
		now,
		deliveryJobClaimed,
		MaxDeliveryAttempts,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if err = markOverdueErasureUnsafe(
		ctx,
		tx,
		s.environmentID,
		now,
	); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return s.finalizeDeliveryMarkers(ctx)
}

// RecoverInvalidTokenErasures is called only by the deletion-only worker at
// startup. It releases expired claims and makes pending markers immediately
// available so an overdue marker can be cleared before retention readiness.
func (s *Store) RecoverInvalidTokenErasures(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrDeliveryQueueUnavailable
	}
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
			    SET state = $1, available_at = $2
			  WHERE state = $3
			    AND available_at <= $2
			    AND environment = $4`,
		erasureJobPending,
		now,
		erasureJobClaimed,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
			    SET available_at = LEAST(available_at, $1)
			  WHERE state = $2
			    AND environment = $3`,
		now,
		erasureJobPending,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if err = markOverdueErasureUnsafe(
		ctx,
		tx,
		s.environmentID,
		now,
	); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}

func (s *Store) ClaimDeliveryJobs(
	ctx context.Context,
	limit int,
	claimTTL time.Duration,
) ([]ClaimedDeliveryJob, error) {
	if s == nil || s.db == nil || s.encryption == nil ||
		limit <= 0 || limit > 128 ||
		claimTTL < time.Second || claimTTL > time.Minute {
		return nil, ErrDeliveryJobInvalid
	}
	if err := s.RequireRetentionSafe(ctx); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if err := s.RecoverDeliveryJobs(ctx); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	now := s.now().UTC()
	claimDeadline := now.Add(claimTTL)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(
		ctx,
		`SELECT jobs.job_id, jobs.lease_id, jobs.encrypted_job,
		        jobs.attempts, jobs.expires_at, jobs.traffic_class,
		        jobs.a9_installation_binding_id,
		        jobs.a9_sequencer_epoch,
		        jobs.a9_subscription_generation,
		        jobs.a9_binding_id,
		        jobs.a9_binding_version,
		        jobs.a9_assertion_hash,
		        jobs.a9_assertion_stream_sequence,
		        jobs.a9_topic_key_epoch,
		        jobs.a9_topic_binding,
		        jobs.a9_route_key_epoch,
		        jobs.a9_keyset_sequence,
		        jobs.a9_keyset_hash,
		        jobs.a9_watermark_sequence
		   FROM hytch_push_vault.delivery_jobs AS jobs
		   JOIN hytch_push_vault.subscription_leases AS leases
		     ON leases.lease_id = jobs.lease_id
		   JOIN hytch_push_vault.installation_states AS states
		     ON states.installation_lookup = leases.installation_lookup
		  WHERE jobs.state = $1
		    AND jobs.available_at <= $2
		    AND jobs.expires_at > $2
		    AND jobs.attempts < $3
		    AND states.state = $4
			    AND (
			      leases.state = $4
		      OR (
		        leases.state = $5
		        AND leases.topic_kind = $6
			        AND leases.push_mode = $7
			      )
			    )
			    AND jobs.environment = $8
			    AND leases.environment = $8
			    AND states.environment = $8
			  ORDER BY jobs.available_at, jobs.created_at
			  LIMIT $9
			  FOR UPDATE OF jobs SKIP LOCKED`,
		deliveryJobPending,
		now,
		MaxDeliveryAttempts,
		stateActive,
		stateSuppressed,
		topicWelcome,
		pushSuppressed,
		s.environmentID,
		limit,
	)
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	type encryptedJobRow struct {
		jobID     []byte
		leaseID   []byte
		encrypted []byte
		attempts  int16
		expiresAt time.Time
		traffic   sql.NullInt16
		a9        a9DeliverySnapshotRow
	}
	var encryptedRows []encryptedJobRow
	for rows.Next() {
		var row encryptedJobRow
			destinations := []any{
				&row.jobID,
				&row.leaseID,
				&row.encrypted,
				&row.attempts,
				&row.expiresAt,
				&row.traffic,
			}
			destinations = append(
				destinations,
				row.a9.scanDestinations()...,
			)
			if err = rows.Scan(destinations...); err != nil {
			_ = rows.Close()
			return nil, ErrDeliveryQueueUnavailable
		}
		encryptedRows = append(encryptedRows, row)
	}
	if err = rows.Close(); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if err = rows.Err(); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}

	claimed := make([]ClaimedDeliveryJob, 0, len(encryptedRows))
	for _, row := range encryptedRows {
		plaintext, openErr := s.encryption.Open(
			deliveryJobContext(row.jobID),
			row.encrypted,
		)
		if openErr != nil {
			if _, err = s.markDeliveryJobFinalTx(
				ctx,
				tx,
				row.jobID,
				DeliveryFinalMaterialInvalid,
			); err != nil {
				return nil, ErrDeliveryQueueUnavailable
			}
			continue
		}
			var job SerializedDeliveryJob
			decodeErr := json.Unmarshal(plaintext, &job)
			zero(plaintext)
			a9ShapeValid := row.a9.empty() || row.a9.complete()
			a9ModeMatches := s.a9Enabled == row.a9.complete()
			a9SnapshotMatches := (row.a9.empty() && job.A9 == nil) ||
				row.a9.matches(job.A9)
			if decodeErr != nil ||
				validateSerializedDeliveryJob(job, now) != nil ||
				!job.Expiration.UTC().Equal(row.expiresAt.UTC()) ||
				!a9ShapeValid ||
				!a9SnapshotMatches ||
				(row.traffic.Valid &&
					row.traffic.Int16 != int16(job.TrafficClass)) {
			if _, err = s.markDeliveryJobFinalTx(
				ctx,
				tx,
				row.jobID,
				DeliveryFinalMaterialInvalid,
			); err != nil {
				return nil, ErrDeliveryQueueUnavailable
				}
				continue
			}
			if !a9ModeMatches {
				if _, err = s.markDeliveryJobFinalTx(
					ctx,
					tx,
					row.jobID,
					DeliveryFinalSafetyInvalidated,
				); err != nil {
					return nil, ErrDeliveryQueueUnavailable
				}
				continue
			}
		if _, err = tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.delivery_jobs
				    SET state = $1,
				        available_at = LEAST($2, expires_at),
				        traffic_class = $6
				  WHERE job_id = $3
				    AND attempts < $4
				    AND environment = $5`,
			deliveryJobClaimed,
			claimDeadline,
			row.jobID,
			MaxDeliveryAttempts,
			s.environmentID,
			int16(job.TrafficClass),
		); err != nil {
			return nil, ErrDeliveryQueueUnavailable
		}
		claimed = append(claimed, ClaimedDeliveryJob{
			JobID:     append([]byte(nil), row.jobID...),
			LeaseID:   append([]byte(nil), row.leaseID...),
			Job:       cloneSerializedDeliveryJob(job),
			Attempts:  int(row.attempts) + 1,
			ExpiresAt: row.expiresAt.UTC(),
		})
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if err = s.finalizeDeliveryMarkers(ctx); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	return claimed, nil
}

type deliveryAttemptGuard struct {
	store              *Store
	tx                 *sql.Tx
	jobID              []byte
	job                SerializedDeliveryJob
	leaseID            []byte
	installationLookup []byte
	priorAttempts      int
	nextAttempts       int
}

func (g *deliveryAttemptGuard) Complete(
	ctx context.Context,
	result DeliveryAttemptResult,
) error {
	if g == nil || g.store == nil || g.tx == nil ||
		len(g.jobID) != 16 || len(g.leaseID) != 16 ||
		len(g.installationLookup) != 32 ||
		g.nextAttempts != g.priorAttempts+1 ||
		g.nextAttempts <= 0 || g.nextAttempts > MaxDeliveryAttempts {
		return ErrDeliveryJobInvalid
	}
	var (
		dbResult      sql.Result
		err           error
		finalReason   DeliveryFinalReason
		finalizeAfter bool
	)
	switch result.Outcome {
	case DeliveryAttemptSent:
		dbResult, err = g.tx.ExecContext(
			ctx,
			`DELETE FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1
			    AND state = $2
			    AND attempts = $3
			    AND environment = $4`,
			g.jobID,
			deliveryJobClaimed,
			g.priorAttempts,
			g.store.environmentID,
		)
	case DeliveryAttemptRejected:
		finalReason = DeliveryFinalTerminalRejected
		finalizeAfter = true
		dbResult, err = g.markFinal(ctx, finalReason)
	case DeliveryAttemptTransient:
		if g.nextAttempts >= MaxDeliveryAttempts ||
			result.RetryAt.IsZero() ||
			!result.RetryAt.UTC().Before(g.job.Expiration.UTC()) {
			finalReason = DeliveryFinalTTLExpired
			if g.nextAttempts >= MaxDeliveryAttempts {
				finalReason = DeliveryFinalRetryExhausted
			}
			finalizeAfter = true
			dbResult, err = g.markFinal(ctx, finalReason)
		} else {
			dbResult, err = g.tx.ExecContext(
				ctx,
				`UPDATE hytch_push_vault.delivery_jobs
				    SET state = $1,
				        attempts = $2,
				        available_at = $3
				  WHERE job_id = $4
				    AND state = $5
				    AND attempts = $6
				    AND environment = $7`,
				deliveryJobPending,
				g.nextAttempts,
				result.RetryAt.UTC(),
				g.jobID,
				deliveryJobClaimed,
				g.priorAttempts,
				g.store.environmentID,
			)
		}
	case DeliveryAttemptInvalidToken:
		if result.RetryAt.IsZero() {
			return ErrDeliveryJobInvalid
		}
		if err = g.convertInvalidTokenTx(
			ctx,
			result.RetryAt.UTC(),
		); err != nil {
			_ = g.Release()
			return err
		}
		if err = g.commit(); err != nil {
			return err
		}
		if err = g.store.finalizeDeliveryMarkers(ctx); err != nil {
			return ErrDeliveryFinalizationPending
		}
		return nil
	default:
		return ErrDeliveryJobInvalid
	}
	if err != nil {
		_ = g.Release()
		return ErrDeliveryQueueUnavailable
	}
	affected, err := dbResult.RowsAffected()
	if err != nil || affected != 1 {
		_ = g.Release()
		return ErrDeliveryQueueUnavailable
	}
	if err = g.commit(); err != nil {
		return err
	}
	if finalizeAfter {
		return g.store.completeDeliveryFinalization(ctx, g.jobID)
	}
	return nil
}

func (g *deliveryAttemptGuard) markFinal(
	ctx context.Context,
	reason DeliveryFinalReason,
) (sql.Result, error) {
	if g == nil || g.store == nil || g.tx == nil ||
		!validDeliveryFinalReason(reason) ||
		(g.job.TrafficClass != DeliveryTrafficConversation &&
			g.job.TrafficClass != DeliveryTrafficWelcome) {
		return nil, ErrDeliveryJobInvalid
	}
	return g.tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
		    SET lease_id = NULL,
		        installation_lookup = NULL,
		        encrypted_job = $1,
		        state = $2,
		        attempts = $3,
		        retry_exponent = 0,
		        available_at = $4,
		        traffic_class = $5,
		        final_reason = $6,
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
		  WHERE job_id = $7
		    AND state = $8
		    AND attempts = $9
		    AND environment = $10`,
		[]byte{0},
		deliveryJobFinal,
		g.nextAttempts,
		g.store.now().UTC(),
		int16(g.job.TrafficClass),
		int16(reason),
		g.jobID,
		deliveryJobClaimed,
		g.priorAttempts,
		g.store.environmentID,
	)
}

func (g *deliveryAttemptGuard) convertInvalidTokenTx(
	ctx context.Context,
	availableAt time.Time,
) error {
	marker := SerializedDeliveryJob{
		DeviceToken:  g.job.DeviceToken,
		Expiration:   g.job.Expiration.UTC(),
		TrafficClass: g.job.TrafficClass,
		EraseOnly:    true,
	}
	plaintext, err := json.Marshal(marker)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	defer zero(plaintext)
	encryptedMarker, err := g.store.encryption.Seal(
		deliveryJobContext(g.jobID),
		plaintext,
	)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	now := g.store.now().UTC()
	if _, err = g.tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.installation_states
			    SET state = $1, revoked_at = COALESCE(revoked_at, $2)
			  WHERE installation_lookup = $3
			    AND environment = $4`,
		stateBlocked,
		now,
		g.installationLookup,
		g.store.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if _, err = g.tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.subscription_leases
			    SET state = $1, revoked_at = COALESCE(revoked_at, $2)
			  WHERE installation_lookup = $3
			    AND environment = $4`,
		stateBlocked,
		now,
		g.installationLookup,
		g.store.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if err = g.store.markDeliveryJobsSafetyForInstallationTx(
		ctx,
		g.tx,
		g.installationLookup,
		g.jobID,
	); err != nil {
		return err
	}
	if _, err = g.tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.delivery_jobs
			  WHERE installation_lookup = $1
			    AND job_id <> $2
			    AND environment = $3`,
		g.installationLookup,
		g.jobID,
		g.store.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	dbResult, err := g.tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
		    SET lease_id = NULL,
		        installation_lookup = $1,
		        encrypted_job = $2,
		        state = $3,
		        attempts = 0,
		        retry_exponent = 0,
		        available_at = $4,
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
			  WHERE job_id = $5
			    AND state = $6
			    AND attempts = $7
			    AND environment = $8`,
		g.installationLookup,
		encryptedMarker,
		erasureJobPending,
		availableAt,
		g.jobID,
		deliveryJobClaimed,
		g.priorAttempts,
		g.store.environmentID,
	)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	affected, err := dbResult.RowsAffected()
	if err != nil || affected != 1 {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}

func (g *deliveryAttemptGuard) commit() error {
	if g == nil || g.tx == nil {
		return ErrDeliveryJobInvalid
	}
	tx := g.tx
	g.tx = nil
	if err := tx.Commit(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}

func (g *deliveryAttemptGuard) RecordAttempt(ctx context.Context) error {
	if g == nil || g.tx == nil || len(g.jobID) != 16 ||
		g.nextAttempts != g.priorAttempts+1 ||
		g.nextAttempts <= 0 || g.nextAttempts > MaxDeliveryAttempts {
		return ErrDeliveryJobInvalid
	}
	result, err := g.tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
			    SET attempts = $1
			  WHERE job_id = $2
			    AND state = $3
			    AND attempts = $4
			    AND environment = $5`,
		g.nextAttempts,
		g.jobID,
		deliveryJobClaimed,
		g.priorAttempts,
		g.store.environmentID,
	)
	if err != nil {
		_ = g.Release()
		return ErrDeliveryQueueUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		_ = g.Release()
		return ErrDeliveryQueueUnavailable
	}
	return g.commit()
}

func (g *deliveryAttemptGuard) Release() error {
	if g == nil || g.tx == nil {
		return nil
	}
	tx := g.tx
	g.tx = nil
	if err := tx.Rollback(); err != nil &&
		!errors.Is(err, sql.ErrTxDone) {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}

// AcquireDeliveryAttempt rechecks current authority immediately before APNS
// and holds shared retention/authority locks plus the claimed job row lock
// until Complete, RecordAttempt, or Release. A concurrent revocation, token
// rotation, or unsafe retention transition therefore completes either before
// validation or after the Apple request has returned, never in the
// validation-to-egress gap.
func (s *Store) AcquireDeliveryAttempt(
	ctx context.Context,
	job ClaimedDeliveryJob,
) (DeliveryAttemptGuard, bool, error) {
	if s == nil || s.db == nil || s.encryption == nil {
		return nil, false, ErrDeliveryJobInvalid
	}
	now := s.now().UTC()
	if len(job.JobID) != 16 ||
		len(job.LeaseID) != 16 ||
		job.Attempts <= 0 || job.Attempts > MaxDeliveryAttempts ||
		validateSerializedDeliveryJob(job.Job, now) != nil ||
		!job.ExpiresAt.UTC().Equal(job.Job.Expiration.UTC()) ||
		s.a9Enabled != (job.Job.A9 != nil) {
		return nil, false, ErrDeliveryJobInvalid
	}
	var expectedTopicKind int16
	var expectedPushMode int16
	var expectedLeaseState int16
	switch job.Job.TrafficClass {
	case DeliveryTrafficConversation:
		expectedTopicKind = topicConversation
		expectedPushMode = pushAlert
		expectedLeaseState = stateActive
	case DeliveryTrafficWelcome:
		if !s.welcomeEnabled {
			return nil, false, nil
		}
		expectedTopicKind = topicWelcome
		expectedPushMode = pushSuppressed
		expectedLeaseState = stateSuppressed
	default:
		return nil, false, ErrDeliveryJobInvalid
	}
	var topicBindingLease a9trust.TopicBindingLease
	if s.a9Enabled {
		if s.a9Trust == nil {
			return nil, false, ErrDeliveryQueueUnavailable
		}
		var acquireErr error
		topicBindingLease, acquireErr =
			s.a9Trust.AcquireTopicBindingLease(
				ctx,
				now,
				job.Job.A9.KeysetSequence,
				job.Job.A9.KeysetHash,
			)
		if acquireErr != nil || topicBindingLease == nil {
			return nil, false, ErrDeliveryQueueUnavailable
		}
		defer func() {
			if topicBindingLease != nil {
				topicBindingLease.Close()
			}
		}()
	}
	tx, err := s.db.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelReadCommitted},
	)
	if err != nil {
		return nil, false, ErrDeliveryQueueUnavailable
	}
	guard := &deliveryAttemptGuard{
		store:         s,
		tx:            tx,
		jobID:         append([]byte(nil), job.JobID...),
		job:           cloneSerializedDeliveryJob(job.Job),
		leaseID:       append([]byte(nil), job.LeaseID...),
		priorAttempts: job.Attempts - 1,
		nextAttempts:  job.Attempts,
	}
	if _, err = tx.ExecContext(
		ctx,
		`SET LOCAL lock_timeout = '5s'`,
	); err != nil {
		_ = guard.Release()
		return nil, false, ErrDeliveryQueueUnavailable
	}
	var currentA9Route a9CurrentRouteState
	if s.a9Enabled {
		var current bool
		currentA9Route, current, err = s.requireA9CurrentRouteTx(
			ctx,
			tx,
			job.LeaseID,
			job.Job.A9,
		)
		if err != nil {
			_ = guard.Release()
			return nil, false, ErrDeliveryQueueUnavailable
		}
		if !current {
			_ = guard.Release()
			return nil, false, nil
		}
		if !a9TrustClockAligned(now, currentA9Route.databaseNow) {
			_ = guard.Release()
			return nil, false, ErrDeliveryQueueUnavailable
		}
		defer zero(currentA9Route.installationIdentity)
		recomputed, verdict := topicBindingLease.TopicBindingForEpoch(
			ctx,
			job.Job.ProviderTopic,
			job.Job.A9.TopicKeyEpoch,
			now,
			job.Job.A9.AssertionExpiresAt,
			true,
		)
		topicMatches := verdict.IsEligible() &&
			a9trust.EqualBinding(
				recomputed,
				job.Job.A9.TopicBinding[:],
			)
		clear(recomputed)
		if !topicMatches {
			_ = guard.Release()
			if !verdict.IsEligible() &&
				verdict.Terminal == "INCONCLUSIVE" {
				return nil, false, ErrDeliveryQueueUnavailable
			}
			return nil, false, nil
		}
		topicBindingLease.Close()
		topicBindingLease = nil
	} else if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		_ = guard.Release()
		return nil, false, ErrDeliveryQueueUnavailable
	}

	var persistedJobExpiresAt time.Time
	if s.a9Enabled {
		var persistedA9 a9DeliverySnapshotRow
		err = tx.QueryRowContext(
			ctx,
			`SELECT expires_at,
			        a9_installation_binding_id,
			        a9_sequencer_epoch,
			        a9_subscription_generation,
			        a9_binding_id,
			        a9_binding_version,
			        a9_assertion_hash,
			        a9_assertion_stream_sequence,
			        a9_topic_key_epoch,
			        a9_topic_binding,
			        a9_route_key_epoch,
			        a9_keyset_sequence,
			        a9_keyset_hash,
			        a9_watermark_sequence
			   FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1
			    AND lease_id = $2
			    AND state = $3
			    AND attempts = $4
			    AND expires_at > $5
			    AND environment = $6
			  FOR UPDATE`,
			job.JobID,
			job.LeaseID,
			deliveryJobClaimed,
			job.Attempts-1,
			a9DeliveryReferenceTime(now, currentA9Route, true),
			s.environmentID,
		).Scan(append(
			[]any{&persistedJobExpiresAt},
			persistedA9.scanDestinations()...,
		)...)
		if errors.Is(err, sql.ErrNoRows) {
			_ = guard.Release()
			return nil, false, nil
		}
		if err != nil {
			_ = guard.Release()
			return nil, false, ErrDeliveryQueueUnavailable
		}
		if !persistedJobExpiresAt.UTC().Equal(job.ExpiresAt.UTC()) ||
			!persistedA9.matches(job.Job.A9) {
			_ = guard.Release()
			return nil, false, nil
		}
	}
	var (
		authorityExpiresAt    time.Time
		currentRouteKeyEpoch  int64
		currentPolicyEpoch    int64
		encryptedNonceState   []byte
		encryptedTopic        []byte
		installationLookup    []byte
		installationIdentity  []byte
		encryptedCurrentToken []byte
		currentAgePolicy      int16
	)
	var authorityRow *sql.Row
	if s.a9Enabled {
		authorityRow = tx.QueryRowContext(
			ctx,
			`SELECT LEAST(
			        leases.expires_at,
			        leases.control_expires_at,
			        states.expires_at,
			        states.control_expires_at
			     ),
			        leases.route_key_epoch,
			        leases.policy_epoch,
			        leases.encrypted_nonce_state,
			        leases.encrypted_topic,
			        leases.installation_lookup,
			        leases.installation_identity,
			        states.encrypted_apns_token,
			        states.age_policy
			   FROM hytch_push_vault.subscription_leases AS leases
			   JOIN hytch_push_vault.installation_states AS states
			     ON states.installation_lookup = leases.installation_lookup
			  WHERE leases.lease_id = $1
			    AND leases.expires_at > $2
			    AND leases.control_expires_at > $2
			    AND states.expires_at > $2
			    AND states.control_expires_at > $2
			    AND states.state = $3
			    AND states.encrypted_apns_token IS NOT NULL
			    AND states.policy_epoch = leases.policy_epoch
			    AND leases.state = $4
			    AND leases.topic_kind = $5
			    AND leases.push_mode = $6
			    AND leases.environment = $7
			    AND states.environment = $7
			  FOR SHARE OF leases, states`,
			job.LeaseID,
			a9DeliveryReferenceTime(now, currentA9Route, true),
			stateActive,
			expectedLeaseState,
			expectedTopicKind,
			expectedPushMode,
			s.environmentID,
		)
	} else {
		authorityRow = tx.QueryRowContext(
			ctx,
			`SELECT LEAST(
			        leases.expires_at,
			        leases.control_expires_at,
			        states.expires_at,
			        states.control_expires_at
			     ),
			        leases.route_key_epoch,
			        leases.policy_epoch,
			        leases.encrypted_nonce_state,
			        leases.encrypted_topic,
			        leases.installation_lookup,
			        leases.installation_identity,
			        states.encrypted_apns_token,
			        states.age_policy
			   FROM hytch_push_vault.delivery_jobs AS jobs
			   JOIN hytch_push_vault.subscription_leases AS leases
			     ON leases.lease_id = jobs.lease_id
			   JOIN hytch_push_vault.installation_states AS states
			     ON states.installation_lookup = leases.installation_lookup
			  WHERE jobs.job_id = $1
			    AND jobs.lease_id = $2
			    AND jobs.state = $3
			    AND jobs.attempts = $4
			    AND jobs.expires_at > $5
			    AND jobs.a9_installation_binding_id IS NULL
			    AND leases.expires_at > $5
			    AND leases.control_expires_at > $5
			    AND states.expires_at > $5
			    AND states.control_expires_at > $5
			    AND states.state = $6
			    AND states.encrypted_apns_token IS NOT NULL
			    AND states.policy_epoch = leases.policy_epoch
			    AND leases.state = $7
			    AND leases.topic_kind = $8
			    AND leases.push_mode = $9
			    AND jobs.environment = $10
			    AND leases.environment = $10
			    AND states.environment = $10
			  FOR UPDATE OF jobs
			  FOR SHARE OF leases, states`,
			job.JobID,
			job.LeaseID,
			deliveryJobClaimed,
			job.Attempts-1,
			now,
			stateActive,
			expectedLeaseState,
			expectedTopicKind,
			expectedPushMode,
			s.environmentID,
		)
	}
	err = authorityRow.Scan(
		&authorityExpiresAt,
		&currentRouteKeyEpoch,
		&currentPolicyEpoch,
		&encryptedNonceState,
		&encryptedTopic,
		&installationLookup,
		&installationIdentity,
		&encryptedCurrentToken,
		&currentAgePolicy,
	)
	if errors.Is(err, sql.ErrNoRows) {
		_ = guard.Release()
		return nil, false, nil
	}
	if err != nil {
		_ = guard.Release()
		return nil, false, ErrDeliveryQueueUnavailable
	}
	defer zero(installationIdentity)
	if currentAgePolicy == ageTeen && !s.teenConversationEnabled {
		_ = guard.Release()
		return nil, false, nil
	}
	if s.a9Enabled &&
		subtle.ConstantTimeCompare(
			installationIdentity,
			currentA9Route.installationIdentity,
		) != 1 {
		_ = guard.Release()
		return nil, false, nil
	}
	if s.a9Enabled {
		currentTopic, openErr := s.encryption.Open(
			leaseContext(job.LeaseID, "topic"),
			encryptedTopic,
		)
		if openErr != nil {
			_ = guard.Release()
			return nil, false, ErrDeliveryQueueUnavailable
		}
		topicMatches := subtle.ConstantTimeCompare(
			currentTopic,
			job.Job.ProviderTopic,
		) == 1
		zero(currentTopic)
		if !topicMatches {
			_ = guard.Release()
			return nil, false, nil
		}
	}
	matches, err := s.deliveryAuthorityMatches(
		job.Job,
		job.LeaseID,
		installationLookup,
		encryptedCurrentToken,
		encryptedNonceState,
		currentPolicyEpoch,
		currentRouteKeyEpoch,
	)
	if err != nil {
		_ = guard.Release()
		return nil, false, err
	}
	if !matches {
		_ = guard.Release()
		return nil, false, nil
	}
	if s.a9Enabled {
		var finalDatabaseNow time.Time
		if err = tx.QueryRowContext(
			ctx,
			`SELECT pg_catalog.clock_timestamp()`,
		).Scan(&finalDatabaseNow); err != nil {
			_ = guard.Release()
			return nil, false, ErrDeliveryQueueUnavailable
		}
		if !a9DeliveryStillCurrent(
			now,
			s.now().UTC(),
			finalDatabaseNow.UTC(),
			persistedJobExpiresAt.UTC(),
			authorityExpiresAt.UTC(),
			currentA9Route,
			job.Job.A9,
		) {
			_ = guard.Release()
			return nil, false, nil
		}
	}
	guard.installationLookup = append(
		[]byte(nil),
		installationLookup...,
	)
	return guard, true, nil
}

func a9DeliveryStillCurrent(
	evaluationTime time.Time,
	hostNow time.Time,
	databaseNow time.Time,
	jobExpiresAt time.Time,
	gate6ExpiresAt time.Time,
	route a9CurrentRouteState,
	snapshot *interfaces.A9RouteSnapshot,
) bool {
	reference, current := a9RouteStillCurrentAt(
		evaluationTime,
		hostNow,
		databaseNow,
		route,
		snapshot,
	)
	return current &&
		reference.Before(jobExpiresAt.UTC()) &&
		reference.Before(gate6ExpiresAt.UTC())
}

func a9DeliveryReferenceTime(
	now time.Time,
	state a9CurrentRouteState,
	enabled bool,
) time.Time {
	if enabled && state.databaseNow.After(now) {
		return state.databaseNow
	}
	return now
}

// ValidateDeliveryClaim is retained as a read-only compatibility helper for
// diagnostics and focused store tests. APNS egress must use
// AcquireDeliveryAttempt so the locks remain held through the request.
func (s *Store) ValidateDeliveryClaim(
	ctx context.Context,
	job ClaimedDeliveryJob,
) (bool, error) {
	guard, valid, err := s.AcquireDeliveryAttempt(ctx, job)
	if guard != nil {
		if releaseErr := guard.Release(); err == nil && releaseErr != nil {
			err = releaseErr
		}
	}
	return valid, err
}

func (s *Store) deliveryAuthorityMatches(
	job SerializedDeliveryJob,
	leaseID []byte,
	installationLookup []byte,
	encryptedCurrentToken []byte,
	encryptedNonceState []byte,
	currentPolicyEpoch int64,
	currentRouteKeyEpoch int64,
) (bool, error) {
	if currentPolicyEpoch <= 0 ||
		uint64(currentPolicyEpoch) != job.PolicyEpoch ||
		currentRouteKeyEpoch <= 0 ||
		uint64(currentRouteKeyEpoch) != uint64(job.RouteKeyEpoch) {
		return false, nil
	}
	currentToken, err := s.encryption.Open(
		installationContext(installationLookup, "apns-token"),
		encryptedCurrentToken,
	)
	if err != nil {
		return false, ErrDeliveryQueueUnavailable
	}
	defer zero(currentToken)
	jobToken, err := hex.DecodeString(job.DeviceToken)
	if err != nil {
		return false, ErrDeliveryJobInvalid
	}
	defer zero(jobToken)
	if len(currentToken) != len(jobToken) ||
		subtle.ConstantTimeCompare(currentToken, jobToken) != 1 {
		return false, nil
	}
	nonceBytes, err := s.encryption.Open(
		leaseContext(leaseID, "nonce-state"),
		encryptedNonceState,
	)
	if err != nil {
		return false, ErrDeliveryQueueUnavailable
	}
	nonce, err := decodeNonceState(nonceBytes)
	zero(nonceBytes)
	if err != nil ||
		nonce.Prefix != job.NoncePrefix ||
		job.DeliverySequence >= nonce.NextSequence {
		return false, nil
	}
	return true, nil
}

// ClaimErasureJobs remains available while retention is unsafe. Erasure is a
// deletion-authority path, not an APNS egress path, and is required to restore
// retention health.
func (s *Store) ClaimErasureJobs(
	ctx context.Context,
	limit int,
	claimTTL time.Duration,
) ([]ClaimedDeliveryJob, error) {
	if s == nil || s.db == nil || s.encryption == nil ||
		limit <= 0 || limit > 128 ||
		claimTTL < time.Second || claimTTL > time.Minute {
		return nil, ErrDeliveryJobInvalid
	}
	now := s.now().UTC()
	claimDeadline := now.Add(claimTTL)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
		    SET state = $1, available_at = $2
		  WHERE state = $3
		    AND available_at <= $2
		    AND environment = $4`,
		erasureJobPending,
		now,
		erasureJobClaimed,
		s.environmentID,
	); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if err = markOverdueErasureUnsafe(
		ctx,
		tx,
		s.environmentID,
		now,
	); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(
		ctx,
		`SELECT job_id, installation_lookup, encrypted_job, attempts,
		        retry_exponent, expires_at
			   FROM hytch_push_vault.delivery_jobs
			  WHERE state = $1
			    AND available_at <= $2
			    AND environment = $3
			  ORDER BY available_at, created_at
			  LIMIT $4
			  FOR UPDATE SKIP LOCKED`,
		erasureJobPending,
		now,
		s.environmentID,
		limit,
	)
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	type encryptedErasureRow struct {
		jobID              []byte
		installationLookup []byte
		encrypted          []byte
		attempts           int16
		retryExponent      int16
		expiresAt          time.Time
	}
	var encryptedRows []encryptedErasureRow
	for rows.Next() {
		var row encryptedErasureRow
		if err = rows.Scan(
			&row.jobID,
			&row.installationLookup,
			&row.encrypted,
			&row.attempts,
			&row.retryExponent,
			&row.expiresAt,
		); err != nil {
			_ = rows.Close()
			return nil, ErrDeliveryQueueUnavailable
		}
		encryptedRows = append(encryptedRows, row)
	}
	if err = rows.Close(); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if err = rows.Err(); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	claimed := make([]ClaimedDeliveryJob, 0, len(encryptedRows))
	for _, row := range encryptedRows {
		if len(row.installationLookup) != 32 {
			return nil, ErrDeliveryQueueUnavailable
		}
		plaintext, openErr := s.encryption.Open(
			deliveryJobContext(row.jobID),
			row.encrypted,
		)
		if openErr != nil {
			return nil, ErrDeliveryQueueUnavailable
		}
		var job SerializedDeliveryJob
		decodeErr := json.Unmarshal(plaintext, &job)
		zero(plaintext)
		if decodeErr != nil ||
			validateErasureMarker(job) != nil ||
			!job.Expiration.UTC().Equal(row.expiresAt.UTC()) {
			return nil, ErrDeliveryQueueUnavailable
		}
		if _, err = tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.delivery_jobs
				    SET state = $1,
				        available_at = $2
				  WHERE job_id = $3
				    AND environment = $4`,
			erasureJobClaimed,
			claimDeadline,
			row.jobID,
			s.environmentID,
		); err != nil {
			return nil, ErrDeliveryQueueUnavailable
		}
		nextRetryExponent := int(row.retryExponent) + 1
		if nextRetryExponent > maxErasureRetryExponent {
			nextRetryExponent = maxErasureRetryExponent
		}
		claimed = append(claimed, ClaimedDeliveryJob{
			JobID: append([]byte(nil), row.jobID...),
			InstallationLookup: append(
				[]byte(nil),
				row.installationLookup...,
			),
			Job:           cloneSerializedDeliveryJob(job),
			Attempts:      int(row.attempts),
			RetryExponent: nextRetryExponent,
			ExpiresAt:     row.expiresAt.UTC(),
		})
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	return claimed, nil
}

func (s *Store) RescheduleDeliveryJob(
	ctx context.Context,
	jobID []byte,
	attempts int,
	availableAt time.Time,
) error {
	if s == nil || s.db == nil || len(jobID) != 16 || attempts <= 0 {
		return ErrDeliveryJobInvalid
	}
	now := s.now().UTC()
	if attempts >= MaxDeliveryAttempts {
		return s.FinalizeDeliveryJob(
			ctx,
			jobID,
			DeliveryFinalRetryExhausted,
		)
	}
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
		    SET state = $1, available_at = $3
		  WHERE job_id = $4
		    AND state = $5
			    AND attempts = $2
			    AND expires_at > $6
			    AND $3 < expires_at
			    AND environment = $7`,
		deliveryJobPending,
		attempts,
		availableAt.UTC(),
		jobID,
		deliveryJobClaimed,
		now,
		s.environmentID,
	)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if updated == 0 {
		return s.FinalizeDeliveryJob(
			ctx,
			jobID,
			DeliveryFinalTTLExpired,
		)
	}
	return nil
}

// ConvertInvalidTokenToErasure atomically blocks the destination, removes
// every other queued delivery for the installation, and replaces the original
// APNS payload with a minimal encrypted token-verification marker.
func (s *Store) ConvertInvalidTokenToErasure(
	ctx context.Context,
	jobID []byte,
	failedDeviceToken string,
	trafficClass DeliveryTrafficClass,
	availableAt time.Time,
) ([]byte, error) {
	failedToken, decodeErr := hex.DecodeString(failedDeviceToken)
	if s == nil || s.db == nil || s.encryption == nil ||
		len(jobID) != 16 || decodeErr != nil || len(failedToken) != 32 ||
		(trafficClass != DeliveryTrafficConversation &&
			trafficClass != DeliveryTrafficWelcome) {
		return nil, ErrDeliveryJobInvalid
	}
	defer zero(failedToken)
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	var installationLookup []byte
	var encryptedCurrentToken []byte
	var expiresAt time.Time
	err = tx.QueryRowContext(
		ctx,
		`SELECT leases.installation_lookup,
		        states.encrypted_apns_token, jobs.expires_at
		   FROM hytch_push_vault.delivery_jobs AS jobs
		   JOIN hytch_push_vault.subscription_leases AS leases
		     ON leases.lease_id = jobs.lease_id
			   JOIN hytch_push_vault.installation_states AS states
			     ON states.installation_lookup = leases.installation_lookup
			  WHERE jobs.job_id = $1
			    AND jobs.state = $2
			    AND jobs.environment = $3
			    AND leases.environment = $3
			    AND states.environment = $3
			  FOR UPDATE OF jobs, leases, states`,
		jobID,
		deliveryJobClaimed,
		s.environmentID,
	).Scan(
		&installationLookup,
		&encryptedCurrentToken,
		&expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	currentToken, err := s.encryption.Open(
		installationContext(installationLookup, "apns-token"),
		encryptedCurrentToken,
	)
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	defer zero(currentToken)
	if len(currentToken) != len(failedToken) ||
		subtle.ConstantTimeCompare(currentToken, failedToken) != 1 {
		if _, err = s.markDeliveryJobFinalTx(
			ctx,
			tx,
			jobID,
			DeliveryFinalSafetyInvalidated,
		); err != nil {
			return nil, ErrDeliveryQueueUnavailable
		}
		if err = tx.Commit(); err != nil {
			return nil, ErrDeliveryQueueUnavailable
		}
		if err = s.completeDeliveryFinalization(ctx, jobID); err != nil {
			return nil, ErrDeliveryFinalizationPending
		}
		return nil, nil
	}
	marker := SerializedDeliveryJob{
		DeviceToken:  failedDeviceToken,
		Expiration:   expiresAt.UTC(),
		TrafficClass: trafficClass,
		EraseOnly:    true,
	}
	plaintext, err := json.Marshal(marker)
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	defer zero(plaintext)
	encryptedMarker, err := s.encryption.Seal(
		deliveryJobContext(jobID),
		plaintext,
	)
	if err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.installation_states
			    SET state = $1, revoked_at = COALESCE(revoked_at, $2)
			  WHERE installation_lookup = $3
			    AND environment = $4`,
		stateBlocked,
		now,
		installationLookup,
		s.environmentID,
	); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.subscription_leases
			    SET state = $1, revoked_at = COALESCE(revoked_at, $2)
			  WHERE installation_lookup = $3
			    AND environment = $4`,
		stateBlocked,
		now,
		installationLookup,
		s.environmentID,
	); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if err = s.markDeliveryJobsSafetyForInstallationTx(
		ctx,
		tx,
		installationLookup,
		jobID,
	); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.delivery_jobs
			  WHERE installation_lookup = $1
			    AND job_id <> $2
			    AND environment = $3`,
		installationLookup,
		jobID,
		s.environmentID,
	); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
		    SET lease_id = NULL,
		        installation_lookup = $1,
		        encrypted_job = $2,
		        state = $3,
		        attempts = 0,
		        retry_exponent = 0,
		        available_at = $4,
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
			  WHERE job_id = $5
			    AND environment = $6`,
		installationLookup,
		encryptedMarker,
		erasureJobPending,
		availableAt.UTC(),
		jobID,
		s.environmentID,
	); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrDeliveryQueueUnavailable
	}
	if err = s.finalizeDeliveryMarkers(ctx); err != nil {
		return nil, ErrDeliveryFinalizationPending
	}
	return append([]byte(nil), installationLookup...), nil
}

func (s *Store) RescheduleInvalidTokenErasure(
	ctx context.Context,
	jobID []byte,
	availableAt time.Time,
) error {
	if s == nil || s.db == nil || len(jobID) != 16 {
		return ErrDeliveryJobInvalid
	}
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
			    SET state = $1,
			        retry_exponent = LEAST(retry_exponent + 1, $2),
			        available_at = $3
			  WHERE job_id = $4
			    AND state = $5
			    AND environment = $6`,
		erasureJobPending,
		maxErasureRetryExponent,
		availableAt.UTC(),
		jobID,
		erasureJobClaimed,
		s.environmentID,
	)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if affected == 0 {
		return nil
	}
	if err = markOverdueErasureUnsafe(
		ctx,
		tx,
		s.environmentID,
		now,
	); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}

func (s *Store) ReleaseDeliveryJob(ctx context.Context, jobID []byte) error {
	if s == nil || s.db == nil || s.encryption == nil || len(jobID) != 16 {
		return ErrDeliveryJobInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	var exhausted bool
	if err = tx.QueryRowContext(
		ctx,
		`SELECT EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.delivery_jobs
		      WHERE job_id = $1
		        AND state = $2
		        AND attempts >= $3
		        AND environment = $4
		      FOR UPDATE
		 )`,
		jobID,
		deliveryJobClaimed,
		MaxDeliveryAttempts,
		s.environmentID,
	).Scan(&exhausted); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if exhausted {
		if _, err = s.markDeliveryJobFinalTx(
			ctx,
			tx,
			jobID,
			DeliveryFinalRetryExhausted,
		); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.delivery_jobs
		    SET state = CASE state
		          WHEN $1::SMALLINT THEN $2::SMALLINT
		          WHEN $3::SMALLINT THEN $4::SMALLINT
			        END,
			        available_at = LEAST(available_at, $5)
			  WHERE job_id = $6
			    AND state IN ($1, $3)
			    AND environment = $7`,
		deliveryJobClaimed,
		deliveryJobPending,
		erasureJobClaimed,
		erasureJobPending,
		s.now().UTC(),
		jobID,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if err = tx.Commit(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if exhausted {
		return s.completeDeliveryFinalization(ctx, jobID)
	}
	return nil
}

func (s *Store) DeleteErasureJob(ctx context.Context, jobID []byte) error {
	if s == nil || s.db == nil || len(jobID) != 16 {
		return ErrDeliveryJobInvalid
	}
	if _, err := s.db.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1
			    AND state IN ($2, $3)
			    AND environment = $4`,
		jobID,
		erasureJobPending,
		erasureJobClaimed,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}

// EraseInvalidAPNSToken compares against the current installation token and
// removes matching token ciphertext, routes, wrapped per-value keys, and
// normal queued work in one transaction. The caller deletes the independent
// erasure marker only after this succeeds; physical installation deletion also
// cascades it because no token ciphertext can remain then. PostgreSQL page/WAL
// reclamation and backup expiry remain separate retention controls.
func (s *Store) EraseInvalidAPNSToken(
	ctx context.Context,
	installationLookup []byte,
	failedDeviceToken string,
) error {
	failedToken, decodeErr := hex.DecodeString(failedDeviceToken)
	if s == nil || s.db == nil || s.encryption == nil ||
		len(installationLookup) != 32 ||
		decodeErr != nil || len(failedToken) != 32 {
		return ErrDeliveryJobInvalid
	}
	defer zero(failedToken)
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if err = requireLookupKeyBoundTx(
		ctx,
		tx,
		s.lookup,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}

	var installationIdentity []byte
	var encryptedCurrentToken []byte
	var installationPolicyEpoch int64
	var installationKeyVersion int64
	err = tx.QueryRowContext(
		ctx,
		`SELECT installation_identity, encrypted_apns_token,
		        policy_epoch, encryption_key_version
			   FROM hytch_push_vault.installation_states
			  WHERE installation_lookup = $1
			    AND environment = $2
			  FOR UPDATE`,
		installationLookup,
		s.environmentID,
	).Scan(
		&installationIdentity,
		&encryptedCurrentToken,
		&installationPolicyEpoch,
		&installationKeyVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if len(encryptedCurrentToken) == 0 {
		return nil
	}
	currentToken, err := s.encryption.Open(
		installationContext(installationLookup, "apns-token"),
		encryptedCurrentToken,
	)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	defer zero(currentToken)
	if len(currentToken) != len(failedToken) ||
		subtle.ConstantTimeCompare(currentToken, failedToken) != 1 {
		return nil
	}

	rows, err := tx.QueryContext(
		ctx,
		`SELECT route_identity, route_key_epoch, encryption_key_version
			   FROM hytch_push_vault.subscription_leases
			  WHERE installation_lookup = $1
			    AND environment = $2
			  FOR UPDATE`,
		installationLookup,
		s.environmentID,
	)
	if err != nil {
		return ErrDeliveryQueueUnavailable
	}
	type routeHistory struct {
		identity             []byte
		epoch                int64
		encryptionKeyVersion int64
	}
	var routeHistories []routeHistory
	for rows.Next() {
		var identity []byte
		var routeEpoch int64
		var encryptionKeyVersion int64
		if err = rows.Scan(
			&identity,
			&routeEpoch,
			&encryptionKeyVersion,
		); err != nil {
			_ = rows.Close()
			return ErrDeliveryQueueUnavailable
		}
		routeHistories = append(routeHistories, routeHistory{
			identity:             append([]byte(nil), identity...),
			epoch:                routeEpoch,
			encryptionKeyVersion: encryptionKeyVersion,
		})
	}
	if err = rows.Close(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if err = rows.Err(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	for _, history := range routeHistories {
		if history.epoch <= 0 ||
			history.epoch > maxRouteKeyEpoch ||
			history.encryptionKeyVersion <= 0 ||
			history.encryptionKeyVersion >
				int64(maxDeletionTombstoneKeyVersion) ||
			retireRouteKeyHistory(
				ctx,
				tx,
				s.environmentID,
				history.identity,
				uint32(history.epoch),
				now,
			) != nil {
			return ErrDeliveryQueueUnavailable
		}
		if err = upsertDeletionTombstone(
			ctx,
			tx,
			s.environmentID,
			deletionTargetRoute,
			history.identity,
			uint32(history.encryptionKeyVersion),
			uint64(history.epoch),
			now,
		); err != nil {
			return ErrDeliveryQueueUnavailable
		}
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.installation_states
		    SET encrypted_apns_token = NULL,
		        state = $1,
		        revoked_at = COALESCE(revoked_at, $2),
			        expires_at = LEAST(expires_at, $2),
			        control_expires_at = LEAST(control_expires_at, $2)
			  WHERE installation_lookup = $3
			    AND environment = $4`,
		stateBlocked,
		now,
		installationLookup,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if err = s.markDeliveryJobsSafetyForInstallationTx(
		ctx,
		tx,
		installationLookup,
		nil,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.subscription_leases
			  WHERE installation_lookup = $1
			    AND environment = $2`,
		installationLookup,
		s.environmentID,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if len(installationIdentity) != 32 ||
		installationPolicyEpoch <= 0 ||
		uint64(installationPolicyEpoch) >
			maxInstallationTombstoneFenceEpoch ||
		installationKeyVersion <= 0 ||
		installationKeyVersion >
			int64(maxDeletionTombstoneKeyVersion) {
		return ErrDeliveryQueueUnavailable
	}
	if err = upsertDeletionTombstone(
		ctx,
		tx,
		s.environmentID,
		deletionTargetInstallation,
		installationIdentity,
		uint32(installationKeyVersion),
		uint64(installationPolicyEpoch),
		now,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	if err = tx.Commit(); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return s.finalizeDeliveryMarkers(ctx)
}

func validateSerializedDeliveryJob(
	job SerializedDeliveryJob,
	now time.Time,
) error {
	if job.EraseOnly {
		return ErrDeliveryJobInvalid
	}
	token, err := hex.DecodeString(job.DeviceToken)
	defer zero(token)
	if err != nil || len(token) != 32 ||
		len(job.Topic) == 0 || len(job.Topic) > 256 ||
		len(job.Payload) == 0 || len(job.Payload) >= 4096 ||
		job.PolicyEpoch == 0 ||
		job.PolicyEpoch > gate8wrapper.MaxCanonicalInteger ||
		job.RouteKeyEpoch == 0 ||
		job.DeliverySequence > gate8wrapper.MaxCanonicalInteger ||
		job.AliasDay != gate8wrapper.UTCDay(now) ||
		len(job.RouteAlias) != gate8wrapper.RouteAliasSize ||
		job.Expiration.IsZero() ||
		!job.Expiration.UTC().After(now.UTC()) {
		return ErrDeliveryJobInvalid
	}
	if (len(job.ProviderTopic) == 0) != (job.A9 == nil) {
		return ErrDeliveryJobInvalid
	}
	if job.A9 != nil &&
		(len(job.ProviderTopic) != 33 ||
			job.TrafficClass != DeliveryTrafficConversation ||
			job.Expiration.UTC().After(
				job.A9.AssertionExpiresAt.UTC(),
			) ||
			!validA9RouteSnapshot(job.A9, job.RouteKeyEpoch, now)) {
		return ErrDeliveryJobInvalid
	}
	switch job.TrafficClass {
	case DeliveryTrafficConversation:
		if job.PushType != "alert" || job.Priority != 10 ||
			len(job.WelcomeAuthorizationID) != 0 ||
			len(job.WelcomeEnvelopeDigest) != 0 {
			return ErrDeliveryJobInvalid
		}
	case DeliveryTrafficWelcome:
		if job.PushType != "background" || job.Priority != 5 ||
			len(job.WelcomeAuthorizationID) != 16 ||
			len(job.WelcomeEnvelopeDigest) != sha256.Size {
			return ErrDeliveryJobInvalid
		}
	default:
		return ErrDeliveryJobInvalid
	}
	return nil
}

func validA9RouteSnapshot(
	snapshot *interfaces.A9RouteSnapshot,
	routeKeyEpoch uint32,
	now time.Time,
) bool {
	return snapshot != nil &&
		snapshot.SubscriptionGeneration > 0 &&
		snapshot.SubscriptionGeneration <= gate8wrapper.MaxCanonicalInteger &&
		snapshot.BindingVersion > 0 &&
		snapshot.BindingVersion <= gate8wrapper.MaxCanonicalInteger &&
		snapshot.AssertionStreamSequence > 0 &&
		snapshot.AssertionStreamSequence <=
			gate8wrapper.MaxCanonicalInteger &&
		snapshot.TopicKeyEpoch > 0 &&
		snapshot.RouteKeyEpoch > 0 &&
		snapshot.RouteKeyEpoch == routeKeyEpoch &&
		snapshot.KeysetSequence > 0 &&
		snapshot.KeysetSequence <= gate8wrapper.MaxCanonicalInteger &&
		snapshot.WatermarkSequence > 0 &&
		snapshot.WatermarkSequence <= gate8wrapper.MaxCanonicalInteger &&
		!snapshot.AssertionExpiresAt.IsZero() &&
		snapshot.AssertionExpiresAt.UTC().After(now.UTC())
}

func validateErasureMarker(job SerializedDeliveryJob) error {
	token, err := hex.DecodeString(job.DeviceToken)
	defer zero(token)
	if !job.EraseOnly || err != nil || len(token) != 32 ||
		job.Topic != "" || len(job.Payload) != 0 ||
		job.PushType != "" || job.Priority != 0 ||
		job.PolicyEpoch != 0 || job.RouteKeyEpoch != 0 ||
		job.NoncePrefix != 0 || job.DeliverySequence != 0 ||
		job.AliasDay != "" || len(job.RouteAlias) != 0 ||
		len(job.ProviderTopic) != 0 || job.A9 != nil ||
		len(job.WelcomeAuthorizationID) != 0 ||
		len(job.WelcomeEnvelopeDigest) != 0 ||
		(job.TrafficClass != DeliveryTrafficConversation &&
			job.TrafficClass != DeliveryTrafficWelcome) ||
		job.Expiration.IsZero() {
		return ErrDeliveryJobInvalid
	}
	return nil
}

func cloneSerializedDeliveryJob(job SerializedDeliveryJob) SerializedDeliveryJob {
	return SerializedDeliveryJob{
		DeviceToken:      job.DeviceToken,
		Topic:            job.Topic,
		ProviderTopic:    append([]byte(nil), job.ProviderTopic...),
		Payload:          append([]byte(nil), job.Payload...),
		PushType:         job.PushType,
		Priority:         job.Priority,
		Expiration:       job.Expiration.UTC(),
		TrafficClass:     job.TrafficClass,
		PolicyEpoch:      job.PolicyEpoch,
		RouteKeyEpoch:    job.RouteKeyEpoch,
		NoncePrefix:      job.NoncePrefix,
		DeliverySequence: job.DeliverySequence,
		AliasDay:         job.AliasDay,
		RouteAlias:       append([]byte(nil), job.RouteAlias...),
		WelcomeAuthorizationID: append(
			[]byte(nil),
			job.WelcomeAuthorizationID...,
		),
		WelcomeEnvelopeDigest: append(
			[]byte(nil),
			job.WelcomeEnvelopeDigest...,
		),
		A9:        cloneA9RouteSnapshot(job.A9),
		EraseOnly: job.EraseOnly,
	}
}

func cloneA9RouteSnapshot(
	snapshot *interfaces.A9RouteSnapshot,
) *interfaces.A9RouteSnapshot {
	if snapshot == nil {
		return nil
	}
	cloned := *snapshot
	return &cloned
}

func deliveryJobContext(jobID []byte) []byte {
	return vaultContext("delivery-job", jobID, "apns-request")
}

func (s *Store) deliverySourceEventLookup(
	leaseID []byte,
	trafficClass DeliveryTrafficClass,
	sourceEventID string,
) ([]byte, error) {
	if len(leaseID) != 16 || len(sourceEventID) == 0 {
		return nil, ErrDeliveryJobInvalid
	}
	input := make([]byte, 0, len(leaseID)+len(sourceEventID)+10)
	input = append(input, leaseID...)
	input = append(input, byte(trafficClass))
	input = binary.BigEndian.AppendUint64(input, uint64(len(sourceEventID)))
	input = append(input, sourceEventID...)
	return s.lookup.Digest("delivery-source-event", 0, input)
}

func markOverdueErasureUnsafe(
	ctx context.Context,
	tx *sql.Tx,
	environmentID int16,
	now time.Time,
) error {
	if tx == nil ||
		(environmentID != environmentDevelopment &&
			environmentID != environmentProduction) {
		return ErrDeliveryQueueUnavailable
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.retention_state
		    SET is_safe = FALSE, fixed_outcome = $2
		  WHERE environment = $1
		    AND EXISTS (
		      SELECT 1
		        FROM hytch_push_vault.delivery_jobs
		       WHERE environment = $1
		         AND state IN ($3, $4)
		         AND created_at + INTERVAL '15 minutes' <= $5
		    )`,
		environmentID,
		retentionOutcomeUnsafe,
		erasureJobPending,
		erasureJobClaimed,
		now,
	); err != nil {
		return ErrDeliveryQueueUnavailable
	}
	return nil
}
