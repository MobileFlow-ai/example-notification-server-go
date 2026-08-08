package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

const (
	aggregateEventSafetyControl int16 = 1
	aggregateEventLeaseRefresh  int16 = 2
	aggregateEventDeliveryFinal int16 = 3
	aggregateEventDeliveryQueue int16 = 4
	aggregateEventDeliveryRate  int16 = 5

	aggregateComponentBridge int16 = 1

	aggregateOutcomeActive  int16 = 1
	aggregateOutcomeRevoked int16 = 2

	aggregatePrivacyVersion int16 = 2
	maxCountBucket          int16 = 7
)

var ErrAggregateInvalid = errors.New("operational aggregate invalid")

// DeliveryObservationEvent is a fixed operational dimension. Values are
// deliberately closed: callers cannot supply labels, identifiers, provider
// reasons, or arbitrary metric names.
type DeliveryObservationEvent uint8

const (
	DeliveryObservationTerminal DeliveryObservationEvent = iota + 1
	DeliveryObservationQueue
	DeliveryObservationRateLimit
)

// DeliveryObservationOutcome is interpreted together with Event. Keeping the
// outcome set fixed prevents APNS reason strings and other provider-controlled
// values from entering the operational aggregate.
type DeliveryObservationOutcome uint8

const (
	DeliveryOutcomeTerminalRejected DeliveryObservationOutcome = iota + 1
	DeliveryOutcomeRetryExhausted
	DeliveryOutcomeTTLExpired
	DeliveryOutcomeQueueAccepted
	DeliveryOutcomeQueueBackpressure
	DeliveryOutcomeRateDelayed
	DeliveryOutcomeRateCancelled
	DeliveryOutcomeSafetyInvalidated
	DeliveryOutcomeMaterialInvalid
)

// DeliveryObservationBucket is a coarse ordinal only. Depending on Event it
// represents an attempt stage, queue-utilization band, remaining-lifetime
// band, or rate-wait band. Exact counts and durations are never accepted.
type DeliveryObservationBucket uint8

const (
	DeliveryBucketMinimal DeliveryObservationBucket = iota
	DeliveryBucketLow
	DeliveryBucketModerate
	DeliveryBucketHigh
	DeliveryBucketCritical
)

// DeliveryObservation contains only allowlisted, dimensionless enums. It has
// no field capable of carrying a job ID, route alias, token, APNS reason,
// payload size, exact count, or timestamp.
type DeliveryObservation struct {
	Event           DeliveryObservationEvent
	Outcome         DeliveryObservationOutcome
	TrafficClass    DeliveryTrafficClass
	ThresholdBucket DeliveryObservationBucket
	LatencyBucket   DeliveryObservationBucket
}

// DeliveryObservationRecorder is narrow enough for APNS rate-pressure
// instrumentation without granting delivery workers access to vault data.
type DeliveryObservationRecorder interface {
	RecordDeliveryObservation(
		ctx context.Context,
		observation DeliveryObservation,
	) error
}

type operationalAggregateObservation struct {
	eventName     int16
	outcome       int16
	trafficClass  int16
	sizeBucket    *int16
	latencyBucket int16
}

// RecordOperationalAggregate accepts only fixed dimensionless enums. It never
// accepts a label, ID, raw count, exact size, or exact duration. Cells remain
// inside the vault and are retained for at most 30 days.
func (s *Store) RecordOperationalAggregate(
	ctx context.Context,
	eventName int16,
	outcome int16,
	latencyBucket int16,
) error {
	if s == nil || s.db == nil ||
		(eventName != aggregateEventSafetyControl &&
			eventName != aggregateEventLeaseRefresh) ||
		(outcome != aggregateOutcomeActive &&
			outcome != aggregateOutcomeRevoked) ||
		latencyBucket < 0 || latencyBucket > 4 {
		return ErrAggregateInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if err = s.recordOperationalAggregateTx(
		ctx,
		tx,
		operationalAggregateObservation{
			eventName:     eventName,
			outcome:       outcome,
			trafficClass:  0,
			latencyBucket: latencyBucket,
		},
		s.now().UTC(),
	); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

// RecordDeliveryObservation stores one privacy-safe, approximate operational
// observation. Delivery correctness never depends on this best-effort public
// wrapper; terminal failure paths use the transaction-bound helper below.
func (s *Store) RecordDeliveryObservation(
	ctx context.Context,
	observation DeliveryObservation,
) error {
	if s == nil || s.db == nil || !validDeliveryObservation(observation) {
		return ErrAggregateInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if err = s.recordDeliveryObservationTx(
		ctx,
		tx,
		observation,
		s.now().UTC(),
	); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *Store) recordDeliveryObservationTx(
	ctx context.Context,
	tx *sql.Tx,
	observation DeliveryObservation,
	now time.Time,
) error {
	if !validDeliveryObservation(observation) {
		return ErrAggregateInvalid
	}
	eventName := int16(0)
	switch observation.Event {
	case DeliveryObservationTerminal:
		eventName = aggregateEventDeliveryFinal
	case DeliveryObservationQueue:
		eventName = aggregateEventDeliveryQueue
	case DeliveryObservationRateLimit:
		eventName = aggregateEventDeliveryRate
	default:
		return ErrAggregateInvalid
	}
	sizeBucket := int16(observation.ThresholdBucket)
	return s.recordOperationalAggregateTx(
		ctx,
		tx,
		operationalAggregateObservation{
			eventName:     eventName,
			outcome:       int16(observation.Outcome),
			trafficClass:  int16(observation.TrafficClass),
			sizeBucket:    &sizeBucket,
			latencyBucket: int16(observation.LatencyBucket),
		},
		now.UTC(),
	)
}

func (s *Store) recordOperationalAggregateTx(
	ctx context.Context,
	tx *sql.Tx,
	observation operationalAggregateObservation,
	now time.Time,
) error {
	if s == nil || tx == nil ||
		(s.environmentID != environmentDevelopment &&
			s.environmentID != environmentProduction) ||
		!validOperationalAggregateObservation(observation) ||
		now.IsZero() {
		return ErrAggregateInvalid
	}
	now = now.UTC()
	bucketDay := now.Truncate(24 * time.Hour)
	bucketHour := int16(now.Hour())
	expiresOn := bucketDay.AddDate(0, 0, 30)
	var sizeBucket any
	if observation.sizeBucket != nil {
		sizeBucket = *observation.sizeBucket
	}
	result, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.operational_aggregates (
		     bucket_day, bucket_hour, event_name, component, environment,
		     traffic_class, outcome, count_bucket, size_bucket,
		     latency_bucket, privacy_version, expires_on
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$11)
		 ON CONFLICT (
		     bucket_day, bucket_hour, event_name, component, environment,
		     traffic_class, outcome, privacy_version
		 ) DO NOTHING`,
		bucketDay,
		bucketHour,
		observation.eventName,
		aggregateComponentBridge,
		s.environmentID,
		observation.trafficClass,
		observation.outcome,
		sizeBucket,
		observation.latencyBucket,
		aggregatePrivacyVersion,
		expiresOn,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return ErrStoreUnavailable
	}
	if inserted == 1 {
		return nil
	}

	var currentBucket int16
	if err = tx.QueryRowContext(
		ctx,
		`SELECT count_bucket
		   FROM hytch_push_vault.operational_aggregates
		  WHERE bucket_day = $1
		    AND bucket_hour = $2
		    AND event_name = $3
		    AND component = $4
		    AND environment = $5
		    AND traffic_class = $6
		    AND outcome = $7
		    AND privacy_version = $8
		  FOR UPDATE`,
		bucketDay,
		bucketHour,
		observation.eventName,
		aggregateComponentBridge,
		s.environmentID,
		observation.trafficClass,
		observation.outcome,
		aggregatePrivacyVersion,
	).Scan(&currentBucket); err != nil {
		return ErrStoreUnavailable
	}
	promote, err := randomizedAggregatePromotion(
		currentBucket,
		s.aggregateEntropy(),
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	nextBucket := currentBucket
	if promote && nextBucket < maxCountBucket {
		nextBucket++
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.operational_aggregates
		    SET count_bucket = $9,
		        size_bucket = CASE
		            WHEN $10::SMALLINT IS NULL THEN size_bucket
		            ELSE GREATEST(COALESCE(size_bucket, 0), $10)
		        END,
		        latency_bucket = GREATEST(latency_bucket, $11)
		  WHERE bucket_day = $1
		    AND bucket_hour = $2
		    AND event_name = $3
		    AND component = $4
		    AND environment = $5
		    AND traffic_class = $6
		    AND outcome = $7
		    AND privacy_version = $8`,
		bucketDay,
		bucketHour,
		observation.eventName,
		aggregateComponentBridge,
		s.environmentID,
		observation.trafficClass,
		observation.outcome,
		aggregatePrivacyVersion,
		nextBucket,
		sizeBucket,
		observation.latencyBucket,
	); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *Store) aggregateEntropy() io.Reader {
	if s != nil && s.aggregateRandom != nil {
		return s.aggregateRandom
	}
	return rand.Reader
}

func validOperationalAggregateObservation(
	observation operationalAggregateObservation,
) bool {
	if observation.eventName < aggregateEventSafetyControl ||
		observation.eventName > aggregateEventDeliveryRate ||
		observation.outcome <= 0 ||
		observation.trafficClass < 0 ||
		observation.trafficClass > int16(DeliveryTrafficWelcome) ||
		observation.latencyBucket < int16(DeliveryBucketMinimal) ||
		observation.latencyBucket > int16(DeliveryBucketCritical) {
		return false
	}
	if observation.sizeBucket != nil &&
		(*observation.sizeBucket < int16(DeliveryBucketMinimal) ||
			*observation.sizeBucket > int16(DeliveryBucketCritical)) {
		return false
	}
	return true
}

func validDeliveryObservation(observation DeliveryObservation) bool {
	if observation.TrafficClass != DeliveryTrafficUnknown &&
		observation.TrafficClass != DeliveryTrafficConversation &&
		observation.TrafficClass != DeliveryTrafficWelcome {
		return false
	}
	if observation.ThresholdBucket > DeliveryBucketCritical ||
		observation.LatencyBucket > DeliveryBucketCritical {
		return false
	}
	switch observation.Event {
	case DeliveryObservationTerminal:
		if observation.ThresholdBucket < DeliveryBucketLow ||
			observation.ThresholdBucket > DeliveryBucketHigh {
			return false
		}
		switch observation.Outcome {
		case DeliveryOutcomeSafetyInvalidated,
			DeliveryOutcomeMaterialInvalid:
			return true
		case DeliveryOutcomeTerminalRejected,
			DeliveryOutcomeRetryExhausted,
			DeliveryOutcomeTTLExpired:
			return observation.TrafficClass != DeliveryTrafficUnknown
		default:
			return false
		}
	case DeliveryObservationQueue:
		if observation.TrafficClass == DeliveryTrafficUnknown ||
			observation.LatencyBucket != DeliveryBucketMinimal {
			return false
		}
		return observation.Outcome == DeliveryOutcomeQueueAccepted ||
			observation.Outcome == DeliveryOutcomeQueueBackpressure
	case DeliveryObservationRateLimit:
		if observation.TrafficClass == DeliveryTrafficUnknown ||
			observation.ThresholdBucket != DeliveryBucketMinimal {
			return false
		}
		return observation.Outcome == DeliveryOutcomeRateDelayed ||
			observation.Outcome == DeliveryOutcomeRateCancelled
	default:
		return false
	}
}

// randomizedAggregatePromotion is a bounded Morris-style approximate counter.
// Bucket b advances with probability 2^-b and saturates at seven. The vault
// therefore never persists the exact event count, even internally.
func randomizedAggregatePromotion(
	currentBucket int16,
	entropy io.Reader,
) (bool, error) {
	if currentBucket < 1 || currentBucket > maxCountBucket ||
		entropy == nil {
		return false, ErrAggregateInvalid
	}
	if currentBucket == maxCountBucket {
		return false, nil
	}
	var raw [2]byte
	if _, err := io.ReadFull(entropy, raw[:]); err != nil {
		return false, err
	}
	draw := uint32(binary.BigEndian.Uint16(raw[:]))
	threshold := uint32(1) << uint32(16-currentBucket)
	return draw < threshold, nil
}

func revocationLatencyBucket(value time.Duration) int16 {
	switch {
	case value <= 0:
		return 0
	case value <= 30*time.Second:
		return 1
	case value <= time.Minute:
		return 2
	case value <= 2*time.Minute:
		return 3
	default:
		return 4
	}
}
