package vault

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

type deliveryFinalizationFixture struct {
	signed *signedStoreFixture
	db     *sql.DB
	jobID  []byte
	job    SerializedDeliveryJob
	claim  ClaimedDeliveryJob
}

func newDeliveryFinalizationFixture(
	t *testing.T,
	claim bool,
) deliveryFinalizationFixture {
	t.Helper()
	requireVaultIntegrationTests(t)
	fixture, database := newSignedStoreFixture(t)
	period := uint32(688)
	conversation := testTopic(
		t,
		topicpkg.TopicKindGroupMessagesV1,
		0x7a,
	)
	welcome := testTopic(
		t,
		topicpkg.TopicKindWelcomeMessagesV1,
		0x7c,
	)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	request := fixture.refresh(
		t,
		1,
		control,
		fixture.subscription(
			t,
			conversation,
			0x7b,
			1,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		fixture.subscription(
			t,
			welcome,
			0x7d,
			1,
			period,
			authority.PushModeSuppressed,
			1,
		),
	)
	_, err := fixture.store.Refresh(t.Context(), request)
	require.NoError(t, err)
	subscriptions, err := fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.NoError(t, err)
	require.Len(t, subscriptions, 1)
	route := subscriptions[0].SecureRoute
	require.NotNil(t, route)
	job := SerializedDeliveryJob{
		DeviceToken:      hex.EncodeToString(request.APNSToken),
		Topic:            "com.example.hytch.dev",
		Payload:          []byte(`{"aps":{"alert":"fixed test wakeup"}}`),
		PushType:         "alert",
		Priority:         10,
		Expiration:       fixture.now.Add(20 * time.Second),
		TrafficClass:     DeliveryTrafficConversation,
		PolicyEpoch:      route.PolicyEpoch,
		RouteKeyEpoch:    route.RouteKeyEpoch,
		NoncePrefix:      route.NoncePrefix,
		DeliverySequence: route.DeliverySequence,
		AliasDay:         route.AliasDay,
		RouteAlias:       append([]byte(nil), route.RouteAlias...),
	}
	jobID, err := fixture.store.EnqueueDeliveryJob(
		t.Context(),
		route.LeaseID,
		job,
		"delivery-finalization-source",
		10,
	)
	require.NoError(t, err)
	result := deliveryFinalizationFixture{
		signed: fixture,
		db:     database,
		jobID:  jobID,
		job:    job,
	}
	if claim {
		claimed, claimErr := fixture.store.ClaimDeliveryJobs(
			t.Context(),
			1,
			2*time.Second,
		)
		require.NoError(t, claimErr)
		require.Len(t, claimed, 1)
		result.claim = claimed[0]
	}
	return result
}

func requireDeliveryFinalAggregate(
	t *testing.T,
	fixture deliveryFinalizationFixture,
	outcome DeliveryObservationOutcome,
) {
	t.Helper()
	var count int
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.operational_aggregates
		  WHERE event_name = $1
		    AND component = $2
		    AND environment = $3
		    AND traffic_class = $4
		    AND outcome = $5
		    AND privacy_version = $6`,
		aggregateEventDeliveryFinal,
		aggregateComponentBridge,
		environmentDevelopment,
		DeliveryTrafficConversation,
		outcome,
		aggregatePrivacyVersion,
	).Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.operational_aggregates
		  WHERE event_name = $1
		    AND environment <> $2`,
		aggregateEventDeliveryFinal,
		environmentDevelopment,
	).Scan(&count))
	require.Zero(t, count)
}

func TestTerminalAggregateFailureLeavesNonSendablePayloadFreeMarker(
	t *testing.T,
) {
	fixture := newDeliveryFinalizationFixture(t, true)
	guard, valid, err := fixture.signed.store.AcquireDeliveryAttempt(
		t.Context(),
		fixture.claim,
	)
	require.NoError(t, err)
	require.True(t, valid)
	require.NotNil(t, guard)

	_, err = fixture.db.ExecContext(
		t.Context(),
		`CREATE FUNCTION hytch_push_vault.reject_test_delivery_final()
		 RETURNS trigger
		 LANGUAGE plpgsql
		 AS $$
		 BEGIN
		   IF NEW.event_name = 3 THEN
		     RAISE EXCEPTION 'forced aggregate failure';
		   END IF;
		   RETURN NEW;
		 END
		 $$`,
	)
	require.NoError(t, err)
	_, err = fixture.db.ExecContext(
		t.Context(),
		`CREATE TRIGGER reject_test_delivery_final
		   BEFORE INSERT OR UPDATE
		   ON hytch_push_vault.operational_aggregates
		   FOR EACH ROW
		   EXECUTE FUNCTION hytch_push_vault.reject_test_delivery_final()`,
	)
	require.NoError(t, err)
	dropFailureTrigger := func() {
		_, _ = fixture.db.ExecContext(
			t.Context(),
			`DROP TRIGGER IF EXISTS reject_test_delivery_final
			   ON hytch_push_vault.operational_aggregates`,
		)
		_, _ = fixture.db.ExecContext(
			t.Context(),
			`DROP FUNCTION IF EXISTS
			   hytch_push_vault.reject_test_delivery_final()`,
		)
	}
	t.Cleanup(dropFailureTrigger)

	err = guard.Complete(t.Context(), DeliveryAttemptResult{
		Outcome: DeliveryAttemptRejected,
	})
	require.ErrorIs(t, err, ErrDeliveryQueueUnavailable)

	var (
		encrypted          []byte
		state              int16
		attempts           int16
		trafficClass       int16
		finalReason        int16
		leaseID            []byte
		installationLookup []byte
	)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT encrypted_job, state, attempts, traffic_class, final_reason,
		        lease_id, installation_lookup
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		fixture.jobID,
	).Scan(
		&encrypted,
		&state,
		&attempts,
		&trafficClass,
		&finalReason,
		&leaseID,
		&installationLookup,
	))
	require.Equal(t, []byte{0}, encrypted)
	require.False(t, bytes.Contains(encrypted, fixture.job.Payload))
	require.False(t, bytes.Contains(encrypted, []byte(fixture.job.DeviceToken)))
	require.Equal(t, deliveryJobFinal, state)
	require.Equal(t, int16(1), attempts)
	require.Equal(t, int16(DeliveryTrafficConversation), trafficClass)
	require.Equal(t, int16(DeliveryFinalTerminalRejected), finalReason)
	require.Nil(t, leaseID)
	require.Nil(t, installationLookup)

	claimed, claimErr := fixture.signed.store.ClaimDeliveryJobs(
		t.Context(),
		1,
		2*time.Second,
	)
	require.ErrorIs(t, claimErr, ErrDeliveryQueueUnavailable)
	require.Empty(t, claimed)

	dropFailureTrigger()
	require.NoError(t, fixture.signed.store.RecoverDeliveryJobs(t.Context()))
	var remaining int
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		fixture.jobID,
	).Scan(&remaining))
	require.Zero(t, remaining)
	requireDeliveryFinalAggregate(
		t,
		fixture,
		DeliveryOutcomeTerminalRejected,
	)
}

func TestProductionStoreFinalizesRecoveryAndInvalidationReasons(t *testing.T) {
	t.Run("retry exhausted", func(t *testing.T) {
		fixture := newDeliveryFinalizationFixture(t, true)
		_, err := fixture.db.ExecContext(
			t.Context(),
			`UPDATE hytch_push_vault.delivery_jobs
			    SET attempts = $1, available_at = $2
			  WHERE job_id = $3`,
			MaxDeliveryAttempts,
			fixture.signed.now.Add(-time.Second),
			fixture.jobID,
		)
		require.NoError(t, err)
		require.NoError(
			t,
			fixture.signed.store.RecoverDeliveryJobs(t.Context()),
		)
		requireDeliveryFinalAggregate(
			t,
			fixture,
			DeliveryOutcomeRetryExhausted,
		)
	})

	t.Run("ttl expired", func(t *testing.T) {
		fixture := newDeliveryFinalizationFixture(t, false)
		*fixture.signed.now = fixture.signed.now.Add(21 * time.Second)
		require.NoError(
			t,
			fixture.signed.store.RecoverDeliveryJobs(t.Context()),
		)
		requireDeliveryFinalAggregate(
			t,
			fixture,
			DeliveryOutcomeTTLExpired,
		)
	})

	t.Run("safety invalidated", func(t *testing.T) {
		fixture := newDeliveryFinalizationFixture(t, true)
		require.NoError(t, fixture.signed.store.FinalizeDeliveryJob(
			t.Context(),
			fixture.jobID,
			DeliveryFinalSafetyInvalidated,
		))
		requireDeliveryFinalAggregate(
			t,
			fixture,
			DeliveryOutcomeSafetyInvalidated,
		)
	})

	t.Run("invalid material", func(t *testing.T) {
		fixture := newDeliveryFinalizationFixture(t, false)
		_, err := fixture.db.ExecContext(
			t.Context(),
			`UPDATE hytch_push_vault.delivery_jobs
			    SET encrypted_job = $1
			  WHERE job_id = $2`,
			[]byte("corrupt"),
			fixture.jobID,
		)
		require.NoError(t, err)
		claimed, claimErr := fixture.signed.store.ClaimDeliveryJobs(
			t.Context(),
			1,
			2*time.Second,
		)
		require.NoError(t, claimErr)
		require.Empty(t, claimed)
		requireDeliveryFinalAggregate(
			t,
			fixture,
			DeliveryOutcomeMaterialInvalid,
		)
	})
}

func TestDeliveryRateObservationsAreFixedAndEnvironmentScoped(t *testing.T) {
	requireVaultIntegrationTests(t)
	database := testdb.CreateTestDb(t)
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	development := &Store{
		db:              database,
		environmentID:   environmentDevelopment,
		now:             func() time.Time { return now },
		aggregateRandom: &sequenceReader{},
	}
	production := &Store{
		db:              database,
		environmentID:   environmentProduction,
		now:             func() time.Time { return now },
		aggregateRandom: &sequenceReader{},
	}
	delayed := DeliveryObservation{
		Event:           DeliveryObservationRateLimit,
		Outcome:         DeliveryOutcomeRateDelayed,
		TrafficClass:    DeliveryTrafficConversation,
		ThresholdBucket: DeliveryBucketMinimal,
		LatencyBucket:   DeliveryBucketHigh,
	}
	cancelled := DeliveryObservation{
		Event:           DeliveryObservationRateLimit,
		Outcome:         DeliveryOutcomeRateCancelled,
		TrafficClass:    DeliveryTrafficWelcome,
		ThresholdBucket: DeliveryBucketMinimal,
		LatencyBucket:   DeliveryBucketCritical,
	}
	require.NoError(
		t,
		development.RecordDeliveryObservation(t.Context(), delayed),
	)
	require.NoError(
		t,
		development.RecordDeliveryObservation(t.Context(), cancelled),
	)
	require.NoError(
		t,
		production.RecordDeliveryObservation(t.Context(), delayed),
	)

	var (
		developmentDelayed   int
		developmentCancelled int
		productionDelayed    int
		productionCancelled  int
	)
	require.NoError(t, database.QueryRowContext(
		t.Context(),
		`SELECT
		     COUNT(*) FILTER (
		       WHERE environment = $1 AND outcome = $3
		     ),
		     COUNT(*) FILTER (
		       WHERE environment = $1 AND outcome = $4
		     ),
		     COUNT(*) FILTER (
		       WHERE environment = $2 AND outcome = $3
		     ),
		     COUNT(*) FILTER (
		       WHERE environment = $2 AND outcome = $4
		     )
		   FROM hytch_push_vault.operational_aggregates
		  WHERE event_name = $5`,
		environmentDevelopment,
		environmentProduction,
		DeliveryOutcomeRateDelayed,
		DeliveryOutcomeRateCancelled,
		aggregateEventDeliveryRate,
	).Scan(
		&developmentDelayed,
		&developmentCancelled,
		&productionDelayed,
		&productionCancelled,
	))
	require.Equal(t, 1, developmentDelayed)
	require.Equal(t, 1, developmentCancelled)
	require.Equal(t, 1, productionDelayed)
	require.Zero(t, productionCancelled)
}

func TestRetentionSweepCommitsBoundedFinalizationProgress(t *testing.T) {
	requireVaultIntegrationTests(t)
	database := testdb.CreateTestDb(t)
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	keyring, err := NewKeyring(1, map[uint32][]byte{
		1: repeatedBytes(32, 0x51),
	})
	require.NoError(t, err)
	lookup, err := NewLookupKey(repeatedBytes(32, 0x52))
	require.NoError(t, err)
	store := &Store{
		db:              database,
		encryption:      keyring,
		environment:     "development",
		environmentID:   environmentDevelopment,
		now:             func() time.Time { return now },
		aggregateRandom: &sequenceReader{},
	}
	sweeper, err := NewRetentionSweeper(
		database,
		RetentionOptions{
			SweepInterval:        15 * time.Minute,
			Environment:          "development",
			Lookup:               lookup,
			EncryptionKeyVersion: keyring.ActiveVersion(),
			Now:                  func() time.Time { return now },
		},
	)
	require.NoError(t, err)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)

	const remainder = 5
	markerCount := retentionDeliveryFinalizationBatchSize + remainder
	_, err = database.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.delivery_jobs (
		     job_id, encrypted_job, environment, state, attempts,
		     retry_exponent, available_at, expires_at, created_at,
		     traffic_class, final_reason
		 )
		 SELECT
		     decode(md5('retention-final-' || marker_number::TEXT), 'hex'),
		     decode('00', 'hex'),
		     $1,
		     $2,
		     1,
		     0,
		     $3,
		     $4,
		     $3,
		     $5,
		     $6
		   FROM generate_series(1, $7) AS marker_number`,
		environmentDevelopment,
		deliveryJobFinal,
		now,
		now.Add(10*time.Minute),
		DeliveryTrafficUnknown,
		DeliveryFinalSafetyInvalidated,
		markerCount,
	)
	require.NoError(t, err)

	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)
	require.NoError(t, sweeper.Ready(t.Context()))

	var (
		remainingMarkers int
		unsafeRows       int
	)
	require.NoError(t, database.QueryRowContext(
		t.Context(),
		`SELECT
		     COUNT(*),
		     COUNT(*) FILTER (
		       WHERE state <> $1
		          OR encrypted_job <> decode('00', 'hex')
		          OR lease_id IS NOT NULL
		          OR installation_lookup IS NOT NULL
		          OR retry_exponent <> 0
		          OR traffic_class IS NULL
		          OR final_reason IS NULL
		     )
		   FROM hytch_push_vault.delivery_jobs
		  WHERE environment = $2`,
		deliveryJobFinal,
		environmentDevelopment,
	).Scan(&remainingMarkers, &unsafeRows))
	require.Equal(t, remainder, remainingMarkers)
	require.Zero(t, unsafeRows)

	require.NoError(t, store.RecoverDeliveryJobs(t.Context()))
	require.NoError(t, database.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.delivery_jobs
		  WHERE environment = $1`,
		environmentDevelopment,
	).Scan(&remainingMarkers))
	require.Zero(t, remainingMarkers)
}
