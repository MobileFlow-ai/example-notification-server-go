package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestDeliveryJobStoreEncryptedBoundedLifecycleAndPersistentErasure(t *testing.T) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	keyring, err := NewKeyring(1, map[uint32][]byte{
		1: repeatedBytes(32, 0x41),
	})
	require.NoError(t, err)
	keyring.random = &sequenceReader{}
	lookup, err := NewLookupKey(repeatedBytes(32, 0x42))
	require.NoError(t, err)
	store := &Store{
		db:                db,
		encryption:        keyring,
		lookup:            lookup,
		environment:       "dev",
		environmentID:     environmentDevelopment,
		lookupEnvironment: "development",
		now:               func() time.Time { return now },
		random:            &sequenceReader{},
	}
	sweeper, err := NewRetentionSweeper(db, RetentionOptions{
		Environment:          "dev",
		Lookup:               lookup,
		EncryptionKeyVersion: keyring.ActiveVersion(),
		Now:                  func() time.Time { return now },
	})
	require.NoError(t, err)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)

	installationLookup := repeatedBytes(32, 0x11)
	leaseID := repeatedBytes(16, 0x12)
	currentToken := repeatedBytes(32, 0x31)
	encryptedCurrentToken, err := keyring.Seal(
		installationContext(installationLookup, "apns-token"),
		currentToken,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.installation_states (
		     installation_lookup, incarnation_lookup, lookup_key_epoch,
		     generation, idempotency_digest, control_event_digest,
		     encrypted_apns_token, environment, payload_schema, age_policy,
		     policy_epoch, state, encryption_key_version, created_at,
		     refreshed_at, expires_at, control_expires_at,
		     installation_identity
		 ) VALUES ($1,$2,1,1,$3,$4,$5,1,1,1,1,2,1,$6,$6,$7,$8,$9)`,
		installationLookup,
		repeatedBytes(32, 0x13),
		repeatedBytes(32, 0x14),
		repeatedBytes(32, 0x15),
		encryptedCurrentToken,
		now,
		now.Add(7*24*time.Hour),
		now.Add(45*time.Second),
		repeatedBytes(32, 0x10),
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.subscription_leases (
		     lease_id, installation_lookup, installation_identity,
		     topic_lookup, lookup_key_epoch,
		     encrypted_topic, encrypted_route_key, encrypted_hmac_keys,
		     encrypted_receive_capability, environment, payload_schema,
		     topic_kind, push_mode, state, generation, policy_epoch,
		     route_key_epoch, encrypted_nonce_state, encryption_key_version,
		     issued_at, refreshed_at, expires_at, control_expires_at,
		     route_identity
		 ) VALUES (
		     $1,$2,$9,$3,1,$4,$4,$4,$4,1,1,1,2,2,1,1,1,$4,1,
		     $5,$5,$6,$7,$8
		 )`,
		leaseID,
		installationLookup,
		repeatedBytes(32, 0x16),
		[]byte{2},
		now,
		now.Add(7*24*time.Hour),
		now.Add(45*time.Second),
		repeatedBytes(32, 0x1b),
		repeatedBytes(32, 0x10),
	)
	require.NoError(t, err)

	welcomeLeaseID := repeatedBytes(16, 0x17)
	suppressedConversationLeaseID := repeatedBytes(16, 0x18)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.subscription_leases (
		     lease_id, installation_lookup, installation_identity,
		     topic_lookup, lookup_key_epoch,
		     encrypted_topic, encrypted_route_key, encrypted_hmac_keys,
		     encrypted_receive_capability, environment, payload_schema,
		     topic_kind, push_mode, state, generation, policy_epoch,
		     route_key_epoch, encrypted_nonce_state, encryption_key_version,
		     issued_at, refreshed_at, expires_at, control_expires_at,
		     route_identity
		 ) VALUES
		   ($1,$2,$12,$3,1,$4,$4,$4,$4,1,1,2,1,4,1,1,1,$4,1,
		    $5,$5,$6,$7,$10),
		   ($8,$2,$12,$9,1,$4,$4,$4,$4,1,1,1,1,4,1,1,1,$4,1,
		    $5,$5,$6,$7,$11)`,
		welcomeLeaseID,
		installationLookup,
		repeatedBytes(32, 0x19),
		[]byte{2},
		now,
		now.Add(7*24*time.Hour),
		now.Add(45*time.Second),
		suppressedConversationLeaseID,
		repeatedBytes(32, 0x1a),
		repeatedBytes(32, 0x1c),
		repeatedBytes(32, 0x1d),
		repeatedBytes(32, 0x10),
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.route_key_history (
		     environment, route_identity, route_key_epoch,
		     route_key_commitment,
		     updated_at, expires_at
		 ) VALUES
		   ($9,$1,1,$4,$7,$8),
		   ($9,$2,1,$5,$7,$8),
		   ($9,$3,1,$6,$7,$8)`,
		repeatedBytes(32, 0x1b),
		repeatedBytes(32, 0x1c),
		repeatedBytes(32, 0x1d),
		repeatedBytes(32, 0x2b),
		repeatedBytes(32, 0x2c),
		repeatedBytes(32, 0x2d),
		now,
		now.Add(15*24*time.Hour),
		store.environmentID,
	)
	require.NoError(t, err)
	const noncePrefix = uint32(0x01020304)
	for _, id := range [][]byte{
		leaseID,
		welcomeLeaseID,
		suppressedConversationLeaseID,
	} {
		nonceCiphertext, nonceErr := keyring.Seal(
			leaseContext(id, "nonce-state"),
			encodeNonceState(nonceState{
				Prefix:       noncePrefix,
				NextSequence: 1,
			}),
		)
		require.NoError(t, nonceErr)
		_, nonceErr = db.ExecContext(
			t.Context(),
			`UPDATE hytch_push_vault.subscription_leases
			    SET encrypted_nonce_state = $1
			  WHERE lease_id = $2`,
			nonceCiphertext,
			id,
		)
		require.NoError(t, nonceErr)
	}

	job := SerializedDeliveryJob{
		DeviceToken:      hex.EncodeToString(currentToken),
		Topic:            "com.example.app",
		Payload:          []byte(`{"hytch_wrapper":{"header":"exact","ciphertext":"exact"}}`),
		PushType:         "alert",
		Priority:         10,
		Expiration:       now.Add(10 * time.Minute),
		TrafficClass:     DeliveryTrafficConversation,
		PolicyEpoch:      1,
		RouteKeyEpoch:    1,
		NoncePrefix:      noncePrefix,
		DeliverySequence: 0,
		AliasDay:         gate8wrapper.UTCDay(now),
		RouteAlias:       repeatedBytes(gate8wrapper.RouteAliasSize, 0x2e),
	}
	welcomeJob := job
	welcomeJob.PushType = "background"
	welcomeJob.Priority = 5
	welcomeJob.TrafficClass = DeliveryTrafficWelcome
	welcomeJob.Expiration = now.Add(45 * time.Second)
	welcomeJob.WelcomeAuthorizationID = repeatedBytes(16, 0x2f)
	welcomeJob.WelcomeEnvelopeDigest = repeatedBytes(32, 0x30)

	// Simulate one Welcome job persisted by a pre-hard-close build. The current
	// kill switch must reject it at the final authority boundary without
	// spending an APNS attempt, even though the claim was already reserved.
	t.Run("hard-closed Welcome invalidates persisted queued work", func(t *testing.T) {
		persistedWelcomeJobID := repeatedBytes(16, 0x2e)
		serializedWelcome, marshalErr := json.Marshal(welcomeJob)
		require.NoError(t, marshalErr)
		encryptedWelcome, sealErr := keyring.Seal(
			deliveryJobContext(persistedWelcomeJobID),
			serializedWelcome,
		)
		require.NoError(t, sealErr)
		_, insertErr := db.ExecContext(
			t.Context(),
			`INSERT INTO hytch_push_vault.delivery_jobs (
			     job_id, lease_id, encrypted_job, environment,
			     state, attempts, available_at, expires_at, created_at,
			     traffic_class
			 ) VALUES ($1,$2,$3,$4,$5,0,$6,$7,$6,$8)`,
			persistedWelcomeJobID,
			welcomeLeaseID,
			encryptedWelcome,
			store.environmentID,
			deliveryJobPending,
			now,
			welcomeJob.Expiration,
			int16(DeliveryTrafficWelcome),
		)
		require.NoError(t, insertErr)

		claimedWelcome, claimErr := store.ClaimDeliveryJobs(
			t.Context(),
			1,
			2*time.Second,
		)
		require.NoError(t, claimErr)
		require.Len(t, claimedWelcome, 1)
		require.Equal(t, persistedWelcomeJobID, claimedWelcome[0].JobID)
		attemptGuard, valid, acquireErr := store.AcquireDeliveryAttempt(
			t.Context(),
			claimedWelcome[0],
		)
		require.NoError(t, acquireErr)
		require.False(t, valid)
		require.Nil(t, attemptGuard)
		var persistedAttempts int
		require.NoError(t, db.QueryRowContext(
			t.Context(),
			`SELECT attempts
			   FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1`,
			persistedWelcomeJobID,
		).Scan(&persistedAttempts))
		require.Zero(t, persistedAttempts)
		require.NoError(t, store.FinalizeDeliveryJob(
			t.Context(),
			persistedWelcomeJobID,
			DeliveryFinalSafetyInvalidated,
		))
	})

	// The same opaque source event remains domain-separated across Welcome and
	// conversation leases/traffic classes.
	const sharedSourceEvent = "opaque-source-event"
	_, err = store.EnqueueDeliveryJob(
		t.Context(),
		suppressedConversationLeaseID,
		job,
		"suppressed-conversation-source",
		10,
	)
	require.ErrorIs(t, err, ErrDeliveryJobInvalid)
	mismatchedWelcome := welcomeJob
	mismatchedWelcome.PushType = "alert"
	mismatchedWelcome.Priority = 10
	_, err = store.EnqueueDeliveryJob(
		t.Context(),
		welcomeLeaseID,
		mismatchedWelcome,
		"mismatched-welcome-source",
		10,
	)
	require.ErrorIs(t, err, ErrDeliveryJobInvalid)

	jobID, err := store.EnqueueDeliveryJob(
		t.Context(),
		leaseID,
		job,
		sharedSourceEvent,
		1,
	)
	require.NoError(t, err)
	require.Len(t, jobID, 16)
	duplicateJobID, err := store.EnqueueDeliveryJob(
		t.Context(),
		leaseID,
		job,
		sharedSourceEvent,
		1,
	)
	require.NoError(t, err)
	require.Nil(t, duplicateJobID)

	var encrypted []byte
	var storedExpiry time.Time
	var storedAttempts int
	var storedState int16
	var storedLeaseID []byte
	var storedInstallationLookup []byte
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT encrypted_job, expires_at, attempts, state
			   FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1`,
			jobID,
		).Scan(&encrypted, &storedExpiry, &storedAttempts, &storedState),
	)
	require.NotContains(t, encrypted, []byte(job.DeviceToken))
	require.NotContains(t, encrypted, job.Payload)
	require.Equal(t, now.Add(45*time.Second), storedExpiry.UTC())
	require.Zero(t, storedAttempts)
	require.Equal(t, deliveryJobPending, storedState)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.delivery_jobs
		    SET state = $1
		  WHERE job_id = $2`,
		erasureJobPending,
		jobID,
	)
	require.Error(t, err)

	conversationLookup, err := store.deliverySourceEventLookup(
		leaseID,
		DeliveryTrafficConversation,
		sharedSourceEvent,
	)
	require.NoError(t, err)
	welcomeLookup, err := store.deliverySourceEventLookup(
		welcomeLeaseID,
		DeliveryTrafficWelcome,
		sharedSourceEvent,
	)
	require.NoError(t, err)
	require.Len(t, conversationLookup, 32)
	require.Len(t, welcomeLookup, 32)
	require.NotEqual(t, conversationLookup, welcomeLookup)
	require.False(t, bytes.Contains(conversationLookup, []byte(sharedSourceEvent)))
	var dedupeCount int
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FROM hytch_push_vault.delivery_dedupes`,
		).Scan(&dedupeCount),
	)
	require.Equal(t, 1, dedupeCount)
	// Even an exact lookup collision is partitioned by traffic class in the
	// database key, so it cannot suppress a different delivery semantic.
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.delivery_dedupes (
			     lease_id, source_event_lookup, environment, traffic_class,
			     created_at, expires_at
			 ) VALUES ($1,$2,$3,$4,$5,$6)`,
		leaseID,
		conversationLookup,
		store.environmentID,
		int16(DeliveryTrafficWelcome),
		now,
		now.Add(maxDeliveryJobLifetime),
	)
	require.NoError(t, err)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FROM hytch_push_vault.delivery_dedupes`,
		).Scan(&dedupeCount),
	)
	require.Equal(t, 2, dedupeCount)

	_, err = store.EnqueueDeliveryJob(
		t.Context(),
		leaseID,
		job,
		"new-source-while-full",
		1,
	)
	require.ErrorIs(t, err, ErrDeliveryQueueFull)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FROM hytch_push_vault.delivery_dedupes`,
		).Scan(&dedupeCount),
	)
	require.Equal(t, 2, dedupeCount)
	var (
		queueAcceptedCells     int
		queueBackpressureCells int
		otherEnvironmentCells  int
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
		     COUNT(*) FILTER (WHERE outcome = $1),
		     COUNT(*) FILTER (WHERE outcome = $2),
		     COUNT(*) FILTER (WHERE environment <> $3)
		   FROM hytch_push_vault.operational_aggregates
		  WHERE event_name = $4`,
		DeliveryOutcomeQueueAccepted,
		DeliveryOutcomeQueueBackpressure,
		store.environmentID,
		aggregateEventDeliveryQueue,
	).Scan(
		&queueAcceptedCells,
		&queueBackpressureCells,
		&otherEnvironmentCells,
	))
	require.Equal(t, 1, queueAcceptedCells)
	require.Equal(t, 1, queueBackpressureCells)
	require.Zero(t, otherEnvironmentCells)

	// A valid queued job cannot be claimed, and therefore cannot reach APNS,
	// while the shared retention guard is unsafe.
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.retention_state
		    SET is_safe = FALSE, fixed_outcome = $1
		  WHERE environment = $2`,
		retentionOutcomeUnsafe,
		store.environmentID,
	)
	require.NoError(t, err)
	claimed, err := store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.ErrorIs(t, err, ErrDeliveryQueueUnavailable)
	require.Empty(t, claimed)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT attempts, state
			   FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1`,
			jobID,
		).Scan(&storedAttempts, &storedState),
	)
	require.Zero(t, storedAttempts)
	require.Equal(t, deliveryJobPending, storedState)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.retention_state
		    SET next_deadline_at = $1
		  WHERE environment = $2`,
		now.Add(-time.Second),
		store.environmentID,
	)
	require.NoError(t, err)
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.ErrorIs(t, err, ErrDeliveryQueueUnavailable)
	require.Empty(t, claimed)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT attempts, state
			   FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1`,
			jobID,
		).Scan(&storedAttempts, &storedState),
	)
	require.Zero(t, storedAttempts)
	require.Equal(t, deliveryJobPending, storedState)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)

	// Claiming reserves work without spending an APNS attempt. The final
	// authority guard records an attempt only after egress is invoked, so a
	// graceful shutdown before egress can release even the third reservation
	// without losing the job.
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, 1, claimed[0].Attempts)
	require.Equal(t, job.Payload, claimed[0].Job.Payload)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT attempts, state
			   FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1`,
			jobID,
		).Scan(&storedAttempts, &storedState),
	)
	require.Zero(t, storedAttempts)
	require.Equal(t, deliveryJobClaimed, storedState)
	validClaim, err := store.ValidateDeliveryClaim(
		t.Context(),
		claimed[0],
	)
	require.NoError(t, err)
	require.True(t, validClaim)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.installation_states
		    SET state = $1
		  WHERE installation_lookup = $2`,
		stateBlocked,
		installationLookup,
	)
	require.NoError(t, err)
	validClaim, err = store.ValidateDeliveryClaim(
		t.Context(),
		claimed[0],
	)
	require.NoError(t, err)
	require.False(t, validClaim)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.installation_states
		    SET state = $1
		  WHERE installation_lookup = $2`,
		stateActive,
		installationLookup,
	)
	require.NoError(t, err)
	require.NoError(t, store.ReleaseDeliveryJob(t.Context(), jobID))
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, 1, claimed[0].Attempts)
	attemptGuard, validClaim, err := store.AcquireDeliveryAttempt(
		t.Context(),
		claimed[0],
	)
	require.NoError(t, err)
	require.True(t, validClaim)
	require.NotNil(t, attemptGuard)
	require.NoError(t, attemptGuard.RecordAttempt(t.Context()))
	now = now.Add(3 * time.Second)
	require.NoError(t, store.RecoverDeliveryJobs(t.Context()))
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, 2, claimed[0].Attempts)
	require.Equal(t, job.Payload, claimed[0].Job.Payload)
	attemptGuard, validClaim, err = store.AcquireDeliveryAttempt(
		t.Context(),
		claimed[0],
	)
	require.NoError(t, err)
	require.True(t, validClaim)
	require.NoError(t, attemptGuard.RecordAttempt(t.Context()))
	now = now.Add(3 * time.Second)
	require.NoError(t, store.RecoverDeliveryJobs(t.Context()))
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, MaxDeliveryAttempts, claimed[0].Attempts)
	attemptGuard, validClaim, err = store.AcquireDeliveryAttempt(
		t.Context(),
		claimed[0],
	)
	require.NoError(t, err)
	require.True(t, validClaim)
	require.NoError(t, attemptGuard.RecordAttempt(t.Context()))
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT attempts, state
			   FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1`,
			jobID,
		).Scan(&storedAttempts, &storedState),
	)
	require.Equal(t, MaxDeliveryAttempts, storedAttempts)
	require.Equal(t, deliveryJobClaimed, storedState)
	now = now.Add(3 * time.Second)
	require.NoError(t, store.RecoverDeliveryJobs(t.Context()))
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.NoError(t, err)
	require.Empty(t, claimed)
	var deliveryCount int
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FROM hytch_push_vault.delivery_jobs`,
		).Scan(&deliveryCount),
	)
	require.Zero(t, deliveryCount)

	// Dedupe outlives successful/exhausted job deletion, so a redelivered
	// stream event cannot recreate the APNS job inside the 15-minute window.
	duplicateJobID, err = store.EnqueueDeliveryJob(
		t.Context(),
		leaseID,
		job,
		sharedSourceEvent,
		1,
	)
	require.NoError(t, err)
	require.Nil(t, duplicateJobID)

	retryJobID, err := store.EnqueueDeliveryJob(
		t.Context(),
		leaseID,
		job,
		"transient-source-event",
		1,
	)
	require.NoError(t, err)
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, 1, claimed[0].Attempts)
	attemptGuard, validClaim, err = store.AcquireDeliveryAttempt(
		t.Context(),
		claimed[0],
	)
	require.NoError(t, err)
	require.True(t, validClaim)
	require.NoError(t, attemptGuard.RecordAttempt(t.Context()))
	require.NoError(
		t,
		store.RescheduleDeliveryJob(
			t.Context(),
			retryJobID,
			claimed[0].Attempts,
			now.Add(2*time.Second),
		),
	)
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.NoError(t, err)
	require.Empty(t, claimed)
	now = now.Add(2 * time.Second)
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, 2, claimed[0].Attempts)
	require.NoError(t, store.FinalizeDeliveryJob(
		t.Context(),
		retryJobID,
		DeliveryFinalSafetyInvalidated,
	))

	invalidJobID, err := store.EnqueueDeliveryJob(
		t.Context(),
		leaseID,
		job,
		"invalid-token-source-event",
		1,
	)
	require.NoError(t, err)
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, 1, claimed[0].Attempts)
	attemptGuard, validClaim, err = store.AcquireDeliveryAttempt(
		t.Context(),
		claimed[0],
	)
	require.NoError(t, err)
	require.True(t, validClaim)
	require.NoError(t, attemptGuard.RecordAttempt(t.Context()))
	convertedInstallationLookup, err := store.ConvertInvalidTokenToErasure(
		t.Context(),
		invalidJobID,
		job.DeviceToken,
		job.TrafficClass,
		now,
	)
	require.NoError(t, err)
	require.Equal(t, installationLookup, convertedInstallationLookup)

	var installationState int16
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT state
			   FROM hytch_push_vault.installation_states
			  WHERE installation_lookup = $1`,
			installationLookup,
		).Scan(&installationState),
	)
	require.Equal(t, stateBlocked, installationState)
	var blockedLeases int
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*)
			   FROM hytch_push_vault.subscription_leases
			  WHERE installation_lookup = $1 AND state = $2`,
			installationLookup,
			stateBlocked,
		).Scan(&blockedLeases),
	)
	require.Equal(t, 3, blockedLeases)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT attempts, state, lease_id, installation_lookup
			   FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1`,
			invalidJobID,
		).Scan(
			&storedAttempts,
			&storedState,
			&storedLeaseID,
			&storedInstallationLookup,
		),
	)
	require.Zero(t, storedAttempts)
	require.Equal(t, erasureJobPending, storedState)
	require.Nil(t, storedLeaseID)
	require.Equal(t, installationLookup, storedInstallationLookup)

	rotatedInstallationLookup := repeatedBytes(32, 0x1b)
	rotatedCurrentTokenCiphertext, err := keyring.Seal(
		installationContext(rotatedInstallationLookup, "apns-token"),
		currentToken,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.installation_states
		    SET installation_lookup = $1,
		        encrypted_apns_token = $2
		  WHERE installation_lookup = $3`,
		rotatedInstallationLookup,
		rotatedCurrentTokenCiphertext,
		installationLookup,
	)
	require.NoError(t, err)
	installationLookup = rotatedInstallationLookup
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT installation_lookup
			   FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1`,
			invalidJobID,
		).Scan(&storedInstallationLookup),
	)
	require.Equal(t, installationLookup, storedInstallationLookup)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.delivery_jobs
		    SET available_at = $1
		  WHERE job_id = $2`,
		now.Add(10*time.Minute),
		invalidJobID,
	)
	require.NoError(t, err)
	require.NoError(t, store.RecoverInvalidTokenErasures(t.Context()))

	erasureClaims, err := store.ClaimErasureJobs(
		t.Context(),
		1,
		2*time.Second,
	)
	require.NoError(t, err)
	require.Len(t, erasureClaims, 1)
	require.Zero(t, erasureClaims[0].Attempts)
	require.Equal(t, 1, erasureClaims[0].RetryExponent)
	require.Equal(
		t,
		installationLookup,
		erasureClaims[0].InstallationLookup,
	)
	require.True(t, erasureClaims[0].Job.EraseOnly)
	require.Equal(t, job.DeviceToken, erasureClaims[0].Job.DeviceToken)
	require.Empty(t, erasureClaims[0].Job.Topic)
	require.Empty(t, erasureClaims[0].Job.Payload)
	require.Empty(t, erasureClaims[0].Job.PushType)
	require.NoError(
		t,
		store.RescheduleInvalidTokenErasure(
			t.Context(),
			invalidJobID,
			now,
		),
	)
	for _, expectedRetryExponent := range []int{2, 3, 4} {
		erasureClaims, err = store.ClaimErasureJobs(
			t.Context(),
			1,
			2*time.Second,
		)
		require.NoError(t, err)
		require.Len(t, erasureClaims, 1)
		require.Zero(t, erasureClaims[0].Attempts)
		require.Equal(
			t,
			expectedRetryExponent,
			erasureClaims[0].RetryExponent,
		)
		require.True(t, erasureClaims[0].Job.EraseOnly)
		require.Empty(t, erasureClaims[0].Job.Payload)
		require.NoError(
			t,
			store.RescheduleInvalidTokenErasure(
				t.Context(),
				invalidJobID,
				now,
			),
		)
	}
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1 AND state = $2`,
			invalidJobID,
			erasureJobPending,
		).Scan(&deliveryCount),
	)
	require.Equal(t, 1, deliveryCount)

	// Erasure retries survive the original 15-minute delivery lifetime. An
	// unresolved marker older than 15 minutes makes retention/readiness unsafe,
	// while the deletion path itself remains callable to restore safety.
	now = now.Add(16 * time.Minute)
	_, err = sweeper.Sweep(t.Context())
	require.ErrorIs(t, err, ErrRetentionUnsafe)
	require.ErrorIs(t, store.RequireRetentionSafe(t.Context()), ErrRetentionUnsafe)
	claimed, err = store.ClaimDeliveryJobs(t.Context(), 1, 2*time.Second)
	require.ErrorIs(t, err, ErrDeliveryQueueUnavailable)
	require.Empty(t, claimed)
	erasureClaims, err = store.ClaimErasureJobs(
		t.Context(),
		1,
		2*time.Second,
	)
	require.NoError(t, err)
	require.Len(t, erasureClaims, 1)
	require.Zero(t, erasureClaims[0].Attempts)
	require.Equal(t, 5, erasureClaims[0].RetryExponent)
	require.Empty(t, erasureClaims[0].Job.Payload)
	require.NoError(
		t,
		store.RescheduleInvalidTokenErasure(
			t.Context(),
			invalidJobID,
			now,
		),
	)

	// The marker has atomically moved from its lease locator to the
	// installation locator. Removing the original lease therefore cannot
	// abandon the unresolved erasure.
	_, err = db.ExecContext(
		t.Context(),
		`DELETE FROM hytch_push_vault.subscription_leases
		  WHERE lease_id = $1`,
		leaseID,
	)
	require.NoError(t, err)
	require.NoError(t, store.RecoverDeliveryJobs(t.Context()))
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1
			    AND lease_id IS NULL
			    AND installation_lookup = $2`,
			invalidJobID,
			installationLookup,
		).Scan(&deliveryCount),
	)
	require.Equal(t, 1, deliveryCount)

	replacementToken := repeatedBytes(32, 0x32)
	encryptedReplacementToken, err := keyring.Seal(
		installationContext(installationLookup, "apns-token"),
		replacementToken,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.installation_states
		    SET encrypted_apns_token = $1,
		        encryption_key_version = 19
		  WHERE installation_lookup = $2`,
		encryptedReplacementToken,
		installationLookup,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.subscription_leases
		    SET encryption_key_version = CASE route_identity
		          WHEN $1 THEN 17
		          ELSE 18
		        END
		  WHERE installation_lookup = $2`,
		repeatedBytes(32, 0x1c),
		installationLookup,
	)
	require.NoError(t, err)

	require.NoError(
		t,
		store.EraseInvalidAPNSToken(
			t.Context(),
			installationLookup,
			job.DeviceToken,
		),
	)
	var token []byte
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT encrypted_apns_token, state
			   FROM hytch_push_vault.installation_states
			  WHERE installation_lookup = $1`,
			installationLookup,
		).Scan(&token, &installationState),
	)
	require.NotEmpty(t, token)
	require.Equal(t, stateBlocked, installationState)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1`,
			invalidJobID,
		).Scan(&deliveryCount),
	)
	require.Equal(t, 1, deliveryCount)

	require.NoError(
		t,
		store.EraseInvalidAPNSToken(
			t.Context(),
			installationLookup,
			hex.EncodeToString(replacementToken),
		),
	)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT encrypted_apns_token, state
			   FROM hytch_push_vault.installation_states
			  WHERE installation_lookup = $1`,
			installationLookup,
		).Scan(&token, &installationState),
	)
	require.Nil(t, token)
	require.Equal(t, stateBlocked, installationState)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1`,
			invalidJobID,
		).Scan(&deliveryCount),
	)
	require.Equal(t, 1, deliveryCount)
	require.NoError(t, store.DeleteErasureJob(t.Context(), invalidJobID))
	for _, table := range []string{
		"subscription_leases",
		"delivery_jobs",
		"delivery_dedupes",
	} {
		var count int
		require.NoError(
			t,
			db.QueryRowContext(
				t.Context(),
				`SELECT COUNT(*) FROM hytch_push_vault.`+table,
			).Scan(&count),
		)
		require.Zero(t, count)
	}
	var (
		tombstones int
		keyVersion int32
		fenceEpoch int64
	)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*), MIN(key_version), MIN(fence_epoch)
				   FROM hytch_push_vault.deletion_tombstones
				  WHERE target_kind = $1
				    AND target_identity = $2`,
			deletionTargetInstallation,
			repeatedBytes(32, 0x10),
		).Scan(&tombstones, &keyVersion, &fenceEpoch),
	)
	require.Equal(t, 1, tombstones)
	require.Equal(t, int32(19), keyVersion)
	require.Equal(t, int64(1), fenceEpoch)
	for _, route := range []struct {
		identity   []byte
		keyVersion int32
	}{
		{identity: repeatedBytes(32, 0x1c), keyVersion: 17},
		{identity: repeatedBytes(32, 0x1d), keyVersion: 18},
	} {
		require.NoError(
			t,
			db.QueryRowContext(
				t.Context(),
				`SELECT key_version, fence_epoch
				   FROM hytch_push_vault.deletion_tombstones
				  WHERE target_kind = $1
				    AND target_identity = $2`,
				deletionTargetRoute,
				route.identity,
			).Scan(&keyVersion, &fenceEpoch),
		)
		require.Equal(t, route.keyVersion, keyVersion)
		require.Equal(t, int64(1), fenceEpoch)
	}
}
