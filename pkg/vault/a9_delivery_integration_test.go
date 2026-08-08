package vault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a9api"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

var (
	_ A9Trust                   = (*a9DeliveryTrustStub)(nil)
	_ a9trust.TopicBindingLease = (*a9DeliveryTopicBindingLease)(nil)
)

type a9DeliveryTrustStub struct {
	mu               sync.Mutex
	sequence         uint64
	hash             [32]byte
	providerTopic    []byte
	topicKeyEpoch    uint32
	assertionExpires time.Time
	binding          [32]byte
	acquisitions     int
	evaluations      int
	closes           int
}

func (trust *a9DeliveryTrustStub) AcquireCurrentTopicBindingLease(
	_ context.Context,
	_ time.Time,
) (a9trust.TopicBindingLease, uint64, [32]byte, error) {
	trust.mu.Lock()
	defer trust.mu.Unlock()
	trust.acquisitions++
	return &a9DeliveryTopicBindingLease{trust: trust},
		trust.sequence,
		trust.hash,
		nil
}

func (trust *a9DeliveryTrustStub) AcquireTopicBindingLease(
	_ context.Context,
	_ time.Time,
	sequence uint64,
	hash [32]byte,
) (a9trust.TopicBindingLease, error) {
	trust.mu.Lock()
	defer trust.mu.Unlock()
	if sequence != trust.sequence || hash != trust.hash {
		return nil, ErrStoreUnavailable
	}
	trust.acquisitions++
	return &a9DeliveryTopicBindingLease{trust: trust}, nil
}

func (trust *a9DeliveryTrustStub) counts() (int, int, int) {
	trust.mu.Lock()
	defer trust.mu.Unlock()
	return trust.acquisitions, trust.evaluations, trust.closes
}

type a9DeliveryTopicBindingLease struct {
	mu     sync.Mutex
	trust  *a9DeliveryTrustStub
	closed bool
}

func (lease *a9DeliveryTopicBindingLease) CandidateTopicBindings(
	_ context.Context,
	providerTopic []byte,
	_ time.Time,
) ([]a9trust.TopicBindingCandidate, a9trust.Verdict) {
	lease.trust.mu.Lock()
	defer lease.trust.mu.Unlock()
	lease.trust.evaluations++
	if !bytes.Equal(providerTopic, lease.trust.providerTopic) {
		return nil, a9trust.Invalid("TOPIC_BINDING")
	}
	return []a9trust.TopicBindingCandidate{{
		TopicKeyEpoch: lease.trust.topicKeyEpoch,
		TopicBinding:  lease.trust.binding,
	}}, a9trust.Eligible()
}

func (lease *a9DeliveryTopicBindingLease) TopicBindingForEpoch(
	_ context.Context,
	providerTopic []byte,
	topicKeyEpoch uint32,
	_ time.Time,
	assertionExpiresAt time.Time,
	alreadyAccepted bool,
) ([]byte, a9trust.Verdict) {
	lease.trust.mu.Lock()
	defer lease.trust.mu.Unlock()
	lease.trust.evaluations++
	if !alreadyAccepted ||
		!bytes.Equal(providerTopic, lease.trust.providerTopic) ||
		topicKeyEpoch != lease.trust.topicKeyEpoch ||
		!assertionExpiresAt.Equal(lease.trust.assertionExpires) {
		return nil, a9trust.Invalid("TOPIC_BINDING")
	}
	return append([]byte(nil), lease.trust.binding[:]...), a9trust.Eligible()
}

func (lease *a9DeliveryTopicBindingLease) Close() {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return
	}
	lease.closed = true
	lease.trust.mu.Lock()
	lease.trust.closes++
	lease.trust.mu.Unlock()
}

type a9DeliveryTestFixture struct {
	runtime      *a9RuntimeFixture
	leaseID      []byte
	installation [16]byte
	epoch        [16]byte
	binding      [16]byte
	job          SerializedDeliveryJob
	trust        *a9DeliveryTrustStub
}

func a9DeliveryWaitForBlockedBackend(
	t *testing.T,
	fixture *a9DeliveryTestFixture,
	blockerPID int,
) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var blocked bool
		err := fixture.runtime.db.QueryRowContext(
			t.Context(),
			`SELECT EXISTS (
			     SELECT 1
			       FROM pg_catalog.pg_stat_activity AS activity
			      WHERE activity.pid <> $1
			        AND $1 = ANY(
			          pg_catalog.pg_blocking_pids(activity.pid)
			        )
			 )`,
			blockerPID,
		).Scan(&blocked)
		require.NoError(t, err)
		if blocked {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatal("timed out waiting for the database lock waiter")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func a9DeliveryWaitForDatabaseTime(
	t *testing.T,
	fixture *a9DeliveryTestFixture,
	target time.Time,
) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var databaseNow time.Time
		err := fixture.runtime.db.QueryRowContext(
			t.Context(),
			`SELECT pg_catalog.clock_timestamp()`,
		).Scan(&databaseNow)
		require.NoError(t, err)
		if !databaseNow.UTC().Before(target.UTC()) {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf(
				"database clock did not reach %s",
				target.UTC().Format(time.RFC3339Nano),
			)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newA9DeliveryTestFixture(t *testing.T) *a9DeliveryTestFixture {
	t.Helper()
	runtime := newA9RuntimeFixture(t)
	var installation, epoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xb1}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xb2}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xb3}, 16))

	control := runtime.control(
		0x41,
		installation,
		epoch,
		1,
		binding,
		1,
		a9trust.ControlActionUpsert,
	)
	require.NotNil(t, control.Assertion)
	control.IssuedAt = runtime.now
	control.Assertion.IssuedAt = runtime.now
	_, err := runtime.store.ApplyControl(t.Context(), control)
	require.NoError(t, err)
	watermark := runtime.watermark(
		0x42,
		installation,
		epoch,
		1,
		1,
		a9trust.WatermarkStatusCurrent,
	)
	watermark.IssuedAt = runtime.now
	_, err = runtime.store.ApplyWatermark(
		t.Context(),
		watermark,
	)
	require.NoError(t, err)

	providerTopic := topicpkg.NewTopic(
		topicpkg.TopicKindGroupMessagesV1,
		bytes.Repeat([]byte{0x51}, 32),
	)
	policy := runtime.signed.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		runtime.signed.incarnationID,
	)
	gate6Subscription := runtime.signed.subscription(
		t,
		providerTopic,
		0x52,
		1,
		688,
		authority.PushModeAlertAllowed,
		1,
	)
	request := runtime.replaceRequest(
		t,
		0x43,
		installation,
		epoch,
		binding,
		control.AssertionHash,
		control.Assertion.TopicBinding,
		0,
		providerTopic,
		policy,
		gate6Subscription,
	)
	t.Cleanup(request.Close)
	result, err := runtime.store.Replace(
		t.Context(),
		request,
		a9api.KeysetReceipt{
			Sequence: 1,
			Hash:     runtime.keysetHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeApplied, result.Outcome)

	subscriptions, err := runtime.store.GetSubscriptions(
		t.Context(),
		providerTopic,
		688,
	)
	require.NoError(t, err)
	require.Len(t, subscriptions, 1)
	secureRoute := subscriptions[0].SecureRoute
	require.NotNil(t, secureRoute)
	require.NotNil(t, control.Assertion)

	snapshot := &interfaces.A9RouteSnapshot{
		InstallationBindingID:   installation,
		SequencerEpoch:          epoch,
		SubscriptionGeneration:  1,
		BindingID:               binding,
		BindingVersion:          1,
		AssertionHash:           control.AssertionHash,
		AssertionStreamSequence: 1,
		AssertionExpiresAt:      control.Assertion.ExpiresAt.UTC(),
		TopicKeyEpoch:           request.Subscriptions[0].TopicKeyEpoch,
		TopicBinding:            request.Subscriptions[0].TopicBinding,
		RouteKeyEpoch:           secureRoute.RouteKeyEpoch,
		KeysetSequence:          1,
		KeysetHash:              runtime.keysetHash,
		WatermarkSequence:       1,
	}
	job := SerializedDeliveryJob{
		DeviceToken:      hex.EncodeToString(request.APNSToken[:]),
		Topic:            "com.example.hytch.dev",
		ProviderTopic:    append([]byte(nil), providerTopic.Bytes()...),
		Payload:          []byte(`{"aps":{"alert":"fixed A9 wakeup"}}`),
		PushType:         "alert",
		Priority:         10,
		Expiration:       runtime.now.Add(10 * time.Second),
		TrafficClass:     DeliveryTrafficConversation,
		PolicyEpoch:      secureRoute.PolicyEpoch,
		RouteKeyEpoch:    secureRoute.RouteKeyEpoch,
		NoncePrefix:      secureRoute.NoncePrefix,
		DeliverySequence: secureRoute.DeliverySequence,
		AliasDay:         secureRoute.AliasDay,
		RouteAlias:       append([]byte(nil), secureRoute.RouteAlias...),
		A9:               snapshot,
	}
	trust := &a9DeliveryTrustStub{
		sequence:         snapshot.KeysetSequence,
		hash:             snapshot.KeysetHash,
		providerTopic:    append([]byte(nil), job.ProviderTopic...),
		topicKeyEpoch:    snapshot.TopicKeyEpoch,
		assertionExpires: snapshot.AssertionExpiresAt,
		binding:          snapshot.TopicBinding,
	}
	handle := &A9TrustHandle{}
	require.NoError(t, handle.Bind(trust))
	runtime.store.a9Enabled = true
	runtime.store.a9Trust = handle

	return &a9DeliveryTestFixture{
		runtime:      runtime,
		leaseID:      append([]byte(nil), secureRoute.LeaseID...),
		installation: installation,
		epoch:        epoch,
		binding:      binding,
		job:          job,
		trust:        trust,
	}
}

func (fixture *a9DeliveryTestFixture) enqueueAndClaim(
	t *testing.T,
) ([]byte, ClaimedDeliveryJob) {
	t.Helper()
	jobID, err := fixture.runtime.store.EnqueueDeliveryJob(
		t.Context(),
		fixture.leaseID,
		fixture.job,
		"a9-delivery-integration-source",
		10,
	)
	require.NoError(t, err)
	require.Len(t, jobID, 16)

	var persisted a9DeliverySnapshotRow
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`SELECT a9_installation_binding_id, a9_sequencer_epoch,
		        a9_subscription_generation, a9_binding_id,
		        a9_binding_version, a9_assertion_hash,
		        a9_assertion_stream_sequence, a9_topic_key_epoch,
		        a9_topic_binding, a9_route_key_epoch,
		        a9_keyset_sequence, a9_keyset_hash,
		        a9_watermark_sequence
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		jobID,
	).Scan(persisted.scanDestinations()...))
	require.True(t, persisted.matches(fixture.job.A9))

	claimed, err := fixture.runtime.store.ClaimDeliveryJobs(
		t.Context(),
		1,
		30*time.Second,
	)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, jobID, claimed[0].JobID)
	require.Equal(t, fixture.job, claimed[0].Job)
	require.Equal(t, 1, claimed[0].Attempts)
	return jobID, claimed[0]
}

func TestA9DeliveryEnqueueClaimAndPreEgressRoundTrip(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture := newA9DeliveryTestFixture(t)
	jobID, claimed := fixture.enqueueAndClaim(t)

	guard, current, err := fixture.runtime.store.AcquireDeliveryAttempt(
		t.Context(),
		claimed,
	)
	require.NoError(t, err)
	require.True(t, current)
	require.NotNil(t, guard)
	require.NoError(t, guard.Release())

	var state, attempts int16
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`SELECT state, attempts
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		jobID,
	).Scan(&state, &attempts))
	require.Equal(t, deliveryJobClaimed, state)
	require.Zero(t, attempts)
	acquisitions, evaluations, closes := fixture.trust.counts()
	require.Equal(t, 2, acquisitions)
	require.Equal(t, 2, evaluations)
	require.Equal(t, 2, closes)
}

func TestA9DeliveryFinalDatabaseTimeRejectsExpiredGate6Route(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	fixture := newA9DeliveryTestFixture(t)
	jobID, claimed := fixture.enqueueAndClaim(t)

	// Hold the claimed row after A9 authority can be checked but before the
	// delivery path loads the durable job and Gate-6 rows.
	blocker, err := fixture.runtime.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	blockerOpen := true
	t.Cleanup(func() {
		if blockerOpen {
			_ = blocker.Rollback()
		}
	})
	var blockerPID int
	require.NoError(t, blocker.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.pg_backend_pid()
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1
		  FOR UPDATE`,
		jobID,
	).Scan(&blockerPID))

	// The row predicates below the lock use the original evaluation time.
	// Advancing the database past this exact boundary therefore exercises the
	// final clock_timestamp() currentness check, not an earlier predicate.
	var gate6ExpiresAt time.Time
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`UPDATE hytch_push_vault.subscription_leases
		    SET control_expires_at =
		          pg_catalog.clock_timestamp() + INTERVAL '1 second'
		  WHERE lease_id = $1
		RETURNING control_expires_at`,
		fixture.leaseID,
	).Scan(&gate6ExpiresAt))

	type attemptOutcome struct {
		guard   DeliveryAttemptGuard
		current bool
		err     error
	}
	attemptContext, cancelAttempt := context.WithTimeout(
		t.Context(),
		5*time.Second,
	)
	defer cancelAttempt()
	attemptDone := make(chan attemptOutcome, 1)
	go func() {
		guard, current, acquireErr :=
			fixture.runtime.store.AcquireDeliveryAttempt(
				attemptContext,
				claimed,
			)
		attemptDone <- attemptOutcome{
			guard:   guard,
			current: current,
			err:     acquireErr,
		}
	}()

	a9DeliveryWaitForBlockedBackend(t, fixture, blockerPID)
	a9DeliveryWaitForDatabaseTime(t, fixture, gate6ExpiresAt)
	require.NoError(t, blocker.Rollback())
	blockerOpen = false

	var outcome attemptOutcome
	select {
	case outcome = <-attemptDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the delivery currentness decision")
	}
	if outcome.guard != nil {
		t.Cleanup(func() { _ = outcome.guard.Release() })
	}
	require.NoError(t, outcome.err)
	require.False(t, outcome.current)
	require.Nil(t, outcome.guard)

	var state, attempts int16
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`SELECT state, attempts
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		jobID,
	).Scan(&state, &attempts))
	require.Equal(t, deliveryJobClaimed, state)
	require.Zero(t, attempts)
}

func TestA9DeliveryAttemptGuardBlocksRevocationUntilRelease(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	fixture := newA9DeliveryTestFixture(t)
	jobID, claimed := fixture.enqueueAndClaim(t)

	guard, current, err := fixture.runtime.store.AcquireDeliveryAttempt(
		t.Context(),
		claimed,
	)
	require.NoError(t, err)
	require.True(t, current)
	require.NotNil(t, guard)
	guardOpen := true
	t.Cleanup(func() {
		if guardOpen {
			_ = guard.Release()
		}
	})
	internalGuard, ok := guard.(*deliveryAttemptGuard)
	require.True(t, ok)
	var blockerPID int
	require.NoError(t, internalGuard.tx.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.pg_backend_pid()`,
	).Scan(&blockerPID))

	revoke := fixture.runtime.control(
		0x44,
		fixture.installation,
		fixture.epoch,
		2,
		fixture.binding,
		2,
		a9trust.ControlActionRevoke,
	)
	revoke.IssuedAt = fixture.runtime.now
	type controlOutcome struct {
		result a9api.Result
		err    error
	}
	revokeContext, cancelRevoke := context.WithTimeout(
		t.Context(),
		5*time.Second,
	)
	defer cancelRevoke()
	revokeDone := make(chan controlOutcome, 1)
	go func() {
		result, applyErr := fixture.runtime.store.ApplyControl(
			revokeContext,
			revoke,
		)
		revokeDone <- controlOutcome{result: result, err: applyErr}
	}()

	a9DeliveryWaitForBlockedBackend(t, fixture, blockerPID)
	select {
	case outcome := <-revokeDone:
		t.Fatalf(
			"revocation completed while the attempt guard was held: %+v",
			outcome,
		)
	default:
	}
	require.NoError(t, guard.Release())
	guardOpen = false

	var revokeOutcome controlOutcome
	select {
	case revokeOutcome = <-revokeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for revocation after guard release")
	}
	require.NoError(t, revokeOutcome.err)
	require.Equal(
		t,
		a9api.ResultStateRevoked,
		revokeOutcome.result.State,
	)

	secondGuard, secondCurrent, err :=
		fixture.runtime.store.AcquireDeliveryAttempt(
			t.Context(),
			claimed,
		)
	if secondGuard != nil {
		t.Cleanup(func() { _ = secondGuard.Release() })
	}
	require.NoError(t, err)
	require.False(t, secondCurrent)
	require.Nil(t, secondGuard)

	var remaining, maximumAttempts int
	var terminalOrDeleted bool
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*), COALESCE(MAX(attempts), 0),
		        COALESCE(BOOL_AND(
		          state = $2 AND
		          final_reason = $3 AND
		          a9_installation_binding_id IS NULL
		        ), TRUE)
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		jobID,
		deliveryJobFinal,
		int16(DeliveryFinalSafetyInvalidated),
	).Scan(&remaining, &maximumAttempts, &terminalOrDeleted))
	require.LessOrEqual(t, remaining, 1)
	require.Zero(t, maximumAttempts)
	require.True(t, terminalOrDeleted)
}

func TestA9DeliveryRevocationBeforePreEgressSpendsNoAttempt(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture := newA9DeliveryTestFixture(t)
	jobID, claimed := fixture.enqueueAndClaim(t)

	revoke := fixture.runtime.control(
		0x44,
		fixture.installation,
		fixture.epoch,
		2,
		fixture.binding,
		2,
		a9trust.ControlActionRevoke,
	)
	revoke.IssuedAt = fixture.runtime.now
	result, err := fixture.runtime.store.ApplyControl(t.Context(), revoke)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultStateRevoked, result.State)
	watermark := fixture.runtime.watermark(
		0x45,
		fixture.installation,
		fixture.epoch,
		2,
		2,
		a9trust.WatermarkStatusCurrent,
	)
	watermark.IssuedAt = fixture.runtime.now
	_, err = fixture.runtime.store.ApplyWatermark(t.Context(), watermark)
	require.NoError(t, err)

	guard, current, err := fixture.runtime.store.AcquireDeliveryAttempt(
		t.Context(),
		claimed,
	)
	require.NoError(t, err)
	require.False(t, current)
	require.Nil(t, guard)

	var remaining, maximumAttempts int
	var terminalOrDeleted bool
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*), COALESCE(MAX(attempts), 0),
		        COALESCE(BOOL_AND(
		          state = $2 AND
		          final_reason = $3 AND
		          a9_installation_binding_id IS NULL AND
		          a9_sequencer_epoch IS NULL AND
		          a9_subscription_generation IS NULL AND
		          a9_binding_id IS NULL AND
		          a9_binding_version IS NULL AND
		          a9_assertion_hash IS NULL AND
		          a9_assertion_stream_sequence IS NULL AND
		          a9_topic_key_epoch IS NULL AND
		          a9_topic_binding IS NULL AND
		          a9_route_key_epoch IS NULL AND
		          a9_keyset_sequence IS NULL AND
		          a9_keyset_hash IS NULL AND
		          a9_watermark_sequence IS NULL
		        ), TRUE)
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		jobID,
		deliveryJobFinal,
		int16(DeliveryFinalSafetyInvalidated),
	).Scan(&remaining, &maximumAttempts, &terminalOrDeleted))
	require.LessOrEqual(t, remaining, 1)
	require.Zero(t, maximumAttempts)
	require.True(t, terminalOrDeleted)
}

func TestA9DeliveryClaimRejectsEncryptedSnapshotMismatch(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture := newA9DeliveryTestFixture(t)
	jobID, err := fixture.runtime.store.EnqueueDeliveryJob(
		t.Context(),
		fixture.leaseID,
		fixture.job,
		"a9-delivery-mismatch-source",
		10,
	)
	require.NoError(t, err)

	var encrypted []byte
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`SELECT encrypted_job
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		jobID,
	).Scan(&encrypted))
	plaintext, err := fixture.runtime.store.encryption.Open(
		deliveryJobContext(jobID),
		encrypted,
	)
	require.NoError(t, err)
	var mismatched SerializedDeliveryJob
	require.NoError(t, json.Unmarshal(plaintext, &mismatched))
	zero(plaintext)
	require.NotNil(t, mismatched.A9)
	mismatched.A9.WatermarkSequence++
	plaintext, err = json.Marshal(mismatched)
	require.NoError(t, err)
	defer zero(plaintext)
	encrypted, err = fixture.runtime.store.encryption.Seal(
		deliveryJobContext(jobID),
		plaintext,
	)
	require.NoError(t, err)
	_, err = fixture.runtime.db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.delivery_jobs
		    SET encrypted_job = $1
		  WHERE job_id = $2`,
		encrypted,
		jobID,
	)
	require.NoError(t, err)

	claimed, err := fixture.runtime.store.ClaimDeliveryJobs(
		t.Context(),
		1,
		30*time.Second,
	)
	require.NoError(t, err)
	require.Empty(t, claimed)
	var remaining int
	require.NoError(t, fixture.runtime.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.delivery_jobs
		  WHERE job_id = $1`,
		jobID,
	).Scan(&remaining))
	require.Zero(t, remaining)
}
