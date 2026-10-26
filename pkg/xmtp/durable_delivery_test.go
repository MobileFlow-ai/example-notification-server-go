package xmtp

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/delivery"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/notificationqueue"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func durableTestRequest(installationID string) interfaces.SendRequest {
	shouldPush := true
	req := testConversationRequest(&shouldPush)
	req.IdempotencyKey = "message"
	req.Installation.Id = installationID
	req.Installation.DeliveryMechanism.Token = installationID + "-token"
	return req
}

func claimDurableTestEnvelope(t *testing.T, store *notificationqueue.Store) *interfaces.NotificationEnvelope {
	t.Helper()
	require.NoError(t, store.Enqueue(t.Context(), "v4", "message", []byte("ciphertext")))
	env, err := store.Claim(t.Context(), "v4")
	require.NoError(t, err)
	require.NotNil(t, env)
	return env
}

func receiptState(t *testing.T, ctx context.Context, store interface {
	ClaimRecipient(context.Context, interfaces.NotificationEnvelope, string) (string, bool, error)
}, env interfaces.NotificationEnvelope, id string) bool {
	t.Helper()
	_, done, err := store.ClaimRecipient(ctx, env, id)
	require.NoError(t, err)
	return done
}

func TestDurableDelivery_RestartRetriesOnlyFailedRecipient(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	env := claimDurableTestEnvelope(t, store)
	requests := []interfaces.SendRequest{durableTestRequest("device-a"), durableTestRequest("device-b")}
	provider := mocks.NewDelivery(t)
	provider.On("CanDeliver", mock.Anything).Return(true)
	transient := &delivery.ApnsRejection{StatusCode: 429}
	provider.On("Send", mock.Anything, mock.MatchedBy(func(r interfaces.SendRequest) bool { return r.Installation.Id == "device-a" })).Return(transient).Once()
	provider.On("Send", mock.Anything, mock.MatchedBy(func(r interfaces.SendRequest) bool { return r.Installation.Id == "device-b" })).Return(nil).Once()
	dispatcher := newDeliveryDispatcher(ctx, []interfaces.Delivery{provider})
	dispatcher.queue = store
	attemptCtx := context.WithValue(ctx, envelopeContextKey{}, env)
	require.NoError(t, dispatcher.prepareRecipients(attemptCtx, requests))
	require.ErrorIs(t, dispatcher.dispatchContext(attemptCtx, requests[0]), transient)
	require.NoError(t, dispatcher.dispatchContext(attemptCtx, requests[1]))
	require.NoError(t, store.Finish(ctx, *env, "pending", "processing"))
	_, err := db.ExecContext(ctx, "UPDATE notification_queue.notification_envelopes SET next_attempt_at=clock_timestamp() - INTERVAL '1 second' WHERE id=$1", env.ID)
	require.NoError(t, err)

	restarted := notificationqueue.New(db)
	retry, err := restarted.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, retry)
	retryCtx := context.WithValue(ctx, envelopeContextKey{}, retry)
	retryProvider := mocks.NewDelivery(t)
	retryProvider.On("CanDeliver", mock.Anything).Return(true)
	retryProvider.On("Send", mock.Anything, mock.MatchedBy(func(r interfaces.SendRequest) bool { return r.Installation.Id == "device-a" })).Return(nil).Once()
	recovered := newDeliveryDispatcher(ctx, []interfaces.Delivery{retryProvider})
	recovered.queue = restarted
	// A device subscribed after admission is not a recipient of this message.
	requests = append(requests, durableTestRequest("new-device"))
	require.NoError(t, recovered.prepareRecipients(retryCtx, requests))
	for _, req := range requests {
		require.NoError(t, recovered.dispatchContext(retryCtx, req))
	}
	retryProvider.AssertNumberOfCalls(t, "Send", 1)
	require.NoError(t, restarted.Finish(ctx, *retry, "complete", ""))
}

func TestDurableDelivery_CleanupFailureIsNotPermanentAcknowledgment(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	env := claimDurableTestEnvelope(t, store)
	req := durableTestRequest("device")
	provider := mocks.NewDelivery(t)
	provider.On("CanDeliver", mock.Anything).Return(true)
	provider.On("Send", mock.Anything, mock.Anything).Return(&delivery.ApnsRejection{StatusCode: 410, InvalidToken: true, Permanent: true, UnregisteredAt: time.Now()})
	failure := errors.New("database unavailable")
	dispatcher := newDeliveryDispatcher(ctx, []interfaces.Delivery{provider}, &recordingInvalidator{err: failure})
	dispatcher.queue = store
	attemptCtx := context.WithValue(ctx, envelopeContextKey{}, env)
	require.NoError(t, dispatcher.prepareRecipients(attemptCtx, []interfaces.SendRequest{req}))
	require.ErrorIs(t, dispatcher.dispatchContext(attemptCtx, req), failure)
	var status, class string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT status, failure_class FROM notification_queue.notification_recipient_receipts WHERE envelope_id=$1 AND installation_id='device'", env.ID).Scan(&status, &class))
	require.Equal(t, "pending", status)
	require.Equal(t, "token_cleanup", class)
}

// Permanent provider rejections are recorded once and never resent; with no
// provider for the mechanism the recipient is rejected instead of retried.
func TestDurableDelivery_PermanentOutcomesAreRecordedNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name      string
		providers func(t *testing.T) []interfaces.Delivery
		class     string
	}{
		{"provider_permanent", func(t *testing.T) []interfaces.Delivery {
			provider := mocks.NewDelivery(t)
			provider.On("CanDeliver", mock.Anything).Return(true)
			provider.On("Send", mock.Anything, mock.Anything).Return(&delivery.ApnsRejection{StatusCode: 400, Reason: "BadDeviceToken", Permanent: true}).Once()
			return []interfaces.Delivery{provider}
		}, "provider_permanent"},
		{"no_provider", func(*testing.T) []interfaces.Delivery { return nil }, "no_provider"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testutils.CreateTestDb(t)
			ctx := t.Context()
			store := notificationqueue.New(db)
			env := claimDurableTestEnvelope(t, store)
			req := durableTestRequest("device")
			cleanup := &recordingInvalidator{}
			dispatcher := newDeliveryDispatcher(ctx, tc.providers(t), cleanup)
			dispatcher.queue = store
			attemptCtx := context.WithValue(ctx, envelopeContextKey{}, env)
			require.NoError(t, dispatcher.prepareRecipients(attemptCtx, []interfaces.SendRequest{req}))
			require.NoError(t, dispatcher.dispatchContext(attemptCtx, req))
			require.NoError(t, dispatcher.dispatchContext(attemptCtx, req), "a decided recipient is skipped")
			var status, class string
			require.NoError(t, db.QueryRowContext(ctx, "SELECT status, failure_class FROM notification_queue.notification_recipient_receipts WHERE envelope_id=$1 AND installation_id='device'", env.ID).Scan(&status, &class))
			require.Equal(t, "rejected", status)
			require.Equal(t, tc.class, class)
			require.Zero(t, cleanup.calls, "a rejection that does not prove the token dead keeps the registration")
		})
	}
}

// The initial recipient snapshot holds only policy-eligible recipients.
func TestDurableDelivery_PolicyIneligibleRecipientIsNotSnapshotted(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	env := claimDurableTestEnvelope(t, store)
	eligible := durableTestRequest("eligible")
	silent := durableTestRequest("silent")
	silent.Subscription.IsSilent = true
	provider := mocks.NewDelivery(t)
	dispatcher := newDeliveryDispatcher(ctx, []interfaces.Delivery{provider})
	dispatcher.queue = store
	attemptCtx := context.WithValue(ctx, envelopeContextKey{}, env)
	require.NoError(t, dispatcher.prepareRecipients(attemptCtx, []interfaces.SendRequest{eligible, silent}))
	var count int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM notification_queue.notification_recipient_receipts WHERE envelope_id=$1", env.ID).Scan(&count))
	require.Equal(t, 1, count)
	require.True(t, receiptState(t, ctx, store, *env, "silent"), "an ineligible recipient is not part of the snapshot")
	require.NoError(t, dispatcher.dispatchContext(attemptCtx, silent))
	provider.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}

func TestDurableDelivery_LostEnvelopeLeaseCancelsProcessing(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	old := claimDurableTestEnvelope(t, store)
	started := make(chan struct{})
	finished := make(chan struct{})
	var ready atomic.Bool
	ready.Store(true)
	go func() {
		defer close(finished)
		processDurableEnvelopeWithHeartbeat(ctx, store, *old, &ready, testutils.TestLogger(t), 10*time.Millisecond, func(work context.Context, _ []byte) error {
			close(started)
			<-work.Done()
			return work.Err()
		})
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not begin processing")
	}
	_, err := db.ExecContext(ctx, "UPDATE notification_queue.notification_envelopes SET lease_until=clock_timestamp() - INTERVAL '1 second' WHERE id=$1", old.ID)
	require.NoError(t, err)
	replacement, err := store.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, replacement)
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("stale worker failed to stop after lease loss")
	}
	require.False(t, ready.Load())
	var lease string
	var status string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT lease_id,status FROM notification_queue.notification_envelopes WHERE id=$1", old.ID).Scan(&lease, &status))
	require.Equal(t, replacement.LeaseID, lease)
	require.Equal(t, "pending", status)
	require.NoError(t, store.Finish(ctx, *replacement, "complete", ""))
}

// blockingRenewQueue holds a renewal open until its context ends, so the
// renewal is still in flight when processing completes.
type blockingRenewQueue struct {
	interfaces.NotificationQueue
	renewing chan struct{}
	once     atomic.Bool
}

func (q *blockingRenewQueue) Renew(ctx context.Context, _ interfaces.NotificationEnvelope) error {
	if q.once.CompareAndSwap(false, true) {
		close(q.renewing)
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestDurableDelivery_CompletionDuringRenewalIsNotLeaseLoss(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	env := claimDurableTestEnvelope(t, store)
	queue := &blockingRenewQueue{NotificationQueue: store, renewing: make(chan struct{})}
	var ready atomic.Bool
	ready.Store(true)
	healthy := processDurableEnvelopeWithHeartbeat(ctx, queue, *env, &ready, testutils.TestLogger(t), time.Millisecond, func(context.Context, []byte) error {
		<-queue.renewing
		return nil
	})
	require.True(t, healthy)
	require.True(t, ready.Load(), "a renewal cancelled by completion must not mark the worker unhealthy")
	var status string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT status FROM notification_queue.notification_envelopes WHERE id=$1", env.ID).Scan(&status))
	require.Equal(t, "complete", status)
}

// A panicking envelope is recorded dead before the listener fails closed, so a
// restart cannot reclaim the same poison frame up to the attempt limit.
func TestDurableDelivery_PanicMarksEnvelopeDead(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	env := claimDurableTestEnvelope(t, store)
	var ready atomic.Bool
	ready.Store(true)
	healthy := processDurableEnvelopeWithHeartbeat(ctx, store, *env, &ready, testutils.TestLogger(t), time.Hour, func(context.Context, []byte) error {
		panic("attacker-controlled detail")
	})
	require.False(t, healthy)
	require.False(t, ready.Load())
	var status, class string
	var payload []byte
	require.NoError(t, db.QueryRowContext(ctx, "SELECT status, failure_class, payload FROM notification_queue.notification_envelopes WHERE id=$1", env.ID).Scan(&status, &class, &payload))
	require.Equal(t, "dead", status)
	require.Equal(t, "processing_panic", class)
	require.Empty(t, payload)
	next, err := store.Claim(ctx, "v4")
	require.NoError(t, err)
	require.Nil(t, next)
}

func TestDurableDelivery_RecipientLimitIsDeadNotRetried(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	env := claimDurableTestEnvelope(t, store)
	var ready atomic.Bool
	ready.Store(true)
	require.True(t, processDurableEnvelopeWithHeartbeat(ctx, store, *env, &ready, testutils.TestLogger(t), time.Hour, func(work context.Context, _ []byte) error {
		ids := make([]string, notificationqueue.MaxRecipients+1)
		for i := range ids {
			ids[i] = "device"
		}
		return store.PrepareRecipients(work, *capturedEnvelope(work), ids)
	}))
	var status, class string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT status, failure_class FROM notification_queue.notification_envelopes WHERE id=$1", env.ID).Scan(&status, &class))
	require.Equal(t, "dead", status)
	require.Equal(t, "recipient_limit", class)
}

// The first attempt's recipient snapshot is authoritative: a retry whose
// current recipient set grew past the limit must not abandon it.
func TestDurableDelivery_PreparedSnapshotSurvivesLargerRetrySet(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	env := claimDurableTestEnvelope(t, store)
	require.False(t, env.RecipientsPrepared)
	require.NoError(t, store.PrepareRecipients(ctx, *env, []string{"device-a", "device-b"}))
	require.NoError(t, store.Finish(ctx, *env, "pending", "processing"))
	_, err := db.ExecContext(ctx, "UPDATE notification_queue.notification_envelopes SET next_attempt_at=clock_timestamp() - INTERVAL '1 second' WHERE id=$1", env.ID)
	require.NoError(t, err)
	retry, err := store.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, retry)
	require.True(t, retry.RecipientsPrepared)
	grown := make([]string, notificationqueue.MaxRecipients+1)
	for i := range grown {
		grown[i] = fmt.Sprintf("device-%d", i)
	}
	require.NoError(t, store.PrepareRecipients(ctx, *retry, grown))
	var count int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM notification_queue.notification_recipient_receipts WHERE envelope_id=$1", env.ID).Scan(&count))
	require.Equal(t, 2, count)
}

// A provider acceptance that lands while the listener stops is still
// recorded, so a restart does not resend it.
func TestDurableDelivery_AcceptanceDuringShutdownIsRecorded(t *testing.T) {
	db := testutils.CreateTestDb(t)
	store := notificationqueue.New(db)
	env := claimDurableTestEnvelope(t, store)
	listenerCtx, stop := context.WithCancel(t.Context())
	defer stop()
	req := durableTestRequest("device")
	provider := mocks.NewDelivery(t)
	provider.On("CanDeliver", mock.Anything).Return(true)
	provider.On("Send", mock.Anything, mock.Anything).Run(func(mock.Arguments) { stop() }).Return(nil).Once()
	dispatcher := newDeliveryDispatcher(listenerCtx, []interfaces.Delivery{provider})
	dispatcher.queue = store
	attemptCtx := context.WithValue(listenerCtx, envelopeContextKey{}, env)
	require.NoError(t, dispatcher.prepareRecipients(attemptCtx, []interfaces.SendRequest{req}))
	require.NoError(t, dispatcher.dispatchContext(attemptCtx, req))
	require.Error(t, listenerCtx.Err())
	var status string
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT status FROM notification_queue.notification_recipient_receipts WHERE envelope_id=$1 AND installation_id='device'", env.ID).Scan(&status))
	require.Equal(t, "accepted", status)
}
