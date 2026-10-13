package xmtp

import (
	"context"
	"errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/delivery"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/notificationqueue"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	"sync/atomic"
	"testing"
	"time"
)

func TestDurableDelivery_RestartRetriesOnlyFailedRecipient(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	require.NoError(t, store.Enqueue(ctx, "v4", "message", []byte("ciphertext")))
	env, err := store.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, env)
	requests := []interfaces.SendRequest{
		{IdempotencyKey: "message", Installation: interfaces.Installation{Id: "device-a"}},
		{IdempotencyKey: "message", Installation: interfaces.Installation{Id: "device-b"}},
	}
	provider := mocks.NewDelivery(t)
	provider.On("CanDeliver", mock.Anything).Return(true)
	transient := &delivery.ApnsRejection{StatusCode: 429}
	provider.On("Send", mock.Anything, mock.MatchedBy(func(r interfaces.SendRequest) bool { return r.Installation.Id == "device-a" })).Return(transient).Once()
	provider.On("Send", mock.Anything, mock.MatchedBy(func(r interfaces.SendRequest) bool { return r.Installation.Id == "device-b" })).Return(nil).Once()
	dispatcher := deliveryDispatcher{ctx: ctx, logger: testutils.TestLogger(t), queue: store, deliveryServices: []interfaces.Delivery{provider}}
	attemptCtx := context.WithValue(ctx, envelopeContextKey{}, env)
	require.NoError(t, dispatcher.prepareRecipients(attemptCtx, requests))
	require.ErrorIs(t, dispatcher.deliverWithContext(attemptCtx, requests[0]), transient)
	require.NoError(t, dispatcher.deliverWithContext(attemptCtx, requests[1]))
	require.NoError(t, store.Finish(ctx, *env, "pending", "processing"))
	_, err = db.ExecContext(ctx, "UPDATE notification_envelopes SET next_attempt_at=clock_timestamp() - INTERVAL '1 second' WHERE id=$1", env.ID)
	require.NoError(t, err)
	restarted := notificationqueue.New(db)
	retry, err := restarted.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, retry)
	retryCtx := context.WithValue(ctx, envelopeContextKey{}, retry)
	retryProvider := mocks.NewDelivery(t)
	retryProvider.On("CanDeliver", mock.Anything).Return(true)
	retryProvider.On("Send", mock.Anything, mock.MatchedBy(func(r interfaces.SendRequest) bool { return r.Installation.Id == "device-a" })).Return(nil).Once()
	recovered := deliveryDispatcher{ctx: ctx, logger: testutils.TestLogger(t), queue: restarted, deliveryServices: []interfaces.Delivery{retryProvider}}
	// A newly subscribed device after admission is not a recipient of this old message.
	requests = append(requests, interfaces.SendRequest{IdempotencyKey: "message", Installation: interfaces.Installation{Id: "new-device"}})
	require.NoError(t, recovered.prepareRecipients(retryCtx, requests))
	for _, req := range requests {
		require.NoError(t, recovered.deliverWithContext(retryCtx, req))
	}
	retryProvider.AssertNumberOfCalls(t, "Send", 1)
	require.NoError(t, restarted.Finish(ctx, *retry, "complete", ""))
}

func TestDurableDelivery_CleanupFailureIsNotPermanentAcknowledgment(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	require.NoError(t, store.Enqueue(ctx, "v4", "message", []byte("ciphertext")))
	env, err := store.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, env)
	req := interfaces.SendRequest{IdempotencyKey: "message", Installation: interfaces.Installation{Id: "device"}}
	provider := mocks.NewDelivery(t)
	provider.On("CanDeliver", mock.Anything).Return(true)
	provider.On("Send", mock.Anything, mock.Anything).Return(&delivery.ApnsRejection{StatusCode: 400, InvalidToken: true, Permanent: true})
	failure := errors.New("database unavailable")
	dispatcher := deliveryDispatcher{ctx: ctx, logger: testutils.TestLogger(t), queue: store, invalidTokens: &recordingInvalidator{err: failure}, deliveryServices: []interfaces.Delivery{provider}}
	attemptCtx := context.WithValue(ctx, envelopeContextKey{}, env)
	require.NoError(t, dispatcher.prepareRecipients(attemptCtx, []interfaces.SendRequest{req}))
	require.ErrorIs(t, dispatcher.deliverWithContext(attemptCtx, req), failure)
	var status string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT status FROM notification_recipient_receipts WHERE envelope_id=$1 AND installation_id='device'", env.ID).Scan(&status))
	require.Equal(t, "pending", status)
}

func TestDurableDelivery_LostEnvelopeLeaseCancelsProcessing(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := notificationqueue.New(db)
	require.NoError(t, store.Enqueue(ctx, "v4", "message", []byte("ciphertext")))
	old, err := store.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, old)
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
	_, err = db.ExecContext(ctx, "UPDATE notification_envelopes SET lease_until=clock_timestamp() - INTERVAL '1 second' WHERE id=$1", old.ID)
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
	require.NoError(t, db.QueryRowContext(ctx, "SELECT lease_id,status FROM notification_envelopes WHERE id=$1", old.ID).Scan(&lease, &status))
	require.Equal(t, replacement.LeaseID, lease)
	require.Equal(t, "pending", status)
	require.NoError(t, store.Finish(ctx, *replacement, "complete", ""))
}
