package notificationqueue

import (
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	"sync"
	"testing"
)

func TestQueue_RestartDuplicateAndRecipientAck(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := New(db)
	require.NoError(t, store.Enqueue(ctx, "v4", "message-one", []byte("encrypted")))
	require.NoError(t, store.Enqueue(ctx, "v4", "message-one", []byte("encrypted")))
	env, err := store.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, env)
	require.NoError(t, store.PrepareRecipients(ctx, *env, []string{"device-a", "device-b"}))
	ticket, done, err := store.ClaimRecipient(ctx, *env, "device-a")
	require.NoError(t, err)
	require.False(t, done)
	require.NoError(t, store.FinishRecipient(ctx, *env, "device-a", ticket, "accepted", ""))
	require.NoError(t, store.Finish(ctx, *env, "pending", "provider_transient"))
	// Recreate the store and advance only the test fixture's retry deadline.
	_, err = db.ExecContext(ctx, "UPDATE notification_envelopes SET next_attempt_at=clock_timestamp() - INTERVAL '1 second' WHERE id=$1", env.ID)
	require.NoError(t, err)
	restarted := New(db)
	retry, err := restarted.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, retry)
	require.Equal(t, env.ID, retry.ID)
	require.Equal(t, int32(2), retry.Attempts)
	_, done, err = restarted.ClaimRecipient(ctx, *retry, "device-a")
	require.NoError(t, err)
	require.True(t, done, "accepted device must not be sent again")
	ticket, done, err = restarted.ClaimRecipient(ctx, *retry, "device-b")
	require.NoError(t, err)
	require.False(t, done)
	require.NoError(t, restarted.FinishRecipient(ctx, *retry, "device-b", ticket, "accepted", ""))
	require.NoError(t, restarted.Finish(ctx, *retry, "complete", ""))
	require.NoError(t, restarted.Enqueue(ctx, "v4", "message-one", []byte("encrypted")))
	next, err := restarted.Claim(ctx, "v4")
	require.NoError(t, err)
	require.Nil(t, next)
	var payload []byte
	require.NoError(t, db.QueryRowContext(ctx, "SELECT payload FROM notification_envelopes WHERE id=$1", env.ID).Scan(&payload))
	require.Empty(t, payload)
}

func TestQueue_ConcurrentClaimsHaveOneOwner(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := New(db)
	require.NoError(t, store.Enqueue(ctx, "v3", "one", []byte("ciphertext")))
	var group sync.WaitGroup
	results := make(chan bool, 10)
	failures := make(chan error, 10)
	for i := 0; i < 10; i++ {
		group.Add(1)
		go func() { defer group.Done(); env, err := store.Claim(ctx, "v3"); failures <- err; results <- env != nil }()
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		require.NoError(t, err)
	}
	claimed := 0
	for yes := range results {
		if yes {
			claimed++
		}
	}
	require.Equal(t, 1, claimed)
}

func TestQueue_ExpiredLeaseCannotAcknowledgeReplacement(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := New(db)
	require.NoError(t, store.Enqueue(ctx, "v4", "one", []byte("ciphertext")))
	old, err := store.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, old)
	require.NoError(t, store.PrepareRecipients(ctx, *old, []string{"device"}))
	oldTicket, done, err := store.ClaimRecipient(ctx, *old, "device")
	require.NoError(t, err)
	require.False(t, done)
	_, err = db.ExecContext(ctx, "UPDATE notification_envelopes SET lease_until=clock_timestamp() - INTERVAL '1 second' WHERE id=$1", old.ID)
	require.NoError(t, err)
	replacement, err := New(db).Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, replacement)
	require.NotEqual(t, old.LeaseID, replacement.LeaseID)
	require.ErrorIs(t, store.FinishRecipient(ctx, *old, "device", oldTicket, "accepted", ""), ErrLeaseLost)
	require.ErrorIs(t, store.Renew(ctx, *old), ErrLeaseLost)
	require.ErrorIs(t, store.Finish(ctx, *old, "complete", ""), ErrLeaseLost)
	require.NoError(t, store.Finish(ctx, *replacement, "complete", ""))
}

func TestQueue_PermanentAndTransientRecipientOutcomes(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := New(db)
	require.NoError(t, store.Enqueue(ctx, "v4", "one", []byte("ciphertext")))
	env, err := store.Claim(ctx, "v4")
	require.NoError(t, err)
	require.NotNil(t, env)
	require.NoError(t, store.PrepareRecipients(ctx, *env, []string{"permanent", "temporary"}))
	ticket, done, err := store.ClaimRecipient(ctx, *env, "permanent")
	require.NoError(t, err)
	require.False(t, done)
	_, _, err = store.ClaimRecipient(ctx, *env, "permanent")
	require.ErrorIs(t, err, ErrRecipientBusy)
	require.NoError(t, store.FinishRecipient(ctx, *env, "permanent", ticket, "rejected", "provider_permanent"))
	_, done, err = store.ClaimRecipient(ctx, *env, "permanent")
	require.NoError(t, err)
	require.True(t, done)
	ticket, done, err = store.ClaimRecipient(ctx, *env, "temporary")
	require.NoError(t, err)
	require.False(t, done)
	require.NoError(t, store.FinishRecipient(ctx, *env, "temporary", ticket, "pending", "provider_transient"))
	next, done, err := store.ClaimRecipient(ctx, *env, "temporary")
	require.NoError(t, err)
	require.False(t, done)
	require.NotEqual(t, ticket, next)
	require.ErrorIs(t, store.FinishRecipient(ctx, *env, "temporary", ticket, "accepted", ""), ErrLeaseLost)
}

func TestQueue_ExhaustionExpiryAndPrivacyRetention(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := New(db)
	require.NoError(t, store.Enqueue(ctx, "v3", "exhausted", []byte("encrypted")))
	_, err := db.ExecContext(ctx, "UPDATE notification_envelopes SET attempts=11")
	require.NoError(t, err)
	env, err := store.Claim(ctx, "v3")
	require.NoError(t, err)
	require.NotNil(t, env)
	require.NoError(t, store.Finish(ctx, *env, "pending", "provider_transient"))
	var status string
	var payload []byte
	require.NoError(t, db.QueryRowContext(ctx, "SELECT status,payload FROM notification_envelopes WHERE id=$1", env.ID).Scan(&status, &payload))
	require.Equal(t, "dead", status)
	require.Empty(t, payload)
	require.NoError(t, store.Enqueue(ctx, "v3", "expired", []byte("encrypted")))
	_, err = db.ExecContext(ctx, "UPDATE notification_envelopes SET created_at=clock_timestamp() - INTERVAL '2 days' WHERE message_key='expired'")
	require.NoError(t, err)
	require.NoError(t, store.Maintain(ctx))
	require.NoError(t, db.QueryRowContext(ctx, "SELECT status,payload FROM notification_envelopes WHERE message_key='expired'").Scan(&status, &payload))
	require.Equal(t, "dead", status)
	require.Empty(t, payload)
	_, err = db.ExecContext(ctx, "UPDATE notification_envelopes SET created_at=clock_timestamp() - INTERVAL '8 days'")
	require.NoError(t, err)
	require.NoError(t, store.Maintain(ctx))
	var count int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM notification_envelopes").Scan(&count))
	require.Zero(t, count)
}

func TestQueue_CapacityPreservesDuplicatesAndBackpressuresNewWork(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := New(db)
	// Use small encrypted fixture bodies; exercise the real capacity query and
	// unique-key behavior without allocating the 512MiB byte limit in a test.
	_, err := db.ExecContext(ctx, "INSERT INTO notification_envelopes(listener,message_key,payload) SELECT 'v3', 'capacity-'||n::text, 'encrypted'::bytea FROM generate_series(1,100000) n")
	require.NoError(t, err)
	require.NoError(t, store.Enqueue(ctx, "v3", "capacity-1", []byte("encrypted")), "a duplicate must remain acknowledged even while the queue is full")
	require.Error(t, store.Enqueue(ctx, "v3", "new-frame", []byte("encrypted")))
	var count int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM notification_envelopes").Scan(&count))
	require.Equal(t, 100000, count)
}
