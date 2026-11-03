package notificationqueue

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestRetainedOversizeRejectionsShareAdmissionCountAndRetention(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := New(db)
	_, err := db.ExecContext(ctx, `INSERT INTO notification_queue.notification_envelopes(listener,message_key,payload,status,failure_class)
SELECT 'v3','oversized-'||n::text,''::bytea,'dead','oversized' FROM generate_series(1,100000) n`)
	require.NoError(t, err)
	body := bytes.Repeat([]byte{7}, MaxEnvelopeBytes+1)
	// An already committed rejection remains reconciled even when full.
	require.ErrorIs(t, store.Enqueue(ctx, "v3", "oversized-1", body), interfaces.ErrNotificationEnvelopeTooLarge)
	for _, payload := range [][]byte{body, []byte("ordinary envelope")} {
		err = store.Enqueue(ctx, "v3", "new-source", payload)
		require.Error(t, err)
		require.False(t, errors.Is(err, interfaces.ErrNotificationEnvelopeTooLarge), "capacity failure is not an acknowledged rejection")
	}
	var count int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM notification_queue.notification_envelopes`).Scan(&count))
	require.Equal(t, 100000, count)
	_, err = db.ExecContext(ctx, `UPDATE notification_queue.notification_envelopes SET created_at=clock_timestamp()-INTERVAL '8 days'`)
	require.NoError(t, err)
	require.NoError(t, store.Maintain(ctx))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM notification_queue.notification_envelopes`).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, store.Enqueue(ctx, "v3", "after-retention", []byte("ordinary envelope")))
}

func TestRetainedOversizeRejectionsConsumeMetadataByteBudget(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	store := New(db)
	body := bytes.Repeat([]byte{7}, MaxEnvelopeBytes+1)
	require.ErrorIs(t, store.Enqueue(ctx, "v4", "oversized-1", body), interfaces.ErrNotificationEnvelopeTooLarge)
	require.ErrorIs(t, store.Enqueue(ctx, "v4", "oversized-2", body), interfaces.ErrNotificationEnvelopeTooLarge)
	ordinary := []byte("encrypted frame")
	require.NoError(t, store.Enqueue(ctx, "v4", "ordinary", ordinary))
	capacity, err := store.queries.NotificationPendingCapacity(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 3, capacity.Count)
	require.EqualValues(t, 2*rejectedEnvelopeMetadataBytes+len(ordinary), capacity.Bytes)
	var retainedBytes int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT coalesce(sum(octet_length(payload)),0) FROM notification_queue.notification_envelopes WHERE failure_class='oversized'`).Scan(&retainedBytes))
	require.Zero(t, retainedBytes, "oversized original bytes are never retained")
}

func TestOversizeRejectionWaitsForTheSharedAdmissionLock(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	held, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = held.Rollback() }()
	_, err = held.ExecContext(ctx, `SELECT pg_advisory_xact_lock(830178462)`)
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() { result <- New(db).Enqueue(ctx, "v3", "oversized", bytes.Repeat([]byte{1}, MaxEnvelopeBytes+1)) }()
	// Inspect a real PostgreSQL lock wait, rather than infer serialization from
	// how long an arbitrary timer happened to run on this machine.
	require.Eventually(t, func() bool {
		var waiting bool
		err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
WHERE l.locktype='advisory' AND NOT l.granted AND a.datname=current_database())`).Scan(&waiting)
		return err == nil && waiting
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, held.Rollback())
	select {
	case err := <-result:
		require.ErrorIs(t, err, interfaces.ErrNotificationEnvelopeTooLarge)
	case <-time.After(3 * time.Second):
		t.Fatal("rejection did not finish after releasing admission lock")
	}
}

func TestOversizeRejectionCommitFailureNeverAcknowledgesTheFrame(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	_, err := db.ExecContext(ctx, `CREATE FUNCTION fail_oversize_commit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'synthetic rejection commit failure'; END; $$;
CREATE CONSTRAINT TRIGGER reject_oversize_commit AFTER INSERT ON notification_queue.notification_envelopes
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_oversize_commit();`)
	require.NoError(t, err)
	payload := bytes.Repeat([]byte{1}, MaxEnvelopeBytes+1)
	err = New(db).Enqueue(ctx, "v4", "oversized", payload)
	require.Error(t, err)
	require.False(t, errors.Is(err, interfaces.ErrNotificationEnvelopeTooLarge))
	var count int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM notification_queue.notification_envelopes`).Scan(&count))
	require.Zero(t, count)
	_, err = db.ExecContext(ctx, `DROP TRIGGER reject_oversize_commit ON notification_queue.notification_envelopes; DROP FUNCTION fail_oversize_commit()`)
	require.NoError(t, err)
	require.ErrorIs(t, New(db).Enqueue(ctx, "v4", "oversized", payload), interfaces.ErrNotificationEnvelopeTooLarge)
}
