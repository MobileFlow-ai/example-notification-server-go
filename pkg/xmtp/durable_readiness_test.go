package xmtp

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/notificationqueue"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
)

type failingMaintenanceQueue struct {
	interfaces.NotificationQueue
	fail atomic.Bool
}

func (q *failingMaintenanceQueue) Maintain(ctx context.Context) error {
	if q.fail.Load() {
		return errors.New("maintenance unavailable")
	}
	return q.NotificationQueue.Maintain(ctx)
}

func TestDurableReadiness_IdleWorkersCannotHideMaintenanceFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	queue := &failingMaintenanceQueue{NotificationQueue: notificationqueue.New(testutils.CreateTestDb(t))}
	queue.fail.Store(true)
	health := startDurableWorkersWithMaintenanceInterval(ctx, queue, "v4", 2, testutils.TestLogger(t), 10*time.Millisecond, nil, func(context.Context, []byte) error { return nil })
	require.Eventually(t, func() bool { return health.workers[0].Load() && health.workers[1].Load() }, 3*time.Second, 10*time.Millisecond)
	require.False(t, health.Ready(), "successful empty claims cannot hide failed maintenance")
	queue.fail.Store(false)
	require.Eventually(t, health.Ready, 3*time.Second, 10*time.Millisecond)
}

type failingAdmissionQueue struct {
	interfaces.NotificationQueue
	fail atomic.Bool
}

func (q *failingAdmissionQueue) Enqueue(ctx context.Context, version, key string, payload []byte) error {
	if q.fail.Load() {
		return errors.New("queue at capacity")
	}
	return q.NotificationQueue.Enqueue(ctx, version, key, payload)
}

func TestDurableReadiness_IdleWorkersCannotHidePausedAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	logger := testutils.TestLogger(t)
	queue := &failingAdmissionQueue{NotificationQueue: notificationqueue.New(testutils.CreateTestDb(t))}
	listener := &V4Listener{}
	listener.SetNotificationQueue(queue)
	listener.ready.Store(true) // A connected stream is independent of durable admission.
	listener.queueHealth.Store(startDurableWorkersWithMaintenanceInterval(ctx, queue, "v4", 2, logger, 10*time.Millisecond, nil, func(context.Context, []byte) error { return nil }))
	require.Eventually(t, listener.Ready, 3*time.Second, 10*time.Millisecond)
	queue.fail.Store(true)
	finished := make(chan bool, 1)
	go func() {
		finished <- persistEnvelope(ctx, queue, "v4", "held-frame", []byte("encrypted"), &listener.admissionReady, logger)
	}()
	require.Eventually(t, func() bool { return !listener.Ready() }, 3*time.Second, 10*time.Millisecond)
	// Let both workers complete further empty claims while admission is paused.
	time.Sleep(1100 * time.Millisecond)
	require.False(t, listener.Ready())
	queue.fail.Store(false)
	select {
	case persisted := <-finished:
		require.True(t, persisted)
	case <-time.After(3 * time.Second):
		t.Fatal("held frame did not persist after admission recovered")
	}
	require.Eventually(t, listener.Ready, 3*time.Second, 10*time.Millisecond)
}
