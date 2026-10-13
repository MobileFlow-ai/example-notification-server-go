package xmtp

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"go.uber.org/zap"
)

type envelopeContextKey struct{}

func capturedEnvelope(ctx context.Context) *interfaces.NotificationEnvelope {
	value, _ := ctx.Value(envelopeContextKey{}).(*interfaces.NotificationEnvelope)
	return value
}

type invalidEnvelopeError struct{ cause error }

func (e *invalidEnvelopeError) Error() string { return "invalid persisted notification envelope" }
func (e *invalidEnvelopeError) Unwrap() error { return e.cause }

// No in-memory acknowledgment precedes Enqueue. If persistence is unavailable,
// keep this received frame and stop consuming the stream until it is durable.
func persistEnvelope(ctx context.Context, queue interfaces.NotificationQueue, version, key string, payload []byte, ready *atomic.Bool, logger *zap.Logger) bool {
	delay := STARTING_SLEEP_TIME
	for {
		if ctx.Err() != nil {
			return false
		}
		if err := queue.Enqueue(ctx, version, key, payload); err == nil {
			ready.Store(true)
			return true
		} else if errors.Is(err, interfaces.ErrInvalidNotificationEnvelope) {
			ready.Store(false)
			logger.Error("notification envelope exceeds durable admission constraints; listener halted")
			return false
		}
		ready.Store(false)
		logger.Error("notification persistence failed; stream consumption paused")
		if !waitNotificationRetry(ctx, delay) {
			return false
		}
		delay = cappedBackoff(delay)
	}
}
func waitNotificationRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Keep admission, maintenance, and each delivery worker independent. An idle
// worker must not conceal another worker's lost lease or database failure.
type durableWorkerHealth struct {
	maintenance atomic.Bool
	workers     []atomic.Bool
}

func (h *durableWorkerHealth) Ready() bool {
	if h == nil || !h.maintenance.Load() {
		return false
	}
	for i := range h.workers {
		if !h.workers[i].Load() {
			return false
		}
	}
	return true
}
func startDurableWorkers(ctx context.Context, queue interfaces.NotificationQueue, version string, count int, logger *zap.Logger, process func(context.Context, []byte) error) *durableWorkerHealth {
	return startDurableWorkersWithMaintenanceInterval(ctx, queue, version, count, logger, 30*time.Second, process)
}

func startDurableWorkersWithMaintenanceInterval(ctx context.Context, queue interfaces.NotificationQueue, version string, count int, logger *zap.Logger, maintenanceInterval time.Duration, process func(context.Context, []byte) error) *durableWorkerHealth {
	if count < 1 {
		count = 1
	}
	health := &durableWorkerHealth{workers: make([]atomic.Bool, count)}
	go func() {
		defer health.maintenance.Store(false)
		for ctx.Err() == nil {
			err := queue.Maintain(ctx)
			health.maintenance.Store(err == nil)
			if err != nil {
				logger.Error("notification queue maintenance failed")
			}
			if !waitNotificationRetry(ctx, maintenanceInterval) {
				return
			}
		}
	}()
	for i := 0; i < count; i++ {
		ready := &health.workers[i]
		go func() {
			defer ready.Store(false)
			for ctx.Err() == nil {
				env, err := queue.Claim(ctx, version)
				if err != nil {
					ready.Store(false)
					logger.Error("notification queue claim failed")
					if !waitNotificationRetry(ctx, time.Second) {
						return
					}
					continue
				}
				ready.Store(true)
				if env == nil {
					if !waitNotificationRetry(ctx, time.Second) {
						return
					}
					continue
				}
				processDurableEnvelope(ctx, queue, *env, ready, logger, process)
			}
		}()
	}
	return health
}
func processDurableEnvelope(ctx context.Context, queue interfaces.NotificationQueue, env interfaces.NotificationEnvelope, ready *atomic.Bool, logger *zap.Logger, process func(context.Context, []byte) error) {
	processDurableEnvelopeWithHeartbeat(ctx, queue, env, ready, logger, 20*time.Second, process)
}

func processDurableEnvelopeWithHeartbeat(ctx context.Context, queue interfaces.NotificationQueue, env interfaces.NotificationEnvelope, ready *atomic.Bool, logger *zap.Logger, interval time.Duration, process func(context.Context, []byte) error) {
	workCtx, cancel := context.WithCancel(context.WithValue(ctx, envelopeContextKey{}, &env))
	heartbeatDone := make(chan struct{})
	var leaseHealthy atomic.Bool
	leaseHealthy.Store(true)
	go func() {
		defer close(heartbeatDone)
		for waitNotificationRetry(workCtx, interval) {
			if err := queue.Renew(workCtx, env); err != nil {
				ready.Store(false)
				leaseHealthy.Store(false)
				cancel()
				return
			}
		}
	}()
	err := process(workCtx, env.Payload)
	// Stop and join the lease renewer before closing this generation.
	cancel()
	<-heartbeatDone
	if ctx.Err() != nil || !leaseHealthy.Load() {
		return
	}
	outcome, class := "complete", ""
	if err != nil {
		outcome, class = "pending", "processing"
		var invalid *invalidEnvelopeError
		if errors.As(err, &invalid) {
			outcome, class = "dead", "invalid_envelope"
		}
	}
	if err := queue.Finish(ctx, env, outcome, class); err != nil {
		ready.Store(false)
		logger.Error("notification queue completion failed; lease will recover")
	}
}

// Subscriptions bound ingestion to this application's topics. Database failure
// pauses this already received frame; it is never interpreted as no subscribers.
func waitForKnownSubscriptions(ctx context.Context, ready *atomic.Bool, logger *zap.Logger, lookup func() (bool, error)) (bool, bool) {
	delay := STARTING_SLEEP_TIME
	for ctx.Err() == nil {
		known, err := lookup()
		if err == nil {
			ready.Store(true)
			return known, true
		}
		ready.Store(false)
		logger.Error("notification subscription lookup failed; admission paused")
		if !waitNotificationRetry(ctx, delay) {
			return false, false
		}
		delay = cappedBackoff(delay)
	}
	return false, false
}
