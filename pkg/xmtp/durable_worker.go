package xmtp

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"go.uber.org/zap"
)

// admissionLookupTimeout bounds the per-frame subscription lookup that runs
// on the receive goroutine before a frame is persisted.
const admissionLookupTimeout = 10 * time.Second

// durableAttemptTimeout bounds one processing attempt of a claimed envelope,
// so a stalled query cannot hold a worker while its heartbeat keeps the lease
// alive. Recipients already decided stay decided; the rest retry.
const durableAttemptTimeout = 5 * time.Minute

// idleClaimInterval is how long an idle durable worker waits before its next
// claim. Each wait adds up to idleClaimJitter so workers do not poll in phase.
const (
	idleClaimInterval = time.Second
	idleClaimJitter   = 500 * time.Millisecond
)

type envelopeContextKey struct{}

func capturedEnvelope(ctx context.Context) *interfaces.NotificationEnvelope {
	if ctx == nil {
		return nil
	}
	value, _ := ctx.Value(envelopeContextKey{}).(*interfaces.NotificationEnvelope)
	return value
}

type invalidEnvelopeError struct{ cause error }

func (e *invalidEnvelopeError) Error() string { return "invalid persisted notification envelope" }
func (e *invalidEnvelopeError) Unwrap() error { return e.cause }

// persistEnvelope durably admits one received frame before any worker can
// see it. No in-memory acknowledgment precedes Enqueue. While persistence is
// unavailable it keeps this frame and pauses stream consumption until the
// frame is durable. A frame the queue can never admit (above the 2 MiB
// admission limit, or otherwise invalid) is skipped so one bad frame cannot
// stop the listener and every durable worker. It returns false only when the
// listener is stopping.
func persistEnvelope(ctx context.Context, queue interfaces.NotificationQueue, version, key string, payload []byte, ready *atomic.Bool, logger *zap.Logger) bool {
	delay := STARTING_SLEEP_TIME
	for {
		if ctx.Err() != nil {
			return false
		}
		err := queue.Enqueue(ctx, version, key, payload)
		if err == nil {
			ready.Store(true)
			return true
		}
		if errors.Is(err, interfaces.ErrInvalidNotificationEnvelope) {
			// The database answered, so admission itself is healthy.
			ready.Store(true)
			logger.Warn("notification envelope outside durable admission limits; frame skipped")
			return true
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

func startDurableWorkers(ctx context.Context, queue interfaces.NotificationQueue, version string, count int, logger *zap.Logger, failClosed func(), process func(context.Context, []byte) error) *durableWorkerHealth {
	return startDurableWorkersWithMaintenanceInterval(ctx, queue, version, count, logger, 30*time.Second, failClosed, process)
}

func startDurableWorkersWithMaintenanceInterval(ctx context.Context, queue interfaces.NotificationQueue, version string, count int, logger *zap.Logger, maintenanceInterval time.Duration, failClosed func(), process func(context.Context, []byte) error) *durableWorkerHealth {
	if count < 1 {
		count = 1
	}
	health := &durableWorkerHealth{workers: make([]atomic.Bool, count)}
	go runListenerGoroutine(func() {
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
	}, failClosed)
	for i := 0; i < count; i++ {
		ready := &health.workers[i]
		go runListenerGoroutine(func() {
			defer ready.Store(false)
			for ctx.Err() == nil {
				env, err := queue.Claim(ctx, version)
				if err != nil {
					ready.Store(false)
					logger.Error("notification queue claim failed")
					if !waitNotificationRetry(ctx, idleClaimInterval) {
						return
					}
					continue
				}
				ready.Store(true)
				if env == nil {
					if !waitNotificationRetry(ctx, idleClaimInterval+rand.N(idleClaimJitter)) {
						return
					}
					continue
				}
				if !processDurableEnvelope(ctx, queue, *env, ready, logger, process) {
					if failClosed != nil {
						failClosed()
					}
					return
				}
			}
		}, failClosed)
	}
	return health
}

func processDurableEnvelope(ctx context.Context, queue interfaces.NotificationQueue, env interfaces.NotificationEnvelope, ready *atomic.Bool, logger *zap.Logger, process func(context.Context, []byte) error) bool {
	return processDurableEnvelopeWithHeartbeat(ctx, queue, env, ready, logger, 20*time.Second, process)
}

// processDurableEnvelopeWithHeartbeat runs one claimed envelope under a
// renewed lease. It returns false only after a processing panic: the
// envelope is first recorded as dead so a restart cannot reclaim the same
// poison frame, and the caller then fails the listener closed as the
// in-memory path does for any internal panic.
func processDurableEnvelopeWithHeartbeat(ctx context.Context, queue interfaces.NotificationQueue, env interfaces.NotificationEnvelope, ready *atomic.Bool, logger *zap.Logger, interval time.Duration, process func(context.Context, []byte) error) (healthy bool) {
	workCtx, cancel := context.WithTimeout(context.WithValue(ctx, envelopeContextKey{}, &env), durableAttemptTimeout)
	heartbeatDone := make(chan struct{})
	var leaseHealthy atomic.Bool
	leaseHealthy.Store(true)
	go func() {
		defer close(heartbeatDone)
		for waitNotificationRetry(workCtx, interval) {
			if err := queue.Renew(workCtx, env); err != nil {
				if workCtx.Err() != nil {
					// Processing finished while this renewal was in
					// flight; that is not a lost lease.
					return
				}
				ready.Store(false)
				leaseHealthy.Store(false)
				cancel()
				return
			}
		}
	}()
	stopHeartbeat := func() {
		cancel()
		<-heartbeatDone
	}

	defer func() {
		if recover() == nil {
			return
		}
		// The recovered value may carry attacker-controlled envelope data;
		// it is deliberately discarded.
		stopHeartbeat()
		ready.Store(false)
		healthy = false
		if ctx.Err() != nil || !leaseHealthy.Load() {
			return
		}
		if err := queue.Finish(ctx, env, "dead", "processing_panic"); err != nil {
			logger.Error("notification queue completion failed; lease will recover")
		}
	}()

	err := process(workCtx, env.Payload)
	// Stop and join the lease renewer before closing this generation.
	stopHeartbeat()
	if ctx.Err() != nil || !leaseHealthy.Load() {
		return true
	}
	outcome, class := "complete", ""
	if err != nil {
		outcome, class = "pending", "processing"
		var invalid *invalidEnvelopeError
		switch {
		case errors.As(err, &invalid):
			outcome, class = "dead", "invalid_envelope"
		case errors.Is(err, interfaces.ErrNotificationRecipientLimit):
			outcome, class = "dead", "recipient_limit"
		}
	}
	if err := queue.Finish(ctx, env, outcome, class); err != nil {
		ready.Store(false)
		logger.Error("notification queue completion failed; lease will recover")
	}
	return true
}

// Subscriptions bound ingestion to this application's topics. Database failure
// pauses this already received frame; it is never interpreted as no subscribers.
func waitForKnownSubscriptions(ctx context.Context, ready *atomic.Bool, logger *zap.Logger, lookup func(context.Context) (bool, error)) (bool, bool) {
	delay := STARTING_SLEEP_TIME
	for ctx.Err() == nil {
		lookupCtx, cancel := context.WithTimeout(ctx, admissionLookupTimeout)
		known, err := lookup(lookupCtx)
		cancel()
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
