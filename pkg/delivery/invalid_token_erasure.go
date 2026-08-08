package delivery

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"go.uber.org/zap"
)

const (
	defaultErasurePollInterval = 500 * time.Millisecond
	defaultErasureClaimTTL     = 15 * time.Second
	defaultErasureOperationTTL = 5 * time.Second
	defaultErasureRetryInitial = 500 * time.Millisecond
	defaultErasureRetryMaximum = 30 * time.Second
)

var ErrInvalidTokenErasureUnavailable = errors.New(
	"invalid-token erasure unavailable",
)

// InvalidTokenErasureWorker is a deletion-only control worker. It deliberately
// has no APNS client or credential dependency, so the APNS kill switch cannot
// prevent privacy cleanup.
type InvalidTokenErasureWorker struct {
	store  vault.InvalidTokenErasureStore
	eraser vault.InvalidAPNSTokenEraser
	logger *zap.Logger
	clock  apnsClock
	jitter io.Reader

	poll         time.Duration
	claimTTL     time.Duration
	operationTTL time.Duration
	retryInitial time.Duration
	retryMaximum time.Duration

	mu        sync.Mutex
	failOnce  sync.Once
	jitterMu  sync.Mutex
	errorLogs privacySafeErrorLimiter
	started   bool
	failed    chan struct{}
	workCtx   context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func NewInvalidTokenErasureWorker(
	logger *zap.Logger,
	store vault.InvalidTokenErasureStore,
	eraser vault.InvalidAPNSTokenEraser,
) (*InvalidTokenErasureWorker, error) {
	if store == nil || eraser == nil {
		return nil, ErrInvalidTokenErasureUnavailable
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &InvalidTokenErasureWorker{
		store:        store,
		eraser:       eraser,
		logger:       logger,
		clock:        realAPNSClock{},
		jitter:       rand.Reader,
		poll:         defaultErasurePollInterval,
		claimTTL:     defaultErasureClaimTTL,
		operationTTL: defaultErasureOperationTTL,
		retryInitial: defaultErasureRetryInitial,
		retryMaximum: defaultErasureRetryMaximum,
		failed:       make(chan struct{}),
	}, nil
}

// Start first recovers and synchronously drains immediately available markers.
// Only after that does it launch the recurring worker. This gives an overdue
// marker a deletion path before retention readiness is evaluated.
func (w *InvalidTokenErasureWorker) Start(ctx context.Context) error {
	if w == nil || w.store == nil || w.eraser == nil {
		return ErrInvalidTokenErasureUnavailable
	}
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()

	if err := w.store.RecoverInvalidTokenErasures(ctx); err != nil {
		return ErrInvalidTokenErasureUnavailable
	}
	if err := w.drainAvailableSafely(ctx); err != nil {
		return err
	}

	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return nil
	}
	w.workCtx, w.cancel = context.WithCancel(ctx)
	w.started = true
	w.wg.Add(1)
	w.mu.Unlock()
	go w.run()
	return nil
}

func (w *InvalidTokenErasureWorker) Stop(ctx context.Context) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	if !w.started {
		w.mu.Unlock()
		return nil
	}
	cancel := w.cancel
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	stopped := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
		return nil
	case <-ctx.Done():
		return ErrInvalidTokenErasureUnavailable
	}
}

func (w *InvalidTokenErasureWorker) Ready() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.started &&
		w.workCtx != nil &&
		w.workCtx.Err() == nil
}

func (w *InvalidTokenErasureWorker) Failed() <-chan struct{} {
	if w == nil || w.failed == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return w.failed
}

func (w *InvalidTokenErasureWorker) drainAvailable(ctx context.Context) error {
	for {
		jobs, err := w.store.ClaimErasureJobs(ctx, 16, w.claimTTL)
		if err != nil {
			return ErrInvalidTokenErasureUnavailable
		}
		if len(jobs) == 0 {
			return nil
		}
		for _, job := range jobs {
			w.process(job)
		}
	}
}

func (w *InvalidTokenErasureWorker) drainAvailableSafely(
	ctx context.Context,
) (err error) {
	defer func() {
		if recover() != nil {
			w.logWorkerError()
			err = ErrInvalidTokenErasureUnavailable
		}
	}()
	return w.drainAvailable(ctx)
}

func (w *InvalidTokenErasureWorker) run() {
	defer w.wg.Done()
	defer func() {
		if recover() != nil {
			w.logWorkerError()
			w.failOnce.Do(func() {
				close(w.failed)
			})
			w.mu.Lock()
			cancel := w.cancel
			w.mu.Unlock()
			if cancel != nil {
				cancel()
			}
		}
	}()
	for {
		if w.workCtx.Err() != nil {
			return
		}
		jobs, err := w.store.ClaimErasureJobs(
			w.workCtx,
			1,
			w.claimTTL,
		)
		if err != nil {
			w.logWorkerError()
			if !w.waitForWork() {
				return
			}
			continue
		}
		if len(jobs) == 0 {
			if !w.waitForWork() {
				return
			}
			continue
		}
		job := jobs[0]
		if w.workCtx.Err() != nil {
			w.release(job.JobID)
			return
		}
		w.process(job)
	}
}

func (w *InvalidTokenErasureWorker) waitForWork() bool {
	select {
	case <-w.workCtx.Done():
		return false
	case <-w.clock.After(w.poll):
		return true
	}
}

func (w *InvalidTokenErasureWorker) process(
	job vault.ClaimedDeliveryJob,
) {
	eraseContext, eraseCancel := context.WithTimeout(
		context.Background(),
		w.operationTTL,
	)
	eraseErr := w.eraser.EraseInvalidAPNSToken(
		eraseContext,
		job.InstallationLookup,
		job.Job.DeviceToken,
	)
	eraseCancel()
	if eraseErr == nil {
		updateContext, updateCancel := context.WithTimeout(
			context.Background(),
			w.operationTTL,
		)
		err := w.store.DeleteErasureJob(updateContext, job.JobID)
		updateCancel()
		if err != nil {
			w.logWorkerError()
		}
		return
	}
	w.logWorkerError()
	availableAt := w.clock.Now().UTC().Add(
		w.retryDelay(job.RetryExponent),
	)
	updateContext, updateCancel := context.WithTimeout(
		context.Background(),
		w.operationTTL,
	)
	err := w.store.RescheduleInvalidTokenErasure(
		updateContext,
		job.JobID,
		availableAt,
	)
	updateCancel()
	if err != nil {
		w.logWorkerError()
	}
}

func (w *InvalidTokenErasureWorker) retryDelay(attempts int) time.Duration {
	w.jitterMu.Lock()
	defer w.jitterMu.Unlock()
	return jitteredAPNSBackoff(
		w.retryInitial,
		w.retryMaximum,
		attempts,
		w.jitter,
	)
}

func (w *InvalidTokenErasureWorker) release(jobID []byte) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		w.operationTTL,
	)
	defer cancel()
	if err := w.store.ReleaseDeliveryJob(ctx, jobID); err != nil {
		w.logWorkerError()
	}
}

func (w *InvalidTokenErasureWorker) logWorkerError() {
	if w == nil {
		return
	}
	w.errorLogs.Log(
		w.logger,
		w.clock.Now().UTC(),
		"invalid-token erasure worker degraded",
	)
}
