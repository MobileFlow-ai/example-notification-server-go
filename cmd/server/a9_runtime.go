package main

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9api"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/registration"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"go.uber.org/zap"
)

var (
	errA9RuntimeConfiguration = errors.New(
		"a9 runtime configuration invalid",
	)
	errA9RuntimeUnavailable = errors.New(
		"a9 runtime unavailable",
	)
)

const (
	a9RefreshAttemptTimeout = 40 * time.Second
	a9RefreshLeadTime       = 30 * time.Second
	a9RefreshRetryDelay     = 5 * time.Second
	a9ReadinessTimeout      = time.Second
)

// a9Runtime owns the root-pinned trust manager and the dedicated private
// authority listener. The public API and XMTP listener receive only the vault
// boundary; neither receives A9 transport credentials.
type a9Runtime struct {
	manager *a9trust.Manager
	private *a9PrivateSurface
}

// initializeA9Runtime consumes the TOPIC key file exactly once and transfers
// ownership of its mutable secret buffer into the trust manager. It performs
// the initial remote/durable join before returning any listener that could be
// exposed by the caller.
func initializeA9Runtime(
	ctx context.Context,
	config options.A9Options,
	environment string,
	db *sql.DB,
	store *vault.Store,
	trustHandle *vault.A9TrustHandle,
) (*a9Runtime, error) {
	if ctx == nil ||
		!config.Enabled ||
		config.TopicCommitmentKeysJSON != "" ||
		db == nil ||
		store == nil ||
		trustHandle == nil {
		return nil, errA9RuntimeConfiguration
	}
	origin, err := a9trust.ParseKeysetOrigin(config.KeysetOrigin)
	if err != nil {
		return nil, errA9RuntimeConfiguration
	}
	rootPin, err := a9trust.ParseRootPin(
		config.PinnedRootPublicKeyBase64URL,
		config.PinnedRootKeyID,
	)
	if err != nil {
		return nil, errA9RuntimeConfiguration
	}
	defer clear(rootPin.PublicKey[:])

	topicKeys, err := loadA9TopicKeySet(
		config.TopicCommitmentKeysFilePath,
		environment,
	)
	if err != nil {
		return nil, errA9RuntimeConfiguration
	}
	manager, err := a9trust.NewManager(a9trust.ManagerOptions{
		Environment: environment,
		Origin:      origin,
		RootPin:     rootPin,
		TopicKeys:   topicKeys,
		Store:       database.NewA9KeysetStore(db),
		RequestTimeout: time.Duration(
			config.KeysetRequestTimeoutSeconds,
		) * time.Second,
	})
	if err != nil {
		topicKeys.Close()
		return nil, errA9RuntimeConfiguration
	}
	closeManager := true
	defer func() {
		if closeManager {
			_ = manager.Close()
		}
	}()

	refreshContext, refreshCancel := context.WithTimeout(
		ctx,
		a9RefreshAttemptTimeout,
	)
	err = manager.Refresh(refreshContext)
	refreshCancel()
	if err != nil {
		return nil, errA9RuntimeUnavailable
	}

	handler, err := a9api.NewHandler(a9api.HandlerOptions{
		Environment: environment,
		Trust:       manager,
		ReplayStore: database.NewA9ReplayStore(db),
		Store:       store,
		KeyState:    manager,
	})
	if err != nil {
		return nil, errA9RuntimeConfiguration
	}
	privateOptions, valid := checkedA9PrivateServerOptions(config)
	if !valid {
		return nil, errA9RuntimeConfiguration
	}
	privateServer, err := a9api.NewPrivateTLSServer(
		handler,
		privateOptions,
	)
	if err != nil {
		return nil, errA9RuntimeConfiguration
	}
	if err = trustHandle.Bind(manager); err != nil {
		return nil, errA9RuntimeConfiguration
	}

	closeManager = false
	return &a9Runtime{
		manager: manager,
		private: newA9PrivateSurface(
			privateServer,
			privateOptions.BindAddress,
		),
	}, nil
}

// secureRegistrationForMode retains the legacy authenticated endpoint only in
// non-A9 secure-vault mode. A9 mode has one authority ingress: the dedicated
// TLS listener assembled above.
func secureRegistrationForMode(
	refresher registration.Refresher,
	bearerToken string,
	a9Enabled bool,
) (*registration.Handler, error) {
	if a9Enabled {
		return nil, nil
	}
	return registration.NewHandler(refresher, bearerToken)
}

type a9PrivateSurface struct {
	server      *a9api.PrivateTLSServer
	bindAddress string
	ready       atomic.Bool

	mu          sync.Mutex
	started     bool
	stopping    bool
	failed      chan struct{}
	done        chan struct{}
	failureOnce sync.Once
}

func newA9PrivateSurface(
	server *a9api.PrivateTLSServer,
	bindAddress string,
) *a9PrivateSurface {
	return &a9PrivateSurface{
		server:      server,
		bindAddress: bindAddress,
		failed:      make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// Start reserves the configured private address synchronously. No public or
// XMTP surface needs to start before a bind failure is known.
func (surface *a9PrivateSurface) Start() error {
	if surface == nil || surface.server == nil {
		return errA9RuntimeConfiguration
	}
	surface.mu.Lock()
	if surface.started {
		surface.mu.Unlock()
		return errA9RuntimeConfiguration
	}
	listener, err := net.Listen("tcp", surface.bindAddress)
	if err != nil {
		surface.mu.Unlock()
		return errA9RuntimeUnavailable
	}
	surface.started = true
	surface.ready.Store(true)
	surface.mu.Unlock()

	go surface.serve(listener)
	go surface.monitorServerFailure(surface.server.Failed())
	return nil
}

func (surface *a9PrivateSurface) serve(listener net.Listener) {
	failed := true
	defer func() {
		panicked := recover() != nil
		_ = listener.Close()
		surface.ready.Store(false)
		handlerFailed := false
		select {
		case <-surface.server.Failed():
			handlerFailed = true
		default:
		}
		if panicked || failed || handlerFailed {
			surface.signalFailure()
		}
		close(surface.done)
	}()
	err := surface.server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		failed = false
		return
	}
	surface.mu.Lock()
	stopping := surface.stopping
	surface.mu.Unlock()
	if stopping && err == nil {
		failed = false
	}
}

func (surface *a9PrivateSurface) monitorServerFailure(
	failed <-chan struct{},
) {
	if surface == nil || failed == nil {
		return
	}
	select {
	case <-failed:
		surface.ready.Store(false)
		surface.signalFailure()
	case <-surface.done:
	}
}

func (surface *a9PrivateSurface) signalFailure() {
	if surface == nil {
		return
	}
	surface.failureOnce.Do(func() {
		close(surface.failed)
	})
}

func (surface *a9PrivateSurface) Failed() <-chan struct{} {
	if surface == nil {
		return nil
	}
	return surface.failed
}

func (surface *a9PrivateSurface) Ready() bool {
	return surface != nil && surface.ready.Load()
}

func (surface *a9PrivateSurface) Shutdown(ctx context.Context) error {
	if surface == nil || surface.server == nil || ctx == nil {
		return errA9RuntimeConfiguration
	}
	surface.mu.Lock()
	if !surface.started {
		surface.mu.Unlock()
		return nil
	}
	surface.stopping = true
	surface.ready.Store(false)
	surface.mu.Unlock()
	if err := surface.server.Shutdown(ctx); err != nil {
		return errA9RuntimeUnavailable
	}
	select {
	case <-surface.done:
		select {
		case <-surface.failed:
			return errA9RuntimeUnavailable
		default:
			return nil
		}
	case <-ctx.Done():
		return errA9RuntimeUnavailable
	}
}

type a9RefreshManager interface {
	Refresh(context.Context) error
	NextRefresh() (time.Time, bool)
}

func runA9RefreshWorker(
	ctx context.Context,
	manager a9RefreshManager,
	runtimeLogger *zap.Logger,
	cancel context.CancelFunc,
) {
	defer func() {
		if recover() != nil {
			if cancel != nil {
				cancel()
			}
			if runtimeLogger != nil {
				runtimeLogger.Error("A9 keyset refresh worker stopped")
			}
		}
	}()
	if ctx == nil || manager == nil {
		if cancel != nil {
			cancel()
		}
		return
	}

	failureLogged := false
	var successfulDeadline time.Time
	for {
		nextRefresh, ok := manager.NextRefresh()
		if !ok || nextRefresh.IsZero() {
			if ctx.Err() != nil {
				return
			}
			if runtimeLogger != nil {
				runtimeLogger.Error("A9 keyset trust unavailable")
			}
			if cancel != nil {
				cancel()
			}
			return
		}
		wakeAt := a9RefreshWakeAt(
			nextRefresh,
			successfulDeadline,
		)
		if !waitUntilA9Refresh(ctx, wakeAt) {
			return
		}

		refreshContext, refreshCancel := context.WithTimeout(
			ctx,
			a9RefreshAttemptTimeout,
		)
		err := manager.Refresh(refreshContext)
		refreshCancel()
		if ctx.Err() != nil {
			return
		}
		refreshedDeadline, available := manager.NextRefresh()
		if err == nil &&
			available &&
			time.Now().UTC().Before(refreshedDeadline) {
			failureLogged = false
			successfulDeadline = nextRefresh
			continue
		}
		successfulDeadline = time.Time{}
		if !failureLogged && runtimeLogger != nil {
			runtimeLogger.Error("A9 keyset refresh failed")
			failureLogged = true
		}
		if !available {
			if cancel != nil {
				cancel()
			}
			return
		}
		// A retained snapshot can remain retryable after its serving deadline.
		// Manager readiness and every routing/egress lease independently deny
		// use at that deadline; keeping this worker alive permits recovery from
		// a transient modern-api outage without creating a permissive window.
		if !waitA9Duration(ctx, a9RefreshRetryDelay) {
			return
		}
	}
}

func a9RefreshWakeAt(
	nextRefresh time.Time,
	successfulDeadline time.Time,
) time.Time {
	if nextRefresh.Equal(successfulDeadline) {
		// A successful early refresh can legitimately replay the same signed
		// object. Do not poll it continuously during the lead window; make one
		// final attempt at the manager's hard deadline.
		return nextRefresh
	}
	return nextRefresh.Add(-a9RefreshLeadTime)
}

func waitUntilA9Refresh(
	ctx context.Context,
	deadline time.Time,
) bool {
	delay := time.Until(deadline)
	if delay <= 0 {
		return ctx.Err() == nil
	}
	return waitA9Duration(ctx, delay)
}

func waitA9Duration(
	ctx context.Context,
	delay time.Duration,
) bool {
	timer := time.NewTimer(delay)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

type a9ReadinessProvider interface {
	Ready(
		context.Context,
		time.Time,
	) error
}

// a9TrustReady performs a bounded, read-only durable-current join and requires
// the exact current-epoch TOPIC secret without waiting behind keyset refresh.
func a9TrustReady(manager a9ReadinessProvider) bool {
	if manager == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		a9ReadinessTimeout,
	)
	defer cancel()
	err := manager.Ready(
		ctx,
		time.Now().UTC(),
	)
	return err == nil && ctx.Err() == nil
}

func monitorA9PrivateSurfaceFailure(
	ctx context.Context,
	failed <-chan struct{},
	runtimeLogger *zap.Logger,
	cancel context.CancelFunc,
) {
	if failed == nil {
		return
	}
	defer func() {
		if recover() != nil {
			if cancel != nil {
				cancel()
			}
			if runtimeLogger != nil {
				runtimeLogger.Error("A9 private listener monitor stopped")
			}
		}
	}()
	select {
	case <-failed:
		if cancel != nil {
			cancel()
		}
		if runtimeLogger != nil {
			runtimeLogger.Error("A9 private listener stopped")
		}
	case <-ctx.Done():
	}
}
