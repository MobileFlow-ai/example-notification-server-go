package main

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a10registration"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"go.uber.org/zap"
)

var (
	errA10RuntimeConfiguration = errors.New("a10 runtime configuration invalid")
	errA10RuntimeUnavailable   = errors.New("a10 runtime unavailable")
)

const (
	a10RefreshAttemptTimeout = 40 * time.Second
	a10RefreshLeadTime       = 30 * time.Second
	a10RefreshRetryDelay     = 5 * time.Second
	a10ReadinessTimeout      = time.Second
)

type a10Runtime struct {
	manager *a10registration.KeysetManager
	handler *a10registration.Handler
}

func initializeA10Runtime(ctx context.Context, config options.A10Options, environment, topic string, db *sql.DB, store *vault.Store) (*a10Runtime, error) {
	if ctx == nil || !config.Enabled || db == nil || store == nil {
		return nil, errA10RuntimeConfiguration
	}
	origin, err := a10registration.ParseKeysetOrigin(config.KeysetOrigin)
	if err != nil {
		return nil, errA10RuntimeConfiguration
	}
	rootPin, err := a9trust.ParseRootPin(config.PinnedRootPublicKeyBase64URL, config.PinnedRootKeyID)
	if err != nil {
		return nil, errA10RuntimeConfiguration
	}
	defer clear(rootPin.PublicKey[:])
	manager, err := a10registration.NewKeysetManager(a10registration.KeysetManagerOptions{
		Environment:    environment,
		Origin:         origin,
		RootPin:        rootPin,
		Store:          database.NewA10KeysetStore(db),
		RequestTimeout: time.Duration(config.KeysetRequestTimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, errA10RuntimeConfiguration
	}
	refreshContext, cancel := context.WithTimeout(ctx, a10RefreshAttemptTimeout)
	err = manager.Refresh(refreshContext)
	cancel()
	if err != nil {
		return nil, errA10RuntimeUnavailable
	}
	sink, err := vault.NewA10RegistrationSink(store, topic)
	if err != nil {
		return nil, errA10RuntimeConfiguration
	}
	handler, err := a10registration.NewHandler(a10registration.Options{
		Enabled:      true,
		Environment:  environment,
		AllowedTopic: topic,
		RootPin:      rootPin,
		Keysets:      manager,
		Replay:       database.NewA10ReplayStore(db),
		Sink:         sink,
	})
	if err != nil {
		return nil, errA10RuntimeConfiguration
	}
	return &a10Runtime{manager: manager, handler: handler}, nil
}

func a10TrustReady(manager *a10registration.KeysetManager) bool {
	if manager == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), a10ReadinessTimeout)
	defer cancel()
	_, err := manager.CurrentA10Keyset(ctx)
	return err == nil && ctx.Err() == nil
}

func runA10RefreshWorker(ctx context.Context, manager *a10registration.KeysetManager, runtimeLogger *zap.Logger, cancel context.CancelFunc) {
	defer func() {
		if recover() != nil {
			if runtimeLogger != nil {
				runtimeLogger.Error("A10 keyset refresh worker stopped")
			}
			if cancel != nil {
				cancel()
			}
		}
	}()
	if ctx == nil || manager == nil {
		if cancel != nil {
			cancel()
		}
		return
	}
	var successfulDeadline time.Time
	for {
		deadline, ok := manager.NextRefresh()
		if !ok || deadline.IsZero() {
			if ctx.Err() == nil && cancel != nil {
				cancel()
			}
			return
		}
		wakeAt := deadline.Add(-a10RefreshLeadTime)
		if deadline.Equal(successfulDeadline) {
			wakeAt = deadline
		}
		if !waitUntilA9Refresh(ctx, wakeAt) {
			return
		}
		refreshContext, refreshCancel := context.WithTimeout(ctx, a10RefreshAttemptTimeout)
		err := manager.Refresh(refreshContext)
		refreshCancel()
		if ctx.Err() != nil {
			return
		}
		refreshedDeadline, available := manager.NextRefresh()
		if err == nil && available && time.Now().UTC().Before(refreshedDeadline) {
			successfulDeadline = deadline
			continue
		}
		successfulDeadline = time.Time{}
		if runtimeLogger != nil {
			runtimeLogger.Error("A10 keyset refresh failed")
		}
		if !available || !waitA9Duration(ctx, a10RefreshRetryDelay) {
			if !available && cancel != nil {
				cancel()
			}
			return
		}
	}
}
