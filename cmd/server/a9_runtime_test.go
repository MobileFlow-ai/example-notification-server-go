package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type a9ReadinessProviderStub struct {
	err     error
	calls   int
	bounded bool
	sampled time.Time
}

func (provider *a9ReadinessProviderStub) Ready(
	ctx context.Context,
	sampled time.Time,
) error {
	provider.calls++
	_, provider.bounded = ctx.Deadline()
	provider.sampled = sampled
	return provider.err
}

func TestA9TrustReadinessUsesBoundedNonMutatingCheck(t *testing.T) {
	provider := &a9ReadinessProviderStub{}

	require.True(t, a9TrustReady(provider))
	require.Equal(t, 1, provider.calls)
	require.True(t, provider.bounded)
	require.False(t, provider.sampled.IsZero())
}

func TestA9TrustReadinessFailsClosed(t *testing.T) {
	require.False(t, a9TrustReady(nil))

	provider := &a9ReadinessProviderStub{
		err: errors.New("unavailable"),
	}
	require.False(t, a9TrustReady(provider))
	require.Equal(t, 1, provider.calls)
}

type a9RefreshManagerStub struct {
	mu           sync.Mutex
	next         time.Time
	available    bool
	refreshErr   error
	refreshCalls int
	onRefresh    func()
	panicNext    bool
}

func (manager *a9RefreshManagerStub) NextRefresh() (time.Time, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.panicNext {
		panic("A9_REFRESH_PANIC_CANARY")
	}
	return manager.next, manager.available
}

func (manager *a9RefreshManagerStub) Refresh(context.Context) error {
	manager.mu.Lock()
	manager.refreshCalls++
	onRefresh := manager.onRefresh
	err := manager.refreshErr
	manager.mu.Unlock()
	if onRefresh != nil {
		onRefresh()
	}
	return err
}

func TestA9RefreshWorkerRefreshesBeforeCurrentnessDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	manager := &a9RefreshManagerStub{
		next:      time.Now().UTC().Add(time.Second),
		available: true,
		onRefresh: cancel,
	}
	done := make(chan struct{})
	go func() {
		runA9RefreshWorker(ctx, manager, zap.NewNop(), cancel)
		close(done)
	}()

	require.Eventually(t, func() bool {
		select {
		case <-done:
			manager.mu.Lock()
			defer manager.mu.Unlock()
			return manager.refreshCalls == 1
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestA9RefreshWorkerDoesNotSpinOnIdenticalEarlyRefresh(
	t *testing.T,
) {
	next := time.Now().UTC().Add(time.Hour)
	require.Equal(
		t,
		next,
		a9RefreshWakeAt(next, next),
	)
	require.Equal(
		t,
		next.Add(-a9RefreshLeadTime),
		a9RefreshWakeAt(next, time.Time{}),
	)
}

func TestA9RefreshWorkerCancelsWhenTrustHasNoCurrentReceipt(
	t *testing.T,
) {
	core, observed := observer.New(zap.ErrorLevel)
	ctx, cancel := context.WithCancel(t.Context())
	manager := &a9RefreshManagerStub{}
	done := make(chan struct{})
	go func() {
		runA9RefreshWorker(ctx, manager, zap.New(core), cancel)
		close(done)
	}()

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return ctx.Err() != nil
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
	entries := observed.All()
	require.Len(t, entries, 1)
	require.Equal(t, "A9 keyset trust unavailable", entries[0].Message)
	require.Empty(t, entries[0].Context)
}

func TestA9RefreshWorkerPanicCancelsWithoutLoggingPanicValue(
	t *testing.T,
) {
	core, observed := observer.New(zap.ErrorLevel)
	ctx, cancel := context.WithCancel(t.Context())
	manager := &a9RefreshManagerStub{panicNext: true}
	done := make(chan struct{})
	go func() {
		runA9RefreshWorker(ctx, manager, zap.New(core), cancel)
		close(done)
	}()

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return ctx.Err() != nil
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
	entries := observed.All()
	require.Len(t, entries, 1)
	require.Equal(
		t,
		"A9 keyset refresh worker stopped",
		entries[0].Message,
	)
	require.NotContains(t, entries[0].Message, "A9_REFRESH_PANIC_CANARY")
	require.Empty(t, entries[0].Context)
}

func TestA9PrivateListenerFailureCancelsRuntimeWithFixedLog(
	t *testing.T,
) {
	core, observed := observer.New(zap.ErrorLevel)
	ctx, cancel := context.WithCancel(t.Context())
	failed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		monitorA9PrivateSurfaceFailure(
			ctx,
			failed,
			zap.New(core),
			cancel,
		)
		close(done)
	}()
	close(failed)

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return ctx.Err() != nil
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
	entries := observed.All()
	require.Len(t, entries, 1)
	require.Equal(t, "A9 private listener stopped", entries[0].Message)
	require.Empty(t, entries[0].Context)
}

func TestA9PrivateHandlerFailureMarksSurfaceUnavailable(
	t *testing.T,
) {
	handlerFailed := make(chan struct{})
	surface := &a9PrivateSurface{
		failed: make(chan struct{}),
		done:   make(chan struct{}),
	}
	surface.ready.Store(true)
	monitorDone := make(chan struct{})
	go func() {
		surface.monitorServerFailure(handlerFailed)
		close(monitorDone)
	}()

	close(handlerFailed)
	select {
	case <-monitorDone:
	case <-time.After(time.Second):
		t.Fatal("handler failure monitor did not stop")
	}
	require.False(t, surface.Ready())
	select {
	case <-surface.Failed():
	default:
		t.Fatal("handler panic did not fail the private surface")
	}
}

type a9RegistrationRefresher struct{}

func (a9RegistrationRefresher) Refresh(
	context.Context,
	vault.RefreshRequest,
) (*vault.RefreshResult, error) {
	return nil, vault.ErrStoreUnavailable
}

func TestA9ModeNeverConstructsLegacyRegistrationHandler(t *testing.T) {
	handler, err := secureRegistrationForMode(nil, "", true)
	require.NoError(t, err)
	require.Nil(t, handler)

	handler, err = secureRegistrationForMode(
		a9RegistrationRefresher{},
		"01234567890123456789012345678901",
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, handler)
}
