package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type a10ReadinessProviderStub struct {
	err     error
	calls   int
	bounded bool
}

func (provider *a10ReadinessProviderStub) CurrentA10Keyset(ctx context.Context) ([]byte, error) {
	provider.calls++
	_, provider.bounded = ctx.Deadline()
	return []byte("keyset"), provider.err
}

func TestA10TrustReadinessUsesBoundedDurableCurrentCheck(t *testing.T) {
	provider := &a10ReadinessProviderStub{}
	require.True(t, a10TrustReady(provider))
	require.Equal(t, 1, provider.calls)
	require.True(t, provider.bounded)
}

func TestA10TrustReadinessFailsClosed(t *testing.T) {
	require.False(t, a10TrustReady(nil))
	provider := &a10ReadinessProviderStub{err: errors.New("unavailable")}
	require.False(t, a10TrustReady(provider))
	require.Equal(t, 1, provider.calls)
}

type a10RefreshManagerStub struct {
	mu           sync.Mutex
	next         time.Time
	available    bool
	refreshErr   error
	refreshCalls int
	onRefresh    func()
	panicNext    bool
}

func (manager *a10RefreshManagerStub) NextRefresh() (time.Time, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.panicNext {
		panic("A10_REFRESH_PANIC_CANARY")
	}
	return manager.next, manager.available
}

func (manager *a10RefreshManagerStub) Refresh(context.Context) error {
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

func TestA10RefreshWorkerRefreshesBeforeBoundedDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	manager := &a10RefreshManagerStub{
		next:      time.Now().UTC().Add(time.Second),
		available: true,
		onRefresh: cancel,
	}
	done := make(chan struct{})
	go func() {
		runA10RefreshWorker(ctx, manager, zap.NewNop(), cancel)
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

func TestA10RefreshWorkerDoesNotSpinOnIdenticalEarlyRefresh(t *testing.T) {
	next := time.Now().UTC().Add(time.Hour)
	require.Equal(t, next, a10RefreshWakeAt(next, next))
	require.Equal(
		t,
		next.Add(-a10RefreshLeadTime),
		a10RefreshWakeAt(next, time.Time{}),
	)
}

func TestA10RefreshWorkerCancelsWhenNoCurrentReceiptExists(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	manager := &a10RefreshManagerStub{}
	done := make(chan struct{})
	go func() {
		runA10RefreshWorker(ctx, manager, zap.NewNop(), cancel)
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
}

func TestA10RefreshWorkerPanicCancelsWithoutLoggingPanicValue(t *testing.T) {
	core, observed := observer.New(zap.ErrorLevel)
	ctx, cancel := context.WithCancel(t.Context())
	manager := &a10RefreshManagerStub{panicNext: true}
	done := make(chan struct{})
	go func() {
		runA10RefreshWorker(ctx, manager, zap.New(core), cancel)
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
	require.Equal(t, "A10 keyset refresh worker stopped", entries[0].Message)
	require.NotContains(t, entries[0].Message, "A10_REFRESH_PANIC_CANARY")
	require.Empty(t, entries[0].Context)
}
