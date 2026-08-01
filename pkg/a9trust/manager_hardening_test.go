package a9trust

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type latchRetryStore struct {
	memoryKeysetStore
	latchFailures int
	latchCalls    int
	bounded       bool
}

func (store *latchRetryStore) LatchKeysetUncertainty(
	ctx context.Context,
	_ string,
	reason string,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.latchCalls++
	_, store.bounded = ctx.Deadline()
	if err := ctx.Err(); err != nil {
		return err
	}
	if store.latchFailures > 0 {
		store.latchFailures--
		return errors.New("storage down")
	}
	store.state.Uncertain = true
	store.latches = append(store.latches, reason)
	return nil
}

func TestManagerRetriesPendingLatchWithOwnedBoundedContext(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &latchRetryStore{latchFailures: 1}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)

	if err := manager.LatchArtifactUncertainty(
		Invalid("BAD_SIGNATURE"),
	); !errors.Is(err, ErrKeysetRejected) {
		t.Fatalf("non-key-state latch error = %v", err)
	}
	if store.latchCalls != 0 {
		t.Fatal("untrusted artifact verdict reached the durable latch")
	}
	err := manager.LatchArtifactUncertainty(
		Inconclusive("KEY_STATE"),
	)
	if !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Fatalf("first latch error = %v", err)
	}
	if !manager.isHardUncertain() {
		t.Fatal("failed durable write reopened local trust")
	}
	if err := manager.Refresh(
		context.Background(),
	); !errors.Is(err, ErrKeysetUnavailable) {
		t.Fatalf("retry error = %v", err)
	}
	store.mu.Lock()
	latchCalls := store.latchCalls
	bounded := store.bounded
	latches := append([]string(nil), store.latches...)
	store.mu.Unlock()
	if latchCalls != 2 || !bounded ||
		len(latches) != 1 ||
		latches[0] != "KEY_STATE" {
		t.Fatalf(
			"latch receipt calls=%d bounded=%v latches=%v",
			latchCalls,
			bounded,
			latches,
		)
	}
}

type recoveringLatchStore struct {
	memoryKeysetStore
	available chan struct{}
}

type observableLatchStore struct {
	memoryKeysetStore
	attempts  chan int64
	calls     atomic.Int64
	successAt atomic.Int64
}

func (store *observableLatchStore) LatchKeysetUncertainty(
	ctx context.Context,
	_ string,
	reason string,
) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("unbounded latch")
	}
	call := store.calls.Add(1)
	store.attempts <- call
	if successAt := store.successAt.Load(); successAt == 0 ||
		call < successAt {
		return errors.New("storage down")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.state.Uncertain = true
	store.latches = append(store.latches, reason)
	return nil
}

func (store *recoveringLatchStore) LatchKeysetUncertainty(
	ctx context.Context,
	_ string,
	reason string,
) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("unbounded latch")
	}
	select {
	case <-store.available:
	case <-ctx.Done():
		return ctx.Err()
	default:
		return errors.New("storage down")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.state.Uncertain = true
	store.latches = append(store.latches, reason)
	return nil
}

func TestManagerCloseReportsPendingLatchAndRetriesAfterClose(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &recoveringLatchStore{
		available: make(chan struct{}),
	}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)

	if err := manager.LatchArtifactUncertainty(
		Inconclusive("KEY_STATE"),
	); !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Fatalf("initial latch error = %v", err)
	}
	if err := manager.Close(); !errors.Is(
		err,
		ErrTrustStoreUnavailable,
	) {
		t.Fatalf("close receipt error = %v", err)
	}
	if !manager.hasPendingLatch() {
		t.Fatal("Close discarded the pending hard-latch reason")
	}

	close(store.available)
	select {
	case <-manager.latchDone:
	case <-time.After(2 * time.Second):
		t.Fatal("manager-owned retry did not survive Close")
	}
	if manager.hasPendingLatch() {
		t.Fatal("durable latch receipt was not recorded")
	}
	store.mu.Lock()
	latches := append([]string(nil), store.latches...)
	uncertain := store.state.Uncertain
	store.mu.Unlock()
	if !uncertain || len(latches) != 1 ||
		latches[0] != "KEY_STATE" {
		t.Fatalf(
			"durable latch receipt uncertain=%v latches=%v",
			uncertain,
			latches,
		)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("second Close after receipt = %v", err)
	}
}

func TestManagerCloseContextCanRestartWaitAfterTimeout(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &recoveringLatchStore{
		available: make(chan struct{}),
	}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	var release sync.Once
	t.Cleanup(func() {
		release.Do(func() { close(store.available) })
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		_ = manager.CloseContext(ctx)
	})

	if err := manager.LatchArtifactUncertainty(
		Inconclusive("KEY_STATE"),
	); !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Fatalf("initial latch error = %v", err)
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		25*time.Millisecond,
	)
	err := manager.CloseContext(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded close error = %v", err)
	}
	awaitManagerClosed(t, manager)
	select {
	case <-manager.latchDone:
		t.Fatal("retry worker stopped before the hard latch was durable")
	default:
	}

	release.Do(func() { close(store.available) })
	ctx, cancel = context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	defer cancel()
	if err := manager.CloseContext(ctx); err != nil {
		t.Fatalf("restarted close wait error = %v", err)
	}
	select {
	case <-manager.latchDone:
	default:
		t.Fatal("CloseContext succeeded before the retry worker stopped")
	}
	if manager.hasPendingLatch() {
		t.Fatal("CloseContext succeeded with a pending durable latch")
	}
}

func TestManagerCloseContextIsBoundedByActiveVerifier(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &blockingCurrentStore{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	verified := make(chan error, 1)
	go func() {
		_, err := manager.Verifier(
			context.Background(),
			fixture.issuedAt,
		)
		verified <- err
	}()
	<-store.entered
	ctx, cancel := context.WithTimeout(
		context.Background(),
		25*time.Millisecond,
	)
	err := manager.CloseContext(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		close(store.release)
		t.Fatalf("active-verifier close error = %v", err)
	}

	close(store.release)
	if err := <-verified; err != nil {
		t.Fatalf("active verifier failed: %v", err)
	}
	ctx, cancel = context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer cancel()
	if err := manager.CloseContext(ctx); err != nil {
		t.Fatalf("close after verifier release = %v", err)
	}
}

func TestManagerConcurrentCloseContextWaitsShareOneShutdown(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &recoveringLatchStore{
		available: make(chan struct{}),
	}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	var release sync.Once
	t.Cleanup(func() {
		release.Do(func() { close(store.available) })
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		_ = manager.CloseContext(ctx)
	})
	if err := manager.LatchArtifactUncertainty(
		Inconclusive("KEY_STATE"),
	); !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Fatalf("initial latch error = %v", err)
	}

	const callers = 8
	results := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func() {
			ctx, cancel := context.WithTimeout(
				context.Background(),
				2*time.Second,
			)
			defer cancel()
			results <- manager.CloseContext(ctx)
		}()
	}
	awaitManagerClosed(t, manager)
	release.Do(func() { close(store.available) })
	for index := 0; index < callers; index++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent CloseContext %d error = %v", index, err)
		}
	}
	select {
	case <-manager.latchDone:
	default:
		t.Fatal("concurrent CloseContext returned before worker shutdown")
	}
	store.mu.Lock()
	latches := append([]string(nil), store.latches...)
	store.mu.Unlock()
	if len(latches) != 1 || latches[0] != "KEY_STATE" {
		t.Fatalf("durable latch receipts = %v", latches)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("compatible Close after CloseContext = %v", err)
	}
}

func awaitManagerClosed(t *testing.T, manager *Manager) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if manager.isClosed() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("manager shutdown did not close trust state")
		case <-ticker.C:
		}
	}
}

func TestManagerLatchRetryWakesImmediatelyOnNewSignal(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &observableLatchStore{
		attempts: make(chan int64, 8),
	}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	manager.latchRetryMin = 5 * time.Second
	manager.latchRetryMax = 5 * time.Second

	if err := manager.LatchArtifactUncertainty(
		Inconclusive("KEY_STATE"),
	); !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Fatalf("initial latch error = %v", err)
	}
	awaitLatchAttempt(t, store.attempts, 1)
	awaitLatchAttempt(t, store.attempts, 2)

	manager.requestLatchRetry()
	awaitLatchAttempt(t, store.attempts, 3)

	store.successAt.Store(4)
	if err := manager.Close(); err != nil {
		t.Fatalf("close after signaled retry = %v", err)
	}
	awaitLatchAttempt(t, store.attempts, 4)
}

func TestManagerCloseWakesPendingFiveSecondLatchBackoff(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &observableLatchStore{
		attempts: make(chan int64, 8),
	}
	store.successAt.Store(4)
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	manager.latchRetryMin = 5 * time.Second
	manager.latchRetryMax = 5 * time.Second

	if err := manager.LatchArtifactUncertainty(
		Inconclusive("KEY_STATE"),
	); !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Fatalf("initial latch error = %v", err)
	}
	awaitLatchAttempt(t, store.attempts, 1)
	awaitLatchAttempt(t, store.attempts, 2)

	if err := manager.Close(); !errors.Is(
		err,
		ErrTrustStoreUnavailable,
	) {
		t.Fatalf("close receipt error = %v", err)
	}
	awaitLatchAttempt(t, store.attempts, 3)
	awaitLatchAttempt(t, store.attempts, 4)
	select {
	case <-manager.latchDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not wake the pending five-second backoff")
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("second Close after durable receipt = %v", err)
	}
}

func awaitLatchAttempt(
	t *testing.T,
	attempts <-chan int64,
	expected int64,
) {
	t.Helper()
	select {
	case attempt := <-attempts:
		if attempt != expected {
			t.Fatalf("latch attempt = %d, want %d", attempt, expected)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for latch attempt %d", expected)
	}
}

func TestManagerRejectsZeroClockBeforeDurableAcceptance(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(fixture.body)
	}))
	defer server.Close()
	store := &memoryKeysetStore{}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		time.Time{},
		fixture.topicConfig,
	)
	cleanupManager(t, manager)

	if err := manager.Refresh(context.Background()); !errors.Is(
		err,
		ErrKeysetUnavailable,
	) {
		t.Fatalf("zero-clock refresh error = %v", err)
	}
	store.mu.Lock()
	sequence := store.state.Sequence
	latches := len(store.latches)
	store.mu.Unlock()
	if requests != 0 || sequence != 0 || latches != 0 ||
		manager.isHardUncertain() {
		t.Fatalf(
			"zero clock mutated trust requests=%d sequence=%d latches=%d hard=%v",
			requests,
			sequence,
			latches,
			manager.isHardUncertain(),
		)
	}
}

func TestManagerEnforcesRefreshDeadlineAndBindingCurrentness(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &memoryKeysetStore{}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)

	topic, epoch := fixtureTopic(t)
	if _, verdict := manager.TopicBindingForEpoch(
		context.Background(),
		topic,
		epoch,
		fixture.issuedAt,
		fixture.issuedAt.Add(30*time.Second),
		true,
	); verdict.IsEligible() {
		t.Fatal("topic binding was usable before a current durable keyset")
	}
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, verdict := manager.TopicBindingForEpoch(
		context.Background(),
		topic,
		epoch,
		fixture.issuedAt,
		fixture.issuedAt.Add(30*time.Second),
		true,
	); !verdict.IsEligible() {
		t.Fatalf("current topic binding verdict = %+v", verdict)
	}

	refreshDeadline := fixture.issuedAt.Add(10 * time.Second)
	manager.mu.Lock()
	manager.snapshot.nextRefresh = refreshDeadline
	manager.mu.Unlock()
	if _, err := manager.Verifier(
		context.Background(),
		refreshDeadline.Add(-time.Nanosecond),
	); err != nil {
		t.Fatalf("before refresh deadline: %v", err)
	}
	if _, err := manager.Verifier(
		context.Background(),
		refreshDeadline,
	); !errors.Is(err, ErrKeysetUnavailable) {
		t.Fatalf("at refresh deadline error = %v", err)
	}
	if _, verdict := manager.TopicBindingForEpoch(
		context.Background(),
		topic,
		epoch,
		refreshDeadline,
		refreshDeadline.Add(time.Second),
		true,
	); verdict.IsEligible() {
		t.Fatal("topic binding survived the refresh deadline")
	}
}

type blockingCurrentStore struct {
	memoryKeysetStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type countingCurrentStore struct {
	memoryKeysetStore
	currentCalls atomic.Int64
}

func (store *countingCurrentStore) CurrentKeysetState(
	ctx context.Context,
	environment string,
) (KeysetState, error) {
	store.currentCalls.Add(1)
	return store.memoryKeysetStore.CurrentKeysetState(ctx, environment)
}

func TestManagerReadinessDoesNotWaitBehindRefreshTrustMutex(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	refreshEntered := make(chan struct{})
	refreshRelease := make(chan struct{})
	var (
		requests    atomic.Int64
		enteredOnce sync.Once
		releaseOnce sync.Once
	)
	releaseRefresh := func() {
		releaseOnce.Do(func() {
			close(refreshRelease)
		})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if requests.Add(1) > 1 {
			enteredOnce.Do(func() {
				close(refreshEntered)
			})
			select {
			case <-refreshRelease:
			case <-request.Context().Done():
				return
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(fixture.body)
	}))
	defer server.Close()
	defer releaseRefresh()

	store := &memoryKeysetStore{}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- manager.Refresh(context.Background())
	}()
	select {
	case <-refreshEntered:
	case <-time.After(time.Second):
		t.Fatal("refresh did not hold the trust mutex")
	}

	readyContext, readyCancel := context.WithTimeout(
		context.Background(),
		500*time.Millisecond,
	)
	defer readyCancel()
	readyDone := make(chan error, 1)
	go func() {
		readyDone <- manager.Ready(
			readyContext,
			fixture.issuedAt,
		)
	}()
	select {
	case err := <-readyDone:
		if err != nil {
			t.Fatalf("readiness behind refresh: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		releaseRefresh()
		<-readyDone
		t.Fatal("readiness waited behind refresh trust mutex")
	}

	releaseRefresh()
	select {
	case err := <-refreshDone:
		if err != nil {
			t.Fatalf("blocked refresh: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh did not finish after release")
	}
}

func TestManagerReadinessIsBoundedBySlowDurableJoin(t *testing.T) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &blockingCurrentStore{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseStore := func() {
		releaseOnce.Do(func() {
			close(store.release)
		})
	}
	defer releaseStore()
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	readyContext, readyCancel := context.WithTimeout(
		context.Background(),
		25*time.Millisecond,
	)
	defer readyCancel()
	readyDone := make(chan error, 1)
	go func() {
		readyDone <- manager.Ready(
			readyContext,
			fixture.issuedAt,
		)
	}()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("readiness did not attempt its durable join")
	}
	select {
	case err := <-readyDone:
		if !errors.Is(err, ErrTrustStoreUnavailable) {
			t.Fatalf(
				"slow durable join error = %v, want ErrTrustStoreUnavailable",
				err,
			)
		}
	case <-time.After(500 * time.Millisecond):
		releaseStore()
		t.Fatal("readiness exceeded its caller-owned deadline")
	}
}

func TestManagerReadinessRequiresUsableCurrentTopicSecret(
	t *testing.T,
) {
	fixture := managerBoundaryFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &countingCurrentStore{}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	currentEpoch := TopicEpoch(fixture.issuedAt) + 1
	evaluationTime := TopicEpochBoundary(currentEpoch).
		Add(30 * time.Second)
	if err := manager.Ready(
		context.Background(),
		evaluationTime,
	); err != nil {
		t.Fatalf("current topic readiness: %v", err)
	}
	if calls := store.currentCalls.Load(); calls != 1 {
		t.Fatalf("durable readiness joins = %d, want 1", calls)
	}

	manager.topicKeys.mu.Lock()
	removed := false
	for index := range manager.topicKeys.records {
		record := &manager.topicKeys.records[index]
		if record.descriptor.TopicKeyEpoch != currentEpoch {
			continue
		}
		clear(record.key)
		record.key = nil
		removed = true
		break
	}
	manager.topicKeys.mu.Unlock()
	if !removed {
		t.Fatal("fixture did not contain the next current TOPIC secret")
	}
	if err := manager.Ready(
		context.Background(),
		evaluationTime,
	); !errors.Is(err, ErrKeysetUnavailable) {
		t.Fatalf(
			"missing current TOPIC secret error = %v, want ErrKeysetUnavailable",
			err,
		)
	}
	if calls := store.currentCalls.Load(); calls != 1 {
		t.Fatalf(
			"missing local secret performed %d durable joins, want 1",
			calls,
		)
	}
}

func TestManagerReadinessMismatchDoesNotMutateTrustState(t *testing.T) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &memoryKeysetStore{}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	store.state.ObjectHash =
		"0000000000000000000000000000000000000000000000000000000000000000"
	store.mu.Unlock()
	if err := manager.Ready(
		context.Background(),
		fixture.issuedAt,
	); !errors.Is(err, ErrKeysetUnavailable) {
		t.Fatalf(
			"durable mismatch error = %v, want ErrKeysetUnavailable",
			err,
		)
	}
	if manager.isHardUncertain() {
		t.Fatal("readiness mismatch mutated local trust state")
	}
	store.mu.Lock()
	latches := len(store.latches)
	store.mu.Unlock()
	if latches != 0 {
		t.Fatalf("readiness mismatch wrote %d durable latches", latches)
	}
}

func TestManagerTopicBindingLeaseUsesOneJoinForMaximumReplacement(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &countingCurrentStore{}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	sequence, hash := keysetReceiptFromMemoryStore(t, &store.memoryKeysetStore)
	lease, err := manager.AcquireTopicBindingLease(
		context.Background(),
		fixture.issuedAt,
		sequence,
		hash,
	)
	if err != nil {
		t.Fatal(err)
	}

	topic, epoch := fixtureTopic(t)
	for index := 0; index < 2048; index++ {
		if _, verdict := lease.TopicBindingForEpoch(
			context.Background(),
			topic,
			epoch,
			fixture.issuedAt,
			fixture.issuedAt.Add(time.Second),
			true,
		); !verdict.IsEligible() {
			lease.Close()
			t.Fatalf("binding %d verdict = %+v", index, verdict)
		}
	}
	if calls := store.currentCalls.Load(); calls != 1 {
		lease.Close()
		t.Fatalf("durable currentness joins = %d, want 1", calls)
	}
	lease.Close()
	lease.Close()
	if _, verdict := lease.TopicBindingForEpoch(
		context.Background(),
		topic,
		epoch,
		fixture.issuedAt,
		fixture.issuedAt.Add(time.Second),
		true,
	); verdict.Terminal != "INCONCLUSIVE" ||
		verdict.Reason != "TRUST_UNAVAILABLE" {
		t.Fatalf("closed lease verdict = %+v", verdict)
	}
}

func TestManagerCurrentTopicBindingLeaseReturnsReceiptAndCandidates(
	t *testing.T,
) {
	fixture := managerBoundaryFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &countingCurrentStore{}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	expectedSequence, expectedHash := keysetReceiptFromMemoryStore(
		t,
		&store.memoryKeysetStore,
	)
	currentEpoch := TopicEpoch(fixture.issuedAt) + 1
	evaluationTime := TopicEpochBoundary(currentEpoch).Add(30 * time.Second)
	manager.clock = func() time.Time {
		return evaluationTime
	}

	lease, sequence, hash, err := manager.AcquireCurrentTopicBindingLease(
		context.Background(),
		evaluationTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if sequence != expectedSequence || hash != expectedHash {
		t.Fatalf(
			"lease receipt sequence=%d hash=%x, want sequence=%d hash=%x",
			sequence,
			hash,
			expectedSequence,
			expectedHash,
		)
	}
	if calls := store.currentCalls.Load(); calls != 1 {
		t.Fatalf("durable currentness joins = %d, want 1", calls)
	}

	topic, _ := fixtureTopic(t)
	candidates, verdict := lease.CandidateTopicBindings(
		context.Background(),
		topic,
		evaluationTime,
	)
	if !verdict.IsEligible() || len(candidates) != 2 ||
		candidates[0].TopicKeyEpoch != currentEpoch ||
		candidates[1].TopicKeyEpoch != currentEpoch-1 {
		t.Fatalf("candidates=%+v verdict=%+v", candidates, verdict)
	}
	if calls := store.currentCalls.Load(); calls != 1 {
		t.Fatalf("candidate derivation added durable joins: %d", calls)
	}

	if _, verdict = lease.CandidateTopicBindings(
		context.Background(),
		nil,
		evaluationTime,
	); verdict.Terminal != "INVALID" ||
		verdict.Reason != "TOPIC_RESOLVER" {
		t.Fatalf("invalid topic verdict = %+v", verdict)
	}
	manager.mu.RLock()
	hardUncertain := manager.hardUncertain
	manager.mu.RUnlock()
	if hardUncertain {
		t.Fatal("candidate computation globally latched uncertainty")
	}
	if candidates, verdict = lease.CandidateTopicBindings(
		context.Background(),
		topic,
		evaluationTime.Add(time.Nanosecond),
	); candidates != nil ||
		verdict.Terminal != "INCONCLUSIVE" ||
		verdict.Reason != "TRUST_UNAVAILABLE" {
		t.Fatalf("inexact-time candidates=%v verdict=%+v", candidates, verdict)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if candidates, verdict = lease.CandidateTopicBindings(
		cancelled,
		topic,
		evaluationTime,
	); candidates != nil ||
		verdict.Terminal != "INCONCLUSIVE" ||
		verdict.Reason != "TRUST_UNAVAILABLE" {
		t.Fatalf("cancelled candidates=%v verdict=%+v", candidates, verdict)
	}

	manager.clock = func() time.Time {
		return fixture.expiresAt
	}
	if candidates, verdict = lease.CandidateTopicBindings(
		context.Background(),
		topic,
		evaluationTime,
	); candidates != nil ||
		verdict.Terminal != "INCONCLUSIVE" ||
		verdict.Reason != "TRUST_UNAVAILABLE" {
		t.Fatalf("expired candidates=%v verdict=%+v", candidates, verdict)
	}
}

func TestManagerTopicBindingLeasePinsReceiptAndCurrentnessDeadline(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &countingCurrentStore{}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	sequence, hash := keysetReceiptFromMemoryStore(t, &store.memoryKeysetStore)

	wrongHash := hash
	wrongHash[0] ^= 0xff
	if lease, err := manager.AcquireTopicBindingLease(
		context.Background(),
		fixture.issuedAt,
		sequence,
		wrongHash,
	); lease != nil || !errors.Is(err, ErrKeysetUnavailable) {
		if lease != nil {
			lease.Close()
		}
		t.Fatalf("mismatched receipt lease=%v error=%v", lease, err)
	}

	refreshDeadline := fixture.issuedAt.Add(10 * time.Second)
	manager.mu.Lock()
	manager.snapshot.nextRefresh = refreshDeadline
	manager.mu.Unlock()
	var clockNanos atomic.Int64
	clockNanos.Store(fixture.issuedAt.UnixNano())
	manager.clock = func() time.Time {
		return time.Unix(0, clockNanos.Load()).UTC()
	}
	lease, err := manager.AcquireTopicBindingLease(
		context.Background(),
		fixture.issuedAt,
		sequence,
		hash,
	)
	if err != nil {
		t.Fatal(err)
	}
	topic, epoch := fixtureTopic(t)
	clockNanos.Store(refreshDeadline.UnixNano())
	if _, verdict := lease.TopicBindingForEpoch(
		context.Background(),
		topic,
		epoch,
		fixture.issuedAt,
		refreshDeadline.Add(time.Second),
		true,
	); verdict.Terminal != "INCONCLUSIVE" ||
		verdict.Reason != "TRUST_UNAVAILABLE" {
		lease.Close()
		t.Fatalf("expired lease verdict = %+v", verdict)
	}
	lease.Close()
}

func TestManagerTopicBindingLeaseSerializesRefreshAndClose(
	t *testing.T,
) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &countingCurrentStore{}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	sequence, hash := keysetReceiptFromMemoryStore(t, &store.memoryKeysetStore)
	lease, err := manager.AcquireTopicBindingLease(
		context.Background(),
		fixture.issuedAt,
		sequence,
		hash,
	)
	if err != nil {
		t.Fatal(err)
	}

	refreshStarted := make(chan struct{})
	refreshDone := make(chan error, 1)
	go func() {
		close(refreshStarted)
		refreshDone <- manager.Refresh(context.Background())
	}()
	<-refreshStarted
	closeStarted := make(chan struct{})
	closeDone := make(chan error, 1)
	go func() {
		close(closeStarted)
		closeDone <- manager.Close()
	}()
	<-closeStarted

	select {
	case err := <-refreshDone:
		lease.Close()
		t.Fatalf("refresh escaped active lease: %v", err)
	case err := <-closeDone:
		lease.Close()
		t.Fatalf("Close escaped active lease: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	topic, epoch := fixtureTopic(t)
	if _, verdict := lease.TopicBindingForEpoch(
		context.Background(),
		topic,
		epoch,
		fixture.issuedAt,
		fixture.issuedAt.Add(time.Second),
		true,
	); !verdict.IsEligible() {
		lease.Close()
		t.Fatalf("active lease verdict = %+v", verdict)
	}
	lease.Close()

	refreshErr := <-refreshDone
	if refreshErr != nil && !errors.Is(refreshErr, ErrKeysetUnavailable) {
		t.Fatalf("concurrent refresh error = %v", refreshErr)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("concurrent Close error = %v", err)
	}
}

func TestLatchRetryDelayIsBoundedExponential(t *testing.T) {
	delay := latchRetryMinimum
	want := []time.Duration{
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		1600 * time.Millisecond,
		3200 * time.Millisecond,
		5 * time.Second,
		5 * time.Second,
	}
	for index, expected := range want {
		delay = nextLatchRetryDelay(delay, latchRetryMaximum)
		if delay != expected {
			t.Fatalf(
				"backoff %d = %s, want %s",
				index,
				delay,
				expected,
			)
		}
	}
	if got := nextLatchRetryDelay(0, latchRetryMaximum); got !=
		latchRetryMinimum {
		t.Fatalf("zero backoff = %s", got)
	}
}

func keysetReceiptFromMemoryStore(
	t *testing.T,
	store *memoryKeysetStore,
) (uint64, [32]byte) {
	t.Helper()
	store.mu.Lock()
	sequence := store.state.Sequence
	hashText := store.state.ObjectHash
	store.mu.Unlock()
	decoded, err := hex.DecodeString(hashText)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("stored keyset hash %q: %v", hashText, err)
	}
	var hash [32]byte
	copy(hash[:], decoded)
	clear(decoded)
	return sequence, hash
}

func (store *blockingCurrentStore) CurrentKeysetState(
	ctx context.Context,
	environment string,
) (KeysetState, error) {
	store.once.Do(func() {
		close(store.entered)
	})
	select {
	case <-store.release:
	case <-ctx.Done():
		return KeysetState{}, ctx.Err()
	}
	return store.memoryKeysetStore.CurrentKeysetState(ctx, environment)
}

func TestManagerCloseWaitsForActiveVerifier(t *testing.T) {
	fixture := managerFixtureFromCorpus(t)
	server := keysetFixtureServer(t, fixture.body)
	defer server.Close()
	store := &blockingCurrentStore{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		store,
		fixture.issuedAt,
		fixture.topicConfig,
	)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	verified := make(chan error, 1)
	go func() {
		_, err := manager.Verifier(
			context.Background(),
			fixture.issuedAt,
		)
		verified <- err
	}()
	<-store.entered
	closed := make(chan error, 1)
	go func() {
		closed <- manager.Close()
	}()
	select {
	case err := <-closed:
		t.Fatalf(
			"Close returned while verifier was using trust state: %v",
			err,
		)
	case <-time.After(20 * time.Millisecond):
	}
	close(store.release)
	if err := <-verified; err != nil {
		t.Fatalf("active verifier failed: %v", err)
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after verifier released state")
	}
	if _, err := manager.Verifier(
		context.Background(),
		fixture.issuedAt,
	); !errors.Is(err, ErrKeysetUnavailable) {
		t.Fatalf("post-close verifier error = %v", err)
	}
}

func keysetFixtureServer(
	t *testing.T,
	body []byte,
) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(body)
	}))
}

func fixtureTopic(t *testing.T) ([]byte, uint32) {
	t.Helper()
	corpus := loadCorpus(t)
	replace := mustObject(
		t,
		mustObject(t, corpus.positive["subscription_replace"])["value"],
	)
	subscriptions := mustArray(t, replace["subscriptions"])
	subscription := mustObject(t, subscriptions[0])
	topic, err := DecodeBase64URL(
		mustString(t, subscription["topic_base64url"]),
		33,
	)
	if err != nil {
		t.Fatal(err)
	}
	epoch := mustUint(t, subscription["topic_key_epoch"])
	if epoch > uint64(^uint32(0)) {
		t.Fatal("fixture topic epoch overflow")
	}
	return topic, uint32(epoch)
}
