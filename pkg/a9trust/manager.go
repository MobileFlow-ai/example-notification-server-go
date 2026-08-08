package a9trust

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9schema"
)

const (
	KeysetWellKnownPath = "/.well-known/hytch-xmtp-push-a9-keyset-v1.json"
	maxKeysetBodyBytes  = 256 * 1024
	maxRequestTimeout   = 30 * time.Second
	defaultRequestTime  = 10 * time.Second
	maxRefreshInterval  = 6 * time.Hour
	latchRetryMinimum   = 100 * time.Millisecond
	latchRetryMaximum   = 5 * time.Second
)

var (
	// ErrKeysetFetch is intentionally content-free. HTTP and TLS errors can
	// contain network topology and are never returned across the API surface.
	ErrKeysetFetch = errors.New("a9 keyset fetch failed")

	// ErrKeysetRejected means a fetched object violated a signed trust rule or
	// the durable store rejected a rollback/equal-sequence conflict.
	ErrKeysetRejected = errors.New("a9 keyset rejected")

	// ErrKeysetUnavailable means no exact, unexpired, non-uncertain durable and
	// in-memory trust snapshot is available.
	ErrKeysetUnavailable = errors.New("a9 keyset unavailable")

	// ErrTrustStoreUnavailable distinguishes a storage outage from a signed
	// keyset rejection without exposing database details.
	ErrTrustStoreUnavailable = errors.New("a9 trust store unavailable")
)

// KeysetOrigin is an exact HTTPS origin. It cannot carry path, credentials,
// query, fragment, or an alternate discovery endpoint.
type KeysetOrigin struct {
	value string
}

func ParseKeysetOrigin(raw string) (KeysetOrigin, error) {
	parsed, err := url.Parse(raw)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.Path != "" ||
		parsed.RawPath != "" ||
		parsed.RawQuery != "" ||
		parsed.ForceQuery ||
		parsed.Fragment != "" ||
		parsed.Opaque != "" ||
		parsed.String() != raw {
		return KeysetOrigin{}, ErrConfiguration
	}
	return KeysetOrigin{value: raw}, nil
}

func (origin KeysetOrigin) Endpoint() string {
	if origin.value == "" {
		return ""
	}
	return origin.value + KeysetWellKnownPath
}

// AcceptedKeyset contains only root-signed public metadata. The canonical
// bytes are the complete signed object and are safe to retain as append-only
// rotation evidence. No HMAC secret is included.
type AcceptedKeyset struct {
	Environment           string
	Sequence              uint64
	ObjectHash            string
	CanonicalSignedObject []byte
	IssuedAt              time.Time
	ExpiresAt             time.Time
	RootKeyID             string
	OnlineKeys            []OnlineKey
	CommitmentKeys        []CommitmentKey
}

// KeysetState is the durable high-water/uncertainty row used to join every
// verifier and pre-egress decision to the accepted append-only history.
type KeysetState struct {
	Environment string
	Sequence    uint64
	ObjectHash  string
	ExpiresAt   time.Time
	Uncertain   bool
}

// KeysetStore owns cross-replica sequence, hash, rotation-history, and
// uncertainty semantics. AcceptKeyset must atomically compare the high-water
// row, validate staged rotation against append-only history, append a new
// accepted candidate or recognize an identical replay, and return the exact
// resulting state. Rollback/equal-different input returns ErrKeysetRejected
// and latches uncertainty in that same transaction.
type KeysetStore interface {
	AcceptKeyset(
		context.Context,
		AcceptedKeyset,
	) (KeysetState, error)
	CurrentKeysetState(
		context.Context,
		string,
	) (KeysetState, error)
	LatchKeysetUncertainty(
		context.Context,
		string,
		string,
	) error
}

type ManagerOptions struct {
	Environment    string
	Origin         KeysetOrigin
	RootPin        RootPin
	TopicKeys      *TopicKeySet
	Store          KeysetStore
	HTTPClient     *http.Client
	RequestTimeout time.Duration
	Clock          func() time.Time
}

// TopicBindingLease pins one exact durable-current keyset snapshot for a
// bounded request-scoped group of topic-binding recomputations. Close must be
// called exactly once by the acquirer; repeated calls are safe.
type TopicBindingLease interface {
	TopicBindingForEpoch(
		context.Context,
		[]byte,
		uint32,
		time.Time,
		time.Time,
		bool,
	) ([]byte, Verdict)
	CandidateTopicBindings(
		context.Context,
		[]byte,
		time.Time,
	) ([]TopicBindingCandidate, Verdict)
	Close()
}

type managerSnapshot struct {
	candidate   AcceptedKeyset
	nextRefresh time.Time
}

type managerReadinessSnapshot struct {
	environment    string
	sequence       uint64
	objectHash     string
	issuedAt       time.Time
	expiresAt      time.Time
	nextRefresh    time.Time
	commitmentKeys []CommitmentKey
}

// Manager fetches root-signed public keysets and exposes a verifier only when
// its local bytes still exactly match the durable high-water state.
type Manager struct {
	environment string
	origin      KeysetOrigin
	rootPin     RootPin
	topicKeys   *TopicKeySet
	store       KeysetStore
	client      *http.Client
	timeout     time.Duration
	clock       func() time.Time

	lifecycle     sync.RWMutex
	trustMu       sync.Mutex
	mu            sync.RWMutex
	snapshot      *managerSnapshot
	hardUncertain bool
	hardReason    string
	hardDurable   bool
	closed        bool

	latchWake     chan struct{}
	latchStop     chan struct{}
	latchDone     chan struct{}
	latchStopOnce sync.Once
	latchRetryMin time.Duration
	latchRetryMax time.Duration

	contextCloseOnce sync.Once
	contextCloseDone chan struct{}
	contextCloseErr  error
}

type managerTopicBindingLease struct {
	mu             sync.RWMutex
	manager        *Manager
	evaluationTime time.Time
	validUntil     time.Time
	closed         bool
}

func NewManager(options ManagerOptions) (*Manager, error) {
	if (options.Environment != "dev" &&
		options.Environment != "production") ||
		options.Origin.Endpoint() == "" ||
		options.RootPin.KeyID == "" ||
		options.TopicKeys == nil ||
		options.TopicKeys.Environment() != options.Environment ||
		options.Store == nil {
		return nil, ErrConfiguration
	}
	recomputedRootID, err := Ed25519KeyID(options.RootPin.PublicKey[:])
	if err != nil || recomputedRootID != options.RootPin.KeyID {
		return nil, ErrConfiguration
	}

	timeout := options.RequestTimeout
	if timeout == 0 {
		timeout = defaultRequestTime
	}
	if timeout <= 0 || timeout > maxRequestTimeout {
		return nil, ErrConfiguration
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	client := &http.Client{}
	if options.HTTPClient != nil {
		*client = *options.HTTPClient
	}
	client.CheckRedirect = func(
		_ *http.Request,
		_ []*http.Request,
	) error {
		return ErrKeysetFetch
	}

	manager := &Manager{
		environment:      options.Environment,
		origin:           options.Origin,
		rootPin:          options.RootPin,
		topicKeys:        options.TopicKeys,
		store:            options.Store,
		client:           client,
		timeout:          timeout,
		clock:            clock,
		latchWake:        make(chan struct{}, 1),
		latchStop:        make(chan struct{}),
		latchDone:        make(chan struct{}),
		latchRetryMin:    latchRetryMinimum,
		latchRetryMax:    latchRetryMaximum,
		contextCloseDone: make(chan struct{}),
	}
	go manager.runLatchRetry()
	return manager, nil
}

// Refresh fetches and validates one candidate. Network/status failures leave
// an already-current snapshot usable until its signed expiry. Invalid signed
// state or durable rollback/conflict latches hard uncertainty.
func (manager *Manager) Refresh(ctx context.Context) error {
	if !manager.beginOperation() {
		return ErrKeysetUnavailable
	}
	defer manager.endOperation()
	manager.trustMu.Lock()
	defer manager.trustMu.Unlock()
	if manager.isHardUncertain() {
		if err := manager.ensureDurableLatch(); err != nil {
			return err
		}
		return ErrKeysetUnavailable
	}
	now := manager.clock().UTC()
	if now.IsZero() {
		return ErrKeysetUnavailable
	}
	raw, err := manager.fetch(ctx)
	if err != nil {
		return ErrKeysetFetch
	}
	candidate, err := manager.validateCandidate(raw, now)
	if err != nil {
		if latchErr := manager.latchHardUncertainty(
			"KEY_STATE",
		); latchErr != nil {
			return latchErr
		}
		return ErrKeysetRejected
	}
	state, err := manager.store.AcceptKeyset(ctx, candidate)
	if err != nil {
		if errors.Is(err, ErrKeysetRejected) {
			// AcceptKeyset contractually latches rollback/equal-sequence
			// conflict in the same transaction that rejects it.
			manager.markHardUncertainty("KEYSET_ROLLBACK", true)
			return ErrKeysetRejected
		}
		return ErrTrustStoreUnavailable
	}
	if !stateMatchesCandidate(state, candidate) || state.Uncertain {
		if state.Uncertain {
			manager.markHardUncertainty("KEYSET_ROLLBACK", true)
		} else if latchErr := manager.latchHardUncertainty(
			"KEYSET_ROLLBACK",
		); latchErr != nil {
			return latchErr
		}
		return ErrKeysetRejected
	}

	nextRefresh := now.Add(maxRefreshInterval)
	expiryRefresh := candidate.ExpiresAt.Add(-30 * time.Second)
	if expiryRefresh.Before(nextRefresh) {
		nextRefresh = expiryRefresh
	}
	if nextRefresh.Before(now) {
		nextRefresh = now
	}
	manager.mu.Lock()
	if !manager.hardUncertain {
		manager.snapshot = &managerSnapshot{
			candidate:   cloneCandidate(candidate),
			nextRefresh: nextRefresh,
		}
	}
	manager.mu.Unlock()
	if manager.isHardUncertain() {
		return ErrKeysetUnavailable
	}
	return nil
}

// Verifier returns a fresh parsed copy of the accepted keyset only after
// joining it to the current durable high-water state.
func (manager *Manager) Verifier(
	ctx context.Context,
	now time.Time,
) (map[string]any, error) {
	if !manager.beginOperation() {
		return nil, ErrKeysetUnavailable
	}
	defer manager.endOperation()
	manager.trustMu.Lock()
	defer manager.trustMu.Unlock()
	candidate, err := manager.currentCandidate(ctx, now.UTC())
	if err != nil {
		return nil, err
	}
	defer wipeCandidate(&candidate)
	value, err := ParseStrictJSON(candidate.CanonicalSignedObject)
	if err != nil {
		return nil, ErrKeysetUnavailable
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrKeysetUnavailable
	}
	return object, nil
}

// AcquireTopicBindingLease performs exactly one durable-currentness join and
// pins the resulting local snapshot for the complete request-scoped binding
// pass. The expected sequence and hash must be the exact provenance returned
// by Verifier for the same request.
func (manager *Manager) AcquireTopicBindingLease(
	ctx context.Context,
	now time.Time,
	expectedSequence uint64,
	expectedHash [32]byte,
) (TopicBindingLease, error) {
	if expectedSequence == 0 ||
		expectedSequence > maxIJSONInteger {
		return nil, ErrKeysetUnavailable
	}
	lease, _, _, err := manager.acquireTopicBindingLease(
		ctx,
		now,
		true,
		expectedSequence,
		expectedHash,
	)
	return lease, err
}

// AcquireCurrentTopicBindingLease performs exactly one durable-currentness
// join and returns both the resulting lease and its exact durable keyset
// provenance. The returned hash is the 32-byte SHA-256 object hash.
func (manager *Manager) AcquireCurrentTopicBindingLease(
	ctx context.Context,
	now time.Time,
) (TopicBindingLease, uint64, [32]byte, error) {
	return manager.acquireTopicBindingLease(
		ctx,
		now,
		false,
		0,
		[32]byte{},
	)
}

// Ready performs a read-only readiness check without acquiring trustMu. It can
// therefore complete under its caller-owned context while Refresh is fetching
// a keyset. Readiness still requires an exact durable-state join and the exact
// root-signed current TOPIC descriptor's locally held secret.
func (manager *Manager) Ready(
	ctx context.Context,
	now time.Time,
) error {
	if ctx == nil ||
		ctx.Err() != nil ||
		now.IsZero() ||
		!manager.beginOperation() {
		return ErrKeysetUnavailable
	}
	defer manager.endOperation()
	now = now.UTC()

	snapshot, ok := manager.readinessSnapshot(now)
	if !ok {
		return ErrKeysetUnavailable
	}
	defer snapshot.clear()
	if !manager.topicKeys.currentEpochUsable(
		now,
		snapshot.commitmentKeys,
	) {
		return ErrKeysetUnavailable
	}

	state, err := manager.store.CurrentKeysetState(
		ctx,
		manager.environment,
	)
	if err != nil || ctx.Err() != nil {
		return ErrTrustStoreUnavailable
	}
	if state.Uncertain ||
		state.Environment != snapshot.environment ||
		state.Sequence != snapshot.sequence ||
		state.ObjectHash != snapshot.objectHash ||
		!state.ExpiresAt.Equal(snapshot.expiresAt) {
		return ErrKeysetUnavailable
	}
	if !manager.readinessSnapshotMatches(snapshot, now) ||
		!manager.topicKeys.currentEpochUsable(
			now,
			snapshot.commitmentKeys,
		) {
		return ErrKeysetUnavailable
	}
	if ctx.Err() != nil {
		return ErrTrustStoreUnavailable
	}
	return nil
}

func (manager *Manager) acquireTopicBindingLease(
	ctx context.Context,
	now time.Time,
	checkExpected bool,
	expectedSequence uint64,
	expectedHash [32]byte,
) (TopicBindingLease, uint64, [32]byte, error) {
	if ctx == nil || now.IsZero() || !manager.beginOperation() {
		return nil, 0, [32]byte{}, ErrKeysetUnavailable
	}
	release := true
	defer func() {
		if release {
			manager.endOperation()
		}
	}()

	manager.trustMu.Lock()
	unlock := true
	defer func() {
		if unlock {
			manager.trustMu.Unlock()
		}
	}()

	evaluationTime := now.UTC()
	candidate, err := manager.currentCandidate(ctx, evaluationTime)
	if err != nil {
		return nil, 0, [32]byte{}, err
	}
	defer wipeCandidate(&candidate)
	decodedHash, err := hex.DecodeString(candidate.ObjectHash)
	if err != nil || len(decodedHash) != len(expectedHash) {
		clear(decodedHash)
		return nil, 0, [32]byte{}, ErrKeysetUnavailable
	}
	var currentHash [32]byte
	copy(currentHash[:], decodedHash)
	clear(decodedHash)
	if checkExpected &&
		(candidate.Sequence != expectedSequence ||
			currentHash != expectedHash) {
		clear(currentHash[:])
		return nil, 0, [32]byte{}, ErrKeysetUnavailable
	}

	manager.mu.RLock()
	snapshotMatches := !manager.closed &&
		!manager.hardUncertain &&
		manager.snapshot != nil &&
		manager.snapshot.candidate.Sequence == candidate.Sequence &&
		manager.snapshot.candidate.ObjectHash == candidate.ObjectHash &&
		manager.snapshot.candidate.ExpiresAt.Equal(candidate.ExpiresAt)
	var nextRefresh time.Time
	if snapshotMatches {
		nextRefresh = manager.snapshot.nextRefresh
	}
	manager.mu.RUnlock()
	if !snapshotMatches ||
		nextRefresh.IsZero() ||
		!evaluationTime.Before(nextRefresh) {
		clear(currentHash[:])
		return nil, 0, [32]byte{}, ErrKeysetUnavailable
	}
	validUntil := candidate.ExpiresAt
	if nextRefresh.Before(validUntil) {
		validUntil = nextRefresh
	}

	lease := &managerTopicBindingLease{
		manager:        manager,
		evaluationTime: evaluationTime,
		validUntil:     validUntil,
	}
	unlock = false
	release = false
	return lease, candidate.Sequence, currentHash, nil
}

func (manager *Manager) NextRefresh() (time.Time, bool) {
	if !manager.beginOperation() {
		return time.Time{}, false
	}
	defer manager.endOperation()
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if manager.hardUncertain || manager.snapshot == nil {
		return time.Time{}, false
	}
	return manager.snapshot.nextRefresh, true
}

func (manager *Manager) readinessSnapshot(
	now time.Time,
) (managerReadinessSnapshot, bool) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if manager.closed ||
		manager.hardUncertain ||
		manager.snapshot == nil {
		return managerReadinessSnapshot{}, false
	}
	candidate := &manager.snapshot.candidate
	if candidate.Environment != manager.environment ||
		candidate.Sequence == 0 ||
		candidate.ObjectHash == "" ||
		now.Before(candidate.IssuedAt) ||
		!now.Before(candidate.ExpiresAt) ||
		manager.snapshot.nextRefresh.IsZero() ||
		!now.Before(manager.snapshot.nextRefresh) {
		return managerReadinessSnapshot{}, false
	}
	snapshot := managerReadinessSnapshot{
		environment: candidate.Environment,
		sequence:    candidate.Sequence,
		objectHash:  candidate.ObjectHash,
		issuedAt:    candidate.IssuedAt,
		expiresAt:   candidate.ExpiresAt,
		nextRefresh: manager.snapshot.nextRefresh,
	}
	snapshot.commitmentKeys = cloneCommitmentKeys(
		candidate.CommitmentKeys,
	)
	return snapshot, true
}

func (manager *Manager) readinessSnapshotMatches(
	expected managerReadinessSnapshot,
	now time.Time,
) bool {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if manager.closed ||
		manager.hardUncertain ||
		manager.snapshot == nil {
		return false
	}
	candidate := &manager.snapshot.candidate
	return candidate.Environment == expected.environment &&
		candidate.Sequence == expected.sequence &&
		candidate.ObjectHash == expected.objectHash &&
		candidate.IssuedAt.Equal(expected.issuedAt) &&
		candidate.ExpiresAt.Equal(expected.expiresAt) &&
		manager.snapshot.nextRefresh.Equal(expected.nextRefresh) &&
		!now.Before(candidate.IssuedAt) &&
		now.Before(candidate.ExpiresAt) &&
		now.Before(manager.snapshot.nextRefresh)
}

func (lease *managerTopicBindingLease) TopicBindingForEpoch(
	ctx context.Context,
	topic []byte,
	epoch uint32,
	now time.Time,
	assertionExpiresAt time.Time,
	alreadyAccepted bool,
) ([]byte, Verdict) {
	if lease == nil {
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	lease.mu.RLock()
	defer lease.mu.RUnlock()
	if lease.closed ||
		lease.manager == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		now.IsZero() ||
		!now.UTC().Equal(lease.evaluationTime) {
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	liveNow := lease.manager.clock().UTC()
	if liveNow.IsZero() ||
		liveNow.Before(lease.evaluationTime) ||
		!liveNow.Before(lease.validUntil) {
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	binding, verdict := lease.manager.topicKeys.BindingForEpoch(
		topic,
		epoch,
		lease.evaluationTime,
		assertionExpiresAt.UTC(),
		alreadyAccepted,
	)
	if verdict.RequiresKeysetUncertainty() {
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	return binding, verdict
}

func (lease *managerTopicBindingLease) CandidateTopicBindings(
	ctx context.Context,
	topic []byte,
	exactEvaluationTime time.Time,
) ([]TopicBindingCandidate, Verdict) {
	if lease == nil {
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	lease.mu.RLock()
	defer lease.mu.RUnlock()
	if lease.closed ||
		lease.manager == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		exactEvaluationTime.IsZero() ||
		!exactEvaluationTime.UTC().Equal(lease.evaluationTime) {
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	liveNow := lease.manager.clock().UTC()
	if liveNow.IsZero() ||
		liveNow.Before(lease.evaluationTime) ||
		!liveNow.Before(lease.validUntil) {
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	candidates, verdict := lease.manager.topicKeys.candidateTopicBindings(
		topic,
		lease.evaluationTime,
	)
	liveNow = lease.manager.clock().UTC()
	if ctx.Err() != nil ||
		liveNow.IsZero() ||
		liveNow.Before(lease.evaluationTime) ||
		!liveNow.Before(lease.validUntil) {
		clearTopicBindingCandidates(candidates)
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	// Route lookup is not evidence of a signature-valid authority artifact.
	// Candidate failure therefore cannot globally latch keyset uncertainty.
	if verdict.RequiresKeysetUncertainty() {
		clearTopicBindingCandidates(candidates)
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	return candidates, verdict
}

func (lease *managerTopicBindingLease) Close() {
	if lease == nil {
		return
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return
	}
	manager := lease.manager
	lease.closed = true
	lease.manager = nil
	lease.evaluationTime = time.Time{}
	lease.validUntil = time.Time{}
	if manager != nil {
		manager.trustMu.Unlock()
		manager.endOperation()
	}
}

func (manager *Manager) TopicBindingForEpoch(
	ctx context.Context,
	topic []byte,
	epoch uint32,
	now time.Time,
	assertionExpiresAt time.Time,
	alreadyAccepted bool,
) ([]byte, Verdict) {
	if !manager.beginOperation() {
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	defer manager.endOperation()
	manager.trustMu.Lock()
	defer manager.trustMu.Unlock()
	candidate, err := manager.currentCandidate(ctx, now.UTC())
	if err != nil {
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	defer wipeCandidate(&candidate)
	binding, verdict := manager.topicKeys.BindingForEpoch(
		topic,
		epoch,
		now.UTC(),
		assertionExpiresAt.UTC(),
		alreadyAccepted,
	)
	// This API is used for request topic-binding recomputation, not for a
	// signature-valid authority artifact. Configuration/currentness failures
	// therefore fail unavailable but can never request a global key-state
	// latch by themselves.
	if verdict.RequiresKeysetUncertainty() {
		return nil, Inconclusive("TRUST_UNAVAILABLE")
	}
	return binding, verdict
}

// LatchArtifactUncertainty durably closes trust after a signature-valid
// artifact proves that referenced key metadata is missing or ambiguous. It
// accepts only fixed verdicts emitted by this package and never relies on the
// caller's request context for the durable write.
func (manager *Manager) LatchArtifactUncertainty(
	verdict Verdict,
) error {
	if !verdict.RequiresKeysetUncertainty() {
		return ErrKeysetRejected
	}
	if !manager.beginOperation() {
		return ErrKeysetUnavailable
	}
	defer manager.endOperation()
	manager.trustMu.Lock()
	defer manager.trustMu.Unlock()
	return manager.latchHardUncertainty(verdict.Reason)
}

func (manager *Manager) Close() error {
	if manager == nil {
		return nil
	}
	manager.lifecycle.Lock()
	manager.trustMu.Lock()
	if manager.isClosed() {
		pending := manager.hasPendingLatch()
		manager.trustMu.Unlock()
		manager.lifecycle.Unlock()
		if pending {
			manager.requestLatchRetry()
			return ErrTrustStoreUnavailable
		}
		return nil
	}
	var latchErr error
	if manager.isHardUncertain() {
		latchErr = manager.ensureDurableLatch()
	}
	manager.mu.Lock()
	if manager.snapshot != nil {
		wipeCandidate(&manager.snapshot.candidate)
	}
	manager.snapshot = nil
	manager.closed = true
	pending := manager.hardUncertain && !manager.hardDurable
	manager.mu.Unlock()
	manager.topicKeys.Close()
	clear(manager.rootPin.PublicKey[:])
	manager.rootPin.KeyID = ""
	manager.trustMu.Unlock()
	manager.lifecycle.Unlock()

	if pending {
		manager.requestLatchRetry()
		return ErrTrustStoreUnavailable
	}
	manager.stopLatchRetry()
	<-manager.latchDone
	return latchErr
}

// CloseContext initiates shutdown once and bounds only the caller's wait.
// A context timeout does not cancel secret erasure or a required durable
// uncertainty latch. Nil is returned only after any hard latch is durable and
// the manager-owned retry worker has stopped.
func (manager *Manager) CloseContext(ctx context.Context) error {
	if manager == nil {
		return nil
	}
	if ctx == nil {
		return ErrConfiguration
	}
	manager.contextCloseOnce.Do(func() {
		go func() {
			manager.contextCloseErr = manager.Close()
			close(manager.contextCloseDone)
		}()
	})
	select {
	case <-manager.contextCloseDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := manager.contextCloseErr; err != nil &&
		!errors.Is(err, ErrTrustStoreUnavailable) {
		return err
	}

	// Close intentionally returns a storage receipt error while the durable
	// latch worker remains alive. Wake that worker and wait for its actual
	// termination before reporting safe completion.
	manager.requestLatchRetry()
	select {
	case <-manager.latchDone:
		if manager.hasPendingLatch() {
			return ErrTrustStoreUnavailable
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (manager *Manager) fetch(ctx context.Context) ([]byte, error) {
	requestContext, cancel := context.WithTimeout(ctx, manager.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodGet,
		manager.origin.Endpoint(),
		nil,
	)
	if err != nil {
		return nil, ErrKeysetFetch
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-cache")
	response, err := manager.client.Do(request)
	if err != nil {
		return nil, ErrKeysetFetch
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK ||
		response.Request == nil ||
		response.Request.URL.String() != manager.origin.Endpoint() {
		return nil, ErrKeysetFetch
	}
	mediaType, _, err := mime.ParseMediaType(
		response.Header.Get("Content-Type"),
	)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return nil, ErrKeysetFetch
	}
	raw, err := io.ReadAll(
		io.LimitReader(response.Body, maxKeysetBodyBytes+1),
	)
	if err != nil || len(raw) == 0 || len(raw) > maxKeysetBodyBytes {
		return nil, ErrKeysetFetch
	}
	return raw, nil
}

func (manager *Manager) validateCandidate(
	raw []byte,
	now time.Time,
) (AcceptedKeyset, error) {
	decoded, err := a9schema.Decode(a9schema.KeysetKind, raw)
	if err != nil {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	object := map[string]any(decoded)
	if verdict := ValidateKeyset(
		object,
		manager.rootPin.PublicKey[:],
		manager.rootPin.KeyID,
		manager.environment,
		now,
	); !verdict.IsEligible() {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	if verdict := ValidateTopicKeySchedule(object); !verdict.IsEligible() {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	if verdict := manager.topicKeys.Reconcile(
		object,
		now,
	); !verdict.IsEligible() {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	canonical, err := Canonicalize(object)
	if err != nil {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	sequence, verdict := positiveInteger(object["keyset_sequence"])
	if !verdict.IsEligible() {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	issuedAt, ok := parseWireTime(objectString(object, "issued_at"))
	if !ok {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	expiresAt, ok := parseWireTime(objectString(object, "expires_at"))
	if !ok {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	onlineKeys, ok := parseOnlineKeys(object["keys"])
	if !ok {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	commitmentKeys, ok := parseCommitmentKeys(object["commitment_keys"])
	if !ok {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	return AcceptedKeyset{
		Environment:           manager.environment,
		Sequence:              sequence,
		ObjectHash:            SHA256LowerHex(canonical),
		CanonicalSignedObject: canonical,
		IssuedAt:              issuedAt,
		ExpiresAt:             expiresAt,
		RootKeyID:             manager.rootPin.KeyID,
		OnlineKeys:            onlineKeys,
		CommitmentKeys:        commitmentKeys,
	}, nil
}

func (manager *Manager) currentCandidate(
	ctx context.Context,
	now time.Time,
) (AcceptedKeyset, error) {
	if now.IsZero() {
		return AcceptedKeyset{}, ErrKeysetUnavailable
	}
	if manager.isHardUncertain() {
		if err := manager.ensureDurableLatch(); err != nil {
			return AcceptedKeyset{}, err
		}
		return AcceptedKeyset{}, ErrKeysetUnavailable
	}
	manager.mu.Lock()
	if manager.closed || manager.snapshot == nil {
		manager.mu.Unlock()
		return AcceptedKeyset{}, ErrKeysetUnavailable
	}
	candidate := cloneCandidate(manager.snapshot.candidate)
	nextRefresh := manager.snapshot.nextRefresh
	manager.mu.Unlock()

	if now.Before(candidate.IssuedAt) ||
		!now.Before(candidate.ExpiresAt) ||
		!now.Before(nextRefresh) {
		wipeCandidate(&candidate)
		return AcceptedKeyset{}, ErrKeysetUnavailable
	}
	state, err := manager.store.CurrentKeysetState(
		ctx,
		manager.environment,
	)
	if err != nil {
		wipeCandidate(&candidate)
		return AcceptedKeyset{}, ErrTrustStoreUnavailable
	}
	if state.Uncertain {
		manager.markHardUncertainty("KEY_STATE", true)
		wipeCandidate(&candidate)
		return AcceptedKeyset{}, ErrKeysetUnavailable
	}
	if state.Environment != manager.environment ||
		state.Sequence < candidate.Sequence ||
		(state.Sequence == candidate.Sequence &&
			(state.ObjectHash != candidate.ObjectHash ||
				!state.ExpiresAt.Equal(candidate.ExpiresAt))) {
		latchErr := manager.latchHardUncertainty("KEYSET_ROLLBACK")
		wipeCandidate(&candidate)
		if latchErr != nil {
			return AcceptedKeyset{}, latchErr
		}
		return AcceptedKeyset{}, ErrKeysetUnavailable
	}
	if state.Sequence > candidate.Sequence ||
		!now.Before(state.ExpiresAt) {
		wipeCandidate(&candidate)
		return AcceptedKeyset{}, ErrKeysetUnavailable
	}

	// Refresh and verification are serialized by trustMu. This second local
	// check also protects against lifecycle state changed by a hard latch.
	manager.mu.RLock()
	stillCurrent := !manager.closed &&
		!manager.hardUncertain &&
		manager.snapshot != nil &&
		manager.snapshot.candidate.Sequence == candidate.Sequence &&
		manager.snapshot.candidate.ObjectHash == candidate.ObjectHash &&
		manager.snapshot.candidate.ExpiresAt.Equal(candidate.ExpiresAt) &&
		now.Before(manager.snapshot.nextRefresh)
	manager.mu.RUnlock()
	if !stillCurrent {
		wipeCandidate(&candidate)
		return AcceptedKeyset{}, ErrKeysetUnavailable
	}
	return candidate, nil
}

func (manager *Manager) latchHardUncertainty(reason string) error {
	manager.markHardUncertainty(reason, false)
	return manager.ensureDurableLatch()
}

func (manager *Manager) markHardUncertainty(
	reason string,
	durable bool,
) {
	manager.mu.Lock()
	if !manager.hardUncertain {
		manager.hardReason = reason
	}
	manager.hardUncertain = true
	if durable {
		manager.hardDurable = true
	}
	pending := !manager.hardDurable && manager.hardReason != ""
	manager.mu.Unlock()
	if pending {
		manager.requestLatchRetry()
	}
}

// ensureDurableLatch intentionally ignores request cancellation. Once signed
// trust becomes ambiguous, persistence is retried with a manager-owned bounded
// context and this process remains closed regardless of the storage result.
func (manager *Manager) ensureDurableLatch() error {
	manager.mu.RLock()
	hard := manager.hardUncertain
	durable := manager.hardDurable
	reason := manager.hardReason
	manager.mu.RUnlock()
	if !hard || durable || reason == "" {
		return nil
	}
	latchContext, cancel := context.WithTimeout(
		context.Background(),
		manager.timeout,
	)
	defer cancel()
	if err := manager.store.LatchKeysetUncertainty(
		latchContext,
		manager.environment,
		reason,
	); err != nil {
		return ErrTrustStoreUnavailable
	}
	manager.mu.Lock()
	if manager.hardUncertain && manager.hardReason == reason {
		manager.hardDurable = true
	}
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) runLatchRetry() {
	defer close(manager.latchDone)
	for {
		select {
		case <-manager.latchStop:
			return
		case <-manager.latchWake:
		}
		retryDelay := manager.latchRetryMin
		if retryDelay <= 0 {
			retryDelay = latchRetryMinimum
		}
		retryMaximum := manager.latchRetryMax
		if retryMaximum <= 0 {
			retryMaximum = latchRetryMaximum
		}
		if retryMaximum < retryDelay {
			retryMaximum = retryDelay
		}
		for {
			manager.trustMu.Lock()
			_ = manager.ensureDurableLatch()
			pending := manager.hasPendingLatch()
			closed := manager.isClosed()
			manager.trustMu.Unlock()
			if !pending {
				if closed {
					return
				}
				break
			}
			switch manager.waitForLatchRetry(retryDelay) {
			case latchRetryStopped:
				return
			case latchRetrySignaled:
				retryDelay = manager.latchRetryMin
				if retryDelay <= 0 {
					retryDelay = latchRetryMinimum
				}
			case latchRetryElapsed:
				retryDelay = nextLatchRetryDelay(
					retryDelay,
					retryMaximum,
				)
			}
		}
	}
}

type latchRetryWaitResult uint8

const (
	latchRetryElapsed latchRetryWaitResult = iota + 1
	latchRetrySignaled
	latchRetryStopped
)

func (manager *Manager) waitForLatchRetry(
	delay time.Duration,
) latchRetryWaitResult {
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
	case <-manager.latchStop:
		return latchRetryStopped
	case <-manager.latchWake:
		return latchRetrySignaled
	case <-timer.C:
		return latchRetryElapsed
	}
}

func nextLatchRetryDelay(
	current time.Duration,
	maximum time.Duration,
) time.Duration {
	if maximum <= 0 {
		maximum = latchRetryMaximum
	}
	if current <= 0 {
		return latchRetryMinimum
	}
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func (manager *Manager) requestLatchRetry() {
	select {
	case manager.latchWake <- struct{}{}:
	default:
	}
}

func (manager *Manager) stopLatchRetry() {
	manager.latchStopOnce.Do(func() {
		close(manager.latchStop)
	})
}

func (manager *Manager) hasPendingLatch() bool {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.hardUncertain &&
		!manager.hardDurable &&
		manager.hardReason != ""
}

func (manager *Manager) isHardUncertain() bool {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.hardUncertain
}

func (manager *Manager) isClosed() bool {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.closed
}

func (manager *Manager) beginOperation() bool {
	if manager == nil {
		return false
	}
	manager.lifecycle.RLock()
	if manager.isClosed() {
		manager.lifecycle.RUnlock()
		return false
	}
	return true
}

func (manager *Manager) endOperation() {
	manager.lifecycle.RUnlock()
}

func stateMatchesCandidate(
	state KeysetState,
	candidate AcceptedKeyset,
) bool {
	return state.Environment == candidate.Environment &&
		state.Sequence == candidate.Sequence &&
		state.ObjectHash == candidate.ObjectHash &&
		state.ExpiresAt.Equal(candidate.ExpiresAt)
}

func (snapshot *managerReadinessSnapshot) clear() {
	if snapshot == nil {
		return
	}
	clear(snapshot.commitmentKeys)
	*snapshot = managerReadinessSnapshot{}
}

func cloneCommitmentKeys(
	keys []CommitmentKey,
) []CommitmentKey {
	cloned := append([]CommitmentKey(nil), keys...)
	for index := range cloned {
		if keys[index].TopicKeyEpoch != nil {
			epoch := *keys[index].TopicKeyEpoch
			cloned[index].TopicKeyEpoch = &epoch
		}
	}
	return cloned
}

func cloneCandidate(candidate AcceptedKeyset) AcceptedKeyset {
	cloned := candidate
	cloned.CanonicalSignedObject = append(
		[]byte(nil),
		candidate.CanonicalSignedObject...,
	)
	cloned.OnlineKeys = make([]OnlineKey, len(candidate.OnlineKeys))
	for index := range candidate.OnlineKeys {
		cloned.OnlineKeys[index] = candidate.OnlineKeys[index]
		cloned.OnlineKeys[index].PublicKey = append(
			[]byte(nil),
			candidate.OnlineKeys[index].PublicKey...,
		)
	}
	cloned.CommitmentKeys = cloneCommitmentKeys(
		candidate.CommitmentKeys,
	)
	return cloned
}

func wipeCandidate(candidate *AcceptedKeyset) {
	if candidate == nil {
		return
	}
	clear(candidate.CanonicalSignedObject)
	candidate.CanonicalSignedObject = nil
	for index := range candidate.OnlineKeys {
		clear(candidate.OnlineKeys[index].PublicKey)
		candidate.OnlineKeys[index].PublicKey = nil
	}
	clear(candidate.OnlineKeys)
	candidate.OnlineKeys = nil
	clear(candidate.CommitmentKeys)
	candidate.CommitmentKeys = nil
	candidate.Environment = ""
	candidate.Sequence = 0
	candidate.ObjectHash = ""
	candidate.IssuedAt = time.Time{}
	candidate.ExpiresAt = time.Time{}
	candidate.RootKeyID = ""
}
