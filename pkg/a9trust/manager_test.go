package a9trust

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9schema"
)

type memoryKeysetStore struct {
	mu          sync.Mutex
	state       KeysetState
	accepted    []AcceptedKeyset
	acceptErr   error
	currentErr  error
	stateMutate func(KeysetState) KeysetState
	latches     []string
}

func (store *memoryKeysetStore) AcceptKeyset(
	_ context.Context,
	candidate AcceptedKeyset,
) (KeysetState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.acceptErr != nil {
		return KeysetState{}, store.acceptErr
	}
	if store.state.Sequence != 0 {
		if candidate.Sequence < store.state.Sequence ||
			(candidate.Sequence == store.state.Sequence &&
				candidate.ObjectHash != store.state.ObjectHash) {
			store.state.Uncertain = true
			return store.state, ErrKeysetRejected
		}
	}
	if candidate.Sequence > store.state.Sequence {
		store.accepted = append(
			store.accepted,
			cloneCandidate(candidate),
		)
		store.state = KeysetState{
			Environment: candidate.Environment,
			Sequence:    candidate.Sequence,
			ObjectHash:  candidate.ObjectHash,
			ExpiresAt:   candidate.ExpiresAt,
		}
	}
	state := store.state
	if store.stateMutate != nil {
		state = store.stateMutate(state)
	}
	return state, nil
}

func (store *memoryKeysetStore) CurrentKeysetState(
	_ context.Context,
	_ string,
) (KeysetState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.currentErr != nil {
		return KeysetState{}, store.currentErr
	}
	return store.state, nil
}

func (store *memoryKeysetStore) LatchKeysetUncertainty(
	_ context.Context,
	_ string,
	reason string,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.state.Uncertain = true
	store.latches = append(store.latches, reason)
	return nil
}

func TestManagerFetchesPersistsAndJoinsCurrentVerifier(t *testing.T) {
	fixture := managerFixtureFromCorpus(t)
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		requests++
		if request.Method != http.MethodGet ||
			request.URL.Path != KeysetWellKnownPath ||
			request.URL.RawQuery != "" ||
			request.Header.Get("Authorization") != "" {
			t.Error("unexpected discovery request")
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
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
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatalf(
			"refresh: %v; accepted=%d latches=%v state=%+v",
			err,
			len(store.accepted),
			store.latches,
			store.state,
		)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	if len(store.accepted) != 1 {
		t.Fatalf("accepted keysets = %d, want 1", len(store.accepted))
	}
	accepted := store.accepted[0]
	if accepted.Sequence != mustUint(t, fixture.keyset["keyset_sequence"]) ||
		accepted.ObjectHash != SHA256LowerHex(fixture.body) {
		t.Fatal("persisted keyset provenance did not match")
	}
	object, err := manager.Verifier(
		context.Background(),
		fixture.issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if objectString(object, "root_signing_key_id") != fixture.rootKeyID {
		t.Fatal("verifier did not return the pinned keyset")
	}
	nextRefresh, ok := manager.NextRefresh()
	if !ok ||
		nextRefresh.After(fixture.issuedAt.Add(maxRefreshInterval)) ||
		!nextRefresh.Before(fixture.expiresAt) {
		t.Fatalf("next refresh = %s, ok=%v", nextRefresh, ok)
	}

	store.mu.Lock()
	store.state.Uncertain = true
	store.mu.Unlock()
	if _, err = manager.Verifier(
		context.Background(),
		fixture.issuedAt,
	); !errors.Is(err, ErrKeysetUnavailable) {
		t.Fatalf("error = %v, want ErrKeysetUnavailable", err)
	}
}

func TestManagerNeverFollowsDiscoveryRedirect(t *testing.T) {
	fixture := managerFixtureFromCorpus(t)
	var redirected bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path == "/redirected" {
			redirected = true
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(fixture.body)
			return
		}
		http.Redirect(
			writer,
			request,
			"/redirected",
			http.StatusTemporaryRedirect,
		)
	}))
	defer server.Close()

	manager := newFixtureManager(
		t,
		fixture,
		server.URL,
		server.Client(),
		&memoryKeysetStore{},
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(
		context.Background(),
	); !errors.Is(err, ErrKeysetFetch) {
		t.Fatalf("error = %v, want ErrKeysetFetch", err)
	}
	if redirected {
		t.Fatal("discovery redirect was followed")
	}
	if manager.isHardUncertain() {
		t.Fatal("transport failure incorrectly became a signed-state latch")
	}
}

func TestManagerInvalidSignedStateLatchesAndCannotSelfRecover(t *testing.T) {
	fixture := managerFixtureFromCorpus(t)
	invalid := cloneViaJCS(t, fixture.keyset)
	invalid["environment"] = "production"
	invalidBody, err := Canonicalize(invalid)
	if err != nil {
		t.Fatal(err)
	}
	var body = invalidBody
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(body)
	}))
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
	if err := manager.Refresh(
		context.Background(),
	); !errors.Is(err, ErrKeysetRejected) {
		t.Fatalf("error = %v, want ErrKeysetRejected", err)
	}
	if !manager.isHardUncertain() ||
		len(store.latches) != 1 ||
		store.latches[0] != "KEY_STATE" {
		t.Fatal("invalid signed state did not latch uncertainty")
	}
	body = fixture.body
	if err := manager.Refresh(
		context.Background(),
	); !errors.Is(err, ErrKeysetUnavailable) {
		t.Fatalf("recovery error = %v, want ErrKeysetUnavailable", err)
	}
	if requests != 1 {
		t.Fatalf("hard-latched manager made %d requests, want 1", requests)
	}
}

func TestManagerRequiresEverySignedTopicDescriptorSecret(t *testing.T) {
	fixture := managerBoundaryFixtureFromCorpus(t)
	value, err := ParseStrictJSON([]byte(fixture.topicConfig))
	if err != nil {
		t.Fatal(err)
	}
	records := value.([]any)
	oneRecord, err := Canonicalize(records[:1])
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
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
		fixture.issuedAt,
		string(oneRecord),
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(
		context.Background(),
	); !errors.Is(err, ErrKeysetRejected) {
		t.Fatalf("error = %v, want ErrKeysetRejected", err)
	}
	if len(store.latches) != 1 {
		t.Fatal("missing topic secret did not latch uncertainty")
	}
}

func TestManagerRejectsFutureKeysetAndStoreMismatch(t *testing.T) {
	fixture := managerFixtureFromCorpus(t)
	for name, test := range map[string]struct {
		now         time.Time
		stateMutate func(KeysetState) KeysetState
		want        error
	}{
		"future issue time": {
			now:  fixture.issuedAt.Add(-time.Millisecond),
			want: ErrKeysetRejected,
		},
		"durable state mismatch": {
			now: fixture.issuedAt,
			stateMutate: func(state KeysetState) KeysetState {
				state.ObjectHash =
					"0000000000000000000000000000000000000000000000000000000000000000"
				return state
			},
			want: ErrKeysetRejected,
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(
				writer http.ResponseWriter,
				_ *http.Request,
			) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write(fixture.body)
			}))
			defer server.Close()
			store := &memoryKeysetStore{stateMutate: test.stateMutate}
			manager := newFixtureManager(
				t,
				fixture,
				server.URL,
				server.Client(),
				store,
				test.now,
				fixture.topicConfig,
			)
			cleanupManager(t, manager)
			if err := manager.Refresh(
				context.Background(),
			); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if !manager.isHardUncertain() {
				t.Fatal("hard trust rejection was not latched")
			}
		})
	}
}

func TestManagerStorageOutageDoesNotReplaceCurrentSnapshot(t *testing.T) {
	fixture := managerFixtureFromCorpus(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
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
		fixture.issuedAt,
		fixture.topicConfig,
	)
	cleanupManager(t, manager)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatalf(
			"refresh: %v; accepted=%d latches=%v state=%+v",
			err,
			len(store.accepted),
			store.latches,
			store.state,
		)
	}
	store.acceptErr = errors.New("storage down")
	if err := manager.Refresh(
		context.Background(),
	); !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Fatalf("error = %v, want ErrTrustStoreUnavailable", err)
	}
	if manager.isHardUncertain() {
		t.Fatal("storage outage incorrectly became signed-state uncertainty")
	}
	store.acceptErr = nil
	if _, err := manager.Verifier(
		context.Background(),
		fixture.issuedAt,
	); err != nil {
		t.Fatalf("current snapshot was lost: %v", err)
	}
	store.currentErr = errors.New("storage down")
	if _, err := manager.Verifier(
		context.Background(),
		fixture.issuedAt,
	); !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Fatalf("error = %v, want ErrTrustStoreUnavailable", err)
	}
}

func TestKeysetOriginIsExactHTTPSOrigin(t *testing.T) {
	valid, err := ParseKeysetOrigin("https://modern-api.internal:8443")
	if err != nil {
		t.Fatal(err)
	}
	if valid.Endpoint() !=
		"https://modern-api.internal:8443"+KeysetWellKnownPath {
		t.Fatalf("endpoint = %s", valid.Endpoint())
	}
	for name, value := range map[string]string{
		"http":           "http://modern-api.internal",
		"path":           "https://modern-api.internal/base",
		"trailing slash": "https://modern-api.internal/",
		"userinfo":       "https://user@modern-api.internal",
		"query":          "https://modern-api.internal?x=1",
		"fragment":       "https://modern-api.internal#x",
		"relative":       "modern-api.internal",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseKeysetOrigin(value)
			if !errors.Is(err, ErrConfiguration) {
				t.Fatalf("error = %v, want ErrConfiguration", err)
			}
		})
	}
}

type managerFixture struct {
	keyset      map[string]any
	body        []byte
	issuedAt    time.Time
	expiresAt   time.Time
	rootKeyID   string
	rootPublic  string
	topicConfig string
}

func managerFixtureFromCorpus(t *testing.T) managerFixture {
	t.Helper()
	corpus := loadCorpus(t)
	keys := mustObject(t, corpus.positive["test_keys"])
	keyset := mustObject(
		t,
		mustObject(t, corpus.positive["keyset"])["value"],
	)
	body, err := Canonicalize(keyset)
	if err != nil {
		t.Fatal(err)
	}
	return managerFixture{
		keyset:      keyset,
		body:        body,
		issuedAt:    mustWireTime(t, keyset["issued_at"]),
		expiresAt:   mustWireTime(t, keyset["expires_at"]),
		rootKeyID:   mustString(t, keys["root_signing_key_id"]),
		rootPublic:  mustString(t, keys["root_public_key_base64url"]),
		topicConfig: topicKeyConfig(t, keyset, keys),
	}
}

func newFixtureManager(
	t *testing.T,
	fixture managerFixture,
	originValue string,
	client *http.Client,
	store KeysetStore,
	now time.Time,
	topicConfig string,
) *Manager {
	t.Helper()
	origin, err := ParseKeysetOrigin(originValue)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ParseRootPin(fixture.rootPublic, fixture.rootKeyID)
	if err != nil {
		t.Fatal(err)
	}
	topicKeys, err := parseTopicKeySetBytes(
		[]byte(topicConfig),
		"dev",
		func() time.Time {
			return now
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := a9schema.Decode(a9schema.KeysetKind, fixture.body)
	if err != nil {
		t.Fatalf("fixture schema: %v", err)
	}
	keysetObject := map[string]any(decoded)
	if verdict := ValidateKeyset(
		keysetObject,
		root.PublicKey[:],
		root.KeyID,
		"dev",
		fixture.issuedAt,
	); !verdict.IsEligible() {
		t.Fatalf("fixture keyset verdict: %+v", verdict)
	}
	if verdict := ValidateTopicKeySchedule(
		keysetObject,
	); !verdict.IsEligible() {
		t.Fatalf("fixture topic schedule: %+v", verdict)
	}
	manager, err := NewManager(ManagerOptions{
		Environment: "dev",
		Origin:      origin,
		RootPin:     root,
		TopicKeys:   topicKeys,
		Store:       store,
		HTTPClient:  client,
		Clock: func() time.Time {
			return now
		},
	})
	if err != nil {
		topicKeys.Close()
		t.Fatal(err)
	}
	return manager
}

func cleanupManager(t *testing.T, manager *Manager) {
	t.Helper()
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("manager Close: %v", err)
		}
	})
}

func managerBoundaryFixtureFromCorpus(t *testing.T) managerFixture {
	t.Helper()
	corpus := loadCorpus(t)
	keys := mustObject(t, corpus.positive["test_keys"])
	boundary := mustObject(t, corpus.positive["topic_epoch_boundary"])
	keyset := mustObject(
		t,
		mustObject(t, boundary["transition_keyset"])["value"],
	)
	body, err := Canonicalize(keyset)
	if err != nil {
		t.Fatal(err)
	}
	return managerFixture{
		keyset:      keyset,
		body:        body,
		issuedAt:    mustWireTime(t, keyset["issued_at"]),
		expiresAt:   mustWireTime(t, keyset["expires_at"]),
		rootKeyID:   mustString(t, keys["root_signing_key_id"]),
		rootPublic:  mustString(t, keys["root_public_key_base64url"]),
		topicConfig: topicKeyConfig(t, keyset, keys),
	}
}
