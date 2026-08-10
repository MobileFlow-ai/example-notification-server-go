package a10registration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

type memoryKeysetStore struct {
	mu        sync.Mutex
	state     KeysetState
	acceptErr error
	readErr   error
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func (store *memoryKeysetStore) AcceptA10Keyset(_ context.Context, accepted AcceptedKeyset) (KeysetState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.acceptErr != nil {
		return KeysetState{}, store.acceptErr
	}
	store.state = KeysetState{
		Environment: accepted.Environment,
		Sequence:    accepted.Sequence,
		ObjectHash:  accepted.ObjectHash,
		ExpiresAt:   accepted.ExpiresAt,
	}
	return store.state, nil
}

func (store *memoryKeysetStore) CurrentA10KeysetState(_ context.Context, _ string) (KeysetState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state, store.readErr
}

func TestKeysetManagerRefreshesRootPinnedExactEndpointAndJoinsStore(t *testing.T) {
	fixture := readPositiveFixture(t)
	raw, err := json.Marshal(fixture.Keyset)
	if err != nil {
		t.Fatal(err)
	}
	requested := make(chan *http.Request, 1)
	manager, store := newTestKeysetManager(
		t,
		fixtureHTTPClient(raw, func(request *http.Request) { requested <- request }),
		fixture,
	)
	if err = manager.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	request := <-requested
	if request.URL.Path != KeysetWellKnownPath || request.Method != http.MethodGet ||
		request.Header.Get("Accept") != "application/json" {
		t.Fatal("keyset manager did not use the exact discovery request")
	}
	current, err := manager.CurrentA10Keyset(t.Context())
	if err != nil || string(current) != string(raw) {
		t.Fatal("manager did not expose the exact durable-current keyset")
	}
	current[0] ^= 1
	again, err := manager.CurrentA10Keyset(t.Context())
	if err != nil || string(again) != string(raw) {
		t.Fatal("caller mutated manager-owned keyset bytes")
	}
	store.mu.Lock()
	if store.state.Sequence != 1 || store.state.ObjectHash == "" || store.state.Uncertain {
		t.Fatal("accepted keyset did not join exact high-water state")
	}
	store.mu.Unlock()
}

func TestKeysetManagerFailsClosedOnStoreUncertaintyAndMismatch(t *testing.T) {
	fixture := readPositiveFixture(t)
	raw, _ := json.Marshal(fixture.Keyset)
	manager, store := newTestKeysetManager(t, fixtureHTTPClient(raw, nil), fixture)
	if err := manager.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	store.state.Uncertain = true
	store.mu.Unlock()
	if _, err := manager.CurrentA10Keyset(t.Context()); !errors.Is(err, ErrKeysetUnavailable) {
		t.Fatal("durable uncertainty did not close current keyset access")
	}

	store.mu.Lock()
	store.state.Uncertain = false
	store.state.ObjectHash = strings.Repeat("0", 64)
	store.mu.Unlock()
	if _, err := manager.CurrentA10Keyset(t.Context()); !errors.Is(err, ErrKeysetUnavailable) {
		t.Fatal("durable/local hash mismatch did not close current keyset access")
	}
}

func TestKeysetManagerRejectsStoreConflictAndTreatsOutageAsUnavailable(t *testing.T) {
	fixture := readPositiveFixture(t)
	raw, _ := json.Marshal(fixture.Keyset)
	manager, store := newTestKeysetManager(t, fixtureHTTPClient(raw, nil), fixture)

	store.acceptErr = ErrKeysetRejected
	if err := manager.Refresh(t.Context()); !errors.Is(err, ErrKeysetRejected) {
		t.Fatal("durable high-water conflict did not reject candidate")
	}
	store.acceptErr = errors.New("database unavailable")
	if err := manager.Refresh(t.Context()); !errors.Is(err, ErrKeysetUnavailable) {
		t.Fatal("store outage did not fail unavailable")
	}
}

func TestKeysetOriginIsExactHTTPSOrigin(t *testing.T) {
	valid, err := ParseKeysetOrigin("https://modern-api.internal")
	if err != nil || valid.Endpoint() != "https://modern-api.internal"+KeysetWellKnownPath {
		t.Fatal("exact HTTPS A10 keyset origin was rejected")
	}
	for _, invalid := range []string{
		"http://modern-api.internal",
		"https://user@modern-api.internal",
		"https://modern-api.internal/",
		"https://modern-api.internal/path",
		"https://modern-api.internal?query=1",
		"https://modern-api.internal#fragment",
	} {
		if _, err = ParseKeysetOrigin(invalid); !errors.Is(err, ErrKeysetConfiguration) {
			t.Fatalf("unsafe origin accepted: %s", invalid)
		}
	}
}

func newTestKeysetManager(t *testing.T, client *http.Client, fixture fixtureFile) (*KeysetManager, *memoryKeysetStore) {
	t.Helper()
	origin, err := ParseKeysetOrigin("https://modern-api.internal")
	if err != nil {
		t.Fatal(err)
	}
	rootPublic := decodeB64(t, fixture.RootPublicKeyBase64URL)
	rootID, err := a9trust.Ed25519KeyID(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	var pin a9trust.RootPin
	pin.KeyID = rootID
	copy(pin.PublicKey[:], rootPublic)
	store := &memoryKeysetStore{}
	manager, err := NewKeysetManager(KeysetManagerOptions{
		Environment:    "dev",
		Origin:         origin,
		RootPin:        pin,
		Store:          store,
		HTTPClient:     client,
		RequestTimeout: time.Second,
		Clock: func() time.Time {
			return time.Unix(fixture.FixtureTimeUnix, 0).UTC()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager, store
}

func fixtureHTTPClient(raw []byte, observe func(*http.Request)) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if observe != nil {
			observe(request)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(raw))),
			Request:    request,
		}, nil
	})}
}
