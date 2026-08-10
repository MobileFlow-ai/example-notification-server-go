package a10registration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

const (
	KeysetWellKnownPath = "/.well-known/hytch-xmtp-push-registration-keyset-v1.json"
	maxKeysetBodyBytes  = 32 * 1024
	maxKeysetTimeout    = 30 * time.Second
)

var (
	ErrKeysetConfiguration = errors.New("a10 keyset configuration invalid")
	ErrKeysetUnavailable   = errors.New("a10 keyset unavailable")
	ErrKeysetRejected      = errors.New("a10 keyset rejected")
)

type KeysetOrigin struct {
	value string
}

func ParseKeysetOrigin(raw string) (KeysetOrigin, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.String() != raw {
		return KeysetOrigin{}, ErrKeysetConfiguration
	}
	return KeysetOrigin{value: raw}, nil
}

func (origin KeysetOrigin) Endpoint() string {
	if origin.value == "" {
		return ""
	}
	return origin.value + KeysetWellKnownPath
}

type AcceptedKeyset struct {
	Environment           string
	Sequence              uint64
	ObjectHash            string
	CanonicalSignedObject []byte
	IssuedAt              time.Time
	ExpiresAt             time.Time
}

type KeysetState struct {
	Environment string
	Sequence    uint64
	ObjectHash  string
	ExpiresAt   time.Time
	Uncertain   bool
}

// KeysetStore is deliberately only an interface in the dormant skeleton.
// Its future database implementation must atomically enforce monotonic
// sequence, equal-sequence byte identity, and a durable uncertainty latch.
type KeysetStore interface {
	AcceptA10Keyset(context.Context, AcceptedKeyset) (KeysetState, error)
	CurrentA10KeysetState(context.Context, string) (KeysetState, error)
}

type KeysetManagerOptions struct {
	Environment    string
	Origin         KeysetOrigin
	RootPin        a9trust.RootPin
	Store          KeysetStore
	HTTPClient     *http.Client
	RequestTimeout time.Duration
	Clock          func() time.Time
}

type keysetSnapshot struct {
	accepted AcceptedKeyset
}

// KeysetManager implements KeysetSource only when its exact local bytes still
// match the separately durable A10 high-water state.
type KeysetManager struct {
	mu          sync.RWMutex
	environment string
	origin      KeysetOrigin
	rootPin     a9trust.RootPin
	store       KeysetStore
	client      *http.Client
	timeout     time.Duration
	clock       func() time.Time
	snapshot    *keysetSnapshot
}

func NewKeysetManager(options KeysetManagerOptions) (*KeysetManager, error) {
	rootID, err := a9trust.Ed25519KeyID(options.RootPin.PublicKey[:])
	if err != nil || rootID != options.RootPin.KeyID ||
		(options.Environment != "dev" && options.Environment != "production") ||
		options.Origin.Endpoint() == "" || options.Store == nil ||
		options.RequestTimeout < time.Second || options.RequestTimeout > maxKeysetTimeout {
		return nil, ErrKeysetConfiguration
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &KeysetManager{
		environment: options.Environment,
		origin:      options.Origin,
		rootPin:     options.RootPin,
		store:       options.Store,
		client:      client,
		timeout:     options.RequestTimeout,
		clock:       clock,
	}, nil
}

func (manager *KeysetManager) Refresh(ctx context.Context) error {
	if manager == nil || ctx == nil {
		return ErrKeysetUnavailable
	}
	requestContext, cancel := context.WithTimeout(ctx, manager.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodGet,
		manager.origin.Endpoint(),
		nil,
	)
	if err != nil {
		return ErrKeysetUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := manager.client.Do(request)
	if err != nil {
		return ErrKeysetUnavailable
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil ||
		mediaType != "application/json" || response.Request == nil ||
		response.Request.URL.String() != manager.origin.Endpoint() {
		return ErrKeysetUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxKeysetBodyBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxKeysetBodyBytes {
		return ErrKeysetUnavailable
	}
	accepted, err := manager.validateCandidate(raw, manager.clock().UTC())
	if err != nil {
		return err
	}
	state, err := manager.store.AcceptA10Keyset(requestContext, accepted)
	if err != nil {
		if errors.Is(err, ErrKeysetRejected) {
			return ErrKeysetRejected
		}
		return ErrKeysetUnavailable
	}
	if !stateMatches(state, accepted) {
		return ErrKeysetRejected
	}
	manager.mu.Lock()
	manager.snapshot = &keysetSnapshot{accepted: cloneAccepted(accepted)}
	manager.mu.Unlock()
	return nil
}

func (manager *KeysetManager) CurrentA10Keyset(ctx context.Context) ([]byte, error) {
	if manager == nil || ctx == nil {
		return nil, ErrKeysetUnavailable
	}
	manager.mu.RLock()
	if manager.snapshot == nil {
		manager.mu.RUnlock()
		return nil, ErrKeysetUnavailable
	}
	accepted := cloneAccepted(manager.snapshot.accepted)
	manager.mu.RUnlock()

	state, err := manager.store.CurrentA10KeysetState(ctx, manager.environment)
	now := manager.clock().UTC()
	if err != nil || !stateMatches(state, accepted) || now.Before(accepted.IssuedAt) ||
		!now.Before(accepted.ExpiresAt) {
		return nil, ErrKeysetUnavailable
	}
	if _, err = manager.validateCandidate(accepted.CanonicalSignedObject, now); err != nil {
		return nil, ErrKeysetUnavailable
	}
	return append([]byte(nil), accepted.CanonicalSignedObject...), nil
}

func (manager *KeysetManager) validateCandidate(raw []byte, now time.Time) (AcceptedKeyset, error) {
	object, err := validateKeyset(raw, manager.rootPin, manager.environment, now)
	if err != nil {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	canonical, err := a9trust.Canonicalize(object)
	if err != nil || !bytes.Equal(canonical, raw) {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	sequence, ok := uintField(object, "keyset_sequence")
	issued, issuedOK := wireTime(stringField(object, "issued_at"))
	expires, expiresOK := wireTime(stringField(object, "expires_at"))
	if !ok || !issuedOK || !expiresOK {
		return AcceptedKeyset{}, ErrKeysetRejected
	}
	digest := sha256.Sum256(canonical)
	return AcceptedKeyset{
		Environment:           manager.environment,
		Sequence:              sequence,
		ObjectHash:            hex.EncodeToString(digest[:]),
		CanonicalSignedObject: append([]byte(nil), canonical...),
		IssuedAt:              issued,
		ExpiresAt:             expires,
	}, nil
}

func stateMatches(state KeysetState, accepted AcceptedKeyset) bool {
	return !state.Uncertain && state.Environment == accepted.Environment &&
		state.Sequence == accepted.Sequence && state.ObjectHash == accepted.ObjectHash &&
		state.ExpiresAt.Equal(accepted.ExpiresAt)
}

func cloneAccepted(value AcceptedKeyset) AcceptedKeyset {
	value.CanonicalSignedObject = append([]byte(nil), value.CanonicalSignedObject...)
	return value
}
