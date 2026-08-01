// Package a9auth verifies and consumes the one-use service JWTs that bind
// modern-api requests to the A9 bridge endpoints.
package a9auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

var (
	// ErrServiceAuth is deliberately content-free. Callers must not expose a
	// failed token, claim, request body, key ID, or parsing detail.
	ErrServiceAuth = errors.New("service authentication invalid")

	// ErrServiceAuthReplay distinguishes a proved duplicate from malformed
	// authentication and from an unavailable replay store.
	ErrServiceAuthReplay = errors.New("service authentication replay")

	// ErrReplayStoreUnavailable means one-use semantics could not be proved.
	// Callers must fail closed and normally map this to a fixed HTTP 503.
	ErrReplayStoreUnavailable = errors.New(
		"service authentication replay store unavailable",
	)
)

// ReplayStore atomically consumes an (environment, jti) pair. It must retain a
// successful consume through retainUntil across process restarts and replicas.
//
// Consume returns (true, nil) only for the first durable consume. It returns
// (false, nil) for a replay. Any storage or commit ambiguity must return a
// non-nil error; it must never be represented as a replay or a successful
// consume.
type ReplayStore interface {
	Consume(
		ctx context.Context,
		environment string,
		jti string,
		retainUntil time.Time,
		now time.Time,
	) (bool, error)
}

// Expectations are the request values to which a service JWT must be bound.
// Keyset must be an immutable snapshot that has already passed root-pinned
// keyset validation and is current for Now.
type Expectations struct {
	Environment string
	Method      string
	Path        string
	RequestBody []byte
	Now         time.Time
	Keyset      map[string]any
}

// VerifiedToken is the minimum authenticated state required by a durable
// replay store. It intentionally contains no compact token or request bytes.
type VerifiedToken = a9trust.VerifiedJWT

// verify authenticates a compact service JWT without consuming its JTI. It is
// intentionally package-private so runtime callers cannot bypass replay
// consumption.
func verify(compact string, expected Expectations) (VerifiedToken, error) {
	if !validExpectations(expected) {
		return VerifiedToken{}, ErrServiceAuth
	}
	now := expected.Now.UTC()
	verified, verdict := a9trust.ValidateJWT(
		compact,
		a9trust.JWTExpectations{
			Environment: expected.Environment,
			Method:      expected.Method,
			Path:        expected.Path,
			RequestBody: expected.RequestBody,
			Now:         now,
			Keyset:      expected.Keyset,
		},
	)
	if !verdict.IsEligible() ||
		keysetEnvironment(expected.Keyset) != expected.Environment ||
		now.Before(verified.IssuedAt.Add(-5*time.Second)) ||
		now.Before(verified.NotBefore.Add(-5*time.Second)) ||
		now.After(verified.RetainUntil) {
		return VerifiedToken{}, ErrServiceAuth
	}
	return verified, nil
}

// VerifyAndConsume verifies the complete service JWT before touching replay
// state, then atomically consumes its JTI. It distinguishes a proved replay
// from an unavailable or ambiguous replay store.
func VerifyAndConsume(
	ctx context.Context,
	compact string,
	expected Expectations,
	store ReplayStore,
) (VerifiedToken, error) {
	verified, err := verify(compact, expected)
	if err != nil {
		return VerifiedToken{}, err
	}
	if ctx == nil || ctx.Err() != nil || store == nil {
		return VerifiedToken{}, ErrReplayStoreUnavailable
	}
	consumed, err := store.Consume(
		ctx,
		verified.Environment,
		verified.JTI,
		verified.RetainUntil,
		expected.Now.UTC(),
	)
	if err != nil {
		return VerifiedToken{}, ErrReplayStoreUnavailable
	}
	if !consumed {
		return VerifiedToken{}, ErrServiceAuthReplay
	}
	return verified, nil
}

func validExpectations(expected Expectations) bool {
	if expected.Environment != "dev" &&
		expected.Environment != "production" {
		return false
	}
	if expected.Now.IsZero() || expected.Keyset == nil {
		return false
	}
	if expected.Method == "" ||
		expected.Method != strings.ToUpper(expected.Method) {
		return false
	}
	return strings.HasPrefix(expected.Path, "/") &&
		!strings.ContainsAny(expected.Path, "?#")
}

func keysetEnvironment(keyset map[string]any) string {
	environment, _ := keyset["environment"].(string)
	return environment
}
