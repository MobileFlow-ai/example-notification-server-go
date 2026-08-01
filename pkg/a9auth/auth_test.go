package a9auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

type authCorpus struct {
	positive map[string]any
	keyset   map[string]any
	seed     []byte
}

type jwtFixture struct {
	compact string
	header  map[string]any
	claims  map[string]any
	body    []byte
}

func loadAuthCorpus(t *testing.T) authCorpus {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	raw, err := os.ReadFile(filepath.Join(
		root,
		"contracts",
		"xmtp_push",
		"a9_adapter",
		"v1",
		"vectors",
		"positive.json",
	))
	require.NoError(t, err)
	value, err := a9trust.ParseStrictJSON(raw)
	require.NoError(t, err)
	positive := mustObject(t, value)
	keyset := mustObject(t, mustObject(t, positive["keyset"])["value"])
	keys := mustObject(t, positive["test_keys"])
	seed, err := a9trust.DecodeBase64URL(
		mustString(t, keys["service_auth_private_seed_base64url"]),
		ed25519.SeedSize,
	)
	require.NoError(t, err)
	return authCorpus{positive: positive, keyset: keyset, seed: seed}
}

func (corpus authCorpus) fixture(t *testing.T, name string) jwtFixture {
	t.Helper()
	jwt := mustObject(t, corpus.positive[name])
	var body []byte
	switch name {
	case "service_jwt":
		body = []byte(mustString(
			t,
			mustObject(
				t,
				corpus.positive["subscription_replace"],
			)["canonical_body_utf8"],
		))
	case "control_apply_service_jwt":
		var err error
		body, err = a9trust.Canonicalize(
			mustObject(t, corpus.positive["control_upsert"])["value"],
		)
		require.NoError(t, err)
	case "watermark_apply_service_jwt":
		var err error
		body, err = a9trust.Canonicalize(
			mustObject(t, corpus.positive["watermark_current"])["value"],
		)
		require.NoError(t, err)
	default:
		t.Fatalf("unknown JWT fixture %q", name)
	}
	return jwtFixture{
		compact: mustString(t, jwt["compact"]),
		header:  mustObject(t, jwt["header"]),
		claims:  mustObject(t, jwt["claims"]),
		body:    body,
	}
}

func (fixture jwtFixture) expectations(
	t *testing.T,
	keyset map[string]any,
) Expectations {
	t.Helper()
	iat := mustUint(t, fixture.claims["iat"])
	return Expectations{
		Environment: mustString(t, fixture.claims["environment"]),
		Method:      mustString(t, fixture.claims["method"]),
		Path:        mustString(t, fixture.claims["path"]),
		RequestBody: append([]byte(nil), fixture.body...),
		Now:         time.Unix(int64(iat), 0).UTC(),
		Keyset:      keyset,
	}
}

func TestVerifyPublishedEndpointVectors(t *testing.T) {
	corpus := loadAuthCorpus(t)
	for _, name := range []string{
		"service_jwt",
		"control_apply_service_jwt",
		"watermark_apply_service_jwt",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := corpus.fixture(t, name)
			expected := fixture.expectations(t, corpus.keyset)

			first, err := verify(fixture.compact, expected)
			require.NoError(t, err)
			second, err := verify(fixture.compact, expected)
			require.NoError(t, err)

			require.Equal(t, first, second)
			require.Equal(t, expected.Environment, first.Environment)
			require.Equal(t, mustString(t, fixture.claims["jti"]), first.JTI)
			require.Equal(t, mustString(t, fixture.header["kid"]), first.KeyID)
			require.Equal(
				t,
				time.Unix(int64(mustUint(t, fixture.claims["iat"])), 0).UTC(),
				first.IssuedAt,
			)
			require.Equal(
				t,
				time.Unix(int64(mustUint(t, fixture.claims["nbf"])), 0).UTC(),
				first.NotBefore,
			)
			require.Equal(
				t,
				time.Unix(int64(mustUint(t, fixture.claims["exp"])), 0).UTC(),
				first.ExpiresAt,
			)
			require.Equal(t, first.ExpiresAt.Add(5*time.Second), first.RetainUntil)
		})
	}
}

func TestVerifyRejectsNoncanonicalOrAmbiguousCompactJWS(t *testing.T) {
	corpus := loadAuthCorpus(t)
	fixture := corpus.fixture(t, "service_jwt")
	expected := fixture.expectations(t, corpus.keyset)
	headerBytes, err := a9trust.Canonicalize(fixture.header)
	require.NoError(t, err)
	claimBytes, err := a9trust.Canonicalize(fixture.claims)
	require.NoError(t, err)

	noncanonicalHeader := []byte(
		`{"typ":"JWT","alg":"EdDSA","kid":"` +
			mustString(t, fixture.header["kid"]) +
			`"}`,
	)
	duplicateClaims := append(
		[]byte(`{"aud":"hytch.xmtp-push-bridge.a9-control",`),
		claimBytes[1:]...,
	)
	whitespaceClaims := append([]byte("{ "), claimBytes[1:]...)
	validSignature, err := a9trust.DecodeBase64URL(
		strings.Split(fixture.compact, ".")[2],
		ed25519.SignatureSize,
	)
	require.NoError(t, err)

	tests := map[string]string{
		"noncanonical header": signRawJWT(t, noncanonicalHeader, claimBytes, corpus.seed),
		"duplicate claim":     signRawJWT(t, headerBytes, duplicateClaims, corpus.seed),
		"whitespace claims":   signRawJWT(t, headerBytes, whitespaceClaims, corpus.seed),
		"padded signature":    fixture.compact + "=",
		"too few segments": strings.Join(
			strings.Split(fixture.compact, ".")[:2],
			".",
		),
		"too many segments": fixture.compact + ".extra",
		"wrong signature length": strings.Join([]string{
			strings.Split(fixture.compact, ".")[0],
			strings.Split(fixture.compact, ".")[1],
			a9trust.EncodeBase64URL(validSignature[:len(validSignature)-1]),
		}, "."),
	}
	for name, compact := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := verify(compact, expected)
			require.ErrorIs(t, err, ErrServiceAuth)
		})
	}
}

func TestVerifyRequiresExactHeaderAndClaimSets(t *testing.T) {
	corpus := loadAuthCorpus(t)
	fixture := corpus.fixture(t, "service_jwt")
	expected := fixture.expectations(t, corpus.keyset)

	tests := map[string]struct {
		mutateHeader func(map[string]any)
		mutateClaims func(map[string]any)
	}{
		"wrong algorithm": {
			mutateHeader: func(value map[string]any) { value["alg"] = "Ed25519" },
		},
		"wrong type": {
			mutateHeader: func(value map[string]any) { value["typ"] = "JWS" },
		},
		"unknown header": {
			mutateHeader: func(value map[string]any) { value["extra"] = "x" },
		},
		"missing header": {
			mutateHeader: func(value map[string]any) { delete(value, "alg") },
		},
		"unknown claim": {
			mutateClaims: func(value map[string]any) { value["extra"] = "x" },
		},
		"missing claim": {
			mutateClaims: func(value map[string]any) { delete(value, "aud") },
		},
		"wrong issuer": {
			mutateClaims: func(value map[string]any) { value["iss"] = "other" },
		},
		"wrong subject": {
			mutateClaims: func(value map[string]any) { value["sub"] = "other" },
		},
		"wrong audience": {
			mutateClaims: func(value map[string]any) { value["aud"] = "other" },
		},
		"wrong environment": {
			mutateClaims: func(value map[string]any) {
				value["environment"] = "production"
			},
		},
		"noncanonical jti": {
			mutateClaims: func(value map[string]any) {
				value["jti"] = strings.ToUpper(mustString(t, value["jti"]))
			},
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			header := cloneObject(t, fixture.header)
			claims := cloneObject(t, fixture.claims)
			if testCase.mutateHeader != nil {
				testCase.mutateHeader(header)
			}
			if testCase.mutateClaims != nil {
				testCase.mutateClaims(claims)
			}
			compact := signJWT(t, header, claims, corpus.seed)
			_, err := verify(compact, expected)
			require.ErrorIs(t, err, ErrServiceAuth)
		})
	}
}

func TestVerifyBindsMethodPathAndExactBody(t *testing.T) {
	corpus := loadAuthCorpus(t)
	fixture := corpus.fixture(t, "service_jwt")
	expected := fixture.expectations(t, corpus.keyset)

	for name, mutate := range map[string]func(*Expectations){
		"expected method":           func(value *Expectations) { value.Method = "POST" },
		"expected path":             func(value *Expectations) { value.Path += "-other" },
		"query in expected path":    func(value *Expectations) { value.Path += "?x=1" },
		"fragment in expected path": func(value *Expectations) { value.Path += "#x" },
		"exact body": func(value *Expectations) {
			value.RequestBody = append(value.RequestBody, '\n')
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := expected
			mutate(&changed)
			_, err := verify(fixture.compact, changed)
			require.ErrorIs(t, err, ErrServiceAuth)
		})
	}

	for name, mutate := range map[string]func(map[string]any){
		"lowercase method":    func(value map[string]any) { value["method"] = "put" },
		"claim path query":    func(value map[string]any) { value["path"] = expected.Path + "?x=1" },
		"claim path fragment": func(value map[string]any) { value["path"] = expected.Path + "#x" },
		"wrong body hash": func(value map[string]any) {
			value["request_sha256"] = strings.Repeat("0", 64)
		},
		"uppercase body hash": func(value map[string]any) {
			value["request_sha256"] = strings.ToUpper(
				mustString(t, value["request_sha256"]),
			)
		},
	} {
		t.Run(name, func(t *testing.T) {
			claims := cloneObject(t, fixture.claims)
			mutate(claims)
			compact := signJWT(t, fixture.header, claims, corpus.seed)
			_, err := verify(compact, expected)
			require.ErrorIs(t, err, ErrServiceAuth)
		})
	}
}

func TestVerifyEnforcesServiceJWTTimeWindow(t *testing.T) {
	corpus := loadAuthCorpus(t)
	fixture := corpus.fixture(t, "service_jwt")
	expected := fixture.expectations(t, corpus.keyset)
	iat := mustUint(t, fixture.claims["iat"])

	for name, mutate := range map[string]func(map[string]any){
		"zero ttl": func(value map[string]any) {
			value["exp"] = json.Number(strconv.FormatUint(iat, 10))
		},
		"ttl above sixty seconds": func(value map[string]any) {
			value["exp"] = json.Number(strconv.FormatUint(iat+61, 10))
		},
		"nbf after iat": func(value map[string]any) {
			value["nbf"] = json.Number(strconv.FormatUint(iat+1, 10))
		},
		"nbf too early": func(value map[string]any) {
			value["nbf"] = json.Number(strconv.FormatUint(iat-6, 10))
		},
		"negative iat": func(value map[string]any) {
			value["iat"] = json.Number("-1")
		},
		"fractional exp": func(value map[string]any) {
			value["exp"] = json.Number(strconv.FormatUint(iat+30, 10) + ".0")
		},
		"unsafe integer": func(value map[string]any) {
			value["exp"] = json.Number("9007199254740992")
		},
	} {
		t.Run(name, func(t *testing.T) {
			claims := cloneObject(t, fixture.claims)
			mutate(claims)
			compact, _, signErr := a9trust.BuildJWT(
				fixture.header,
				claims,
				corpus.seed,
			)
			if signErr != nil {
				claimBytes, canonicalErr := json.Marshal(claims)
				require.NoError(t, canonicalErr)
				headerBytes, canonicalErr := a9trust.Canonicalize(fixture.header)
				require.NoError(t, canonicalErr)
				compact = signRawJWT(t, headerBytes, claimBytes, corpus.seed)
			}
			_, err := verify(compact, expected)
			require.ErrorIs(t, err, ErrServiceAuth)
		})
	}

	nbf := mustUint(t, fixture.claims["nbf"])
	exp := mustUint(t, fixture.claims["exp"])
	for name, now := range map[string]time.Time{
		"before nbf skew": time.Unix(int64(nbf)-6, 0).UTC(),
		"nbf skew cannot compound iat skew": time.Unix(
			int64(nbf)-5,
			0,
		).UTC(),
		"one nanosecond before iat skew": time.Unix(
			int64(iat),
			0,
		).UTC().Add(-5*time.Second - time.Nanosecond),
		"after exp skew":                time.Unix(int64(exp)+6, 0).UTC(),
		"one nanosecond after exp skew": time.Unix(int64(exp)+5, 1).UTC(),
	} {
		t.Run(name, func(t *testing.T) {
			changed := expected
			changed.Now = now
			_, err := verify(fixture.compact, changed)
			require.ErrorIs(t, err, ErrServiceAuth)
		})
	}
	for name, now := range map[string]time.Time{
		"exact iat skew boundary": time.Unix(int64(iat)-5, 0).UTC(),
		"exact exp skew boundary": time.Unix(int64(exp)+5, 0).UTC(),
	} {
		t.Run(name, func(t *testing.T) {
			changed := expected
			changed.Now = now
			_, err := verify(fixture.compact, changed)
			require.NoError(t, err)
		})
	}
}

func TestVerifyRejectsBadSignatureAndUnusableKeyState(t *testing.T) {
	corpus := loadAuthCorpus(t)
	fixture := corpus.fixture(t, "service_jwt")
	expected := fixture.expectations(t, corpus.keyset)
	iat := time.Unix(int64(mustUint(t, fixture.claims["iat"])), 0).UTC()

	signatureSegments := strings.Split(fixture.compact, ".")
	signature, err := a9trust.DecodeBase64URL(
		signatureSegments[2],
		ed25519.SignatureSize,
	)
	require.NoError(t, err)
	signature[0] ^= 0x80
	badSignature := strings.Join([]string{
		signatureSegments[0],
		signatureSegments[1],
		a9trust.EncodeBase64URL(signature),
	}, ".")

	tests := map[string]struct {
		compact string
		keyset  map[string]any
	}{
		"bad signature": {
			compact: badSignature,
			keyset:  corpus.keyset,
		},
		"unknown key": {
			compact: signWithHeaderMutation(
				t,
				fixture,
				corpus.seed,
				func(header map[string]any) {
					header["kid"] = "ed25519-sha256:" + strings.Repeat("0", 64)
				},
			),
			keyset: corpus.keyset,
		},
		"wrong key use": {
			compact: fixture.compact,
			keyset: mutateServiceKey(t, corpus.keyset, func(key map[string]any) {
				key["use"] = "A9_CONTROL"
			}),
		},
		"future key": {
			compact: fixture.compact,
			keyset: mutateServiceKey(t, corpus.keyset, func(key map[string]any) {
				key["not_before"] = iat.Add(time.Millisecond).
					Format("2006-01-02T15:04:05.000Z")
			}),
		},
		"expired key": {
			compact: fixture.compact,
			keyset: mutateServiceKey(t, corpus.keyset, func(key map[string]any) {
				key["not_after"] = iat.Format("2006-01-02T15:04:05.000Z")
			}),
		},
		"wrong public key": {
			compact: fixture.compact,
			keyset: mutateServiceKey(t, corpus.keyset, func(key map[string]any) {
				key["public_key_base64url"] = a9trust.EncodeBase64URL(
					make([]byte, ed25519.PublicKeySize),
				)
			}),
		},
		"wrong keyset environment": {
			compact: fixture.compact,
			keyset: func() map[string]any {
				keyset := cloneObject(t, corpus.keyset)
				keyset["environment"] = "production"
				return keyset
			}(),
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			changed := expected
			changed.Keyset = testCase.keyset
			_, err := verify(testCase.compact, changed)
			require.ErrorIs(t, err, ErrServiceAuth)
		})
	}

	for name, mutate := range map[string]func(*Expectations){
		"nil keyset": func(value *Expectations) { value.Keyset = nil },
		"zero time":  func(value *Expectations) { value.Now = time.Time{} },
		"bad environment": func(value *Expectations) {
			value.Environment = "development"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := expected
			mutate(&changed)
			_, err := verify(fixture.compact, changed)
			require.ErrorIs(t, err, ErrServiceAuth)
		})
	}
}

type memoryReplayStore struct {
	mu      sync.Mutex
	used    map[string]time.Time
	calls   int
	err     error
	records []replayRecord
}

type replayRecord struct {
	environment string
	jti         string
	retainUntil time.Time
	now         time.Time
}

func (store *memoryReplayStore) Consume(
	_ context.Context,
	environment string,
	jti string,
	retainUntil time.Time,
	now time.Time,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls++
	store.records = append(store.records, replayRecord{
		environment: environment,
		jti:         jti,
		retainUntil: retainUntil,
		now:         now,
	})
	if store.err != nil {
		return false, store.err
	}
	if store.used == nil {
		store.used = make(map[string]time.Time)
	}
	for key, deadline := range store.used {
		if now.After(deadline) {
			delete(store.used, key)
		}
	}
	key := environment + "\x00" + jti
	if deadline, exists := store.used[key]; exists && !now.After(deadline) {
		return false, nil
	}
	store.used[key] = retainUntil
	return true, nil
}

func (store *memoryReplayStore) callCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.calls
}

func TestVerifyAndConsumeDistinguishesReplayAndUnavailable(t *testing.T) {
	corpus := loadAuthCorpus(t)
	fixture := corpus.fixture(t, "service_jwt")
	expected := fixture.expectations(t, corpus.keyset)
	store := &memoryReplayStore{}

	verified, err := VerifyAndConsume(
		t.Context(),
		fixture.compact,
		expected,
		store,
	)
	require.NoError(t, err)
	require.Equal(t, 1, store.callCount())
	require.Len(t, store.records, 1)
	require.Equal(t, verified.Environment, store.records[0].environment)
	require.Equal(t, verified.JTI, store.records[0].jti)
	require.Equal(t, verified.RetainUntil, store.records[0].retainUntil)
	require.Equal(t, expected.Now.UTC(), store.records[0].now)

	_, err = VerifyAndConsume(t.Context(), fixture.compact, expected, store)
	require.ErrorIs(t, err, ErrServiceAuthReplay)
	require.Equal(t, 2, store.callCount())

	unavailable := &memoryReplayStore{err: errors.New("database unavailable")}
	_, err = VerifyAndConsume(
		t.Context(),
		fixture.compact,
		expected,
		unavailable,
	)
	require.ErrorIs(t, err, ErrReplayStoreUnavailable)
	require.NotErrorIs(t, err, ErrServiceAuthReplay)

	_, err = VerifyAndConsume(t.Context(), fixture.compact, expected, nil)
	require.ErrorIs(t, err, ErrReplayStoreUnavailable)

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	untouched := &memoryReplayStore{}
	_, err = VerifyAndConsume(cancelled, fixture.compact, expected, untouched)
	require.ErrorIs(t, err, ErrReplayStoreUnavailable)
	require.Zero(t, untouched.callCount())
}

func TestVerifyAndConsumeNeverTouchesStoreBeforeFullVerification(t *testing.T) {
	corpus := loadAuthCorpus(t)
	fixture := corpus.fixture(t, "service_jwt")
	expected := fixture.expectations(t, corpus.keyset)
	store := &memoryReplayStore{}

	_, err := VerifyAndConsume(
		t.Context(),
		fixture.compact+"invalid",
		expected,
		store,
	)
	require.ErrorIs(t, err, ErrServiceAuth)
	require.Zero(t, store.callCount())

	changed := expected
	changed.RequestBody = append(changed.RequestBody, '\n')
	_, err = VerifyAndConsume(t.Context(), fixture.compact, changed, store)
	require.ErrorIs(t, err, ErrServiceAuth)
	require.Zero(t, store.callCount())

	changed = expected
	changed.Now = time.Unix(
		int64(mustUint(t, fixture.claims["exp"]))+5,
		1,
	).UTC()
	_, err = VerifyAndConsume(t.Context(), fixture.compact, changed, store)
	require.ErrorIs(t, err, ErrServiceAuth)
	require.Zero(t, store.callCount())
}

func TestVerifyAndConsumeIsOneUseUnderConcurrency(t *testing.T) {
	corpus := loadAuthCorpus(t)
	fixture := corpus.fixture(t, "service_jwt")
	expected := fixture.expectations(t, corpus.keyset)
	store := &memoryReplayStore{}
	const callers = 24

	results := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := VerifyAndConsume(
				context.Background(),
				fixture.compact,
				expected,
				store,
			)
			results <- err
		}()
	}
	wait.Wait()
	close(results)

	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrServiceAuthReplay):
			replays++
		default:
			t.Fatalf("unexpected error category: %v", err)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, callers-1, replays)
	require.Equal(t, callers, store.callCount())
}

func signJWT(
	t *testing.T,
	header map[string]any,
	claims map[string]any,
	seed []byte,
) string {
	t.Helper()
	compact, _, err := a9trust.BuildJWT(header, claims, seed)
	require.NoError(t, err)
	return compact
}

func signRawJWT(
	t *testing.T,
	header []byte,
	claims []byte,
	seed []byte,
) string {
	t.Helper()
	require.Len(t, seed, ed25519.SeedSize)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	signature := ed25519.Sign(
		ed25519.NewKeyFromSeed(seed),
		[]byte(signingInput),
	)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signWithHeaderMutation(
	t *testing.T,
	fixture jwtFixture,
	seed []byte,
	mutate func(map[string]any),
) string {
	t.Helper()
	header := cloneObject(t, fixture.header)
	mutate(header)
	return signJWT(t, header, fixture.claims, seed)
}

func mutateServiceKey(
	t *testing.T,
	original map[string]any,
	mutate func(map[string]any),
) map[string]any {
	t.Helper()
	keyset := cloneObject(t, original)
	keys, ok := keyset["keys"].([]any)
	require.True(t, ok)
	found := false
	for _, rawKey := range keys {
		key := mustObject(t, rawKey)
		if mustString(t, key["use"]) == "SERVICE_AUTH" {
			mutate(key)
			found = true
			break
		}
	}
	require.True(t, found)
	return keyset
}

func cloneObject(t *testing.T, original map[string]any) map[string]any {
	t.Helper()
	canonical, err := a9trust.Canonicalize(original)
	require.NoError(t, err)
	value, err := a9trust.ParseStrictJSON(canonical)
	require.NoError(t, err)
	return mustObject(t, value)
}

func mustObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	require.True(t, ok)
	return object
}

func mustString(t *testing.T, value any) string {
	t.Helper()
	text, ok := value.(string)
	require.True(t, ok)
	return text
}

func mustUint(t *testing.T, value any) uint64 {
	t.Helper()
	number, ok := value.(json.Number)
	require.True(t, ok)
	parsed, err := strconv.ParseUint(string(number), 10, 64)
	require.NoError(t, err)
	return parsed
}
