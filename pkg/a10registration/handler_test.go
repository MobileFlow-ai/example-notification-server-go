package a10registration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

type fixtureFile struct {
	FixtureTimeUnix        int64          `json:"fixture_time_unix"`
	RootPublicKeyBase64URL string         `json:"root_public_key_base64url"`
	RootKeyID              string         `json:"root_key_id"`
	Keyset                 map[string]any `json:"keyset"`
	RequestBodyBase64URL   string         `json:"request_body_base64url"`
	Credential             string         `json:"credential"`
}

type staticKeysets struct {
	raw []byte
	err error
}

func (source *staticKeysets) CurrentA10Keyset(context.Context) ([]byte, error) {
	return append([]byte(nil), source.raw...), source.err
}

type memoryReplay struct {
	mu          sync.Mutex
	used        map[string]bool
	unavailable bool
	calls       int
}

func (store *memoryReplay) ConsumeA10Registration(_ context.Context, environment, jti string, _ time.Time, _ time.Time) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls++
	if store.unavailable {
		return false, errors.New("unavailable")
	}
	key := environment + "\x00" + jti
	if store.used[key] {
		return false, nil
	}
	store.used[key] = true
	return true, nil
}

type recordingSink struct {
	calls int
	value VerifiedRegistration
	err   error
}

func (sink *recordingSink) RegisterVerified(_ context.Context, value VerifiedRegistration) error {
	sink.calls++
	sink.value = value
	return sink.err
}

type handlerHarness struct {
	fixture fixtureFile
	keysets *staticKeysets
	replay  *memoryReplay
	sink    *recordingSink
	handler *Handler
}

func TestPositiveFixtureReachesDormantHandler(t *testing.T) {
	harness := newHarness(t)
	result := harness.serve(t, http.MethodPut, Path, harness.body(t), harness.fixture.Credential)
	if result.Code != http.StatusNoContent || result.Body.String() != "" {
		t.Fatalf("positive fixture failed: status=%d body=%q", result.Code, result.Body.String())
	}
	if harness.sink.calls != 1 || harness.sink.value.Environment != "dev" ||
		harness.sink.value.APNSTopic != "com.mobileflow.hytchdev" ||
		harness.sink.value.APNSToken.Len() != 32 ||
		harness.sink.value.PayloadSchema != "xmtp.encrypted.v4" {
		t.Fatal("verified fixture did not reach the dormant sink exactly once")
	}
}

func TestHandlerIsDefaultOffAndNeverTouchesDependencies(t *testing.T) {
	handler, err := NewHandler(Options{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, Path, strings.NewReader("{}"))
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	if result.Code != http.StatusNotFound || result.Body.String() != "not_found" {
		t.Fatal("default-off handler did not stay invisible")
	}
}

func TestHandlerRejectsNonCanonicalEnvironmentTopicConfiguration(t *testing.T) {
	harness := newHarness(t)
	_, err := NewHandler(Options{
		Enabled: true, Environment: "dev", AllowedTopic: "org.attacker.push",
		RootPin: harness.handler.rootPin, Keysets: harness.keysets,
		Replay: harness.replay, Sink: harness.sink,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("noncanonical APNs topic configuration was accepted")
	}
}

func TestAllNineteenNegativeFixturesReachProductionGuards(t *testing.T) {
	for _, id := range negativeIDs(t) {
		id := id
		t.Run(id, func(t *testing.T) {
			harness := newHarness(t)
			body := harness.body(t)
			token := harness.fixture.Credential
			method := http.MethodPut
			path := Path
			wantStatus := http.StatusUnauthorized
			wantBody := "unauthorized"

			switch id {
			case "wrong_environment":
				token = mutateToken(t, token, nil, map[string]any{"environment": "production"})
			case "arbitrary_installation":
				body = mutateRequest(t, body, "installation_id_base64url", b64(make([]byte, 32)))
				token = bindTokenToBody(t, token, body, nil)
			case "wrong_installation_binding":
				body = mutateRequest(t, body, "installation_binding_id", b64(make([]byte, 16)))
				token = bindTokenToBody(t, token, body, nil)
			case "wrong_owner_binding":
				body = mutateRequest(t, body, "owner_binding", b64(make([]byte, 32)))
				token = bindTokenToBody(t, token, body, nil)
			case "apns_token_hash_mismatch":
				body = mutateRequest(t, body, "apns_token_base64url", b64(make([]byte, 32)))
				token = bindTokenToBody(t, token, body, nil)
			case "wrong_apns_topic":
				body = mutateRequest(t, body, "apns_topic", "com.hytch.rewards")
				token = bindTokenToBody(t, token, body, map[string]any{"apns_topic": "com.hytch.rewards"})
			case "expired":
				harness.handler.clock = func() time.Time { return time.Unix(harness.fixture.FixtureTimeUnix+66, 0).UTC() }
			case "replayed":
				first := harness.serve(t, method, path, body, token)
				if first.Code != http.StatusNoContent {
					t.Fatal("replay setup did not succeed")
				}
				wantStatus, wantBody = http.StatusConflict, "replay"
			case "tampered_body":
				body = append(body, ' ')
			case "wrong_method":
				method = http.MethodPost
			case "wrong_path":
				path = "/v1/xmtp-push/installations:delete"
			case "wrong_audience":
				token = mutateToken(t, token, nil, map[string]any{"aud": "hytch.xmtp-push-bridge.a9-control"})
			case "bad_signature":
				token = corruptSignature(t, token)
			case "unknown_key":
				token = mutateToken(t, token, map[string]any{"kid": "ed25519-sha256:" + strings.Repeat("0", 64)}, nil)
			case "malformed_jti":
				token = mutateToken(t, token, nil, map[string]any{"jti": "A10"})
			case "lifetime_over_60":
				token = mutateToken(t, token, nil, map[string]any{"exp": json.Number("1786300261")})
			case "future_nbf":
				token = mutateToken(t, token, nil, map[string]any{"nbf": json.Number("1786300201")})
			case "key_wrong_use":
				harness.keysets.raw = mutateKeysetUse(t, harness.keysets.raw, "SERVICE_AUTH")
				wantStatus, wantBody = http.StatusServiceUnavailable, "unavailable"
			case "replay_store_unavailable":
				harness.replay.unavailable = true
				wantStatus, wantBody = http.StatusServiceUnavailable, "unavailable"
			default:
				t.Fatalf("negative fixture %q has no production execution", id)
			}

			result := harness.serve(t, method, path, body, token)
			if result.Code != wantStatus || result.Body.String() != wantBody {
				t.Fatalf("guard %s: status=%d body=%q", id, result.Code, result.Body.String())
			}
			if id != "replayed" && harness.sink.calls != 0 {
				t.Fatalf("guard %s reached the registration sink", id)
			}
			switch id {
			case "replayed":
				if harness.replay.calls != 2 {
					t.Fatal("replay case did not execute exactly two atomic consumes")
				}
			case "replay_store_unavailable":
				if harness.replay.calls != 1 {
					t.Fatal("replay-store outage did not reach the atomic consume boundary")
				}
			default:
				if harness.replay.calls != 0 {
					t.Fatalf("unauthorized guard %s burned the one-use credential", id)
				}
			}
		})
	}
}

func TestOpaqueVariableLengthAPNSTokenBounds(t *testing.T) {
	for _, size := range []int{1, 17, 32, 256} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			harness := newHarness(t)
			tokenBytes := make([]byte, size)
			for index := range tokenBytes {
				tokenBytes[index] = byte(index%251 + 1)
			}
			body := mutateRequest(t, harness.body(t), "apns_token_base64url", b64(tokenBytes))
			hash := sha256.Sum256(tokenBytes)
			credential := bindTokenToBody(t, harness.fixture.Credential, body, map[string]any{
				"apns_token_sha256": hex.EncodeToString(hash[:]),
			})
			result := harness.serve(t, http.MethodPut, Path, body, credential)
			if result.Code != http.StatusNoContent || harness.sink.calls != 1 ||
				harness.sink.value.APNSToken.Len() != size ||
				!bytes.Equal(harness.sink.value.APNSToken.Bytes(), tokenBytes) {
				t.Fatal("bounded opaque APNs token did not reach sink exactly")
			}
		})
	}

	for _, size := range []int{0, 257} {
		t.Run("reject-"+strconv.Itoa(size), func(t *testing.T) {
			harness := newHarness(t)
			tokenBytes := bytes.Repeat([]byte{1}, size)
			body := mutateRequest(t, harness.body(t), "apns_token_base64url", b64(tokenBytes))
			hash := sha256.Sum256(tokenBytes)
			credential := bindTokenToBody(t, harness.fixture.Credential, body, map[string]any{
				"apns_token_sha256": hex.EncodeToString(hash[:]),
			})
			result := harness.serve(t, http.MethodPut, Path, body, credential)
			if result.Code != http.StatusUnauthorized || harness.replay.calls != 0 || harness.sink.calls != 0 {
				t.Fatal("out-of-range APNs token did not fail before replay and sink")
			}
		})
	}
}

func TestA10KeysetSupportsSafeRotationAndRejectsCollapsedOrInvalidWindows(t *testing.T) {
	harness := newHarness(t)
	fixtureTime := time.Unix(harness.fixture.FixtureTimeUnix, 0).UTC()

	verifySeed := sha256.Sum256([]byte("hytch-a10-retiring-online-v1"))
	verifyPublic := ed25519.NewKeyFromSeed(verifySeed[:]).Public().(ed25519.PublicKey)
	verifyOnly := map[string]any{
		"key_id":               keyIDForTest(t, verifyPublic),
		"not_after":            "2026-08-16T18:00:00.000Z",
		"not_before":           "2026-08-08T18:00:00.000Z",
		"public_key_base64url": b64(verifyPublic),
		"state":                "VERIFY_ONLY",
		"use":                  KeyUse,
	}
	rotating := mutateKeyset(t, harness.keysets.raw, func(keyset map[string]any) {
		keyset["keys"] = append(keyset["keys"].([]any), verifyOnly)
	}, nil)
	if _, err := validateKeyset(rotating, harness.handler.rootPin, "dev", fixtureTime); err != nil {
		t.Fatal("one SIGN plus one VERIFY_ONLY key should be valid")
	}

	tests := map[string]func(map[string]any){
		"two-sign": func(keyset map[string]any) {
			second := cloneObject(verifyOnly)
			second["state"] = "SIGN"
			keyset["keys"] = append(keyset["keys"].([]any), second)
		},
		"starts-after-keyset": func(keyset map[string]any) {
			keyset["keys"].([]any)[0].(map[string]any)["not_before"] = "2026-08-09T18:00:01.000Z"
		},
		"ends-before-keyset": func(keyset map[string]any) {
			keyset["keys"].([]any)[0].(map[string]any)["not_after"] = "2026-08-09T18:59:59.000Z"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			raw := mutateKeyset(t, harness.keysets.raw, mutate, nil)
			if _, err := validateKeyset(raw, harness.handler.rootPin, "dev", fixtureTime); err == nil {
				t.Fatal("unsafe keyset descriptor was accepted")
			}
		})
	}

	rootSeed := sha256.Sum256([]byte("hytch-a10-fixture-online-v1"))
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed[:])
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	rootPin := a9trust.RootPin{KeyID: keyIDForTest(t, rootPublic)}
	copy(rootPin.PublicKey[:], rootPublic)
	collapsed := mutateKeyset(t, harness.keysets.raw, func(keyset map[string]any) {
		keyset["root_signing_key_id"] = rootPin.KeyID
	}, rootSeed[:])
	if _, err := validateKeyset(collapsed, rootPin, "dev", fixtureTime); err == nil {
		t.Fatal("offline root and online A10 key trust domains collapsed")
	}
}

func newHarness(t *testing.T) *handlerHarness {
	t.Helper()
	fixture := readPositiveFixture(t)
	keysetRaw, err := json.Marshal(fixture.Keyset)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := a9trust.ParseRootPin(fixture.RootPublicKeyBase64URL, fixture.RootKeyID)
	if err != nil {
		t.Fatal(err)
	}
	harness := &handlerHarness{
		fixture: fixture,
		keysets: &staticKeysets{raw: keysetRaw},
		replay:  &memoryReplay{used: make(map[string]bool)},
		sink:    &recordingSink{},
	}
	harness.handler, err = NewHandler(Options{
		Enabled: true, Environment: "dev", AllowedTopic: "com.mobileflow.hytchdev",
		RootPin: pin, Keysets: harness.keysets, Replay: harness.replay, Sink: harness.sink,
		Clock: func() time.Time { return time.Unix(fixture.FixtureTimeUnix, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return harness
}

func (harness *handlerHarness) body(t *testing.T) []byte {
	t.Helper()
	return decodeB64(t, harness.fixture.RequestBodyBase64URL)
}

func (harness *handlerHarness) serve(t *testing.T, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	result := httptest.NewRecorder()
	harness.handler.ServeHTTP(result, request)
	return result
}

func readPositiveFixture(t *testing.T) fixtureFile {
	t.Helper()
	var fixture fixtureFile
	readFixtureJSON(t, filepath.Join(contractPath(t), "fixtures", "positive.json"), &fixture)
	return fixture
}

func negativeIDs(t *testing.T) []string {
	t.Helper()
	var fixture struct {
		Cases []struct {
			ID string `json:"id"`
		} `json:"cases"`
	}
	readFixtureJSON(t, filepath.Join(contractPath(t), "fixtures", "negative.json"), &fixture)
	ids := make([]string, 0, len(fixture.Cases))
	for _, item := range fixture.Cases {
		ids = append(ids, item.ID)
	}
	if len(ids) != 19 {
		t.Fatal("negative fixture count changed")
	}
	return ids
}

func contractPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve contract path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "contracts", "xmtp_push", "a10_registration", "v1")
}

func readFixtureJSON(t *testing.T, path string, target any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, target) != nil {
		t.Fatalf("cannot read %s", path)
	}
}

func mutateRequest(t *testing.T, body []byte, field string, value any) []byte {
	t.Helper()
	parsed, err := a9trust.ParseStrictJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	request := parsed.(map[string]any)
	request[field] = value
	canonical, err := a9trust.Canonicalize(request)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func bindTokenToBody(t *testing.T, token string, body []byte, claimChanges map[string]any) string {
	t.Helper()
	sum := sha256.Sum256(body)
	if claimChanges == nil {
		claimChanges = make(map[string]any)
	}
	claimChanges["request_sha256"] = hex.EncodeToString(sum[:])
	return mutateToken(t, token, nil, claimChanges)
}

func mutateToken(t *testing.T, token string, headerChanges, claimChanges map[string]any) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("invalid fixture token")
	}
	header := decodeObjectSegment(t, parts[0])
	claims := decodeObjectSegment(t, parts[1])
	for key, value := range headerChanges {
		header[key] = value
	}
	for key, value := range claimChanges {
		claims[key] = value
	}
	headerBytes, err := a9trust.Canonicalize(header)
	if err != nil {
		t.Fatal(err)
	}
	claimBytes, err := a9trust.Canonicalize(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := b64(headerBytes) + "." + b64(claimBytes)
	seed := sha256.Sum256([]byte("hytch-a10-fixture-online-v1"))
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), []byte(input))
	return input + "." + b64(signature)
}

func mutateKeysetUse(t *testing.T, raw []byte, use string) []byte {
	t.Helper()
	parsed, err := a9trust.ParseStrictJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	keyset := parsed.(map[string]any)
	keys := keyset["keys"].([]any)
	keys[0].(map[string]any)["use"] = use
	delete(keyset, "root_signature_base64url")
	canonical, err := a9trust.Canonicalize(keyset)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("hytch-a10-fixture-root-v1"))
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), append([]byte(keysetDomain), canonical...))
	keyset["root_signature_base64url"] = b64(signature)
	result, err := a9trust.Canonicalize(keyset)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mutateKeyset(t *testing.T, raw []byte, mutate func(map[string]any), rootSeed []byte) []byte {
	t.Helper()
	parsed, err := a9trust.ParseStrictJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	keyset := parsed.(map[string]any)
	mutate(keyset)
	delete(keyset, "root_signature_base64url")
	canonical, err := a9trust.Canonicalize(keyset)
	if err != nil {
		t.Fatal(err)
	}
	if rootSeed == nil {
		seed := sha256.Sum256([]byte("hytch-a10-fixture-root-v1"))
		rootSeed = seed[:]
	}
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(rootSeed), append([]byte(keysetDomain), canonical...))
	keyset["root_signature_base64url"] = b64(signature)
	result, err := a9trust.Canonicalize(keyset)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func keyIDForTest(t *testing.T, public []byte) string {
	t.Helper()
	keyID, err := a9trust.Ed25519KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return keyID
}

func corruptSignature(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	signature := decodeB64(t, parts[2])
	signature[0] ^= 1
	return parts[0] + "." + parts[1] + "." + b64(signature)
}

func decodeObjectSegment(t *testing.T, segment string) map[string]any {
	t.Helper()
	parsed, err := a9trust.ParseStrictJSON(decodeB64(t, segment))
	if err != nil {
		t.Fatal(err)
	}
	return parsed.(map[string]any)
}

func decodeB64(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func b64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
