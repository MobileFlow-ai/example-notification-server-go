package a10conformance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	wantPositiveSHA256 = "69d6f7e212fc0f8824a212a6ac384ab53cd6d427d20b0500ad1846e8e0cc84a5"
	wantNegativeSHA256 = "3533c8d93737e00fea3790de92de008dc2cec5d09b8e80887991c35520dfaf43"
	wantNegativeCount  = 19
)

type positiveFixture struct {
	FixtureTimeUnix        int64          `json:"fixture_time_unix"`
	RootPublicKeyBase64URL string         `json:"root_public_key_base64url"`
	RootKeyID              string         `json:"root_key_id"`
	Keyset                 map[string]any `json:"keyset"`
	RequestBodyBase64URL   string         `json:"request_body_base64url"`
	Request                map[string]any `json:"request"`
	Credential             string         `json:"credential"`
	ExpectedStatus         int            `json:"expected_status"`
	ExpectedBody           string         `json:"expected_body"`
}

type negativeFixture struct {
	BaseFixture string `json:"base_fixture"`
	Cases       []struct {
		ID             string `json:"id"`
		Mutation       string `json:"mutation"`
		ExpectedStatus int    `json:"expected_status"`
		ExpectedBody   string `json:"expected_body"`
		Guard          string `json:"guard"`
	} `json:"cases"`
}

func TestPositiveFixtureCryptographyAndBindings(t *testing.T) {
	root := contractRoot(t)
	requireDigest(t, filepath.Join(root, "fixtures", "positive.json"), wantPositiveSHA256)
	var fixture positiveFixture
	readJSON(t, filepath.Join(root, "fixtures", "positive.json"), &fixture)
	if fixture.ExpectedStatus != 204 || fixture.ExpectedBody != "" {
		t.Fatal("positive response is not fixed 204 with an empty body")
	}

	body := decodeB64(t, fixture.RequestBodyBase64URL)
	encodedRequest, err := json.Marshal(fixture.Request)
	if err != nil || string(encodedRequest) != string(body) {
		t.Fatal("request body is not the exact deterministic JSON fixture")
	}

	rootPublic := ed25519.PublicKey(decodeB64(t, fixture.RootPublicKeyBase64URL))
	if keyID(rootPublic) != fixture.RootKeyID {
		t.Fatal("root key ID does not bind the root public key")
	}
	rootSignature := decodeB64(t, stringValue(t, fixture.Keyset, "root_signature_base64url"))
	unsignedKeyset := cloneMap(t, fixture.Keyset)
	delete(unsignedKeyset, "root_signature_base64url")
	keysetBytes, err := json.Marshal(unsignedKeyset)
	if err != nil || !ed25519.Verify(rootPublic, append([]byte("Hytch A10 registration keyset v1\x00"), keysetBytes...), rootSignature) {
		t.Fatal("A10 keyset root signature is invalid")
	}

	parts := strings.Split(fixture.Credential, ".")
	if len(parts) != 3 {
		t.Fatal("credential is not a compact JWS")
	}
	var header, claims map[string]any
	decodeJSONB64(t, parts[0], &header)
	decodeJSONB64(t, parts[1], &claims)
	keys, ok := fixture.Keyset["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatal("fixture does not contain exactly one A10 online key")
	}
	descriptor := keys[0].(map[string]any)
	if stringValue(t, descriptor, "use") != "A10_REGISTRATION" ||
		stringValue(t, header, "kid") != stringValue(t, descriptor, "key_id") {
		t.Fatal("credential did not use the distinct A10 key")
	}
	onlinePublic := ed25519.PublicKey(decodeB64(t, stringValue(t, descriptor, "public_key_base64url")))
	if !ed25519.Verify(onlinePublic, []byte(parts[0]+"."+parts[1]), decodeB64(t, parts[2])) {
		t.Fatal("credential signature is invalid")
	}

	bodyHash := sha256.Sum256(body)
	token := decodeB64(t, stringValue(t, fixture.Request, "apns_token_base64url"))
	tokenHash := sha256.Sum256(token)
	bindings := map[string]string{
		"aud":                       "hytch.xmtp-push-bridge.registration.v1",
		"environment":               stringValue(t, fixture.Request, "environment"),
		"installation_binding_id":   stringValue(t, fixture.Request, "installation_binding_id"),
		"installation_id_base64url": stringValue(t, fixture.Request, "installation_id_base64url"),
		"owner_binding":             stringValue(t, fixture.Request, "owner_binding"),
		"apns_token_sha256":         hex.EncodeToString(tokenHash[:]),
		"apns_topic":                stringValue(t, fixture.Request, "apns_topic"),
		"method":                    "PUT",
		"path":                      "/v1/xmtp-push/installations:register",
		"request_sha256":            hex.EncodeToString(bodyHash[:]),
	}
	for field, want := range bindings {
		if stringValue(t, claims, field) != want {
			t.Fatalf("credential binding %s does not match", field)
		}
	}
	if claims["exp"].(float64)-claims["iat"].(float64) != 60 ||
		claims["nbf"].(float64) > claims["iat"].(float64) {
		t.Fatal("credential lifetime bounds are invalid")
	}
}

func TestNegativeFixtureNamesEveryRequiredGuard(t *testing.T) {
	root := contractRoot(t)
	requireDigest(t, filepath.Join(root, "fixtures", "negative.json"), wantNegativeSHA256)
	var fixture negativeFixture
	readJSON(t, filepath.Join(root, "fixtures", "negative.json"), &fixture)
	if fixture.BaseFixture != "positive.json" || len(fixture.Cases) != wantNegativeCount {
		t.Fatal("negative fixture shape or count changed")
	}
	seen := make(map[string]bool, len(fixture.Cases))
	for _, item := range fixture.Cases {
		if item.ID == "" || item.Mutation == "" || item.Guard == "" || seen[item.ID] {
			t.Fatalf("invalid or duplicate negative fixture %q", item.ID)
		}
		seen[item.ID] = true
		if item.ExpectedBody != "unauthorized" && item.ExpectedBody != "replay" && item.ExpectedBody != "unavailable" {
			t.Fatalf("negative fixture %q exposes a non-fixed error", item.ID)
		}
	}
	for _, required := range []string{
		"wrong_environment", "arbitrary_installation", "wrong_installation_binding",
		"wrong_owner_binding", "apns_token_hash_mismatch", "wrong_apns_topic",
		"expired", "replayed", "tampered_body", "wrong_method", "wrong_path",
		"wrong_audience", "bad_signature", "unknown_key", "malformed_jti",
		"lifetime_over_60", "future_nbf", "key_wrong_use", "replay_store_unavailable",
	} {
		if !seen[required] {
			t.Fatalf("required delete-the-guard fixture %q is missing", required)
		}
	}
}

func contractRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve fixture root")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "contracts", "xmtp_push", "a10_registration", "v1")
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, target) != nil {
		t.Fatalf("cannot read fixture %s", path)
	}
}

func requireDigest(t *testing.T, path, want string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(raw)
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("fixture digest changed: %s", path)
	}
}

func decodeB64(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeJSONB64(t *testing.T, value string, target any) {
	t.Helper()
	if json.Unmarshal(decodeB64(t, value), target) != nil {
		t.Fatal("invalid JWS JSON")
	}
}
func stringValue(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, ok := object[key].(string)
	if !ok {
		t.Fatalf("missing string %s", key)
	}
	return value
}
func cloneMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(value)
	var clone map[string]any
	if json.Unmarshal(raw, &clone) != nil {
		t.Fatal("clone failed")
	}
	return clone
}
func keyID(value []byte) string {
	sum := sha256.Sum256(value)
	return "ed25519-sha256:" + hex.EncodeToString(sum[:])
}
