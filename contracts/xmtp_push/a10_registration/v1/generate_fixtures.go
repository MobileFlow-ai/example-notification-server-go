//go:build ignore

// Generate the deterministic A10 registration fixture. This is not runtime
// code and intentionally uses fixed test seeds and tokens.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

const fixtureNow int64 = 1786300200

func main() {
	rootSeed := sha256.Sum256([]byte("hytch-a10-fixture-root-v1"))
	signerSeed := sha256.Sum256([]byte("hytch-a10-fixture-online-v1"))
	rootKey := ed25519.NewKeyFromSeed(rootSeed[:])
	signerKey := ed25519.NewKeyFromSeed(signerSeed[:])
	rootPublic := rootKey.Public().(ed25519.PublicKey)
	signerPublic := signerKey.Public().(ed25519.PublicKey)
	rootID := keyID(rootPublic)
	signerID := keyID(signerPublic)

	request := map[string]any{
		"apns_token_base64url":      b64(bytes32("fixture-apns-token")),
		"apns_topic":                "com.mobileflow.hytchdev",
		"environment":               "dev",
		"installation_binding_id":   b64(bytes16("fixture-installation-binding")),
		"installation_id_base64url": b64(bytes32("fixture-xmtp-installation")),
		"owner_binding":             b64(bytes32("fixture-owner-binding")),
		"payload_schema":            "xmtp.encrypted.v4",
		"protocol":                  "hytch.xmtp-push.registration-request",
		"schema_version":            1,
	}
	body := mustJSON(request)
	tokenHash := sha256.Sum256(bytes32("fixture-apns-token"))
	bodyHash := sha256.Sum256(body)
	claims := map[string]any{
		"apns_token_sha256":         hex.EncodeToString(tokenHash[:]),
		"apns_topic":                request["apns_topic"],
		"aud":                       "hytch.xmtp-push-bridge.registration.v1",
		"environment":               request["environment"],
		"exp":                       fixtureNow + 60,
		"iat":                       fixtureNow,
		"installation_binding_id":   request["installation_binding_id"],
		"installation_id_base64url": request["installation_id_base64url"],
		"iss":                       "hytch-modern-api",
		"jti":                       "a10a10a1-0810-4a10-8a10-a10a10a10a10",
		"method":                    "PUT",
		"nbf":                       fixtureNow - 1,
		"owner_binding":             request["owner_binding"],
		"path":                      "/v1/xmtp-push/installations:register",
		"request_sha256":            hex.EncodeToString(bodyHash[:]),
		"sub":                       "xmtp-push-registration",
	}
	header := map[string]any{"alg": "EdDSA", "kid": signerID, "typ": "JWT"}
	token := compact(header, claims, signerKey)

	keyset := map[string]any{
		"environment": "dev", "expires_at": "2026-08-09T19:00:00.000Z",
		"issued_at": "2026-08-09T18:00:00.000Z", "keyset_sequence": 1,
		"keys": []any{map[string]any{
			"key_id": signerID, "not_after": "2026-08-16T18:00:00.000Z",
			"not_before": "2026-08-08T18:00:00.000Z", "public_key_base64url": b64(signerPublic),
			"state": "SIGN", "use": "A10_REGISTRATION",
		}},
		"protocol": "hytch.xmtp-push.registration-keyset", "root_signature_algorithm": "Ed25519",
		"root_signing_key_id": rootID, "schema_version": 1,
	}
	keysetSignature := ed25519.Sign(rootKey, append([]byte("Hytch A10 registration keyset v1\x00"), mustJSON(keyset)...))
	keyset["root_signature_base64url"] = b64(keysetSignature)

	fixture := map[string]any{
		"fixture_time_unix":         fixtureNow,
		"root_public_key_base64url": b64(rootPublic),
		"root_key_id":               rootID,
		"keyset":                    keyset,
		"request_body_base64url":    b64(body),
		"request":                   request,
		"credential":                token,
		"expected_status":           204,
		"expected_body":             "",
	}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		panic(err)
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile("fixtures/positive.json", encoded, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote fixtures/positive.json")
}

func compact(header, claims map[string]any, key ed25519.PrivateKey) string {
	input := b64(mustJSON(header)) + "." + b64(mustJSON(claims))
	return input + "." + b64(ed25519.Sign(key, []byte(input)))
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func bytes16(label string) []byte { sum := sha256.Sum256([]byte(label)); return sum[:16] }
func bytes32(label string) []byte { sum := sha256.Sum256([]byte(label)); return sum[:] }
func b64(value []byte) string     { return base64.RawURLEncoding.EncodeToString(value) }
func keyID(value []byte) string {
	sum := sha256.Sum256(value)
	return "ed25519-sha256:" + hex.EncodeToString(sum[:])
}
