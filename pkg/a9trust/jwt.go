package a9trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	jwtHeaderFields = map[string]struct{}{"alg": {}, "kid": {}, "typ": {}}
	jwtClaimFields  = map[string]struct{}{
		"iss": {}, "sub": {}, "aud": {}, "environment": {}, "iat": {},
		"nbf": {}, "exp": {}, "jti": {}, "method": {}, "path": {},
		"request_sha256": {},
	}
)

// BuildJWT produces the compact EdDSA JWS bytes from independently
// canonicalized protected-header and claims objects.
func BuildJWT(header, claims map[string]any, seed []byte) (compact, signingInput string, err error) {
	if len(seed) != ed25519.SeedSize {
		return "", "", errors.New("invalid Ed25519 seed")
	}
	headerBytes, err := Canonicalize(header)
	if err != nil {
		return "", "", err
	}
	claimBytes, err := Canonicalize(claims)
	if err != nil {
		return "", "", err
	}
	headerSegment := EncodeBase64URL(headerBytes)
	claimsSegment := EncodeBase64URL(claimBytes)
	signingInput = headerSegment + "." + claimsSegment
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(signingInput))
	return signingInput + "." + EncodeBase64URL(signature), signingInput, nil
}

type JWTExpectations struct {
	Environment string
	Method      string
	Path        string
	RequestBody []byte
	Now         time.Time
	Keyset      map[string]any
	Replay      *ReplayStore
}

// VerifiedJWT contains only the fixed service-auth fields needed to consume a
// replay fence after the compact token has been completely verified.
type VerifiedJWT struct {
	Environment string
	JTI         string
	KeyID       string
	IssuedAt    time.Time
	NotBefore   time.Time
	ExpiresAt   time.Time
	RetainUntil time.Time
}

// ValidateJWT verifies exact compact/JCS spelling, claims, request binding,
// Ed25519 signature, online key state, and the time window. It deliberately
// does not consume replay state so a production caller can use a durable,
// cross-replica store before parsing the request schema.
func ValidateJWT(
	compact string,
	expected JWTExpectations,
) (VerifiedJWT, Verdict) {
	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	header, ok := decodeCanonicalJSONObject(segments[0])
	if !ok || !exactFields(header, jwtHeaderFields) ||
		objectString(header, "alg") != "EdDSA" ||
		objectString(header, "typ") != "JWT" {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	claims, ok := decodeCanonicalJSONObject(segments[1])
	if !ok || !exactFields(claims, jwtClaimFields) {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	signature, err := DecodeBase64URL(segments[2], ed25519.SignatureSize)
	if err != nil {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	if objectString(claims, "iss") != "hytch-modern-api" ||
		objectString(claims, "sub") != "xmtp-push-a9-adapter" ||
		objectString(claims, "aud") != "hytch.xmtp-push-bridge.a9-control" ||
		objectString(claims, "environment") != expected.Environment {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	jti := objectString(claims, "jti")
	if _, err := ParseCanonicalUUID(jti); err != nil {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	method := objectString(claims, "method")
	path := objectString(claims, "path")
	if method == "" || method != strings.ToUpper(method) || method != expected.Method ||
		path == "" || strings.ContainsAny(path, "?#") || path != expected.Path {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	requestHash := objectString(claims, "request_sha256")
	sum := sha256.Sum256(expected.RequestBody)
	if !IsLowerHexSHA256(requestHash) ||
		!constantTimeStringEqual(requestHash, hex.EncodeToString(sum[:])) {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	iat, verdict := nonnegativeInteger(claims["iat"])
	if !verdict.IsEligible() {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	nbf, verdict := nonnegativeInteger(claims["nbf"])
	if !verdict.IsEligible() {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	exp, verdict := nonnegativeInteger(claims["exp"])
	if !verdict.IsEligible() || exp <= iat || exp-iat > 60 ||
		nbf > iat || nbf+5 < iat {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	issuedAt := time.Unix(int64(iat), 0).UTC()
	notBefore := time.Unix(int64(nbf), 0).UTC()
	retainUntil := time.Unix(int64(exp)+5, 0).UTC()
	now := expected.Now.UTC()
	if now.Before(issuedAt.Add(-5*time.Second)) ||
		now.Before(notBefore.Add(-5*time.Second)) ||
		now.After(retainUntil) {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	if expected.Keyset == nil {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	kid := objectString(header, "kid")
	publicKey, keyVerdict := OnlineKeyAt(
		expected.Keyset,
		kid,
		"SERVICE_AUTH",
		issuedAt,
	)
	if !keyVerdict.IsEligible() {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	signingInput := segments[0] + "." + segments[1]
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(signingInput), signature) {
		return VerifiedJWT{}, Invalid("SERVICE_AUTH")
	}
	return VerifiedJWT{
		Environment: expected.Environment,
		JTI:         jti,
		KeyID:       kid,
		IssuedAt:    issuedAt,
		NotBefore:   notBefore,
		ExpiresAt:   time.Unix(int64(exp), 0).UTC(),
		RetainUntil: retainUntil,
	}, Eligible()
}

// VerifyJWT retains the in-process replay model used by the published
// conformance vectors. Runtime authentication must use a durable replay store
// through pkg/a9auth instead.
func VerifyJWT(compact string, expected JWTExpectations) Verdict {
	verified, verdict := ValidateJWT(compact, expected)
	if !verdict.IsEligible() {
		return verdict
	}
	if expected.Replay == nil ||
		!expected.Replay.Consume(
			verified.Environment,
			verified.JTI,
			verified.RetainUntil,
			expected.Now,
		) {
		return Invalid("SERVICE_AUTH_REPLAY")
	}
	return Eligible()
}

func decodeCanonicalJSONObject(segment string) (map[string]any, bool) {
	decoded, err := decodeBase64URLAny(segment)
	if err != nil {
		return nil, false
	}
	value, err := ParseStrictJSON(decoded)
	if err != nil {
		return nil, false
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	canonical, err := Canonicalize(object)
	if err != nil || EncodeBase64URL(canonical) != segment {
		return nil, false
	}
	return object, true
}

func decodeBase64URLAny(value string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("non-canonical Base64url")
	}
	for i := range value {
		if !isBase64URLByte(value[i]) {
			return nil, errors.New("non-canonical Base64url")
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || EncodeBase64URL(decoded) != value {
		return nil, errors.New("non-canonical Base64url")
	}
	return decoded, nil
}

func exactFields(object map[string]any, allowed map[string]struct{}) bool {
	if len(object) != len(allowed) {
		return false
	}
	for name := range object {
		if _, ok := allowed[name]; !ok {
			return false
		}
	}
	return true
}

// ReplayStore is an in-process model of the contract's atomic
// (environment,jti) consume operation.
type ReplayStore struct {
	mu   sync.Mutex
	used map[string]time.Time
}

func NewReplayStore() *ReplayStore {
	return &ReplayStore{used: make(map[string]time.Time)}
}

func (store *ReplayStore) Consume(environment, jti string, retainUntil, now time.Time) bool {
	if store == nil {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
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
		return false
	}
	store.used[key] = retainUntil
	return true
}
