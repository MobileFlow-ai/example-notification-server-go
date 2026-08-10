// Package a10registration implements the dormant authenticated installation
// registration boundary. It never owns APNS egress.
package a10registration

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

const (
	Path              = "/v1/xmtp-push/installations:register"
	Audience          = "hytch.xmtp-push-bridge.registration.v1"
	KeyUse            = "A10_REGISTRATION"
	keysetProtocol    = "hytch.xmtp-push.registration-keyset"
	requestProtocol   = "hytch.xmtp-push.registration-request"
	keysetDomain      = "Hytch A10 registration keyset v1\x00"
	maxBodyBytes      = 8 * 1024
	maxCredentialSize = 8 * 1024
	minAPNSTokenBytes = 1
	maxAPNSTokenBytes = 256
)

var (
	ErrUnauthorized = errors.New("a10 registration unauthorized")
	ErrReplay       = errors.New("a10 registration replay")
	ErrUnavailable  = errors.New("a10 registration unavailable")
	keyIDPattern    = regexp.MustCompile(`^ed25519-sha256:[0-9a-f]{64}$`)
)

type KeysetSource interface {
	// CurrentA10Keyset returns the exact root-signed bytes only after its
	// implementation has proved durable high-water currentness. A rollback,
	// equal-sequence conflict, or storage ambiguity must return an error.
	CurrentA10Keyset(context.Context) ([]byte, error)
}

type ReplayStore interface {
	ConsumeA10Registration(
		context.Context,
		string,
		string,
		time.Time,
		time.Time,
	) (bool, error)
}

// Sink receives a fully verified registration. Production wiring must use an
// encrypted-vault implementation. This package deliberately has no APNS
// delivery dependency.
type Sink interface {
	RegisterVerified(context.Context, VerifiedRegistration) error
}

type VerifiedRegistration struct {
	Environment           string
	InstallationID        [32]byte
	InstallationBindingID [16]byte
	OwnerBinding          [32]byte
	APNSToken             OpaqueAPNSToken
	APNSTopic             string
	PayloadSchema         string
}

// OpaqueAPNSToken preserves APNs' variable-length token contract without
// exposing mutable handler-owned storage to a sink implementation.
type OpaqueAPNSToken struct {
	value []byte
}

func (token OpaqueAPNSToken) Bytes() []byte {
	return append([]byte(nil), token.value...)
}

func (token OpaqueAPNSToken) Len() int {
	return len(token.value)
}

type Options struct {
	Enabled      bool
	Environment  string
	AllowedTopic string
	RootPin      a9trust.RootPin
	Keysets      KeysetSource
	Replay       ReplayStore
	Sink         Sink
	Clock        func() time.Time
}

type Handler struct {
	enabled      bool
	environment  string
	allowedTopic string
	rootPin      a9trust.RootPin
	keysets      KeysetSource
	replay       ReplayStore
	sink         Sink
	clock        func() time.Time
}

func NewHandler(options Options) (*Handler, error) {
	if !options.Enabled {
		return &Handler{enabled: false}, nil
	}
	expectedTopic := map[string]string{
		"dev":        "com.mobileflow.hytchdev",
		"production": "com.hytch.rewards",
	}[options.Environment]
	if (options.Environment != "dev" && options.Environment != "production") ||
		options.AllowedTopic != expectedTopic || options.RootPin.KeyID == "" ||
		options.Keysets == nil || options.Replay == nil || options.Sink == nil {
		return nil, ErrUnavailable
	}
	recomputed, err := a9trust.Ed25519KeyID(options.RootPin.PublicKey[:])
	if err != nil || recomputed != options.RootPin.KeyID {
		return nil, ErrUnavailable
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Handler{
		enabled: true, environment: options.Environment,
		allowedTopic: options.AllowedTopic, rootPin: options.RootPin,
		keysets: options.Keysets, replay: options.Replay, sink: options.Sink,
		clock: clock,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if handler == nil || !handler.enabled {
		writeFixed(writer, http.StatusNotFound, "not_found")
		return
	}
	if request.Method != http.MethodPut || request.URL.Path != Path ||
		request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.URL.Fragment != "" {
		writeFixed(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxBodyBytes {
		writeFixed(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	compact, ok := bearer(request.Header.Get("Authorization"))
	if !ok {
		writeFixed(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	now := handler.clock().UTC()
	rawKeyset, err := handler.keysets.CurrentA10Keyset(request.Context())
	if err != nil {
		writeFixed(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	keyset, err := validateKeyset(rawKeyset, handler.rootPin, handler.environment, now)
	if err != nil {
		writeFixed(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	claims, err := verifyCredential(compact, body, handler.environment, now, keyset)
	if err != nil {
		writeFixed(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	registration, err := parseRegistration(body, claims, handler.environment, handler.allowedTopic)
	if err != nil {
		writeFixed(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	consumed, err := handler.replay.ConsumeA10Registration(
		request.Context(), claims.environment, claims.jti,
		claims.expiresAt.Add(5*time.Second), now,
	)
	if err != nil {
		writeFixed(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if !consumed {
		writeFixed(writer, http.StatusConflict, "replay")
		return
	}
	if err = handler.sink.RegisterVerified(request.Context(), registration); err != nil {
		writeFixed(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type verifiedClaims struct {
	environment           string
	jti                   string
	expiresAt             time.Time
	installationID        string
	installationBindingID string
	ownerBinding          string
	apnsTokenHash         string
	apnsTopic             string
}

func verifyCredential(compact string, body []byte, environment string, now time.Time, keyset map[string]any) (verifiedClaims, error) {
	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		return verifiedClaims{}, ErrUnauthorized
	}
	header, ok := canonicalObjectSegment(segments[0])
	if !ok || !exactFields(header, "alg", "kid", "typ") ||
		stringField(header, "alg") != "EdDSA" || stringField(header, "typ") != "JWT" {
		return verifiedClaims{}, ErrUnauthorized
	}
	claims, ok := canonicalObjectSegment(segments[1])
	if !ok || !exactFields(claims,
		"apns_token_sha256", "apns_topic", "aud", "environment", "exp", "iat",
		"installation_binding_id", "installation_id_base64url", "iss", "jti",
		"method", "nbf", "owner_binding", "path", "request_sha256", "sub") {
		return verifiedClaims{}, ErrUnauthorized
	}
	if stringField(claims, "iss") != "hytch-modern-api" ||
		stringField(claims, "sub") != "xmtp-push-registration" ||
		stringField(claims, "aud") != Audience ||
		stringField(claims, "environment") != environment ||
		stringField(claims, "method") != http.MethodPut ||
		stringField(claims, "path") != Path {
		return verifiedClaims{}, ErrUnauthorized
	}
	jti := stringField(claims, "jti")
	if _, err := a9trust.ParseCanonicalUUID(jti); err != nil {
		return verifiedClaims{}, ErrUnauthorized
	}
	bodyHash := sha256.Sum256(body)
	if !constantEqual(stringField(claims, "request_sha256"), hex.EncodeToString(bodyHash[:])) {
		return verifiedClaims{}, ErrUnauthorized
	}
	iat, ok := uintField(claims, "iat")
	if !ok {
		return verifiedClaims{}, ErrUnauthorized
	}
	nbf, ok := uintField(claims, "nbf")
	if !ok {
		return verifiedClaims{}, ErrUnauthorized
	}
	exp, ok := uintField(claims, "exp")
	if !ok || exp <= iat || exp-iat > 60 || nbf > iat || nbf+5 < iat {
		return verifiedClaims{}, ErrUnauthorized
	}
	issuedAt := time.Unix(int64(iat), 0).UTC()
	notBefore := time.Unix(int64(nbf), 0).UTC()
	expiresAt := time.Unix(int64(exp), 0).UTC()
	if now.Before(issuedAt.Add(-5*time.Second)) || now.Before(notBefore.Add(-5*time.Second)) || now.After(expiresAt.Add(5*time.Second)) {
		return verifiedClaims{}, ErrUnauthorized
	}
	kid := stringField(header, "kid")
	publicKey, ok := a10KeyAt(keyset, kid, issuedAt)
	if !ok {
		return verifiedClaims{}, ErrUnauthorized
	}
	signature, err := a9trust.DecodeBase64URL(segments[2], ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(publicKey, []byte(segments[0]+"."+segments[1]), signature) {
		return verifiedClaims{}, ErrUnauthorized
	}
	return verifiedClaims{
		environment: environment, jti: jti, expiresAt: expiresAt,
		installationID:        stringField(claims, "installation_id_base64url"),
		installationBindingID: stringField(claims, "installation_binding_id"),
		ownerBinding:          stringField(claims, "owner_binding"),
		apnsTokenHash:         stringField(claims, "apns_token_sha256"),
		apnsTopic:             stringField(claims, "apns_topic"),
	}, nil
}

func parseRegistration(body []byte, claims verifiedClaims, environment, allowedTopic string) (VerifiedRegistration, error) {
	value, err := a9trust.ParseStrictJSON(body)
	request, ok := value.(map[string]any)
	if err != nil || !ok || !exactFields(request,
		"apns_token_base64url", "apns_topic", "environment", "installation_binding_id",
		"installation_id_base64url", "owner_binding", "payload_schema", "protocol", "schema_version") {
		return VerifiedRegistration{}, ErrUnauthorized
	}
	canonical, err := a9trust.Canonicalize(request)
	if err != nil || string(canonical) != string(body) || stringField(request, "protocol") != requestProtocol ||
		!numberEquals(request["schema_version"], 1) || stringField(request, "environment") != environment ||
		stringField(request, "payload_schema") != "xmtp.encrypted.v4" {
		return VerifiedRegistration{}, ErrUnauthorized
	}
	installation, err := a9trust.DecodeBase64URL(stringField(request, "installation_id_base64url"), 32)
	if err != nil || !constantEqual(stringField(request, "installation_id_base64url"), claims.installationID) {
		return VerifiedRegistration{}, ErrUnauthorized
	}
	binding, err := a9trust.DecodeBase64URL(stringField(request, "installation_binding_id"), 16)
	if err != nil || !constantEqual(stringField(request, "installation_binding_id"), claims.installationBindingID) {
		return VerifiedRegistration{}, ErrUnauthorized
	}
	owner, err := a9trust.DecodeBase64URL(stringField(request, "owner_binding"), 32)
	if err != nil || !constantEqual(stringField(request, "owner_binding"), claims.ownerBinding) {
		return VerifiedRegistration{}, ErrUnauthorized
	}
	token, err := decodeOpaqueBase64URL(
		stringField(request, "apns_token_base64url"),
		minAPNSTokenBytes,
		maxAPNSTokenBytes,
	)
	tokenHash := sha256.Sum256(token)
	if err != nil || !constantEqual(hex.EncodeToString(tokenHash[:]), claims.apnsTokenHash) {
		return VerifiedRegistration{}, ErrUnauthorized
	}
	topic := stringField(request, "apns_topic")
	if topic == "" || !constantEqual(topic, claims.apnsTopic) || !constantEqual(topic, allowedTopic) {
		return VerifiedRegistration{}, ErrUnauthorized
	}
	var result VerifiedRegistration
	result.Environment = environment
	copy(result.InstallationID[:], installation)
	copy(result.InstallationBindingID[:], binding)
	copy(result.OwnerBinding[:], owner)
	result.APNSToken = OpaqueAPNSToken{value: append([]byte(nil), token...)}
	result.APNSTopic = topic
	result.PayloadSchema = stringField(request, "payload_schema")
	return result, nil
}

func validateKeyset(raw []byte, pin a9trust.RootPin, environment string, now time.Time) (map[string]any, error) {
	value, err := a9trust.ParseStrictJSON(raw)
	object, ok := value.(map[string]any)
	if err != nil || !ok || !exactFields(object,
		"environment", "expires_at", "issued_at", "keys", "keyset_sequence", "protocol",
		"root_signature_algorithm", "root_signature_base64url", "root_signing_key_id", "schema_version") ||
		stringField(object, "protocol") != keysetProtocol || !numberEquals(object["schema_version"], 1) ||
		stringField(object, "environment") != environment || stringField(object, "root_signature_algorithm") != "Ed25519" ||
		stringField(object, "root_signing_key_id") != pin.KeyID {
		return nil, ErrUnavailable
	}
	issued, ok := wireTime(stringField(object, "issued_at"))
	if !ok {
		return nil, ErrUnavailable
	}
	expires, ok := wireTime(stringField(object, "expires_at"))
	if !ok || !expires.After(issued) || expires.Sub(issued) > 24*time.Hour || now.Before(issued) || !now.Before(expires) {
		return nil, ErrUnavailable
	}
	if sequence, ok := uintField(object, "keyset_sequence"); !ok || sequence == 0 {
		return nil, ErrUnavailable
	}
	keys, ok := object["keys"].([]any)
	if !ok || len(keys) < 1 || len(keys) > 2 {
		return nil, ErrUnavailable
	}
	signCount := 0
	seen := map[string]bool{}
	for _, item := range keys {
		descriptor, ok := item.(map[string]any)
		if !ok || !exactFields(descriptor, "key_id", "not_after", "not_before", "public_key_base64url", "state", "use") ||
			stringField(descriptor, "use") != KeyUse ||
			(stringField(descriptor, "state") != "SIGN" && stringField(descriptor, "state") != "VERIFY_ONLY") {
			return nil, ErrUnavailable
		}
		kid := stringField(descriptor, "key_id")
		public, err := a9trust.DecodeBase64URL(stringField(descriptor, "public_key_base64url"), ed25519.PublicKeySize)
		recomputed, _ := a9trust.Ed25519KeyID(public)
		notBefore, beforeOK := wireTime(stringField(descriptor, "not_before"))
		notAfter, afterOK := wireTime(stringField(descriptor, "not_after"))
		if err != nil || !keyIDPattern.MatchString(kid) || recomputed != kid || seen[kid] || !beforeOK || !afterOK || !notAfter.After(notBefore) {
			return nil, ErrUnavailable
		}
		if subtle.ConstantTimeCompare(public, pin.PublicKey[:]) == 1 ||
			notBefore.After(issued) || notAfter.Before(expires) {
			return nil, ErrUnavailable
		}
		seen[kid] = true
		if stringField(descriptor, "state") == "SIGN" {
			signCount++
		}
	}
	if signCount != 1 {
		return nil, ErrUnavailable
	}
	signature, err := a9trust.DecodeBase64URL(stringField(object, "root_signature_base64url"), ed25519.SignatureSize)
	unsigned := cloneObject(object)
	delete(unsigned, "root_signature_base64url")
	canonical, canonicalErr := a9trust.Canonicalize(unsigned)
	if err != nil || canonicalErr != nil || !ed25519.Verify(pin.PublicKey[:], append([]byte(keysetDomain), canonical...), signature) {
		return nil, ErrUnavailable
	}
	return object, nil
}

func a10KeyAt(keyset map[string]any, kid string, at time.Time) (ed25519.PublicKey, bool) {
	keys, _ := keyset["keys"].([]any)
	for _, item := range keys {
		descriptor, _ := item.(map[string]any)
		if stringField(descriptor, "key_id") != kid || stringField(descriptor, "use") != KeyUse {
			continue
		}
		notBefore, beforeOK := wireTime(stringField(descriptor, "not_before"))
		notAfter, afterOK := wireTime(stringField(descriptor, "not_after"))
		public, err := a9trust.DecodeBase64URL(stringField(descriptor, "public_key_base64url"), ed25519.PublicKeySize)
		if beforeOK && afterOK && err == nil && !at.Before(notBefore) && at.Before(notAfter) {
			return ed25519.PublicKey(public), true
		}
	}
	return nil, false
}

func canonicalObjectSegment(segment string) (map[string]any, bool) {
	raw, err := decodeAnyBase64URL(segment)
	if err != nil {
		return nil, false
	}
	value, err := a9trust.ParseStrictJSON(raw)
	object, ok := value.(map[string]any)
	if err != nil || !ok {
		return nil, false
	}
	canonical, err := a9trust.Canonicalize(object)
	return object, err == nil && a9trust.EncodeBase64URL(canonical) == segment
}

func decodeAnyBase64URL(value string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, ErrUnauthorized
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || a9trust.EncodeBase64URL(raw) != value {
		return nil, ErrUnauthorized
	}
	return raw, nil
}

func decodeOpaqueBase64URL(value string, minimum, maximum int) ([]byte, error) {
	raw, err := decodeAnyBase64URL(value)
	if err != nil || len(raw) < minimum || len(raw) > maximum {
		return nil, ErrUnauthorized
	}
	return raw, nil
}

func bearer(header string) (string, bool) {
	if len(header) <= len("Bearer ") || len(header) > maxCredentialSize+len("Bearer ") || !strings.HasPrefix(header, "Bearer ") {
		return "", false
	}
	compact := strings.TrimPrefix(header, "Bearer ")
	return compact, !strings.ContainsAny(compact, " \t\r\n")
}

func writeFixed(writer http.ResponseWriter, status int, body string) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body)
}

func exactFields(object map[string]any, names ...string) bool {
	if len(object) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return false
		}
	}
	return true
}

func stringField(object map[string]any, name string) string {
	value, _ := object[name].(string)
	return value
}
func uintField(object map[string]any, name string) (uint64, bool) {
	number, ok := object[name].(json.Number)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseUint(string(number), 10, 64)
	return value, err == nil && value <= 9007199254740991
}
func numberEquals(value any, expected uint64) bool {
	number, ok := value.(json.Number)
	return ok && string(number) == strconv.FormatUint(expected, 10)
}
func constantEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
func cloneObject(value map[string]any) map[string]any {
	raw, _ := json.Marshal(value)
	parsed, _ := a9trust.ParseStrictJSON(raw)
	clone, _ := parsed.(map[string]any)
	return clone
}
func wireTime(value string) (time.Time, bool) {
	if len(value) != 24 || !strings.HasSuffix(value, ".000Z") {
		return time.Time{}, false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return parsed.UTC(), err == nil && parsed.UTC().Format("2006-01-02T15:04:05.000Z") == value
}
