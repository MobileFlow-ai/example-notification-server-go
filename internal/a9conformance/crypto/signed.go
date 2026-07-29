package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	AssertionSignatureDomain = []byte("Hytch A9 bridge assertion v1\x00")
	ControlSignatureDomain   = []byte("Hytch A9 bridge control v1\x00")
	WatermarkSignatureDomain = []byte("Hytch A9 bridge control watermark v1\x00")
	KeysetSignatureDomain    = []byte("Hytch A9 bridge keyset v1\x00")
)

// SignedTranscript returns the canonical unsigned object and the exact
// domain-separated signing input.
func SignedTranscript(object map[string]any, signatureField string, domain []byte) ([]byte, []byte, error) {
	if _, exists := object[signatureField]; !exists {
		return nil, nil, fmt.Errorf("missing %s", signatureField)
	}
	unsigned := cloneObject(object)
	delete(unsigned, signatureField)
	canonical, err := Canonicalize(unsigned)
	if err != nil {
		return nil, nil, err
	}
	input := make([]byte, 0, len(domain)+len(canonical))
	input = append(input, domain...)
	input = append(input, canonical...)
	return canonical, input, nil
}

func SignObject(object map[string]any, signatureField string, domain, seed []byte) (string, error) {
	_, input, err := SignedTranscript(object, signatureField, domain)
	if err != nil {
		return "", err
	}
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("Ed25519 seed length is %d", len(seed))
	}
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), input)
	return EncodeBase64URL(signature), nil
}

func VerifyObject(object map[string]any, signatureField string, domain, publicKey []byte) Verdict {
	if len(publicKey) != ed25519.PublicKeySize {
		return Invalid("KEY_STATE")
	}
	encoded, ok := object[signatureField].(string)
	if !ok {
		return Invalid("FIELD_DOMAIN")
	}
	signature, err := DecodeBase64URL(encoded, ed25519.SignatureSize)
	if err != nil {
		return Invalid("NONCANONICAL_BASE64URL")
	}
	_, input, err := SignedTranscript(object, signatureField, domain)
	if err != nil {
		return Invalid("FIELD_DOMAIN")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), input, signature) {
		return Invalid("BAD_SIGNATURE")
	}
	return Eligible()
}

func CanonicalObjectHash(object map[string]any) (string, error) {
	canonical, err := Canonicalize(object)
	if err != nil {
		return "", err
	}
	return SHA256LowerHex(canonical), nil
}

func AssertionHash(object map[string]any) (string, error) {
	canonical, err := Canonicalize(object)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return EncodeBase64URL(sum[:]), nil
}

// ValidateStrictJSON classifies duplicate keys and the v1 numeric profile
// using the terminal/reason vocabulary from the contract.
func ValidateStrictJSON(raw []byte) (any, Verdict) {
	value, err := ParseStrictJSON(raw)
	if err != nil {
		if errors.Is(err, ErrDuplicateKey) {
			return nil, Invalid("DUPLICATE_KEY")
		}
		return nil, Invalid("FIELD_DOMAIN")
	}
	if _, err := Canonicalize(value); err != nil {
		if containsNonIntegerNumber(value) {
			return nil, Invalid("NON_IJSON_NUMBER")
		}
		if containsOutOfRangeInteger(value) {
			return nil, Invalid("INTEGER_RANGE")
		}
		return nil, Invalid("FIELD_DOMAIN")
	}
	return value, Eligible()
}

func containsNonIntegerNumber(value any) bool {
	switch v := value.(type) {
	case json.Number:
		return strings.ContainsAny(string(v), ".eE+-") || string(v) == "-0"
	case []any:
		for _, child := range v {
			if containsNonIntegerNumber(child) {
				return true
			}
		}
	case map[string]any:
		for _, child := range v {
			if containsNonIntegerNumber(child) {
				return true
			}
		}
	}
	return false
}

func containsOutOfRangeInteger(value any) bool {
	switch v := value.(type) {
	case json.Number:
		raw := string(v)
		if strings.ContainsAny(raw, ".eE+-") {
			return false
		}
		n, err := strconv.ParseUint(raw, 10, 64)
		return err != nil || n > maxIJSONInteger
	case []any:
		for _, child := range v {
			if containsOutOfRangeInteger(child) {
				return true
			}
		}
	case map[string]any:
		for _, child := range v {
			if containsOutOfRangeInteger(child) {
				return true
			}
		}
	}
	return false
}

// AssertionExpectations supplies the values the bridge learned through
// independent trusted channels.
type AssertionExpectations struct {
	Environment           string
	InstallationBindingID string
	RosterCommitment      string
	TupleCommitment       string
	TopicBinding          string
	TopicKeyEpoch         uint32
	EvaluationTime        time.Time
	Keyset                map[string]any
}

var assertionFields = map[string]struct{}{
	"protocol": {}, "schema_version": {}, "audience": {}, "purpose": {},
	"environment": {}, "binding_id": {}, "installation_binding_id": {},
	"lease_id": {}, "binding_version": {}, "stream_sequence": {},
	"tuple_commitment": {}, "tuple_commitment_key_id": {},
	"roster_commitment": {}, "roster_commitment_key_id": {},
	"topic_binding": {}, "topic_key_epoch": {}, "conversation_generation": {},
	"roster_version": {}, "state": {}, "issued_at": {}, "expires_at": {},
	"signing_key_id": {}, "signature_algorithm": {}, "signature_base64url": {},
}

// ValidateAssertion validates the cryptographic and transcript-binding portion
// of an assertion. Authority state-machine checks deliberately remain outside
// this package.
func ValidateAssertion(object map[string]any, expected AssertionExpectations) Verdict {
	if _, forbidden := object["roster_digest"]; forbidden {
		return Invalid("UNKNOWN_FIELD_RAW_ROSTER_FORBIDDEN")
	}
	if len(object) != len(assertionFields) {
		return Invalid("FIELD_DOMAIN")
	}
	for name := range object {
		if _, ok := assertionFields[name]; !ok {
			return Invalid("FIELD_DOMAIN")
		}
	}
	if objectString(object, "protocol") != "hytch.a9-bridge-assertion" ||
		!objectIntegerEquals(object, "schema_version", 1) ||
		objectString(object, "state") != "ACTIVE" ||
		objectString(object, "signature_algorithm") != "Ed25519" {
		return Invalid("FIELD_DOMAIN")
	}
	if objectString(object, "audience") != "hytch.xmtp-push-bridge.a9-control" {
		return Invalid("WRONG_AUDIENCE")
	}
	if objectString(object, "purpose") != "conversation_message_push" {
		if strings.Contains(strings.ToLower(objectString(object, "purpose")), "welcome") {
			return Invalid("WELCOME_CLOSED")
		}
		return Invalid("FIELD_DOMAIN")
	}
	environment := objectString(object, "environment")
	if environment != "dev" && environment != "production" {
		return Invalid("FIELD_DOMAIN")
	}
	if expected.Environment != "" && environment != expected.Environment {
		return Invalid("FIELD_DOMAIN")
	}

	for _, field := range []string{"binding_version", "stream_sequence", "topic_key_epoch", "conversation_generation", "roster_version"} {
		n, classification := positiveInteger(object[field])
		if !classification.IsEligible() {
			return classification
		}
		if (field == "topic_key_epoch" && n > uint64(^uint32(0))) ||
			((field == "conversation_generation" || field == "roster_version") && n > uint64(^uint32(0)>>1)) {
			return Invalid("INTEGER_RANGE")
		}
	}
	for _, field := range []struct {
		name   string
		length int
	}{
		{"binding_id", 16}, {"installation_binding_id", 16}, {"lease_id", 16},
		{"tuple_commitment", 32}, {"roster_commitment", 32}, {"topic_binding", 32},
		{"signature_base64url", 64},
	} {
		value, ok := object[field.name].(string)
		if !ok {
			return Invalid("FIELD_DOMAIN")
		}
		if _, err := DecodeBase64URL(value, field.length); err != nil {
			return Invalid("NONCANONICAL_BASE64URL")
		}
	}
	for _, field := range []struct {
		name, prefix string
	}{
		{"signing_key_id", "ed25519-sha256:"},
		{"tuple_commitment_key_id", "hmac-sha256:"},
		{"roster_commitment_key_id", "hmac-sha256:"},
	} {
		value := objectString(object, field.name)
		if !strings.HasPrefix(value, field.prefix) ||
			!lowerHex64Pattern.MatchString(strings.TrimPrefix(value, field.prefix)) {
			return Invalid("FIELD_DOMAIN")
		}
	}

	issued, ok := parseWireTime(objectString(object, "issued_at"))
	if !ok {
		return Invalid("NONCANONICAL_TIME")
	}
	expires, ok := parseWireTime(objectString(object, "expires_at"))
	if !ok {
		return Invalid("NONCANONICAL_TIME")
	}
	if !expires.After(issued) || expires.Sub(issued) > 30*time.Second {
		return Invalid("FIELD_DOMAIN")
	}
	if !expected.EvaluationTime.IsZero() && !expected.EvaluationTime.Before(expires) {
		return Invalid("EXPIRED")
	}
	if expected.InstallationBindingID != "" &&
		objectString(object, "installation_binding_id") != expected.InstallationBindingID {
		return Invalid("INSTALLATION_MISMATCH")
	}
	if expected.RosterCommitment != "" &&
		!constantTimeStringEqual(objectString(object, "roster_commitment"), expected.RosterCommitment) {
		return Invalid("ROSTER_COMMITMENT_MISMATCH")
	}
	if expected.TupleCommitment != "" &&
		!constantTimeStringEqual(objectString(object, "tuple_commitment"), expected.TupleCommitment) {
		return Invalid("TUPLE_COMMITMENT_MISMATCH")
	}
	if expected.TopicBinding != "" &&
		!constantTimeStringEqual(objectString(object, "topic_binding"), expected.TopicBinding) {
		return Invalid("TOPIC_BINDING_MISMATCH")
	}
	topicEpoch, _ := positiveInteger(object["topic_key_epoch"])
	if expected.TopicKeyEpoch != 0 && topicEpoch != uint64(expected.TopicKeyEpoch) {
		return Invalid("TOPIC_KEY_EPOCH")
	}
	if topicEpoch != uint64(TopicEpoch(issued)) {
		return Invalid("TOPIC_KEY_EPOCH")
	}

	if expected.Keyset == nil {
		return Invalid("KEY_STATE")
	}
	publicKey, verdict := OnlineKeyAt(expected.Keyset, objectString(object, "signing_key_id"), "A9_CONTROL", issued)
	if !verdict.IsEligible() {
		return verdict
	}
	return VerifyObject(object, "signature_base64url", AssertionSignatureDomain, publicKey)
}

func objectString(object map[string]any, field string) string {
	value, _ := object[field].(string)
	return value
}

func objectIntegerEquals(object map[string]any, field string, expected uint64) bool {
	value, verdict := nonnegativeInteger(object[field])
	return verdict.IsEligible() && value == expected
}

func positiveInteger(value any) (uint64, Verdict) {
	n, verdict := nonnegativeInteger(value)
	if !verdict.IsEligible() {
		return 0, verdict
	}
	if n == 0 {
		return 0, Invalid("INTEGER_RANGE")
	}
	return n, Eligible()
}

func nonnegativeInteger(value any) (uint64, Verdict) {
	var raw string
	switch v := value.(type) {
	case json.Number:
		raw = string(v)
	case uint32:
		return uint64(v), Eligible()
	case uint64:
		if v > maxIJSONInteger {
			return 0, Invalid("INTEGER_RANGE")
		}
		return v, Eligible()
	case int:
		if v < 0 {
			return 0, Invalid("INTEGER_RANGE")
		}
		raw = strconv.Itoa(v)
	case int64:
		if v < 0 {
			return 0, Invalid("INTEGER_RANGE")
		}
		raw = strconv.FormatInt(v, 10)
	case float32, float64:
		return 0, Invalid("NON_IJSON_NUMBER")
	default:
		return 0, Invalid("FIELD_DOMAIN")
	}
	if strings.ContainsAny(raw, ".eE+-") || raw == "-0" {
		return 0, Invalid("NON_IJSON_NUMBER")
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n > maxIJSONInteger {
		return 0, Invalid("INTEGER_RANGE")
	}
	return n, Eligible()
}

func parseWireTime(value string) (time.Time, bool) {
	if len(value) != len("2006-01-02T15:04:05.000Z") {
		return time.Time{}, false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil || parsed.Format("2006-01-02T15:04:05.000Z") != value {
		return time.Time{}, false
	}
	return parsed, true
}

func constantTimeStringEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
