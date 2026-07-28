package authority

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const (
	receiveCapabilityDomain = "Hytch safety receive capability v1\x00"
	maxCapabilityFieldBytes = 256
	maxIJSONSafeInteger     = uint64(1<<53 - 1)
)

var (
	// ErrCapabilityInvalid is intentionally content-free so callers cannot copy
	// sensitive capability fields into logs, traces, or HTTP responses.
	ErrCapabilityInvalid = errors.New("receive capability invalid")
	// ErrCapabilityExpired is a fixed operational class, not a detailed error.
	ErrCapabilityExpired = errors.New("receive capability expired")
	// ErrCapabilityKeyState covers an unknown signing key or algorithm.
	ErrCapabilityKeyState = errors.New("receive capability key state invalid")
)

type PushMode string

const (
	PushModeAlertAllowed PushMode = "alert_allowed"
	PushModeSuppressed   PushMode = "suppressed"
)

// ReceiveCapabilityV1 is the signed Gate-6 authority carried inside the Gate-8
// encrypted wrapper. String encodings are deliberately explicit so the bridge
// can verify an exact byte contract shared with modern-api and iOS.
type ReceiveCapabilityV1 struct {
	SchemaVersion            uint32 `json:"schema_version"`
	Environment              string `json:"environment"`
	InstallationID           string `json:"installation_id"`
	AccountIncarnationID     string `json:"account_incarnation_id"`
	PolicyEpoch              uint64 `json:"policy_epoch"`
	TopicDigest              string `json:"topic_digest"`
	AliasDay                 string `json:"alias_day"`
	RouteAlias               string `json:"route_alias"`
	ConversationGrantVersion uint64 `json:"conversation_grant_version"`
	RosterVersion            uint64 `json:"roster_version"`
	// ExpectedConversationCommitment is optional for an ordinary conversation
	// route. A Welcome route requires a nonempty value that exactly matches its
	// independently signed Welcome authorization.
	ExpectedConversationCommitment string   `json:"expected_conversation_commitment"`
	PushMode                       PushMode `json:"push_mode"`
	IssuedAt                       string   `json:"issued_at"`
	ExpiresAt                      string   `json:"expires_at"`
	Nonce                          string   `json:"nonce"`
	SigningKeyID                   string   `json:"signing_key_id"`
	Algorithm                      string   `json:"algorithm"`
	Signature                      string   `json:"signature"`
}

type VerifyOptions struct {
	Now                            time.Time
	MaxTTL                         time.Duration
	ExpectedEnvironment            string
	ExpectedInstallationID         string
	ExpectedAccountIncarnationID   string
	ExpectedTopicDigest            string
	ExpectedConversationCommitment string
}

// EffectivePushMode implements Gate 6's fail-closed rule: absent and unknown
// values are suppressed rather than rejected into a permissive fallback.
func (c ReceiveCapabilityV1) EffectivePushMode() PushMode {
	if c.PushMode == PushModeAlertAllowed {
		return PushModeAlertAllowed
	}
	return PushModeSuppressed
}

// SigningBytes returns the strict canonical subset used by this protocol.
// Fields are declared in RFC 8785 lexicographic key order. All accepted strings
// are bounded ASCII and all numbers are unsigned integers, so encoding/json's
// representation is the RFC 8785 representation for this deliberately narrow
// schema.
func (c ReceiveCapabilityV1) SigningBytes() ([]byte, error) {
	if !validCapabilityCanonicalIntegers(c) {
		return nil, ErrCapabilityInvalid
	}
	unsigned := struct {
		AccountIncarnationID           string   `json:"account_incarnation_id"`
		Algorithm                      string   `json:"algorithm"`
		AliasDay                       string   `json:"alias_day"`
		ConversationGrantVersion       uint64   `json:"conversation_grant_version"`
		Environment                    string   `json:"environment"`
		ExpectedConversationCommitment string   `json:"expected_conversation_commitment"`
		ExpiresAt                      string   `json:"expires_at"`
		InstallationID                 string   `json:"installation_id"`
		IssuedAt                       string   `json:"issued_at"`
		Nonce                          string   `json:"nonce"`
		PolicyEpoch                    uint64   `json:"policy_epoch"`
		PushMode                       PushMode `json:"push_mode"`
		RosterVersion                  uint64   `json:"roster_version"`
		RouteAlias                     string   `json:"route_alias"`
		SchemaVersion                  uint32   `json:"schema_version"`
		SigningKeyID                   string   `json:"signing_key_id"`
		TopicDigest                    string   `json:"topic_digest"`
	}{
		AccountIncarnationID:           c.AccountIncarnationID,
		Algorithm:                      c.Algorithm,
		AliasDay:                       c.AliasDay,
		ConversationGrantVersion:       c.ConversationGrantVersion,
		Environment:                    c.Environment,
		ExpectedConversationCommitment: c.ExpectedConversationCommitment,
		ExpiresAt:                      c.ExpiresAt,
		InstallationID:                 c.InstallationID,
		IssuedAt:                       c.IssuedAt,
		Nonce:                          c.Nonce,
		PolicyEpoch:                    c.PolicyEpoch,
		PushMode:                       c.PushMode,
		RosterVersion:                  c.RosterVersion,
		RouteAlias:                     c.RouteAlias,
		SchemaVersion:                  c.SchemaVersion,
		SigningKeyID:                   c.SigningKeyID,
		TopicDigest:                    c.TopicDigest,
	}
	body, err := json.Marshal(unsigned)
	if err != nil {
		return nil, ErrCapabilityInvalid
	}
	return append([]byte(receiveCapabilityDomain), body...), nil
}

func VerifyReceiveCapability(
	c ReceiveCapabilityV1,
	keys map[string]ed25519.PublicKey,
	opts VerifyOptions,
) error {
	if !validCapabilityShape(c) {
		return ErrCapabilityInvalid
	}
	if c.Algorithm != "Ed25519" {
		return ErrCapabilityKeyState
	}
	publicKey, ok := keys[c.SigningKeyID]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return ErrCapabilityKeyState
	}
	signature, err := base64.RawURLEncoding.DecodeString(c.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrCapabilityInvalid
	}
	signingBytes, err := c.SigningBytes()
	if err != nil || !ed25519.Verify(publicKey, signingBytes, signature) {
		return ErrCapabilityInvalid
	}

	issuedAt, expiresAt, err := capabilityTimes(c)
	if err != nil {
		return ErrCapabilityInvalid
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !now.Before(expiresAt) {
		return ErrCapabilityExpired
	}
	maxTTL := opts.MaxTTL
	if maxTTL <= 0 || maxTTL > time.Minute {
		maxTTL = time.Minute
	}
	if expiresAt.Sub(issuedAt) <= 0 || expiresAt.Sub(issuedAt) > maxTTL {
		return ErrCapabilityExpired
	}
	// A future capability is never used to synthesize current authority. A
	// five-second skew allowance is narrow and configurable only in code/tests.
	if issuedAt.After(now.Add(5 * time.Second)) {
		return ErrCapabilityInvalid
	}
	if opts.ExpectedEnvironment != "" && c.Environment != opts.ExpectedEnvironment {
		return ErrCapabilityInvalid
	}
	if opts.ExpectedInstallationID != "" && c.InstallationID != opts.ExpectedInstallationID {
		return ErrCapabilityInvalid
	}
	if opts.ExpectedAccountIncarnationID != "" &&
		c.AccountIncarnationID != opts.ExpectedAccountIncarnationID {
		return ErrCapabilityInvalid
	}
	if opts.ExpectedTopicDigest != "" && c.TopicDigest != opts.ExpectedTopicDigest {
		return ErrCapabilityInvalid
	}
	if opts.ExpectedConversationCommitment != "" &&
		c.ExpectedConversationCommitment != opts.ExpectedConversationCommitment {
		return ErrCapabilityInvalid
	}
	return nil
}

func ParsePublicKeyring(raw string) (map[string]ed25519.PublicKey, error) {
	var encoded map[string]string
	if err := json.Unmarshal([]byte(raw), &encoded); err != nil || len(encoded) == 0 {
		return nil, ErrCapabilityKeyState
	}
	out := make(map[string]ed25519.PublicKey, len(encoded))
	for keyID, value := range encoded {
		if !validASCIIField(keyID, 1, 64) {
			return nil, ErrCapabilityKeyState
		}
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, ErrCapabilityKeyState
		}
		out[keyID] = ed25519.PublicKey(decoded)
	}
	return out, nil
}

func validCapabilityShape(c ReceiveCapabilityV1) bool {
	if !validCapabilityCanonicalIntegers(c) {
		return false
	}
	fields := []string{
		c.Environment,
		c.InstallationID,
		c.AccountIncarnationID,
		c.TopicDigest,
		c.AliasDay,
		c.RouteAlias,
		c.IssuedAt,
		c.ExpiresAt,
		c.Nonce,
		c.SigningKeyID,
		c.Algorithm,
		c.Signature,
	}
	for _, field := range fields {
		if !validASCIIField(field, 1, maxCapabilityFieldBytes) {
			return false
		}
	}
	if c.ExpectedConversationCommitment != "" &&
		!validLowerHexDigest(c.ExpectedConversationCommitment) {
		return false
	}
	if c.PushMode != PushModeAlertAllowed && c.PushMode != PushModeSuppressed {
		// Unknown modes are accepted only as a suppressed authority. They still
		// must be signed, so normalize after signature verification, not before.
		if !validASCIIField(string(c.PushMode), 0, 32) {
			return false
		}
	}
	topicDigest, err := hex.DecodeString(c.TopicDigest)
	if err != nil || len(topicDigest) != 32 || hex.EncodeToString(topicDigest) != c.TopicDigest {
		return false
	}
	routeAlias, err := base64.RawURLEncoding.DecodeString(c.RouteAlias)
	if err != nil || len(routeAlias) != 16 {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(c.Nonce)
	return err == nil && len(nonce) >= 16 && len(nonce) <= 64
}

func validCapabilityCanonicalIntegers(c ReceiveCapabilityV1) bool {
	return c.SchemaVersion == 1 &&
		c.PolicyEpoch > 0 &&
		c.PolicyEpoch <= maxIJSONSafeInteger &&
		c.ConversationGrantVersion > 0 &&
		c.ConversationGrantVersion <= maxIJSONSafeInteger &&
		c.RosterVersion > 0 &&
		c.RosterVersion <= maxIJSONSafeInteger
}

func capabilityTimes(c ReceiveCapabilityV1) (time.Time, time.Time, error) {
	issuedAt, err := time.Parse(time.RFC3339Nano, c.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return issuedAt.UTC(), expiresAt.UTC(), nil
}

func validASCIIField(value string, minLength, maxLength int) bool {
	if len(value) < minLength || len(value) > maxLength {
		return false
	}
	for _, char := range []byte(value) {
		if char < 0x20 || char > 0x7e ||
			char == '<' || char == '>' || char == '&' {
			return false
		}
	}
	return true
}
