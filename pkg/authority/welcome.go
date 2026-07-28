package authority

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const welcomeAuthorizationDomain = "Hytch safety welcome authorization v1\x00"

var (
	// ErrWelcomeAuthorizationInvalid is deliberately content-free. Authorization
	// fields identify an installation and must not be copied into logs.
	ErrWelcomeAuthorizationInvalid  = errors.New("welcome authorization invalid")
	ErrWelcomeAuthorizationExpired  = errors.New("welcome authorization expired")
	ErrWelcomeAuthorizationKeyState = errors.New("welcome authorization key state invalid")
)

// WelcomeAuthorizationV1 is a short-lived, one-use grant for one exact
// encrypted Welcome outer envelope. The bridge verifies it before attempting
// any payload parsing or decryption.
type WelcomeAuthorizationV1 struct {
	SchemaVersion                  uint32 `json:"schema_version"`
	Environment                    string `json:"environment"`
	InstallationID                 string `json:"installation_id"`
	AccountIncarnationID           string `json:"account_incarnation_id"`
	PolicyEpoch                    uint64 `json:"policy_epoch"`
	TopicDigest                    string `json:"topic_digest"`
	OuterEnvelopeDigest            string `json:"outer_envelope_digest"`
	ExpectedConversationCommitment string `json:"expected_conversation_commitment"`
	GrantVersion                   uint64 `json:"grant_version"`
	Nonce                          string `json:"nonce"`
	IssuedAt                       string `json:"issued_at"`
	ExpiresAt                      string `json:"expires_at"`
	SigningKeyID                   string `json:"signing_key_id"`
	Algorithm                      string `json:"algorithm"`
	Signature                      string `json:"signature"`
}

type WelcomeVerifyOptions struct {
	Now                            time.Time
	ExpectedEnvironment            string
	ExpectedInstallationID         string
	ExpectedAccountIncarnationID   string
	ExpectedTopicDigest            string
	ExpectedOuterEnvelopeDigest    string
	ExpectedConversationCommitment string
	ExpectedPolicyEpoch            uint64
}

// SigningBytes returns the fixed, lexicographically keyed wire
// representation. Accepted text is bounded ASCII, so no locale or Unicode
// normalization can alter the signed bytes.
func (a WelcomeAuthorizationV1) SigningBytes() ([]byte, error) {
	if !validWelcomeCanonicalIntegers(a) {
		return nil, ErrWelcomeAuthorizationInvalid
	}
	unsigned := struct {
		AccountIncarnationID           string `json:"account_incarnation_id"`
		Algorithm                      string `json:"algorithm"`
		Environment                    string `json:"environment"`
		ExpectedConversationCommitment string `json:"expected_conversation_commitment"`
		ExpiresAt                      string `json:"expires_at"`
		GrantVersion                   uint64 `json:"grant_version"`
		InstallationID                 string `json:"installation_id"`
		IssuedAt                       string `json:"issued_at"`
		Nonce                          string `json:"nonce"`
		OuterEnvelopeDigest            string `json:"outer_envelope_digest"`
		PolicyEpoch                    uint64 `json:"policy_epoch"`
		SchemaVersion                  uint32 `json:"schema_version"`
		SigningKeyID                   string `json:"signing_key_id"`
		TopicDigest                    string `json:"topic_digest"`
	}{
		AccountIncarnationID:           a.AccountIncarnationID,
		Algorithm:                      a.Algorithm,
		Environment:                    a.Environment,
		ExpectedConversationCommitment: a.ExpectedConversationCommitment,
		ExpiresAt:                      a.ExpiresAt,
		GrantVersion:                   a.GrantVersion,
		InstallationID:                 a.InstallationID,
		IssuedAt:                       a.IssuedAt,
		Nonce:                          a.Nonce,
		OuterEnvelopeDigest:            a.OuterEnvelopeDigest,
		PolicyEpoch:                    a.PolicyEpoch,
		SchemaVersion:                  a.SchemaVersion,
		SigningKeyID:                   a.SigningKeyID,
		TopicDigest:                    a.TopicDigest,
	}
	body, err := json.Marshal(unsigned)
	if err != nil {
		return nil, ErrWelcomeAuthorizationInvalid
	}
	return append([]byte(welcomeAuthorizationDomain), body...), nil
}

func VerifyWelcomeAuthorization(
	authorization WelcomeAuthorizationV1,
	keys map[string]ed25519.PublicKey,
	opts WelcomeVerifyOptions,
) error {
	if !validWelcomeAuthorizationShape(authorization) {
		return ErrWelcomeAuthorizationInvalid
	}
	if authorization.Algorithm != "Ed25519" {
		return ErrWelcomeAuthorizationKeyState
	}
	publicKey, ok := keys[authorization.SigningKeyID]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return ErrWelcomeAuthorizationKeyState
	}
	signature, err := base64.RawURLEncoding.DecodeString(authorization.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrWelcomeAuthorizationInvalid
	}
	signingBytes, err := authorization.SigningBytes()
	if err != nil || !ed25519.Verify(publicKey, signingBytes, signature) {
		return ErrWelcomeAuthorizationInvalid
	}

	issuedAt, expiresAt, err := welcomeAuthorizationTimes(authorization)
	if err != nil {
		return ErrWelcomeAuthorizationInvalid
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !now.Before(expiresAt) ||
		expiresAt.Sub(issuedAt) <= 0 ||
		expiresAt.Sub(issuedAt) > time.Minute {
		return ErrWelcomeAuthorizationExpired
	}
	if issuedAt.After(now.Add(5 * time.Second)) {
		return ErrWelcomeAuthorizationInvalid
	}
	if opts.ExpectedEnvironment != "" &&
		authorization.Environment != opts.ExpectedEnvironment {
		return ErrWelcomeAuthorizationInvalid
	}
	if opts.ExpectedInstallationID != "" &&
		authorization.InstallationID != opts.ExpectedInstallationID {
		return ErrWelcomeAuthorizationInvalid
	}
	if opts.ExpectedAccountIncarnationID != "" &&
		authorization.AccountIncarnationID != opts.ExpectedAccountIncarnationID {
		return ErrWelcomeAuthorizationInvalid
	}
	if opts.ExpectedTopicDigest != "" &&
		authorization.TopicDigest != opts.ExpectedTopicDigest {
		return ErrWelcomeAuthorizationInvalid
	}
	if opts.ExpectedOuterEnvelopeDigest != "" &&
		authorization.OuterEnvelopeDigest != opts.ExpectedOuterEnvelopeDigest {
		return ErrWelcomeAuthorizationInvalid
	}
	if opts.ExpectedConversationCommitment != "" &&
		authorization.ExpectedConversationCommitment !=
			opts.ExpectedConversationCommitment {
		return ErrWelcomeAuthorizationInvalid
	}
	if opts.ExpectedPolicyEpoch != 0 &&
		authorization.PolicyEpoch != opts.ExpectedPolicyEpoch {
		return ErrWelcomeAuthorizationInvalid
	}
	return nil
}

func validWelcomeAuthorizationShape(a WelcomeAuthorizationV1) bool {
	if !validWelcomeCanonicalIntegers(a) {
		return false
	}
	for _, value := range []string{
		a.Environment,
		a.InstallationID,
		a.AccountIncarnationID,
		a.TopicDigest,
		a.OuterEnvelopeDigest,
		a.ExpectedConversationCommitment,
		a.Nonce,
		a.IssuedAt,
		a.ExpiresAt,
		a.SigningKeyID,
		a.Algorithm,
		a.Signature,
	} {
		if !validASCIIField(value, 1, maxCapabilityFieldBytes) {
			return false
		}
	}
	if !validLowerHexDigest(a.TopicDigest) ||
		!validLowerHexDigest(a.OuterEnvelopeDigest) ||
		!validLowerHexDigest(a.ExpectedConversationCommitment) {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(a.Nonce)
	return err == nil && len(nonce) >= 16 && len(nonce) <= 64
}

func validWelcomeCanonicalIntegers(a WelcomeAuthorizationV1) bool {
	return a.SchemaVersion == 1 &&
		a.PolicyEpoch > 0 &&
		a.PolicyEpoch <= maxIJSONSafeInteger &&
		a.GrantVersion > 0 &&
		a.GrantVersion <= maxIJSONSafeInteger
}

func validLowerHexDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil &&
		len(decoded) == 32 &&
		hex.EncodeToString(decoded) == value
}

func welcomeAuthorizationTimes(
	authorization WelcomeAuthorizationV1,
) (time.Time, time.Time, error) {
	issuedAt, err := time.Parse(time.RFC3339Nano, authorization.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, authorization.ExpiresAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return issuedAt.UTC(), expiresAt.UTC(), nil
}
