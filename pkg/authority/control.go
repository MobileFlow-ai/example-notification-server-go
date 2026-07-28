package authority

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const (
	policyControlDomain = "Hytch safety policy control v1\x00"
	maxIJSONInteger     = uint64(1<<53 - 1)
)

var (
	ErrPolicyControlInvalid  = errors.New("policy control invalid")
	ErrPolicyControlExpired  = errors.New("policy control expired")
	ErrPolicyControlKeyState = errors.New("policy control key state invalid")
)

type PolicyState string

const (
	PolicyStateActive  PolicyState = "active"
	PolicyStateRevoked PolicyState = "revoked"
)

type AgePolicy string

const (
	AgePolicyAdult AgePolicy = "adult"
	AgePolicyTeen  AgePolicy = "teen"
)

type PolicyControlV1 struct {
	SchemaVersion        uint32      `json:"schema_version"`
	Environment          string      `json:"environment"`
	InstallationID       string      `json:"installation_id"`
	AccountIncarnationID string      `json:"account_incarnation_id"`
	PolicyEpoch          uint64      `json:"policy_epoch"`
	State                PolicyState `json:"state"`
	AgePolicy            AgePolicy   `json:"age_policy"`
	IssuedAt             string      `json:"issued_at"`
	ExpiresAt            string      `json:"expires_at"`
	SigningKeyID         string      `json:"signing_key_id"`
	Algorithm            string      `json:"algorithm"`
	Signature            string      `json:"signature"`
}

type PolicyVerifyOptions struct {
	Now                          time.Time
	ExpectedEnvironment          string
	ExpectedInstallationID       string
	ExpectedAccountIncarnationID string
}

func (c PolicyControlV1) SigningBytes() ([]byte, error) {
	if c.SchemaVersion != 1 ||
		c.PolicyEpoch == 0 ||
		c.PolicyEpoch > maxIJSONInteger {
		return nil, ErrPolicyControlInvalid
	}
	unsigned := struct {
		AccountIncarnationID string      `json:"account_incarnation_id"`
		AgePolicy            AgePolicy   `json:"age_policy"`
		Algorithm            string      `json:"algorithm"`
		Environment          string      `json:"environment"`
		ExpiresAt            string      `json:"expires_at"`
		InstallationID       string      `json:"installation_id"`
		IssuedAt             string      `json:"issued_at"`
		PolicyEpoch          uint64      `json:"policy_epoch"`
		SchemaVersion        uint32      `json:"schema_version"`
		SigningKeyID         string      `json:"signing_key_id"`
		State                PolicyState `json:"state"`
	}{
		AccountIncarnationID: c.AccountIncarnationID,
		AgePolicy:            c.AgePolicy,
		Algorithm:            c.Algorithm,
		Environment:          c.Environment,
		ExpiresAt:            c.ExpiresAt,
		InstallationID:       c.InstallationID,
		IssuedAt:             c.IssuedAt,
		PolicyEpoch:          c.PolicyEpoch,
		SchemaVersion:        c.SchemaVersion,
		SigningKeyID:         c.SigningKeyID,
		State:                c.State,
	}
	body, err := json.Marshal(unsigned)
	if err != nil {
		return nil, ErrPolicyControlInvalid
	}
	return append([]byte(policyControlDomain), body...), nil
}

func VerifyPolicyControl(
	control PolicyControlV1,
	keys map[string]ed25519.PublicKey,
	opts PolicyVerifyOptions,
) error {
	if !validPolicyControlShape(control) {
		return ErrPolicyControlInvalid
	}
	if control.Algorithm != "Ed25519" {
		return ErrPolicyControlKeyState
	}
	publicKey, ok := keys[control.SigningKeyID]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return ErrPolicyControlKeyState
	}
	signature, err := base64.RawURLEncoding.DecodeString(control.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrPolicyControlInvalid
	}
	signingBytes, err := control.SigningBytes()
	if err != nil || !ed25519.Verify(publicKey, signingBytes, signature) {
		return ErrPolicyControlInvalid
	}

	issuedAt, err := time.Parse(time.RFC3339Nano, control.IssuedAt)
	if err != nil {
		return ErrPolicyControlInvalid
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, control.ExpiresAt)
	if err != nil {
		return ErrPolicyControlInvalid
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !now.Before(expiresAt) {
		return ErrPolicyControlExpired
	}
	maxTTL := time.Minute
	if control.AgePolicy == AgePolicyTeen {
		maxTTL = 30 * time.Second
	}
	if expiresAt.Sub(issuedAt) <= 0 || expiresAt.Sub(issuedAt) > maxTTL {
		return ErrPolicyControlExpired
	}
	if issuedAt.After(now.Add(5 * time.Second)) {
		return ErrPolicyControlInvalid
	}
	if opts.ExpectedEnvironment != "" && control.Environment != opts.ExpectedEnvironment {
		return ErrPolicyControlInvalid
	}
	if opts.ExpectedInstallationID != "" && control.InstallationID != opts.ExpectedInstallationID {
		return ErrPolicyControlInvalid
	}
	if opts.ExpectedAccountIncarnationID != "" &&
		control.AccountIncarnationID != opts.ExpectedAccountIncarnationID {
		return ErrPolicyControlInvalid
	}
	return nil
}

func validPolicyControlShape(control PolicyControlV1) bool {
	if control.SchemaVersion != 1 ||
		control.PolicyEpoch == 0 ||
		control.PolicyEpoch > maxIJSONInteger {
		return false
	}
	if control.State != PolicyStateActive && control.State != PolicyStateRevoked {
		return false
	}
	if control.AgePolicy != AgePolicyAdult && control.AgePolicy != AgePolicyTeen {
		return false
	}
	for _, value := range []string{
		control.Environment,
		control.InstallationID,
		control.AccountIncarnationID,
		control.IssuedAt,
		control.ExpiresAt,
		control.SigningKeyID,
		control.Algorithm,
		control.Signature,
	} {
		if !validASCIIField(value, 1, maxCapabilityFieldBytes) {
			return false
		}
	}
	return true
}
