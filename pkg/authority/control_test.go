package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func signPolicyControl(t *testing.T, control PolicyControlV1) (PolicyControlV1, map[string]ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signingBytes, err := control.SigningBytes()
	require.NoError(t, err)
	control.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(privateKey, signingBytes),
	)
	return control, map[string]ed25519.PublicKey{control.SigningKeyID: publicKey}
}

func TestVerifyPolicyControlAdultAndTeenFreshness(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	base := PolicyControlV1{
		SchemaVersion:        1,
		Environment:          "development",
		InstallationID:       "installation",
		AccountIncarnationID: "incarnation",
		PolicyEpoch:          7,
		State:                PolicyStateActive,
		AgePolicy:            AgePolicyAdult,
		IssuedAt:             now.Format(time.RFC3339Nano),
		ExpiresAt:            now.Add(time.Minute).Format(time.RFC3339Nano),
		SigningKeyID:         "key-1",
		Algorithm:            "Ed25519",
	}
	adult, adultKeys := signPolicyControl(t, base)
	require.NoError(t, VerifyPolicyControl(adult, adultKeys, PolicyVerifyOptions{
		Now:                          now.Add(time.Second),
		ExpectedEnvironment:          "development",
		ExpectedInstallationID:       "installation",
		ExpectedAccountIncarnationID: "incarnation",
	}))

	teenBase := base
	teenBase.AgePolicy = AgePolicyTeen
	teenBase.ExpiresAt = now.Add(31 * time.Second).Format(time.RFC3339Nano)
	teen, teenKeys := signPolicyControl(t, teenBase)
	require.ErrorIs(
		t,
		VerifyPolicyControl(teen, teenKeys, PolicyVerifyOptions{Now: now}),
		ErrPolicyControlExpired,
	)
}

func TestVerifyPolicyControlRejectsCorrectlySignedTTLOverages(
	t *testing.T,
) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		age  AgePolicy
		ttl  time.Duration
	}{
		{
			name: "adult_61_seconds",
			age:  AgePolicyAdult,
			ttl:  61 * time.Second,
		},
		{
			name: "teen_31_seconds",
			age:  AgePolicyTeen,
			ttl:  31 * time.Second,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control, keys := signPolicyControl(t, PolicyControlV1{
				SchemaVersion:        1,
				Environment:          "development",
				InstallationID:       "installation",
				AccountIncarnationID: "incarnation",
				PolicyEpoch:          8,
				State:                PolicyStateActive,
				AgePolicy:            test.age,
				IssuedAt:             now.Format(time.RFC3339Nano),
				ExpiresAt:            now.Add(test.ttl).Format(time.RFC3339Nano),
				SigningKeyID:         "key-1",
				Algorithm:            "Ed25519",
			})
			require.ErrorIs(
				t,
				VerifyPolicyControl(
					control,
					keys,
					PolicyVerifyOptions{Now: now},
				),
				ErrPolicyControlExpired,
			)
		})
	}
}

func TestVerifyPolicyControlRejectsTamperAndRevokedIsValidDeny(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	base := PolicyControlV1{
		SchemaVersion:        1,
		Environment:          "development",
		InstallationID:       "installation",
		AccountIncarnationID: "incarnation",
		PolicyEpoch:          8,
		State:                PolicyStateRevoked,
		AgePolicy:            AgePolicyTeen,
		IssuedAt:             now.Format(time.RFC3339Nano),
		ExpiresAt:            now.Add(30 * time.Second).Format(time.RFC3339Nano),
		SigningKeyID:         "key-1",
		Algorithm:            "Ed25519",
	}
	control, keys := signPolicyControl(t, base)
	require.NoError(t, VerifyPolicyControl(control, keys, PolicyVerifyOptions{Now: now}))

	control.PolicyEpoch++
	require.ErrorIs(
		t,
		VerifyPolicyControl(control, keys, PolicyVerifyOptions{Now: now}),
		ErrPolicyControlInvalid,
	)
}

func TestVerifyPolicyControlRejectsNonIJSONInteger(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	control := PolicyControlV1{
		SchemaVersion:        1,
		Environment:          "development",
		InstallationID:       "installation",
		AccountIncarnationID: "incarnation",
		PolicyEpoch:          maxIJSONInteger + 1,
		State:                PolicyStateActive,
		AgePolicy:            AgePolicyAdult,
		IssuedAt:             now.Format(time.RFC3339Nano),
		ExpiresAt:            now.Add(time.Minute).Format(time.RFC3339Nano),
		SigningKeyID:         "key-1",
		Algorithm:            "Ed25519",
		Signature:            base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	_, err := control.SigningBytes()
	require.ErrorIs(t, err, ErrPolicyControlInvalid)
	require.ErrorIs(
		t,
		VerifyPolicyControl(
			control,
			map[string]ed25519.PublicKey{
				"key-1": make([]byte, ed25519.PublicKeySize),
			},
			PolicyVerifyOptions{Now: now},
		),
		ErrPolicyControlInvalid,
	)
}
