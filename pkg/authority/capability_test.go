package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func signedCapabilityWithTTL(
	t *testing.T,
	now time.Time,
	ttl time.Duration,
) (ReceiveCapabilityV1, map[string]ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	capability := ReceiveCapabilityV1{
		SchemaVersion:                  1,
		Environment:                    "development",
		InstallationID:                 "installation",
		AccountIncarnationID:           "incarnation",
		PolicyEpoch:                    9,
		TopicDigest:                    hex.EncodeToString(make([]byte, 32)),
		AliasDay:                       now.UTC().Format(time.DateOnly),
		RouteAlias:                     base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		ConversationGrantVersion:       3,
		RosterVersion:                  4,
		ExpectedConversationCommitment: "",
		PushMode:                       PushModeAlertAllowed,
		IssuedAt:                       now.UTC().Format(time.RFC3339Nano),
		ExpiresAt:                      now.Add(ttl).UTC().Format(time.RFC3339Nano),
		Nonce:                          base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		SigningKeyID:                   "test-key",
		Algorithm:                      "Ed25519",
	}
	signingBytes, err := capability.SigningBytes()
	require.NoError(t, err)
	capability.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(privateKey, signingBytes),
	)
	return capability, map[string]ed25519.PublicKey{"test-key": publicKey}
}

func signedCapability(t *testing.T, now time.Time) (ReceiveCapabilityV1, map[string]ed25519.PublicKey) {
	t.Helper()
	return signedCapabilityWithTTL(t, now, 45*time.Second)
}

func TestVerifyReceiveCapability(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	capability, keys := signedCapability(t, now)

	err := VerifyReceiveCapability(capability, keys, VerifyOptions{
		Now:                          now.Add(time.Second),
		MaxTTL:                       time.Minute,
		ExpectedEnvironment:          "development",
		ExpectedInstallationID:       "installation",
		ExpectedAccountIncarnationID: "incarnation",
		ExpectedTopicDigest:          capability.TopicDigest,
	})
	require.NoError(t, err)
	require.Equal(t, PushModeAlertAllowed, capability.EffectivePushMode())
}

func TestVerifyReceiveCapabilityFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	valid, keys := signedCapability(t, now)

	tests := []struct {
		name   string
		mutate func(*ReceiveCapabilityV1)
		opts   VerifyOptions
		want   error
	}{
		{
			name: "tampered topic",
			mutate: func(c *ReceiveCapabilityV1) {
				c.TopicDigest = hex.EncodeToString(append([]byte{1}, make([]byte, 31)...))
			},
			want: ErrCapabilityInvalid,
		},
		{
			name: "unknown key",
			mutate: func(c *ReceiveCapabilityV1) {
				c.SigningKeyID = "missing"
			},
			want: ErrCapabilityKeyState,
		},
		{
			name: "expired",
			opts: VerifyOptions{Now: now.Add(time.Minute)},
			want: ErrCapabilityExpired,
		},
		{
			name: "tampered expiry",
			mutate: func(c *ReceiveCapabilityV1) {
				c.ExpiresAt = now.Add(61 * time.Second).Format(time.RFC3339Nano)
			},
			want: ErrCapabilityInvalid,
		},
		{
			name: "teen ttl over maximum",
			opts: VerifyOptions{Now: now, MaxTTL: 30 * time.Second},
			want: ErrCapabilityExpired,
		},
		{
			name: "installation mismatch",
			opts: VerifyOptions{Now: now, ExpectedInstallationID: "other"},
			want: ErrCapabilityInvalid,
		},
		{
			name: "expected conversation mismatch",
			opts: VerifyOptions{
				Now:                            now,
				ExpectedConversationCommitment: strings.Repeat("a", 64),
			},
			want: ErrCapabilityInvalid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capability := valid
			if test.mutate != nil {
				test.mutate(&capability)
			}
			opts := test.opts
			if opts.Now.IsZero() {
				opts.Now = now
			}
			err := VerifyReceiveCapability(capability, keys, opts)
			require.Error(t, err)
			require.True(t, errors.Is(err, test.want), "got %v, want %v", err, test.want)
		})
	}
}

func TestVerifyReceiveCapabilityRejectsCorrectlySignedTTLOverages(
	t *testing.T,
) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		ttl    time.Duration
		maxTTL time.Duration
	}{
		{
			name:   "adult_61_seconds",
			ttl:    61 * time.Second,
			maxTTL: time.Minute,
		},
		{
			name:   "teen_31_seconds",
			ttl:    31 * time.Second,
			maxTTL: 30 * time.Second,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capability, keys := signedCapabilityWithTTL(
				t,
				now,
				test.ttl,
			)
			require.ErrorIs(
				t,
				VerifyReceiveCapability(
					capability,
					keys,
					VerifyOptions{
						Now:    now,
						MaxTTL: test.maxTTL,
					},
				),
				ErrCapabilityExpired,
			)
		})
	}
}

func TestReceiveCapabilityRejectsNonIJSONIntegers(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	for _, mutate := range []func(*ReceiveCapabilityV1){
		func(capability *ReceiveCapabilityV1) {
			capability.PolicyEpoch = maxIJSONSafeInteger + 1
		},
		func(capability *ReceiveCapabilityV1) {
			capability.ConversationGrantVersion = maxIJSONSafeInteger + 1
		},
		func(capability *ReceiveCapabilityV1) {
			capability.RosterVersion = maxIJSONSafeInteger + 1
		},
	} {
		capability, keys := signedCapability(t, now)
		mutate(&capability)
		_, err := capability.SigningBytes()
		require.ErrorIs(t, err, ErrCapabilityInvalid)
		require.ErrorIs(
			t,
			VerifyReceiveCapability(capability, keys, VerifyOptions{Now: now}),
			ErrCapabilityInvalid,
		)
	}
}

func TestUnknownPushModeIsSuppressed(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	capability, _ := signedCapability(t, now)
	capability.PushMode = PushMode("future-mode")
	require.Equal(t, PushModeSuppressed, capability.EffectivePushMode())
}

func TestParsePublicKeyring(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	encoded := base64.RawURLEncoding.EncodeToString(publicKey)

	keyring, err := ParsePublicKeyring(`{"key-1":"` + encoded + `"}`)
	require.NoError(t, err)
	require.Equal(t, []byte(publicKey), []byte(keyring["key-1"]))

	_, err = ParsePublicKeyring(`{"key-1":"bad"}`)
	require.ErrorIs(t, err, ErrCapabilityKeyState)
}
