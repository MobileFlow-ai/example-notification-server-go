package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
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
		SchemaVersion:            1,
		Environment:              "dev",
		InstallationID:           testInstallationID,
		AccountIncarnationID:     testAccountIncarnationID,
		PolicyEpoch:              9,
		TopicDigest:              hex.EncodeToString(make([]byte, 32)),
		AliasDay:                 now.UTC().Format(time.DateOnly),
		RouteAlias:               base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		ConversationGrantVersion: 3,
		RosterVersion:            4,
		PushMode:                 PushModeAlertAllowed,
		IssuedAt:                 now.UTC().Format(time.RFC3339Nano),
		ExpiresAt:                now.Add(ttl).UTC().Format(time.RFC3339Nano),
		Nonce:                    base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		SigningKeyID:             "test-key",
		Algorithm:                "Ed25519",
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

func noncanonicalRawURLTrailingBits(t *testing.T, canonical string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	var trailingBitMask int
	switch len(canonical) % 4 {
	case 2:
		trailingBitMask = 0x0f
	case 3:
		trailingBitMask = 0x03
	default:
		t.Fatalf("encoding has no unused trailing bits: %q", canonical)
	}
	lastIndex := strings.IndexByte(alphabet, canonical[len(canonical)-1])
	require.NotEqual(t, -1, lastIndex)
	require.Zero(t, lastIndex&trailingBitMask)

	malleated := canonical[:len(canonical)-1] +
		string(alphabet[lastIndex|1])
	canonicalBytes, err := base64.RawURLEncoding.DecodeString(canonical)
	require.NoError(t, err)
	malleatedBytes, err := base64.RawURLEncoding.DecodeString(malleated)
	require.NoError(t, err)
	require.Equal(t, canonicalBytes, malleatedBytes)
	_, err = base64.RawURLEncoding.Strict().DecodeString(malleated)
	require.Error(t, err)
	return malleated
}

func TestVerifyReceiveCapability(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	capability, keys := signedCapability(t, now)

	err := VerifyReceiveCapability(capability, keys, VerifyOptions{
		Now:                          now.Add(time.Second),
		MaxTTL:                       time.Minute,
		ExpectedEnvironment:          "dev",
		ExpectedInstallationID:       testInstallationID,
		ExpectedAccountIncarnationID: testAccountIncarnationID,
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
			opts: VerifyOptions{
				Now:                    now,
				ExpectedInstallationID: testOtherInstallationID,
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

func TestReceiveCapabilityV1HasExactGate6Shape(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	capability, _ := signedCapability(t, now)

	encoded, err := json.Marshal(capability)
	require.NoError(t, err)
	var object map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &object))
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	require.Equal(t, []string{
		"account_incarnation_id",
		"algorithm",
		"alias_day",
		"conversation_grant_version",
		"environment",
		"expires_at",
		"installation_id",
		"issued_at",
		"nonce",
		"policy_epoch",
		"push_mode",
		"roster_version",
		"route_alias",
		"schema_version",
		"signature",
		"signing_key_id",
		"topic_digest",
	}, keys)

	signingBytes, err := capability.SigningBytes()
	require.NoError(t, err)
	require.Equal(
		t,
		"Hytch safety receive capability v1\x00"+
			`{"account_incarnation_id":"`+testAccountIncarnationID+`",`+
			`"algorithm":"Ed25519","alias_day":"2026-07-26",`+
			`"conversation_grant_version":3,"environment":"dev",`+
			`"expires_at":"2026-07-26T12:00:45Z",`+
			`"installation_id":"`+testInstallationID+`",`+
			`"issued_at":"2026-07-26T12:00:00Z",`+
			`"nonce":"AAAAAAAAAAAAAAAAAAAAAA","policy_epoch":9,`+
			`"push_mode":"alert_allowed","roster_version":4,`+
			`"route_alias":"AAAAAAAAAAAAAAAAAAAAAA","schema_version":1,`+
			`"signing_key_id":"test-key",`+
			`"topic_digest":"`+strings.Repeat("0", 64)+`"}`,
		string(signingBytes),
	)
}

func TestReceiveCapabilityRejectsNoncanonicalRawURLBase64(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	valid, keys := signedCapability(t, now)

	t.Run("signature", func(t *testing.T) {
		capability := valid
		capability.Signature = noncanonicalRawURLTrailingBits(
			t,
			capability.Signature,
		)
		require.ErrorIs(
			t,
			VerifyReceiveCapability(
				capability,
				keys,
				VerifyOptions{Now: now},
			),
			ErrCapabilityInvalid,
		)
	})

	for _, test := range []struct {
		name   string
		mutate func(*ReceiveCapabilityV1)
	}{
		{
			name: "nonce",
			mutate: func(capability *ReceiveCapabilityV1) {
				capability.Nonce = noncanonicalRawURLTrailingBits(
					t,
					capability.Nonce,
				)
			},
		},
		{
			name: "route alias",
			mutate: func(capability *ReceiveCapabilityV1) {
				capability.RouteAlias = noncanonicalRawURLTrailingBits(
					t,
					capability.RouteAlias,
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			capability := valid
			test.mutate(&capability)
			_, err := capability.SigningBytes()
			require.ErrorIs(t, err, ErrCapabilityInvalid)
		})
	}

	t.Run("public key", func(t *testing.T) {
		encodedKey := base64.RawURLEncoding.EncodeToString(keys["test-key"])
		encodedKey = noncanonicalRawURLTrailingBits(t, encodedKey)
		_, err := ParsePublicKeyring(`{"test-key":"` + encodedKey + `"}`)
		require.ErrorIs(t, err, ErrCapabilityKeyState)
	})
}

func TestReceiveCapabilitySigningRejectsNoncanonicalAuthorityFields(
	t *testing.T,
) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	valid, _ := signedCapability(t, now)
	for _, mutate := range []func(*ReceiveCapabilityV1){
		func(capability *ReceiveCapabilityV1) {
			capability.Environment = "development"
		},
		func(capability *ReceiveCapabilityV1) {
			capability.InstallationID = strings.ToUpper(testInstallationID)
		},
		func(capability *ReceiveCapabilityV1) {
			capability.AccountIncarnationID = strings.ToUpper(
				testAccountIncarnationID,
			)
		},
	} {
		capability := valid
		mutate(&capability)
		_, err := capability.SigningBytes()
		require.ErrorIs(t, err, ErrCapabilityInvalid)
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
