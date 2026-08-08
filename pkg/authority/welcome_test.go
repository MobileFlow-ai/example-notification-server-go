package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func signedWelcomeAuthorization(
	t *testing.T,
	now time.Time,
	ttl time.Duration,
) (WelcomeAuthorizationV1, map[string]ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	topicDigest := sha256.Sum256([]byte("topic"))
	envelopeDigest := sha256.Sum256([]byte("envelope"))
	conversationCommitment, err := ExpectedConversationCommitment(
		"dev",
		testInstallationID,
		testAccountIncarnationID,
		"conversation",
	)
	require.NoError(t, err)
	authorization := WelcomeAuthorizationV1{
		SchemaVersion:        1,
		Environment:          "dev",
		InstallationID:       testInstallationID,
		AccountIncarnationID: testAccountIncarnationID,
		PolicyEpoch:          9,
		TopicDigest:          hex.EncodeToString(topicDigest[:]),
		OuterEnvelopeDigest:  hex.EncodeToString(envelopeDigest[:]),
		ExpectedConversationCommitment: hex.EncodeToString(
			conversationCommitment[:],
		),
		GrantVersion: 3,
		Nonce:        base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		IssuedAt:     now.Format(time.RFC3339Nano),
		ExpiresAt:    now.Add(ttl).Format(time.RFC3339Nano),
		SigningKeyID: "key-1",
		Algorithm:    "Ed25519",
	}
	signingBytes, err := authorization.SigningBytes()
	require.NoError(t, err)
	authorization.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(privateKey, signingBytes),
	)
	return authorization, map[string]ed25519.PublicKey{"key-1": publicKey}
}

func TestVerifyWelcomeAuthorizationBindsExactEnvelopeAndPolicy(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	authorization, keys := signedWelcomeAuthorization(t, now, time.Minute)

	require.NoError(t, VerifyWelcomeAuthorization(
		authorization,
		keys,
		WelcomeVerifyOptions{
			Now:                            now,
			ExpectedEnvironment:            authorization.Environment,
			ExpectedInstallationID:         authorization.InstallationID,
			ExpectedAccountIncarnationID:   authorization.AccountIncarnationID,
			ExpectedTopicDigest:            authorization.TopicDigest,
			ExpectedOuterEnvelopeDigest:    authorization.OuterEnvelopeDigest,
			ExpectedConversationCommitment: authorization.ExpectedConversationCommitment,
			ExpectedPolicyEpoch:            authorization.PolicyEpoch,
		},
	))

	mismatched := authorization
	digest := sha256.Sum256([]byte("hostile-envelope"))
	mismatched.OuterEnvelopeDigest = hex.EncodeToString(digest[:])
	require.ErrorIs(
		t,
		VerifyWelcomeAuthorization(mismatched, keys, WelcomeVerifyOptions{Now: now}),
		ErrWelcomeAuthorizationInvalid,
	)

	require.ErrorIs(
		t,
		VerifyWelcomeAuthorization(
			authorization,
			keys,
			WelcomeVerifyOptions{
				Now:                            now,
				ExpectedConversationCommitment: strings.Repeat("c", 64),
			},
		),
		ErrWelcomeAuthorizationInvalid,
	)
}

func TestWelcomeAuthorizationRejectsNonIJSONIntegers(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	for _, mutate := range []func(*WelcomeAuthorizationV1){
		func(authorization *WelcomeAuthorizationV1) {
			authorization.PolicyEpoch = maxIJSONSafeInteger + 1
		},
		func(authorization *WelcomeAuthorizationV1) {
			authorization.GrantVersion = maxIJSONSafeInteger + 1
		},
	} {
		authorization, keys := signedWelcomeAuthorization(t, now, time.Minute)
		mutate(&authorization)
		_, err := authorization.SigningBytes()
		require.ErrorIs(t, err, ErrWelcomeAuthorizationInvalid)
		require.ErrorIs(
			t,
			VerifyWelcomeAuthorization(
				authorization,
				keys,
				WelcomeVerifyOptions{Now: now},
			),
			ErrWelcomeAuthorizationInvalid,
		)
	}
}

func TestVerifyWelcomeAuthorizationRejectsExpiredAndLongTTL(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	authorization, keys := signedWelcomeAuthorization(t, now, time.Minute+time.Nanosecond)
	require.ErrorIs(
		t,
		VerifyWelcomeAuthorization(authorization, keys, WelcomeVerifyOptions{Now: now}),
		ErrWelcomeAuthorizationExpired,
	)

	authorization, keys = signedWelcomeAuthorization(t, now.Add(-time.Minute), time.Minute)
	require.ErrorIs(
		t,
		VerifyWelcomeAuthorization(authorization, keys, WelcomeVerifyOptions{Now: now}),
		ErrWelcomeAuthorizationExpired,
	)
}

func TestWelcomeAuthorizationSignatureCoversOneTimeNonce(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	authorization, keys := signedWelcomeAuthorization(t, now, time.Minute)
	authorization.Nonce = base64.RawURLEncoding.EncodeToString(
		[]byte("different-nonce!"),
	)
	require.ErrorIs(
		t,
		VerifyWelcomeAuthorization(authorization, keys, WelcomeVerifyOptions{Now: now}),
		ErrWelcomeAuthorizationInvalid,
	)
}

func TestWelcomeAuthorizationRejectsNoncanonicalRawURLBase64(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	valid, keys := signedWelcomeAuthorization(t, now, time.Minute)

	t.Run("signature", func(t *testing.T) {
		authorization := valid
		authorization.Signature = noncanonicalRawURLTrailingBits(
			t,
			authorization.Signature,
		)
		require.ErrorIs(
			t,
			VerifyWelcomeAuthorization(
				authorization,
				keys,
				WelcomeVerifyOptions{Now: now},
			),
			ErrWelcomeAuthorizationInvalid,
		)
	})

	t.Run("nonce", func(t *testing.T) {
		authorization := valid
		authorization.Nonce = noncanonicalRawURLTrailingBits(
			t,
			authorization.Nonce,
		)
		_, err := authorization.SigningBytes()
		require.ErrorIs(t, err, ErrWelcomeAuthorizationInvalid)
	})
}

func TestWelcomeAuthorizationSignatureCoversConversationCommitment(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	authorization, keys := signedWelcomeAuthorization(t, now, time.Minute)
	authorization.ExpectedConversationCommitment = strings.Repeat("d", 64)
	require.ErrorIs(
		t,
		VerifyWelcomeAuthorization(
			authorization,
			keys,
			WelcomeVerifyOptions{Now: now},
		),
		ErrWelcomeAuthorizationInvalid,
	)
}

func TestWelcomeAuthorizationSigningBytesWireVector(t *testing.T) {
	authorization := WelcomeAuthorizationV1{
		SchemaVersion:                  1,
		Environment:                    "dev",
		InstallationID:                 testInstallationID,
		AccountIncarnationID:           testAccountIncarnationID,
		PolicyEpoch:                    9,
		TopicDigest:                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		OuterEnvelopeDigest:            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpectedConversationCommitment: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		GrantVersion:                   3,
		Nonce:                          "MDEyMzQ1Njc4OWFiY2RlZg",
		IssuedAt:                       "2026-07-26T12:00:00Z",
		ExpiresAt:                      "2026-07-26T12:01:00Z",
		SigningKeyID:                   "key-1",
		Algorithm:                      "Ed25519",
	}
	signingBytes, err := authorization.SigningBytes()
	require.NoError(t, err)
	require.Equal(
		t,
		"Hytch safety welcome authorization v1\x00"+
			`{"account_incarnation_id":"`+testAccountIncarnationID+`","algorithm":"Ed25519",`+
			`"environment":"dev",`+
			`"expected_conversation_commitment":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",`+
			`"expires_at":"2026-07-26T12:01:00Z","grant_version":3,`+
			`"installation_id":"`+testInstallationID+`",`+
			`"issued_at":"2026-07-26T12:00:00Z",`+
			`"nonce":"MDEyMzQ1Njc4OWFiY2RlZg",`+
			`"outer_envelope_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",`+
			`"policy_epoch":9,"schema_version":1,"signing_key_id":"key-1",`+
			`"topic_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		string(signingBytes),
	)
}
