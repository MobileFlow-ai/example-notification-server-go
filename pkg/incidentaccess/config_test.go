package incidentaccess

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	requesterSecret = "requester-secret-0123456789abcdef"
	approverSecret  = "approver-secret-0123456789abcdefg"
)

func TestActorCredentialsRetainDigestsAndEnforceSeparateRoles(
	t *testing.T,
) {
	authenticator, approvers, err := ParseActorCredentials(
		testCredentialJSON(t),
	)
	require.NoError(t, err)
	require.Equal(t, []string{"security:approver"}, approvers)
	require.Len(t, authenticator.credentials, 2)

	actor, ok := authenticator.requester("Bearer " + requesterSecret)
	require.True(t, ok)
	require.Equal(t, "oncall:requester", actor)
	_, ok = authenticator.approver("Bearer " + requesterSecret)
	require.False(t, ok)

	actor, ok = authenticator.approver("Bearer " + approverSecret)
	require.True(t, ok)
	require.Equal(t, "security:approver", actor)
	_, ok = authenticator.requester("Bearer " + approverSecret)
	require.False(t, ok)

	encoded, err := json.Marshal(authenticator)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), requesterSecret)
	require.NotContains(t, string(encoded), approverSecret)
}

func TestActorCredentialsRejectAmbiguousOrNonDigestConfiguration(
	t *testing.T,
) {
	requesterDigest := secretDigestB64(requesterSecret)
	approverDigest := secretDigestB64(approverSecret)
	testCases := []string{
		`[{"actor":"oncall:requester","role":"requester",` +
			`"secret":"` + requesterSecret + `"},` +
			`{"actor":"security:approver","role":"approver",` +
			`"secret_sha256_b64":"` + approverDigest + `"}]`,
		`[{"actor":"same:actor","role":"requester",` +
			`"secret_sha256_b64":"` + requesterDigest + `"},` +
			`{"actor":"same:actor","role":"approver",` +
			`"secret_sha256_b64":"` + approverDigest + `"}]`,
		`[{"actor":"oncall:requester","role":"requester",` +
			`"secret_sha256_b64":"` + requesterDigest + `"},` +
			`{"actor":"security:approver","role":"approver",` +
			`"secret_sha256_b64":"` + requesterDigest + `"}]`,
		`[{"actor":"oncall:requester","role":"requester",` +
			`"secret_sha256_b64":"` + requesterDigest + `"}]`,
		`[{"actor":"oncall:requester","role":"requester",` +
			`"secret_sha256_b64":"` + requesterDigest + `="},` +
			`{"actor":"security:approver","role":"approver",` +
			`"secret_sha256_b64":"` + approverDigest + `"}]`,
	}
	for _, raw := range testCases {
		authenticator, approvers, err := ParseActorCredentials(raw)
		require.ErrorIs(t, err, ErrInvalidConfiguration)
		require.Nil(t, authenticator)
		require.Nil(t, approvers)
	}
}

func testCredentialJSON(t *testing.T) string {
	t.Helper()
	encoded, err := json.Marshal([]actorCredentialJSON{
		{
			Actor:           "oncall:requester",
			Role:            actorRoleRequester,
			SecretSHA256B64: secretDigestB64(requesterSecret),
		},
		{
			Actor:           "security:approver",
			Role:            actorRoleApprover,
			SecretSHA256B64: secretDigestB64(approverSecret),
		},
	})
	require.NoError(t, err)
	return string(encoded)
}

func secretDigestB64(secret string) string {
	digest := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
