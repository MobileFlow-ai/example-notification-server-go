package vault

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	out := make([]byte, size)
	_, err := rand.Read(out)
	require.NoError(t, err)
	return out
}

func TestEnvelopeEncryptionRoundTripAndContextBinding(t *testing.T) {
	root := randomBytes(t, 32)
	keyring, err := NewKeyring(2, map[uint32][]byte{1: randomBytes(t, 32), 2: root})
	require.NoError(t, err)

	plaintext := []byte("sensitive route material")
	sealed, err := keyring.Seal([]byte("lease-a:route-key"), plaintext)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), string(plaintext))

	opened, err := keyring.Open([]byte("lease-a:route-key"), sealed)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)

	_, err = keyring.Open([]byte("lease-b:route-key"), sealed)
	require.ErrorIs(t, err, ErrCiphertextInvalid)

	sealed[len(sealed)-1] ^= 1
	_, err = keyring.Open([]byte("lease-a:route-key"), sealed)
	require.ErrorIs(t, err, ErrCiphertextInvalid)
}

func TestEnvelopeEncryptionSupportsOldRootDuringRotation(t *testing.T) {
	oldRoot := randomBytes(t, 32)
	oldKeyring, err := NewKeyring(1, map[uint32][]byte{1: oldRoot})
	require.NoError(t, err)
	sealed, err := oldKeyring.Seal([]byte("lease:token"), []byte("token"))
	require.NoError(t, err)

	rotated, err := NewKeyring(2, map[uint32][]byte{
		1: oldRoot,
		2: randomBytes(t, 32),
	})
	require.NoError(t, err)
	opened, err := rotated.Open([]byte("lease:token"), sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("token"), opened)
}

func TestParseKeyringAndLookupRotation(t *testing.T) {
	root := randomBytes(t, 32)
	encoded := base64.RawURLEncoding.EncodeToString(root)
	keyring, err := ParseKeyring(
		`{"active_version":7,"keys":{"7":"` + encoded + `"}}`,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(7), keyring.activeVersion)

	lookup, err := ParseLookupKey(encoded)
	require.NoError(t, err)
	at := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	current := LookupEpoch(at)
	digest, err := lookup.Digest("topic", current, []byte("topic"))
	require.NoError(t, err)
	require.Len(t, digest, 32)
	require.Equal(t, []uint64{current, current - 1}, CandidateEpochs(at))

	other, err := lookup.Digest("installation", current, []byte("topic"))
	require.NoError(t, err)
	require.NotEqual(t, digest, other)
}
