package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a3trust"
)

func TestReadA3WitnessSeedRequiresStableRestrictedRegularFile(t *testing.T) {
	directory := a3RealTempDir(t)
	path := filepath.Join(directory, "witness-seed")
	seed := bytes.Repeat([]byte{0x51}, ed25519.SeedSize)
	require.NoError(t, os.WriteFile(path, seed, 0o400))
	loaded, err := readA3WitnessSeed(path)
	require.NoError(t, err)
	require.Equal(t, seed, loaded)
	clear(loaded)

	require.NoError(t, os.Chmod(path, 0o440))
	_, err = readA3WitnessSeed(path)
	require.ErrorIs(t, err, errA3RuntimeConfiguration)
	require.NoError(t, os.Chmod(path, 0o600))
	require.NoError(t, os.WriteFile(path, seed[:31], 0o400))
	require.NoError(t, os.Chmod(path, 0o400))
	_, err = readA3WitnessSeed(path)
	require.ErrorIs(t, err, errA3RuntimeConfiguration)
	require.NoError(t, os.Chmod(path, 0o600))
	require.NoError(t, os.WriteFile(path, make([]byte, ed25519.SeedSize), 0o400))
	require.NoError(t, os.Chmod(path, 0o400))
	_, err = readA3WitnessSeed(path)
	require.ErrorIs(t, err, errA3RuntimeConfiguration)

	link := filepath.Join(a3RealTempDir(t), "witness-link")
	require.NoError(t, os.Symlink(path, link))
	_, err = readA3WitnessSeed(link)
	require.ErrorIs(t, err, errA3RuntimeConfiguration)

	realParent := filepath.Join(a3RealTempDir(t), "real-parent")
	require.NoError(t, os.Mkdir(realParent, 0o700))
	realSeed := filepath.Join(realParent, "seed")
	require.NoError(t, os.WriteFile(realSeed, seed, 0o400))
	linkedParent := filepath.Join(a3RealTempDir(t), "linked-parent")
	require.NoError(t, os.Symlink(realParent, linkedParent))
	_, err = readA3WitnessSeed(filepath.Join(linkedParent, "seed"))
	require.ErrorIs(t, err, errA3RuntimeConfiguration)

	require.NoError(t, os.Chmod(path, 0o600))
	require.NoError(t, os.WriteFile(path, seed, 0o400))
	require.NoError(t, os.Chmod(path, 0o400))
	require.NoError(t, os.Chmod(directory, 0o770))
	_, err = readA3WitnessSeed(path)
	require.ErrorIs(t, err, errA3RuntimeConfiguration)
}

func a3RealTempDir(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return resolved
}

func TestParseA3SequencerKeysIsStrictAndCanonical(t *testing.T) {
	publicKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	keyID := a3trust.WitnessKeyID(publicKey)
	raw := `{"` + keyID + `":"` + base64.StdEncoding.EncodeToString(publicKey) + `"}`
	parsed, err := parseA3SequencerKeys(raw)
	require.NoError(t, err)
	require.Equal(t, publicKey, parsed[keyID])

	_, err = parseA3SequencerKeys(`{"` + keyID + `":"` + base64.RawStdEncoding.EncodeToString(publicKey) + `"}`)
	require.Error(t, err)
	_, err = parseA3SequencerKeys(`{"` + keyID + `":"` + base64.StdEncoding.EncodeToString(publicKey) + `","` + keyID + `":"` + base64.StdEncoding.EncodeToString(publicKey) + `"}`)
	require.Error(t, err)
	_, err = parseA3SequencerKeys(`{"ed25519-sha256:` + strings.Repeat("0", 64) + `":"` + base64.StdEncoding.EncodeToString(publicKey) + `"}`)
	require.Error(t, err)
}

func TestA3GRPCTargetRefusesNonLoopbackPlaintext(t *testing.T) {
	require.True(t, validA3GRPCTarget("grpc.dev.xmtp.network:443", true))
	require.True(t, validA3GRPCTarget("127.0.0.1:50051", false))
	require.True(t, validA3GRPCTarget("[::1]:50051", false))
	require.False(t, validA3GRPCTarget("localhost:50051", false))
	require.False(t, validA3GRPCTarget("validation.example:443", false))
}

func TestA3IdentityTargetIsPinnedToReviewedDevEndpoint(t *testing.T) {
	require.True(t, validA3IdentityTarget(
		"dev", a3DevIdentityGRPCAddress,
	))
	require.False(t, validA3IdentityTarget(
		"production", a3DevIdentityGRPCAddress,
	))
	require.False(t, validA3IdentityTarget(
		"dev", "identity.example:443",
	))
	require.False(t, validA3IdentityTarget("dev", "127.0.0.1:50051"))
}

func testA3OpaqueBearer(seed byte) string {
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = seed + byte(index*17)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
