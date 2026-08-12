package main

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/options"
)

func TestLoadA9TopicKeySetTransfersAndClearsOwnedBytes(t *testing.T) {
	path := writeA9TopicKeySource(t, 0o600)
	raw, err := readA9TopicKeySource(path)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	set, err := a9trust.ParseTopicKeySetBytes(raw, "dev")
	require.NoError(t, err)
	require.True(t, allA9ConfigurationBytesZero(raw))
	require.Equal(t, "dev", set.Environment())
	require.Len(t, set.Descriptors(), 1)
	set.Close()

	loaded, err := loadA9TopicKeySet(path, "dev")
	require.NoError(t, err)
	require.Equal(t, "dev", loaded.Environment())
	require.Len(t, loaded.Descriptors(), 1)
	loaded.Close()
	require.Empty(t, loaded.Descriptors())
}

func TestA9TopicKeySourceAcceptsOnlyRestrictedStableRegularFiles(
	t *testing.T,
) {
	for _, mode := range []os.FileMode{0o400, 0o600} {
		path := writeA9TopicKeySource(t, mode)
		raw, err := readA9TopicKeySource(path)
		require.NoError(t, err)
		require.NotEmpty(t, raw)
		clear(raw)
	}

	validPath := writeA9TopicKeySource(t, 0o600)
	tests := map[string]func() string{
		"relative": func() string {
			return filepath.Base(validPath)
		},
		"directory": func() string {
			return t.TempDir()
		},
		"symlink": func() string {
			path := filepath.Join(t.TempDir(), "topic-link.json")
			require.NoError(t, os.Symlink(validPath, path))
			return path
		},
		"group readable": func() string {
			return writeA9TopicKeySource(t, 0o640)
		},
		"world readable": func() string {
			return writeA9TopicKeySource(t, 0o604)
		},
		"owner executable": func() string {
			return writeA9TopicKeySource(t, 0o700)
		},
		"empty": func() string {
			path := filepath.Join(t.TempDir(), "empty.json")
			require.NoError(t, os.WriteFile(path, nil, 0o600))
			require.NoError(t, os.Chmod(path, 0o600))
			return path
		},
		"oversized": func() string {
			path := filepath.Join(t.TempDir(), "oversized.json")
			require.NoError(t, os.WriteFile(
				path,
				make([]byte, maxA9TopicKeySourceBytes+1),
				0o600,
			))
			require.NoError(t, os.Chmod(path, 0o600))
			return path
		},
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			raw, err := readA9TopicKeySource(source())
			require.Nil(t, raw)
			require.ErrorIs(t, err, errA9TopicKeySource)
		})
	}
}

func TestLoadA9TopicKeySetReturnsOnlyFixedConfigurationErrors(
	t *testing.T,
) {
	path := filepath.Join(t.TempDir(), "invalid.json")
	require.NoError(t, os.WriteFile(
		path,
		[]byte(`{"secret":"TOPIC_CANARY"}`),
		0o600,
	))
	require.NoError(t, os.Chmod(path, 0o600))
	set, err := loadA9TopicKeySet(path, "dev")
	require.Nil(t, set)
	require.ErrorIs(t, err, errA9TopicKeySource)
	require.NotContains(t, err.Error(), "TOPIC_CANARY")
	require.NotContains(t, err.Error(), path)
}

func TestCheckedA9PrivateServerOptionsRejectsOverflowBeforeConversion(
	t *testing.T,
) {
	valid := validA9RuntimeOptions(t).A9
	for name, mutate := range map[string]func(*options.A9Options){
		"header timeout": func(config *options.A9Options) {
			config.ReadHeaderTimeoutSeconds = math.MaxInt
		},
		"read timeout": func(config *options.A9Options) {
			config.ReadTimeoutSeconds = math.MaxInt
		},
		"write timeout": func(config *options.A9Options) {
			config.WriteTimeoutSeconds = math.MaxInt
		},
		"idle timeout": func(config *options.A9Options) {
			config.IdleTimeoutSeconds = math.MaxInt
		},
		"header bytes": func(config *options.A9Options) {
			config.MaxHeaderBytes = math.MaxInt
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			checked, ok := checkedA9PrivateServerOptions(candidate)
			require.False(t, ok)
			require.Zero(t, checked)
		})
	}
}

func validA9RuntimeOptions(t *testing.T) options.Options {
	t.Helper()
	config := options.Options{}
	config.A9.Enabled = true
	config.A9.KeysetOrigin = "https://modern-api.internal"
	config.A9.PinnedRootPublicKeyBase64URL = "root-public"
	config.A9.PinnedRootKeyID = "root-key-id"
	config.A9.TopicCommitmentKeysFilePath =
		writeA9TopicKeySource(t, 0o600)
	config.A9.KeysetRequestTimeoutSeconds = 10
	config.A9.PrivateBindAddress = "127.0.0.1:9443"
	config.A9.TLSCertificateFilePath =
		filepath.Join(t.TempDir(), "a9-server-cert.pem")
	config.A9.TLSPrivateKeyFilePath =
		filepath.Join(t.TempDir(), "a9-server-key.pem")
	config.A9.ReadHeaderTimeoutSeconds = 5
	config.A9.ReadTimeoutSeconds = 15
	config.A9.WriteTimeoutSeconds = 15
	config.A9.IdleTimeoutSeconds = 30
	config.A9.MaxHeaderBytes = 16 * 1024
	config.Vault.Enabled = true
	config.Vault.Environment = "dev"
	config.Api.Enabled = true
	config.Xmtp.ListenerEnabled = true
	config.Xmtp.ListenerType = "v4"
	return config
}

func validA10RuntimeOptions(t *testing.T) options.Options {
	t.Helper()
	config := validA9RuntimeOptions(t)
	config.A10.Enabled = true
	config.A10.KeysetOrigin = "https://modern-api.internal"
	config.A10.PinnedRootPublicKeyBase64URL = "a10-root-public"
	config.A10.PinnedRootKeyID = "a10-root-key-id"
	config.A10.KeysetRequestTimeoutSeconds = 10
	config.Apns.Enabled = true
	config.Apns.SecureWrapperRequired = true
	config.Apns.SecureEnvironment = "dev"
	config.Apns.P8CertificateBase64 = "railway-secret-reference"
	config.Apns.KeyId = "key-id"
	config.Apns.TeamId = "team-id"
	config.Apns.Topic = "com.mobileflow.hytchdev"
	config.Apns.Mode = "development"
	return config
}

func writeA9TopicKeySource(
	t *testing.T,
	mode os.FileMode,
) string {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, 32)
	keyID, err := a9trust.HMACKeyID(key)
	require.NoError(t, err)
	now := time.Now().UTC()
	record := map[string]any{
		"environment":     "dev",
		"purpose":         "TOPIC",
		"key_id":          keyID,
		"topic_key_epoch": a9trust.TopicEpoch(now),
		"key_base64url":   a9trust.EncodeBase64URL(key),
		"not_before": a9ConfigurationTime(
			now.Add(-time.Hour),
		),
		"not_after": a9ConfigurationTime(
			now.Add(24 * time.Hour),
		),
	}
	clear(key)
	raw, err := json.Marshal([]any{record})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "topic-keys.json")
	require.NoError(t, os.WriteFile(path, raw, mode))
	clear(raw)
	require.NoError(t, os.Chmod(path, mode))
	return path
}

func a9ConfigurationTime(value time.Time) string {
	return value.UTC().
		Truncate(time.Second).
		Format("2006-01-02T15:04:05.000Z")
}

func allA9ConfigurationBytesZero(value []byte) bool {
	return bytes.Equal(value, make([]byte, len(value)))
}
