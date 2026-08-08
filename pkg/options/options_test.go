package options

import (
	"testing"

	"github.com/jessevdk/go-flags"
	"github.com/stretchr/testify/require"
)

func TestLogicalEnvironmentOptionsAcceptOnlyDevAndProduction(t *testing.T) {
	for _, valid := range []string{"dev", "production"} {
		var parsed Options
		_, err := flags.ParseArgs(
			&parsed,
			[]string{
				"--bridge-environment=" + valid,
				"--apns-secure-environment=" + valid,
			},
		)
		require.NoError(t, err)
		require.Equal(t, valid, parsed.Vault.Environment)
		require.Equal(t, valid, parsed.Apns.SecureEnvironment)
	}

	var parsed Options
	_, err := flags.ParseArgs(
		&parsed,
		[]string{"--bridge-environment=development"},
	)
	require.Error(t, err)
}

func TestAPNSModeForBridgeEnvironment(t *testing.T) {
	mode, valid := APNSModeForBridgeEnvironment("dev")
	require.True(t, valid)
	require.Equal(t, "development", mode)

	mode, valid = APNSModeForBridgeEnvironment("production")
	require.True(t, valid)
	require.Equal(t, "production", mode)

	for _, invalid := range []string{"", "development", "staging"} {
		mode, valid = APNSModeForBridgeEnvironment(invalid)
		require.False(t, valid)
		require.Empty(t, mode)
	}
}

func TestA9OptionsUseDedicatedTrustMaterial(t *testing.T) {
	var parsed Options
	_, err := flags.ParseArgs(
		&parsed,
		[]string{
			"--a9-enabled",
			"--a9-keyset-origin=https://modern-api.internal",
			"--a9-pinned-root-public-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"--a9-pinned-root-key-id=ed25519-sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"--a9-topic-commitment-keys-file-path=/run/secrets/a9-topic-keys.json",
			"--a9-keyset-request-timeout-seconds=15",
			"--a9-private-bind=10.0.0.8:9443",
			"--a9-tls-certificate-file-path=/run/secrets/a9-server-cert.pem",
			"--a9-tls-private-key-file-path=/run/secrets/a9-server-key.pem",
			"--a9-read-header-timeout-seconds=4",
			"--a9-read-timeout-seconds=12",
			"--a9-write-timeout-seconds=13",
			"--a9-idle-timeout-seconds=29",
			"--a9-max-header-bytes=8192",
		},
	)
	require.NoError(t, err)
	require.True(t, parsed.A9.Enabled)
	require.True(t, parsed.A9.HasTrustMaterial())
	require.Equal(t, "https://modern-api.internal", parsed.A9.KeysetOrigin)
	require.Equal(t, 15, parsed.A9.KeysetRequestTimeoutSeconds)
	require.Empty(t, parsed.A9.TopicCommitmentKeysJSON)
	require.Equal(
		t,
		"/run/secrets/a9-topic-keys.json",
		parsed.A9.TopicCommitmentKeysFilePath,
	)
	require.Equal(t, "10.0.0.8:9443", parsed.A9.PrivateBindAddress)
	require.False(t, parsed.A9.AllowWildcardPrivateBind)
	require.Equal(
		t,
		"/run/secrets/a9-server-cert.pem",
		parsed.A9.TLSCertificateFilePath,
	)
	require.Equal(
		t,
		"/run/secrets/a9-server-key.pem",
		parsed.A9.TLSPrivateKeyFilePath,
	)
	require.Equal(t, 4, parsed.A9.ReadHeaderTimeoutSeconds)
	require.Equal(t, 12, parsed.A9.ReadTimeoutSeconds)
	require.Equal(t, 13, parsed.A9.WriteTimeoutSeconds)
	require.Equal(t, 29, parsed.A9.IdleTimeoutSeconds)
	require.Equal(t, 8192, parsed.A9.MaxHeaderBytes)
	require.Empty(t, parsed.Vault.AuthorityPublicKeysJSON)
	require.Empty(t, parsed.Vault.APIBearerToken)
}

func TestA9TrustMaterialPresenceExcludesDefaultTimeout(t *testing.T) {
	var parsed Options
	_, err := flags.ParseArgs(&parsed, nil)
	require.NoError(t, err)
	require.Equal(t, 10, parsed.A9.KeysetRequestTimeoutSeconds)
	require.Equal(t, "127.0.0.1:9443", parsed.A9.PrivateBindAddress)
	require.Equal(t, 5, parsed.A9.ReadHeaderTimeoutSeconds)
	require.Equal(t, 15, parsed.A9.ReadTimeoutSeconds)
	require.Equal(t, 15, parsed.A9.WriteTimeoutSeconds)
	require.Equal(t, 30, parsed.A9.IdleTimeoutSeconds)
	require.Equal(t, 16*1024, parsed.A9.MaxHeaderBytes)
	require.False(t, parsed.A9.HasTrustMaterial())

	parsed.A9.AllowWildcardPrivateBind = true
	require.True(t, parsed.A9.HasTrustMaterial())
	parsed.A9.AllowWildcardPrivateBind = false
	parsed.A9.PinnedRootKeyID = "configured"
	require.True(t, parsed.A9.HasTrustMaterial())
}

func TestA9InlineTopicSecretRemainsDetectableAsRejectedMaterial(
	t *testing.T,
) {
	var parsed Options
	_, err := flags.ParseArgs(
		&parsed,
		[]string{"--a9-topic-commitment-keys-json=secret"},
	)
	require.NoError(t, err)
	require.Equal(t, "secret", parsed.A9.TopicCommitmentKeysJSON)
	require.True(t, parsed.A9.HasTrustMaterial())
}
