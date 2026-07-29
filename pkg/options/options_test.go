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
