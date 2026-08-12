package options

import (
	"reflect"
	"testing"

	"github.com/jessevdk/go-flags"
	"github.com/stretchr/testify/require"
)

func TestLegacyRetirementPreflightIsCLIOnly(t *testing.T) {
	field, found := reflect.TypeFor[Options]().
		FieldByName("PreflightLegacyRetirement")
	require.True(t, found)
	require.Empty(t, field.Tag.Get("env"))

	var parsed Options
	_, err := flags.ParseArgs(
		&parsed,
		[]string{"--preflight-legacy-retirement"},
	)
	require.NoError(t, err)
	require.True(t, parsed.PreflightLegacyRetirement)
}

func TestA9MaterialModesAreCLIOnly(t *testing.T) {
	optionsType := reflect.TypeFor[Options]()
	for _, fieldName := range []string{
		"ProvisionA9Material",
		"PreflightA9RuntimeFiles",
	} {
		field, found := optionsType.FieldByName(fieldName)
		require.True(t, found)
		require.Empty(t, field.Tag.Get("env"))
	}

	var parsed Options
	_, err := flags.ParseArgs(
		&parsed,
		[]string{
			"--provision-a9-material=topic-commitment-keys",
		},
	)
	require.NoError(t, err)
	require.Equal(t, "topic-commitment-keys", parsed.ProvisionA9Material)

	parsed = Options{}
	_, err = flags.ParseArgs(
		&parsed,
		[]string{"--preflight-a9-runtime-files"},
	)
	require.NoError(t, err)
	require.True(t, parsed.PreflightA9RuntimeFiles)
}
