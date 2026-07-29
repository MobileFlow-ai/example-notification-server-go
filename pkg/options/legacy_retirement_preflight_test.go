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
