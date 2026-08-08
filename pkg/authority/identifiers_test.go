package authority

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testInstallationID       = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testOtherInstallationID  = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testAccountIncarnationID = "123e4567-e89b-42d3-a456-426614174000"
)

func TestCanonicalAuthorityIdentifiers(t *testing.T) {
	require.True(t, ValidInstallationID(testInstallationID))
	require.False(t, ValidInstallationID(testInstallationID[:63]))
	require.False(t, ValidInstallationID(strings.ToUpper(testInstallationID)))
	require.False(t, ValidInstallationID(strings.Repeat("g", 64)))

	require.True(t, ValidAccountIncarnationID(testAccountIncarnationID))
	require.False(t, ValidAccountIncarnationID(
		strings.ToUpper(testAccountIncarnationID),
	))
	require.False(t, ValidAccountIncarnationID(
		strings.ReplaceAll(testAccountIncarnationID, "-", ""),
	))
	require.False(t, ValidAccountIncarnationID(
		"{"+testAccountIncarnationID+"}",
	))

	require.True(t, ValidEnvironment(EnvironmentDev))
	require.True(t, ValidEnvironment(EnvironmentProduction))
	require.False(t, ValidEnvironment("development"))
	require.False(t, ValidEnvironment("staging"))
}
