package testutils

import (
	"strings"
	"testing"
)

func TestFormatDatabaseNamePreservesUniqueSuffixWithinPostgresLimit(
	t *testing.T,
) {
	testName := strings.Repeat(
		"TestWelcomeKillSwitchDefaultsClosedAndStopsPersistedAuthority/",
		3,
	)
	first := formatDatabaseName(testName, 123456789012345678)
	second := formatDatabaseName(testName, 123456789012345679)

	if len(first) > postgresIdentifierMaxBytes {
		t.Fatalf(
			"database name is %d bytes; PostgreSQL permits at most %d",
			len(first),
			postgresIdentifierMaxBytes,
		)
	}
	if first == second {
		t.Fatal("unique suffix was lost while bounding database name")
	}
	if !strings.HasSuffix(first, "_123456789012345678") {
		t.Fatalf("database name does not preserve unique suffix: %q", first)
	}
	if !strings.HasSuffix(second, "_123456789012345679") {
		t.Fatalf("database name does not preserve unique suffix: %q", second)
	}
}
