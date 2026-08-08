package testutils

import (
	"strings"
	"testing"
)

func TestTestDSNUsesRuntimeQAOverride(t *testing.T) {
	override := "postgres://runtime-qa@127.0.0.1:15432/bridge_runtime_qa"
	t.Setenv("BRIDGE_TEST_DSN", override)
	if actual := testDSN(); actual != override {
		t.Fatalf("test DSN = %q, want override %q", actual, override)
	}
}

func TestTestDSNDefaultsToHistoricalPort(t *testing.T) {
	t.Setenv("BRIDGE_TEST_DSN", "")
	if actual := testDSN(); actual != defaultTestDSN {
		t.Fatalf("test DSN = %q, want default %q", actual, defaultTestDSN)
	}
}

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
