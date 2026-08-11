package db_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

const (
	legacyActivationSourceSHA256 = "eb9c48abb59f1b2229365b1c3550d3ae" +
		"fe4e9753b8d05f6ec1f7cae43bae5b52"
	hardenedActivationSourceSHA256 = "8087f6e2453e28ed7df95deada8dd1b9" +
		"9876212fff5b53edbec745fff504e222"
)

func TestLegacyRetirementHardeningMigratesExistingVersionTen(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 10))
	require.Equal(
		t,
		legacyActivationSourceSHA256,
		activationFunctionSourceSHA256(t, db),
	)

	require.NoError(t, database.Migrate(t.Context(), db))
	require.Equal(
		t,
		hardenedActivationSourceSHA256,
		activationFunctionSourceSHA256(t, db),
	)
	require.NoError(t, database.RequireCurrentSchema(t.Context(), db))

	var (
		version int
		dirty   bool
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT version, dirty FROM public.schema_migrations`,
	).Scan(&version, &dirty))
	require.Equal(t, 13, version)
	require.False(t, dirty)
}

func TestLegacyRetirementHardeningDownIsSecurityMonotonic(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	require.Equal(
		t,
		hardenedActivationSourceSHA256,
		activationFunctionSourceSHA256(t, db),
	)

	require.NoError(t, database.MigrateUpTo(t.Context(), db, 10))
	require.Equal(
		t,
		hardenedActivationSourceSHA256,
		activationFunctionSourceSHA256(t, db),
	)

	require.NoError(t, database.MigrateUpTo(t.Context(), db, 11))
	require.Equal(
		t,
		hardenedActivationSourceSHA256,
		activationFunctionSourceSHA256(t, db),
	)
}

func activationFunctionSourceSHA256(
	t *testing.T,
	db *sql.DB,
) string {
	t.Helper()
	var (
		source           string
		argumentDefaults int
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT routine.prosrc, routine.pronargdefaults
		   FROM pg_catalog.pg_proc AS routine
		  WHERE routine.oid =
		        'hytch_push_vault.activate_legacy_routing_retirement(text)'
		            ::pg_catalog.regprocedure`,
	).Scan(&source, &argumentDefaults))
	require.Zero(t, argumentDefaults)
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}
