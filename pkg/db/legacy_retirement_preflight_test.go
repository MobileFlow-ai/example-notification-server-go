package db_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestLegacyRetirementPreflightPassesWithoutActivating(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	databaseName := preflightTestDatabaseName(t, db)

	output, passed := database.CheckLegacyRetirementPreflight(
		t.Context(),
		db,
	)
	require.True(t, passed)

	encodedDatabaseName, err := json.Marshal(databaseName)
	require.NoError(t, err)
	require.Equal(t, strings.Join([]string{
		"database=" + string(encodedDatabaseName),
		"transaction_read_only=true",
		"schema_migrations_ready=true",
		"only_client_session=true",
		"no_logical_subscription=true",
		"no_enabled_event_trigger=true",
		"legacy_relations_ready=true",
		"activation_marker_empty=true",
		"activation_functions_ready=true",
		"activation_triggers_ready=true",
		"no_named_non_owner_public_create=true",
		"preflight=pass",
		"",
	}, "\n"), output)

	var markerRows int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.count(*)
		   FROM hytch_push_vault.legacy_routing_activation`,
	).Scan(&markerRows))
	require.Zero(t, markerRows)

	var legacyRelations int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.count(*)
		   FROM pg_catalog.pg_class AS relation
		   JOIN pg_catalog.pg_namespace AS namespace
		     ON namespace.oid = relation.relnamespace
		  WHERE namespace.nspname = 'public'
		    AND relation.relname IN (
		        'installations',
		        'device_delivery_mechanisms',
		        'subscriptions',
		        'subscription_hmac_keys'
		    )`,
	).Scan(&legacyRelations))
	require.Equal(t, 4, legacyRelations)
}

func TestLegacyRetirementPreflightRejectsStaleSchema(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 9))

	output, passed := database.CheckLegacyRetirementPreflight(
		t.Context(),
		db,
	)
	require.False(t, passed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		output,
	)
}

func TestLegacyRetirementPreflightRejectsAnotherClientSession(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	databaseName := preflightTestDatabaseName(t, db)

	otherDB, err := database.CreateDB(
		preflightDatabaseDSN(t, databaseName),
		time.Second,
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, otherDB.Close())
	}()
	otherSession, err := otherDB.Conn(t.Context())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, otherSession.Close())
	}()
	_, err = otherSession.ExecContext(t.Context(), `SELECT 1`)
	require.NoError(t, err)

	output, passed := database.CheckLegacyRetirementPreflight(
		t.Context(),
		db,
	)
	require.False(t, passed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		output,
	)
}

func TestLegacyRetirementPreflightRejectsTriggerDrift(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	_, err := db.ExecContext(
		t.Context(),
		`ALTER TABLE hytch_push_vault.legacy_routing_activation
		     DISABLE TRIGGER hytch_legacy_activation_insert_guard`,
	)
	require.NoError(t, err)

	output, passed := database.CheckLegacyRetirementPreflight(
		t.Context(),
		db,
	)
	require.False(t, passed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		output,
	)
}

func TestLegacyRetirementPreflightRejectsMarkerColumnDrift(t *testing.T) {
	tests := map[string]string{
		"extra column": `ALTER TABLE
			hytch_push_vault.legacy_routing_activation
			ADD COLUMN unexpected TEXT`,
		"nullable activated at": `ALTER TABLE
			hytch_push_vault.legacy_routing_activation
			ALTER COLUMN activated_at DROP NOT NULL`,
	}
	for name, statement := range tests {
		t.Run(name, func(t *testing.T) {
			db := testdb.CreateEmptyTestDb(t)
			require.NoError(t, database.Migrate(t.Context(), db))
			_, err := db.ExecContext(t.Context(), statement)
			require.NoError(t, err)

			output, passed := database.CheckLegacyRetirementPreflight(
				t.Context(),
				db,
			)
			require.False(t, passed)
			require.Equal(
				t,
				database.LegacyRetirementPreflightFailureOutput,
				output,
			)
		})
	}
}

func TestLegacyRetirementPreflightRejectsActivationBodyDrift(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	_, err := db.ExecContext(
		t.Context(),
		`CREATE OR REPLACE FUNCTION
		     hytch_push_vault.activate_legacy_routing_retirement(
		         confirmation TEXT
		     )
		 RETURNS VOID
		 LANGUAGE plpgsql
		 SECURITY DEFINER
		 SET search_path = pg_catalog
		 AS $function$
		 BEGIN
		     NULL;
		 END;
		 $function$`,
	)
	require.NoError(t, err)

	output, passed := database.CheckLegacyRetirementPreflight(
		t.Context(),
		db,
	)
	require.False(t, passed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		output,
	)
}

func TestLegacyRetirementPreflightRejectsActivationDefaultArgument(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	addLegacyRetirementConfirmationDefault(t, db)

	output, passed := database.CheckLegacyRetirementPreflight(
		t.Context(),
		db,
	)
	require.False(t, passed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		output,
	)
}

func TestLegacyRetirementPreflightRejectsGuardBodyDrift(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	_, err := db.ExecContext(
		t.Context(),
		`CREATE OR REPLACE FUNCTION
		     hytch_push_vault.reject_legacy_routing_mutation()
		 RETURNS TRIGGER
		 LANGUAGE plpgsql
		 SECURITY DEFINER
		 SET search_path = pg_catalog
		 AS $function$
		 BEGIN
		     RETURN NULL;
		 END;
		 $function$`,
	)
	require.NoError(t, err)

	output, passed := database.CheckLegacyRetirementPreflight(
		t.Context(),
		db,
	)
	require.False(t, passed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		output,
	)
}

func TestLegacyRetirementPreflightRejectsFunctionACLDrift(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	_, err := db.ExecContext(
		t.Context(),
		`GRANT EXECUTE ON FUNCTION
		     hytch_push_vault.activate_legacy_routing_retirement(TEXT)
		 TO PUBLIC`,
	)
	require.NoError(t, err)

	output, passed := database.CheckLegacyRetirementPreflight(
		t.Context(),
		db,
	)
	require.False(t, passed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		output,
	)
}

func TestLegacyRetirementPreflightRejectsNamedPublicCreateGrant(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	roleName := fmt.Sprintf(
		"preflight_non_owner_%d",
		time.Now().UnixNano(),
	)
	_, err := db.ExecContext(
		t.Context(),
		`CREATE ROLE "`+roleName+`" NOLOGIN`,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()
		_, revokeErr := db.ExecContext(
			cleanupContext,
			`REVOKE CREATE ON SCHEMA public FROM "`+roleName+`"`,
		)
		_, dropErr := db.ExecContext(
			cleanupContext,
			`DROP ROLE IF EXISTS "`+roleName+`"`,
		)
		require.NoError(t, revokeErr)
		require.NoError(t, dropErr)
	})
	_, err = db.ExecContext(
		t.Context(),
		`GRANT CREATE ON SCHEMA public TO "`+roleName+`"`,
	)
	require.NoError(t, err)

	output, passed := database.CheckLegacyRetirementPreflight(
		t.Context(),
		db,
	)
	require.False(t, passed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		output,
	)
}

func TestRunLegacyRetirementPreflightHidesConnectionErrors(t *testing.T) {
	const secret = "preflight-secret-must-not-escape"
	dsn := "postgres://operator:" + secret +
		"@127.0.0.1:1/not-a-database?connect_timeout=1"

	output, passed := database.RunLegacyRetirementPreflight(
		t.Context(),
		dsn,
		0,
	)
	require.False(t, passed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		output,
	)
	require.NotContains(t, output, secret)
}

func TestRunLegacyRetirementPreflightHonorsContextWhileConnecting(
	t *testing.T,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	startedAt := time.Now()

	output, passed := database.RunLegacyRetirementPreflight(
		ctx,
		"postgres://operator:secret@127.0.0.1:1/not-a-database",
		time.Hour,
	)

	require.False(t, passed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		output,
	)
	require.Less(t, time.Since(startedAt), 2*time.Second)
}

func TestRunLegacyRetirementPreflightUsesOneContextAwareConnection(
	t *testing.T,
) {
	contents, err := os.ReadFile("legacy_retirement_preflight.go")
	require.NoError(t, err)
	source := string(contents)

	require.Contains(t, source, "db.SetMaxOpenConns(1)")
	require.Contains(t, source, "db.SetMaxIdleConns(1)")
	require.Contains(t, source, "db.PingContext(ctx)")
	require.NotContains(t, source, "CreateDB(dsn, waitForDB)")
}

func TestLegacyRetirementPreflightQueryIsReadOnly(t *testing.T) {
	contents, err := os.ReadFile(preflightSQLPath(t))
	require.NoError(t, err)
	sql := string(contents)

	executableSQL := stripDollarQuotedBody(
		t,
		sql,
		"$activation_source$",
	)
	executableSQL = stripDollarQuotedBody(t, executableSQL, "$source$")
	require.NotRegexp(
		t,
		regexp.MustCompile(
			`(?im)^\s*(INSERT|UPDATE|DELETE|TRUNCATE|DROP|ALTER|CREATE|CALL|LOCK)\b`,
		),
		executableSQL,
	)
	require.NotRegexp(
		t,
		regexp.MustCompile(
			`(?i)\bSELECT\s+hytch_push_vault\.`+
				`activate_legacy_routing_retirement\s*\(`,
		),
		sql,
	)
	require.NotContains(t, sql, `\gset`)
	require.NotContains(t, sql, `\if`)
}

func TestLegacyRetirementPreflightPinsExactActivationBody(t *testing.T) {
	preflightContents, err := os.ReadFile(preflightSQLPath(t))
	require.NoError(t, err)
	migrationContents, err := os.ReadFile(
		filepath.Join(
			"migrations",
			"00011_harden_legacy_retirement_marker_shape.up.sql",
		),
	)
	require.NoError(t, err)

	expectedBody := functionBody(
		t,
		string(migrationContents),
		"CREATE OR REPLACE FUNCTION\n    "+
			"hytch_push_vault.activate_legacy_routing_retirement(",
		"$function$",
	)
	actualBody := delimitedBody(
		t,
		string(preflightContents),
		"$activation_source$",
	)
	require.Equal(t, expectedBody, actualBody)
}

func TestLegacyRetirementPreflightWrapperUsesExistingBinary(t *testing.T) {
	contents, err := os.ReadFile(preflightScriptPath(t))
	require.NoError(t, err)
	script := string(contents)

	require.Contains(t, script, "BRIDGE_SERVER_BINARY")
	require.Contains(t, script, "--preflight-legacy-retirement")
	require.NotContains(t, script, "psql")
	require.NotContains(t, script, "PGDATABASE")
	require.NotContains(t, script, "--migration-db-connection-string")
}

func addLegacyRetirementConfirmationDefault(
	t *testing.T,
	db *sql.DB,
) {
	t.Helper()
	var (
		definition   string
		sourceBefore string
		databaseName string
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.pg_get_functiondef(routine.oid),
		        routine.prosrc,
		        pg_catalog.current_database()
		   FROM pg_catalog.pg_proc AS routine
		  WHERE routine.oid =
		        'hytch_push_vault.activate_legacy_routing_retirement(text)'
		            ::pg_catalog.regprocedure`,
	).Scan(&definition, &sourceBefore, &databaseName))

	const signatureSuffix = "confirmation text)"
	defaultConfirmation := "RETIRE LEGACY PLAINTEXT ROUTING FROM " +
		databaseName
	defaultedDefinition := strings.Replace(
		definition,
		signatureSuffix,
		"confirmation text DEFAULT '"+
			strings.ReplaceAll(defaultConfirmation, "'", "''")+"')",
		1,
	)
	require.NotEqual(t, definition, defaultedDefinition)
	_, err := db.ExecContext(t.Context(), defaultedDefinition)
	require.NoError(t, err)

	var (
		sourceAfter     string
		argumentDefault int
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT routine.prosrc, routine.pronargdefaults
		   FROM pg_catalog.pg_proc AS routine
		  WHERE routine.oid =
		        'hytch_push_vault.activate_legacy_routing_retirement(text)'
		            ::pg_catalog.regprocedure`,
	).Scan(&sourceAfter, &argumentDefault))
	require.Equal(t, sourceBefore, sourceAfter)
	require.Equal(t, 1, argumentDefault)
}

func stripDollarQuotedBody(
	t *testing.T,
	sql string,
	delimiter string,
) string {
	t.Helper()
	start := strings.Index(sql, delimiter)
	require.NotEqual(t, -1, start)
	bodyStart := start + len(delimiter)
	bodyEndOffset := strings.Index(sql[bodyStart:], delimiter)
	require.NotEqual(t, -1, bodyEndOffset)
	bodyEnd := bodyStart + bodyEndOffset + len(delimiter)
	return sql[:start] + delimiter + delimiter + sql[bodyEnd:]
}

func functionBody(
	t *testing.T,
	sql string,
	functionPrefix string,
	delimiter string,
) string {
	t.Helper()
	functionStart := strings.Index(sql, functionPrefix)
	require.NotEqual(t, -1, functionStart)
	return delimitedBody(t, sql[functionStart:], delimiter)
}

func delimitedBody(
	t *testing.T,
	sql string,
	delimiter string,
) string {
	t.Helper()
	start := strings.Index(sql, delimiter)
	require.NotEqual(t, -1, start)
	bodyStart := start + len(delimiter)
	bodyEndOffset := strings.Index(sql[bodyStart:], delimiter)
	require.NotEqual(t, -1, bodyEndOffset)
	return sql[bodyStart : bodyStart+bodyEndOffset]
}

func preflightTestDatabaseName(t *testing.T, db *sql.DB) string {
	t.Helper()
	var databaseName string
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.current_database()`,
	).Scan(&databaseName))
	return databaseName
}

func preflightScriptPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(
		filepath.Join(
			"..",
			"..",
			"dev",
			"railway-legacy-retirement-preflight",
		),
	)
	require.NoError(t, err)
	return path
}

func preflightSQLPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("legacy_retirement_preflight.sql")
	require.NoError(t, err)
	return path
}

func preflightDatabaseDSN(t *testing.T, databaseName string) string {
	t.Helper()
	parsed, err := url.Parse(testdb.TEST_DSN)
	require.NoError(t, err)
	parsed.Path = "/" + databaseName
	return parsed.String()
}
