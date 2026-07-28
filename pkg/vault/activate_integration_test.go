package vault

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestLegacyRoutingRetirementRequiresExactConfirmationAndPreservesVault(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	store := &Store{db: db}
	seedSecureVaultBinding(t, db)
	seedLegacyRouting(t, db)

	before := captureLegacyRoutingSnapshot(t, db)
	_, err := db.ExecContext(
		t.Context(),
		`SELECT hytch_push_vault.activate_legacy_routing_retirement($1)`,
		legacyRoutingRetirementConfirmation(t, db)+" ",
	)
	requireSQLState(t, err, "22023")
	require.Equal(t, before, captureLegacyRoutingSnapshot(t, db))
	require.ErrorIs(
		t,
		store.RequireLegacyPlaintextRoutingDisabled(t.Context()),
		ErrLegacyPlaintextRoutingEnabled,
	)

	activateLegacyRoutingRetirement(t, db)
	requireLegacyRoutingObjectsAbsent(t, db)
	requireActivationMarkerCount(t, db, 1)

	var secureProductionCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.vault_key_bindings
		  WHERE environment = 2
		    AND lookup_root_commitment = $1`,
		bytes.Repeat([]byte{0x31}, 32),
	).Scan(&secureProductionCount))
	require.Equal(t, 1, secureProductionCount)

	// The owner/migration role is deliberately rejected as a runtime role.
	require.ErrorIs(
		t,
		store.RequireLegacyPlaintextRoutingDisabled(t.Context()),
		ErrLegacyRoutingBarrierInvalid,
	)
}

func TestLegacyRoutingRetirementCannotBeBypassedByReplicaRole(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	activateLegacyRoutingRetirement(t, db)

	replicaConnection, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer func() {
		_, _ = replicaConnection.ExecContext(
			context.Background(),
			`RESET session_replication_role`,
		)
		_ = replicaConnection.Close()
	}()
	_, err = replicaConnection.ExecContext(
		t.Context(),
		`SET session_replication_role = replica`,
	)
	require.NoError(t, err)

	legacyWrites := []string{
		`INSERT INTO public.installations DEFAULT VALUES`,
		`INSERT INTO public.device_delivery_mechanisms DEFAULT VALUES`,
		`INSERT INTO public.subscriptions DEFAULT VALUES`,
		`INSERT INTO public.subscription_hmac_keys DEFAULT VALUES`,
	}
	for _, statement := range legacyWrites {
		_, err = replicaConnection.ExecContext(t.Context(), statement)
		requireSQLState(t, err, "42P01")
	}

	markerMutations := []string{
		`INSERT INTO hytch_push_vault.legacy_routing_activation (
		     singleton,
		     activated_at
		 ) VALUES (TRUE, clock_timestamp())`,
		`UPDATE hytch_push_vault.legacy_routing_activation
		    SET activated_at = clock_timestamp()
		  WHERE singleton`,
		`DELETE FROM hytch_push_vault.legacy_routing_activation
		  WHERE singleton`,
		`TRUNCATE TABLE hytch_push_vault.legacy_routing_activation`,
	}
	for _, statement := range markerMutations {
		_, err = replicaConnection.ExecContext(t.Context(), statement)
		requireSQLState(t, err, "55000")
	}
	requireActivationMarkerCount(t, db, 1)
}

func TestLegacyRoutingRetirementRejectsPreActivationSnapshots(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)

	staleWriter, err := db.BeginTx(
		t.Context(),
		&sql.TxOptions{Isolation: sql.LevelRepeatableRead},
	)
	require.NoError(t, err)
	defer func() { _ = staleWriter.Rollback() }()
	var pinned int
	require.NoError(
		t,
		staleWriter.QueryRowContext(t.Context(), `SELECT 1`).Scan(&pinned),
	)

	staleMarker, err := db.BeginTx(
		t.Context(),
		&sql.TxOptions{Isolation: sql.LevelRepeatableRead},
	)
	require.NoError(t, err)
	defer func() { _ = staleMarker.Rollback() }()
	require.NoError(
		t,
		staleMarker.QueryRowContext(t.Context(), `SELECT 1`).Scan(&pinned),
	)

	activateLegacyRoutingRetirement(t, db)

	_, err = staleWriter.ExecContext(
		t.Context(),
		`INSERT INTO public.installations (id) VALUES ('stale-writer')`,
	)
	require.Error(t, err)
	_, err = staleMarker.ExecContext(
		t.Context(),
		`TRUNCATE TABLE hytch_push_vault.legacy_routing_activation`,
	)
	requireSQLState(t, err, "55000")
}

func TestLegacyRoutingGatePassesRestrictedRuntimeRole(t *testing.T) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	activateLegacyRoutingRetirement(t, db)
	role := createRestrictedGateRole(t, db)
	store := &Store{db: db}

	setRole(t, db, role)
	schemaErr := database.RequireCurrentSchema(t.Context(), db)
	gateErr := store.RequireLegacyPlaintextRoutingDisabled(t.Context())
	resetRole(t, db)

	require.NoError(t, schemaErr)
	require.NoError(t, gateErr)
}

func TestLegacyRoutingGateRejectsBarrierTampering(t *testing.T) {
	requireVaultIntegrationTests(t)
	testCases := []struct {
		name    string
		tamper  func(*testing.T, *sql.DB, string)
		wantErr error
	}{
		{
			name: "recreated legacy relation",
			tamper: func(t *testing.T, db *sql.DB, _ string) {
				_, err := db.ExecContext(
					t.Context(),
					`CREATE TABLE public.installations (id TEXT)`,
				)
				require.NoError(t, err)
			},
			wantErr: ErrLegacyPlaintextRoutingEnabled,
		},
		{
			name: "disabled marker trigger",
			tamper: func(t *testing.T, db *sql.DB, _ string) {
				_, err := db.ExecContext(
					t.Context(),
					`ALTER TABLE
					     hytch_push_vault.legacy_routing_activation
					 DISABLE TRIGGER
					     hytch_legacy_activation_truncate_guard`,
				)
				require.NoError(t, err)
			},
			wantErr: ErrLegacyRoutingBarrierInvalid,
		},
		{
			name: "marker trigger with WHEN clause",
			tamper: func(t *testing.T, db *sql.DB, _ string) {
				_, err := db.ExecContext(
					t.Context(),
					`DROP TRIGGER hytch_legacy_activation_dml_guard
					     ON hytch_push_vault.legacy_routing_activation;
					 CREATE TRIGGER hytch_legacy_activation_dml_guard
					 BEFORE UPDATE OR DELETE
					 ON hytch_push_vault.legacy_routing_activation
					 FOR EACH ROW
					 WHEN (FALSE)
					 EXECUTE FUNCTION
					     hytch_push_vault.reject_legacy_routing_mutation();
					 ALTER TABLE
					     hytch_push_vault.legacy_routing_activation
					 ENABLE ALWAYS TRIGGER
					     hytch_legacy_activation_dml_guard`,
				)
				require.NoError(t, err)
			},
			wantErr: ErrLegacyRoutingBarrierInvalid,
		},
		{
			name: "marker trigger redirected",
			tamper: func(t *testing.T, db *sql.DB, _ string) {
				_, err := db.ExecContext(
					t.Context(),
					`CREATE FUNCTION
					     hytch_push_vault.test_marker_noop()
					 RETURNS TRIGGER
					 LANGUAGE plpgsql
					 AS $function$
					 BEGIN
					     RETURN NEW;
					 END;
					 $function$;
					 DROP TRIGGER hytch_legacy_activation_insert_guard
					     ON hytch_push_vault.legacy_routing_activation;
					 CREATE TRIGGER hytch_legacy_activation_insert_guard
					 BEFORE INSERT
					 ON hytch_push_vault.legacy_routing_activation
					 FOR EACH STATEMENT
					 EXECUTE FUNCTION
					     hytch_push_vault.test_marker_noop();
					 ALTER TABLE
					     hytch_push_vault.legacy_routing_activation
					 ENABLE ALWAYS TRIGGER
					     hytch_legacy_activation_insert_guard`,
				)
				require.NoError(t, err)
			},
			wantErr: ErrLegacyRoutingBarrierInvalid,
		},
		{
			name: "reject function replaced with no-op",
			tamper: func(t *testing.T, db *sql.DB, _ string) {
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
					     RETURN NEW;
					 END;
					 $function$`,
				)
				require.NoError(t, err)
			},
			wantErr: ErrLegacyRoutingBarrierInvalid,
		},
		{
			name: "marker RLS",
			tamper: func(t *testing.T, db *sql.DB, _ string) {
				_, err := db.ExecContext(
					t.Context(),
					`ALTER TABLE
					     hytch_push_vault.legacy_routing_activation
					 ENABLE ROW LEVEL SECURITY;
					 CREATE POLICY hytch_test_marker_visibility
					 ON hytch_push_vault.legacy_routing_activation
					 FOR SELECT
					 USING (TRUE)`,
				)
				require.NoError(t, err)
			},
			wantErr: ErrLegacyRoutingBarrierInvalid,
		},
		{
			name: "marker rewrite rule",
			tamper: func(t *testing.T, db *sql.DB, _ string) {
				_, err := db.ExecContext(
					t.Context(),
					`CREATE RULE hytch_test_marker_rule
					 AS ON UPDATE
					 TO hytch_push_vault.legacy_routing_activation
					 DO ALSO NOTHING`,
				)
				require.NoError(t, err)
			},
			wantErr: ErrLegacyRoutingBarrierInvalid,
		},
		{
			name: "runtime has direct retirement execute",
			tamper: func(t *testing.T, db *sql.DB, role string) {
				_, err := db.ExecContext(
					t.Context(),
					fmt.Sprintf(
						`GRANT EXECUTE ON FUNCTION
						     hytch_push_vault.
						     activate_legacy_routing_retirement(TEXT)
						 TO %s`,
						quotePostgresIdentifier(role),
					),
				)
				require.NoError(t, err)
			},
			wantErr: ErrLegacyRoutingBarrierInvalid,
		},
		{
			name: "disabled current database subscription",
			tamper: func(t *testing.T, db *sql.DB, _ string) {
				createDisabledCurrentDatabaseSubscription(t, db)
			},
			wantErr: ErrLegacyRoutingBarrierInvalid,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			db := testdb.CreateTestDb(t)
			activateLegacyRoutingRetirement(t, db)
			role := createRestrictedGateRole(t, db)
			store := &Store{db: db}

			require.NoError(
				t,
				runLegacyRoutingGateAsRole(t, db, store, role),
			)
			testCase.tamper(t, db, role)
			require.ErrorIs(
				t,
				runLegacyRoutingGateAsRole(t, db, store, role),
				testCase.wantErr,
			)
		})
	}
}

func TestLegacyRoutingRetirementRollsBackWhenDependentViewBlocksDrop(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	seedSecureVaultBinding(t, db)
	seedLegacyRouting(t, db)
	_, err := db.ExecContext(
		t.Context(),
		`CREATE VIEW public.hytch_test_legacy_installations AS
		 SELECT id
		   FROM public.installations`,
	)
	require.NoError(t, err)
	before := captureLegacyRoutingSnapshot(t, db)

	_, err = db.ExecContext(
		t.Context(),
		`SELECT hytch_push_vault.activate_legacy_routing_retirement($1)`,
		legacyRoutingRetirementConfirmation(t, db),
	)
	requireSQLState(t, err, "2BP01")

	require.Equal(t, before, captureLegacyRoutingSnapshot(t, db))
	requireActivationMarkerCount(t, db, 0)
	var viewStillExists bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT to_regclass(
		     'public.hytch_test_legacy_installations'
		 ) IS NOT NULL`,
	).Scan(&viewStillExists))
	require.True(t, viewStillExists)
}

func TestLegacyRoutingRetirementRejectsEnabledEventTrigger(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	seedLegacyRouting(t, db)
	installNoopEventTrigger(t, db)
	_, err := db.ExecContext(
		t.Context(),
		`ALTER EVENT TRIGGER hytch_test_enabled_event_trigger
		 ENABLE REPLICA`,
	)
	require.NoError(t, err)
	before := captureLegacyRoutingSnapshot(t, db)

	_, err = db.ExecContext(
		t.Context(),
		`SELECT hytch_push_vault.activate_legacy_routing_retirement($1)`,
		legacyRoutingRetirementConfirmation(t, db),
	)
	requireSQLState(t, err, "55000")
	require.Equal(t, before, captureLegacyRoutingSnapshot(t, db))
	requireActivationMarkerCount(t, db, 0)
}

func TestLegacyRoutingRetirementRejectsDisabledCurrentDatabaseSubscription(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	seedLegacyRouting(t, db)
	createDisabledCurrentDatabaseSubscription(t, db)
	before := captureLegacyRoutingSnapshot(t, db)

	_, err := db.ExecContext(
		t.Context(),
		`SELECT hytch_push_vault.activate_legacy_routing_retirement($1)`,
		legacyRoutingRetirementConfirmation(t, db),
	)
	requireSQLState(t, err, "55000")
	require.Equal(t, before, captureLegacyRoutingSnapshot(t, db))
	requireActivationMarkerCount(t, db, 0)

	var subscriptionCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM pg_catalog.pg_subscription
		  WHERE subdbid = (
		      SELECT oid
		        FROM pg_catalog.pg_database
		       WHERE datname = current_database()
		  )`,
	).Scan(&subscriptionCount))
	require.Equal(t, 1, subscriptionCount)
}

func TestLegacyRoutingRetirementRejectsNonOwnerPublicCreateGrant(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	seedLegacyRouting(t, db)
	role := createRestrictedGateRole(t, db)
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`GRANT CREATE ON SCHEMA public TO %s`,
			quotePostgresIdentifier(role),
		),
	)
	require.NoError(t, err)
	before := captureLegacyRoutingSnapshot(t, db)
	createGrantCountBefore := publicNonOwnerCreateGrantCount(t, db)
	require.Positive(t, createGrantCountBefore)

	_, err = db.ExecContext(
		t.Context(),
		`SELECT hytch_push_vault.activate_legacy_routing_retirement($1)`,
		legacyRoutingRetirementConfirmation(t, db),
	)
	requireSQLState(t, err, "55000")
	require.Equal(t, before, captureLegacyRoutingSnapshot(t, db))
	require.Equal(
		t,
		createGrantCountBefore,
		publicNonOwnerCreateGrantCount(t, db),
	)
	requireActivationMarkerCount(t, db, 0)

	var roleStillHasCreate bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT has_schema_privilege($1, 'public', 'CREATE')`,
		role,
	).Scan(&roleStillHasCreate))
	require.True(t, roleStillHasCreate)
}

func TestLegacyRoutingRetirementRejectsOwnerMismatch(t *testing.T) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	seedLegacyRouting(t, db)
	role := createOwnerMismatchRole(t, db)
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`ALTER TABLE public.installations OWNER TO %s`,
			quotePostgresIdentifier(role),
		),
	)
	require.NoError(t, err)
	before := captureLegacyRoutingSnapshot(t, db)

	_, err = db.ExecContext(
		t.Context(),
		`SELECT hytch_push_vault.activate_legacy_routing_retirement($1)`,
		legacyRoutingRetirementConfirmation(t, db),
	)
	requireSQLState(t, err, "55000")
	require.Equal(t, before, captureLegacyRoutingSnapshot(t, db))
	requireActivationMarkerCount(t, db, 0)
}

type legacyRoutingSnapshot struct {
	installationOID              int64
	deliveryMechanismOID         int64
	subscriptionOID              int64
	subscriptionHMACKeyOID       int64
	deliveryMechanismSequenceOID int64
	subscriptionSequenceOID      int64
	installationCount            int64
	deliveryMechanismCount       int64
	subscriptionCount            int64
	subscriptionHMACKeyCount     int64
	markerCount                  int64
	secureVaultBindingCount      int64
}

func captureLegacyRoutingSnapshot(
	t *testing.T,
	db *sql.DB,
) legacyRoutingSnapshot {
	t.Helper()
	var snapshot legacyRoutingSnapshot
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
		     'public.installations'::pg_catalog.regclass::OID::BIGINT,
		     'public.device_delivery_mechanisms'
		         ::pg_catalog.regclass::OID::BIGINT,
		     'public.subscriptions'::pg_catalog.regclass::OID::BIGINT,
		     'public.subscription_hmac_keys'
		         ::pg_catalog.regclass::OID::BIGINT,
		     'public.device_delivery_mechanisms_id_seq'
		         ::pg_catalog.regclass::OID::BIGINT,
		     'public.subscriptions_id_seq'
		         ::pg_catalog.regclass::OID::BIGINT,
		     (SELECT COUNT(*) FROM public.installations),
		     (
		         SELECT COUNT(*)
		           FROM public.device_delivery_mechanisms
		     ),
		     (SELECT COUNT(*) FROM public.subscriptions),
		     (SELECT COUNT(*) FROM public.subscription_hmac_keys),
		     (
		         SELECT COUNT(*)
		           FROM hytch_push_vault.legacy_routing_activation
		     ),
		     (
		         SELECT COUNT(*)
		           FROM hytch_push_vault.vault_key_bindings
		     )`,
	).Scan(
		&snapshot.installationOID,
		&snapshot.deliveryMechanismOID,
		&snapshot.subscriptionOID,
		&snapshot.subscriptionHMACKeyOID,
		&snapshot.deliveryMechanismSequenceOID,
		&snapshot.subscriptionSequenceOID,
		&snapshot.installationCount,
		&snapshot.deliveryMechanismCount,
		&snapshot.subscriptionCount,
		&snapshot.subscriptionHMACKeyCount,
		&snapshot.markerCount,
		&snapshot.secureVaultBindingCount,
	))
	return snapshot
}

func seedSecureVaultBinding(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.vault_key_bindings (
		     environment,
		     lookup_root_commitment,
		     bound_at
		 ) VALUES (2, $1, $2)`,
		bytes.Repeat([]byte{0x31}, 32),
		time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
	)
	require.NoError(t, err)
}

func seedLegacyRouting(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO public.installations (id)
		 VALUES ('legacy-installation');
		 INSERT INTO public.device_delivery_mechanisms (
		     installation_id,
		     kind,
		     token
		 ) VALUES (
		     'legacy-installation',
		     'apns',
		     'synthetic-token'
		 );
		 INSERT INTO public.subscriptions (
		     installation_id,
		     topic,
		     is_active,
		     is_silent
		 ) VALUES (
		     'legacy-installation',
		     decode('0001', 'hex'),
		     TRUE,
		     FALSE
		 );
		 INSERT INTO public.subscription_hmac_keys (
		     subscription_id,
		     thirty_day_periods_since_epoch,
		     key
		 ) SELECT
		     id,
		     1,
		     decode('01', 'hex')
		   FROM public.subscriptions
		  WHERE installation_id = 'legacy-installation'`,
	)
	require.NoError(t, err)
}

func requireLegacyRoutingObjectsAbsent(t *testing.T, db *sql.DB) {
	t.Helper()
	objectNames := []string{
		"public.installations",
		"public.device_delivery_mechanisms",
		"public.subscriptions",
		"public.subscription_hmac_keys",
		"public.device_delivery_mechanisms_id_seq",
		"public.subscriptions_id_seq",
	}
	for _, objectName := range objectNames {
		var absent bool
		require.NoError(t, db.QueryRowContext(
			t.Context(),
			`SELECT to_regclass($1) IS NULL`,
			objectName,
		).Scan(&absent))
		require.True(t, absent, objectName)
	}
}

func requireActivationMarkerCount(
	t *testing.T,
	db *sql.DB,
	expected int,
) {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.legacy_routing_activation
		  WHERE singleton`,
	).Scan(&count))
	require.Equal(t, expected, count)
}

func legacyRoutingRetirementConfirmation(t *testing.T, db *sql.DB) string {
	t.Helper()
	var databaseName string
	require.NoError(
		t,
		db.QueryRowContext(t.Context(), `SELECT current_database()`).
			Scan(&databaseName),
	)
	return "RETIRE LEGACY PLAINTEXT ROUTING FROM " + databaseName
}

func activateLegacyRoutingRetirement(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		`SELECT hytch_push_vault.activate_legacy_routing_retirement($1)`,
		legacyRoutingRetirementConfirmation(t, db),
	)
	require.NoError(t, err)
}

func createRestrictedGateRole(t *testing.T, db *sql.DB) string {
	t.Helper()
	role := fmt.Sprintf("hytch_gate_%d", time.Now().UnixNano())
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`CREATE ROLE %s NOLOGIN`,
			quotePostgresIdentifier(role),
		),
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`GRANT USAGE
			     ON SCHEMA hytch_push_vault
			 TO %[1]s;
			 GRANT SELECT
			     ON public.schema_migrations,
			        hytch_push_vault.legacy_routing_activation
			 TO %[1]s`,
			quotePostgresIdentifier(role),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `RESET ROLE`)
		_, _ = db.ExecContext(
			context.Background(),
			fmt.Sprintf(
				`DROP OWNED BY %s`,
				quotePostgresIdentifier(role),
			),
		)
		_, _ = db.ExecContext(
			context.Background(),
			fmt.Sprintf(
				`DROP ROLE IF EXISTS %s`,
				quotePostgresIdentifier(role),
			),
		)
	})
	return role
}

func createOwnerMismatchRole(t *testing.T, db *sql.DB) string {
	t.Helper()
	role := fmt.Sprintf("hytch_owner_mismatch_%d", time.Now().UnixNano())
	var originalOwner string
	require.NoError(
		t,
		db.QueryRowContext(t.Context(), `SELECT current_user`).
			Scan(&originalOwner),
	)
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`CREATE ROLE %s NOLOGIN`,
			quotePostgresIdentifier(role),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(
			context.Background(),
			fmt.Sprintf(
				`ALTER TABLE IF EXISTS public.installations OWNER TO %s`,
				quotePostgresIdentifier(originalOwner),
			),
		)
		_, _ = db.ExecContext(
			context.Background(),
			fmt.Sprintf(
				`DROP OWNED BY %s`,
				quotePostgresIdentifier(role),
			),
		)
		_, _ = db.ExecContext(
			context.Background(),
			fmt.Sprintf(
				`DROP ROLE IF EXISTS %s`,
				quotePostgresIdentifier(role),
			),
		)
	})
	return role
}

func runLegacyRoutingGateAsRole(
	t *testing.T,
	db *sql.DB,
	store *Store,
	role string,
) error {
	t.Helper()
	setRole(t, db, role)
	err := store.RequireLegacyPlaintextRoutingDisabled(t.Context())
	resetRole(t, db)
	return err
}

func setRole(t *testing.T, db *sql.DB, role string) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(`SET ROLE %s`, quotePostgresIdentifier(role)),
	)
	require.NoError(t, err)
}

func resetRole(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `RESET ROLE`)
	require.NoError(t, err)
}

func installNoopEventTrigger(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		`CREATE FUNCTION public.hytch_test_event_trigger()
		 RETURNS event_trigger
		 LANGUAGE plpgsql
		 AS $function$
		 BEGIN
		     NULL;
		 END;
		 $function$;
		 CREATE EVENT TRIGGER hytch_test_enabled_event_trigger
		 ON ddl_command_start
		 EXECUTE FUNCTION public.hytch_test_event_trigger()`,
	)
	require.NoError(t, err)
}

func createDisabledCurrentDatabaseSubscription(
	t *testing.T,
	db *sql.DB,
) {
	t.Helper()
	_, err := db.ExecContext(
		t.Context(),
		`CREATE SUBSCRIPTION hytch_test_disabled_subscription
		 CONNECTION
		     'host=127.0.0.1 port=1 dbname=unreachable'
		 PUBLICATION hytch_test_publication
		 WITH (
		     connect = false,
		     create_slot = false,
		     enabled = false,
		     slot_name = NONE
		 )`,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `RESET ROLE`)
		_, _ = db.ExecContext(
			context.Background(),
			`DROP SUBSCRIPTION IF EXISTS
			     hytch_test_disabled_subscription`,
		)
	})
}

func publicNonOwnerCreateGrantCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM pg_catalog.pg_namespace AS namespace
		   CROSS JOIN LATERAL pg_catalog.aclexplode(
		       COALESCE(
		           namespace.nspacl,
		           pg_catalog.acldefault('n', namespace.nspowner)
		       )
		   ) AS privilege
		  WHERE namespace.nspname = 'public'
		    AND privilege.privilege_type = 'CREATE'
		    AND privilege.grantee <> namespace.nspowner`,
	).Scan(&count))
	return count
}

func requireSQLState(t *testing.T, err error, expected string) {
	t.Helper()
	require.Error(t, err)
	var pgError *pgconn.PgError
	require.ErrorAs(t, err, &pgError)
	require.Equal(t, expected, pgError.Code)
}

func quotePostgresIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
