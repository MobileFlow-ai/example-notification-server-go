package db_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a3trust"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestA3WitnessStoreDurableReplayForkAndPredecessor(t *testing.T) {
	db := testdb.CreateTestDb(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	keyID := a3trust.WitnessKeyID(privateKey.Public().(ed25519.PublicKey))
	store := database.NewA3WitnessStore(db)
	first, leafZero, leafOne := firstA3Proposal(t, 1750000000123)
	accepted, err := store.AcceptDirectoryTreeHead(t.Context(), first, privateKey, keyID)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(privateKey.Public().(ed25519.PublicKey), first.CanonicalHead, accepted.Signature[:]))

	// A new store instance models process restart and must return the exact
	// persisted receipt after a lost response.
	replayed, err := database.NewA3WitnessStore(db).AcceptDirectoryTreeHead(
		t.Context(), first, privateKey, keyID,
	)
	require.NoError(t, err)
	require.True(t, replayed.Replay)
	require.Equal(t, accepted.KeyID, replayed.KeyID)
	require.Equal(t, accepted.Signature, replayed.Signature)
	require.NoError(t, database.NewA3WitnessStore(db).RequireKeyContinuity(
		t.Context(),
		"dev",
		privateKey.Public().(ed25519.PublicKey),
	))
	replacementKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x22}, ed25519.SeedSize),
	)
	_, err = database.NewA3WitnessStore(db).AcceptDirectoryTreeHead(
		t.Context(),
		first,
		replacementKey,
		a3trust.WitnessKeyID(replacementKey.Public().(ed25519.PublicKey)),
	)
	require.ErrorIs(t, err, a3trust.ErrUnavailable)
	require.ErrorIs(
		t,
		database.NewA3WitnessStore(db).RequireKeyContinuity(
			t.Context(),
			"dev",
			replacementKey.Public().(ed25519.PublicKey),
		),
		a3trust.ErrUnavailable,
	)
	var rowsAfterRejectedRotation int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.count(*)
		   FROM hytch_push_vault.a3_directory_witness_heads
		  WHERE environment = 1`,
	).Scan(&rowsAfterRejectedRotation))
	require.Equal(t, 1, rowsAfterRejectedRotation)

	fork := first
	fork.Head.RootHash = hex.EncodeToString(bytes.Repeat([]byte{0x55}, sha256.Size))
	fork.CanonicalHead, err = a3trust.CanonicalTreeHead(fork.Head)
	require.NoError(t, err)
	_, err = store.AcceptDirectoryTreeHead(t.Context(), fork, privateKey, keyID)
	require.ErrorIs(t, err, a3trust.ErrFork)

	secondRoot := a3NodeHash(leafZero, leafOne)
	second := a3trust.WitnessProposal{Head: a3trust.TreeHead{
		Domain: "hytch.directory.tree-head/v1", Environment: "dev",
		PriorRootHash: hex.EncodeToString(leafZero[:]), PriorTreeSize: 1,
		Protocol: 1, RootHash: hex.EncodeToString(secondRoot[:]),
		TimestampMS: 1750000001123, TreeSize: 2,
	}, ConsistencyProof: [][32]byte{leafOne},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	second.CanonicalHead, err = a3trust.CanonicalTreeHead(second.Head)
	require.NoError(t, err)
	_, err = store.AcceptDirectoryTreeHead(t.Context(), second, privateKey, keyID)
	require.NoError(t, err)
	historicalReplay, err := store.AcceptDirectoryTreeHead(
		t.Context(), first, privateKey, keyID,
	)
	require.NoError(t, err)
	require.True(t, historicalReplay.Replay)
	require.Equal(t, accepted.Signature, historicalReplay.Signature)

	leafTwo := a3LeafHash([]byte("two"))
	rootThree := a3NodeHash(secondRoot, leafTwo)
	wrongPredecessor := a3trust.WitnessProposal{Head: a3trust.TreeHead{
		Domain: "hytch.directory.tree-head/v1", Environment: "dev",
		PriorRootHash: hex.EncodeToString(leafZero[:]), PriorTreeSize: 1,
		Protocol: 1, RootHash: hex.EncodeToString(rootThree[:]),
		TimestampMS: 1750000002123, TreeSize: 3,
	}, ConsistencyProof: [][32]byte{leafOne, leafTwo},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	wrongPredecessor.CanonicalHead, err = a3trust.CanonicalTreeHead(wrongPredecessor.Head)
	require.NoError(t, err)
	require.True(t, a3trust.VerifyWitnessExtension(wrongPredecessor.Head, wrongPredecessor.ConsistencyProof))
	_, err = store.AcceptDirectoryTreeHead(t.Context(), wrongPredecessor, privateKey, keyID)
	require.ErrorIs(t, err, a3trust.ErrFork)

	timestampRollback := a3trust.WitnessProposal{Head: a3trust.TreeHead{
		Domain: "hytch.directory.tree-head/v1", Environment: "dev",
		PriorRootHash: hex.EncodeToString(secondRoot[:]), PriorTreeSize: 2,
		Protocol: 1, RootHash: hex.EncodeToString(rootThree[:]),
		TimestampMS: second.Head.TimestampMS - 1, TreeSize: 3,
	}, ConsistencyProof: [][32]byte{leafTwo},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	timestampRollback.CanonicalHead, err = a3trust.CanonicalTreeHead(timestampRollback.Head)
	require.NoError(t, err)
	require.True(t, a3trust.VerifyWitnessExtension(timestampRollback.Head, timestampRollback.ConsistencyProof))
	_, err = store.AcceptDirectoryTreeHead(t.Context(), timestampRollback, privateKey, keyID)
	require.ErrorIs(t, err, a3trust.ErrFork)

	_, err = db.ExecContext(t.Context(), `UPDATE hytch_push_vault.a3_directory_witness_heads SET timestamp_ms = timestamp_ms + 1 WHERE environment = 1`)
	require.Error(t, err)
}

func TestA3WitnessStoreExpiredReplayRemainsExactAndDurable(t *testing.T) {
	db := testdb.CreateTestDb(t)
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x29}, ed25519.SeedSize),
	)
	keyID := a3trust.WitnessKeyID(
		privateKey.Public().(ed25519.PublicKey),
	)
	proposal, _, _ := firstA3Proposal(t, 1750000000123)
	accepted, err := database.NewA3WitnessStore(db).AcceptDirectoryTreeHead(
		t.Context(),
		proposal,
		privateKey,
		keyID,
	)
	require.NoError(t, err)

	proposal.NotBefore = time.Now().UTC().Add(-2 * time.Hour)
	proposal.NotAfter = time.Now().UTC().Add(-time.Hour)
	replayed, err := database.NewA3WitnessStore(db).AcceptDirectoryTreeHead(
		t.Context(),
		proposal,
		privateKey,
		keyID,
	)
	require.NoError(t, err)
	require.True(t, replayed.Replay)
	require.Equal(t, accepted.KeyID, replayed.KeyID)
	require.Equal(t, accepted.Signature, replayed.Signature)

	conflict := proposal
	conflict.Head.RootHash = hex.EncodeToString(
		bytes.Repeat([]byte{0x77}, sha256.Size),
	)
	conflict.CanonicalHead, err = a3trust.CanonicalTreeHead(conflict.Head)
	require.NoError(t, err)
	_, err = database.NewA3WitnessStore(db).AcceptDirectoryTreeHead(
		t.Context(),
		conflict,
		privateKey,
		keyID,
	)
	require.ErrorIs(t, err, a3trust.ErrFork)

	var rows int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.count(*)
		   FROM hytch_push_vault.a3_directory_witness_heads
		  WHERE environment = 1`,
	).Scan(&rows))
	require.Equal(t, 1, rows)
}

func TestA3WitnessStoreSerializesConcurrentFirstHead(t *testing.T) {
	db := testdb.CreateTestDb(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	keyID := a3trust.WitnessKeyID(privateKey.Public().(ed25519.PublicKey))
	first, _, _ := firstA3Proposal(t, 1750000000123)
	other := first
	other.Head.RootHash = hex.EncodeToString(bytes.Repeat([]byte{0x66}, sha256.Size))
	var err error
	other.CanonicalHead, err = a3trust.CanonicalTreeHead(other.Head)
	require.NoError(t, err)

	start := make(chan struct{})
	errorsSeen := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, proposal := range []a3trust.WitnessProposal{first, other} {
		proposal := proposal
		go func() {
			ready.Done()
			<-start
			_, acceptErr := database.NewA3WitnessStore(db).AcceptDirectoryTreeHead(
				t.Context(), proposal, privateKey, keyID,
			)
			errorsSeen <- acceptErr
		}()
	}
	ready.Wait()
	close(start)
	firstErr := <-errorsSeen
	secondErr := <-errorsSeen
	require.True(t,
		(firstErr == nil && errors.Is(secondErr, a3trust.ErrFork)) ||
			(secondErr == nil && errors.Is(firstErr, a3trust.ErrFork)),
	)
	var count int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT pg_catalog.count(*) FROM hytch_push_vault.a3_directory_witness_heads WHERE environment = 1`).Scan(&count))
	require.Equal(t, 1, count)
}

func TestA3WitnessStoreRechecksFreshnessAfterSerializationLock(t *testing.T) {
	db := testdb.CreateTestDb(t)
	blocker, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback() }()
	_, err = blocker.ExecContext(
		t.Context(),
		`SELECT pg_catalog.pg_advisory_xact_lock($1, $2)`,
		0x413357,
		1,
	)
	require.NoError(t, err)

	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x35}, ed25519.SeedSize),
	)
	keyID := a3trust.WitnessKeyID(
		privateKey.Public().(ed25519.PublicKey),
	)
	proposal, _, _ := firstA3Proposal(
		t,
		uint64(time.Now().UTC().UnixMilli()),
	)
	proposal.NotBefore = time.Now().UTC().Add(-time.Minute)
	proposal.NotAfter = time.Now().UTC().Add(2 * time.Second)
	done := make(chan error, 1)
	go func() {
		_, acceptErr := database.NewA3WitnessStore(db).
			AcceptDirectoryTreeHead(
				t.Context(),
				proposal,
				privateKey,
				keyID,
			)
		done <- acceptErr
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		queryErr := db.QueryRowContext(
			t.Context(),
			`SELECT EXISTS (
			     SELECT 1
			       FROM pg_catalog.pg_locks
			      WHERE locktype = 'advisory'
			        AND classid = $1::pg_catalog.oid
			        AND objid = $2::pg_catalog.oid
			        AND NOT granted
			 )`,
			0x413357,
			1,
		).Scan(&waiting)
		return queryErr == nil && waiting
	}, time.Second, 10*time.Millisecond)
	if remaining := time.Until(proposal.NotAfter); remaining > 0 {
		time.Sleep(remaining + 50*time.Millisecond)
	}
	require.NoError(t, blocker.Commit())
	select {
	case acceptErr := <-done:
		require.ErrorIs(t, acceptErr, a3trust.ErrUnavailable)
	case <-time.After(5 * time.Second):
		t.Fatal("A3 witness acceptance did not resume after lock release")
	}
	var rows int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.count(*)
		   FROM hytch_push_vault.a3_directory_witness_heads
		  WHERE environment = 1`,
	).Scan(&rows))
	require.Zero(t, rows)
}

func TestA3WitnessActivationBarrierRequiresRestrictedRuntimeRole(t *testing.T) {
	db := testdb.CreateTestDb(t)
	store := database.NewA3WitnessStore(db)
	require.ErrorIs(
		t,
		store.RequireActivationBarrier(t.Context()),
		database.ErrA3WitnessBarrierInvalid,
	)
	role := createA3WitnessRuntimeRole(t, db)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(`SET ROLE %s`, quoteA3Role(role)),
	)
	require.NoError(t, err)
	require.ErrorIs(
		t,
		store.RequireActivationBarrier(t.Context()),
		database.ErrA3WitnessBarrierInvalid,
	)
	_, err = db.ExecContext(t.Context(), `RESET ROLE`)
	require.NoError(t, err)
	runtimeDB := openA3WitnessRuntimeDB(t, db, role)
	require.NoError(t, database.NewA3WitnessStore(runtimeDB).
		RequireActivationBarrier(t.Context()))
}

func TestA3WitnessActivationBarrierRejectsChangedSessionAuthorization(
	t *testing.T,
) {
	db := testdb.CreateTestDb(t)
	role := createA3WitnessRuntimeRole(t, db)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`SET SESSION AUTHORIZATION %s`,
			quoteA3Role(role),
		),
	)
	require.NoError(t, err)
	require.ErrorIs(
		t,
		database.NewA3WitnessStore(db).RequireActivationBarrier(t.Context()),
		database.ErrA3WitnessBarrierInvalid,
	)
	_, err = db.ExecContext(t.Context(), `RESET SESSION AUTHORIZATION`)
	require.NoError(t, err)
}

func TestA3WitnessActivationBarrierRejectsACLAndCatalogTampering(t *testing.T) {
	for name, tamper := range map[string]func(*testing.T, *sql.DB, string){
		"update privilege": func(t *testing.T, db *sql.DB, role string) {
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`GRANT UPDATE ON TABLE
					     hytch_push_vault.a3_directory_witness_heads
					 TO %s`,
					quoteA3Role(role),
				),
			)
			require.NoError(t, err)
		},
		"public schema create": func(t *testing.T, db *sql.DB, role string) {
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`GRANT CREATE ON SCHEMA public TO %s`,
					quoteA3Role(role),
				),
			)
			require.NoError(t, err)
		},
		"set-only public schema create": func(
			t *testing.T,
			db *sql.DB,
			role string,
		) {
			helper := createA3ProtectedOwnerRole(t, db, role)
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`GRANT CREATE ON SCHEMA public TO %s`,
					quoteA3Role(helper),
				),
			)
			require.NoError(t, err)
			grantA3SetOnlyMembership(t, db, helper, role)
		},
		"set-only schema migrations update": func(
			t *testing.T,
			db *sql.DB,
			role string,
		) {
			helper := createA3ProtectedOwnerRole(t, db, role)
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`GRANT UPDATE ON TABLE public.schema_migrations TO %s`,
					quoteA3Role(helper),
				),
			)
			require.NoError(t, err)
			grantA3SetOnlyMembership(t, db, helper, role)
		},
		"set-only schema migrations grant option": func(
			t *testing.T,
			db *sql.DB,
			role string,
		) {
			helper := createA3ProtectedOwnerRole(t, db, role)
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`GRANT SELECT ON TABLE public.schema_migrations
					 TO %s WITH GRANT OPTION`,
					quoteA3Role(helper),
				),
			)
			require.NoError(t, err)
			grantA3SetOnlyMembership(t, db, helper, role)
		},
		"set-only schema migrations maintain": func(
			t *testing.T,
			db *sql.DB,
			role string,
		) {
			var serverVersion int
			require.NoError(t, db.QueryRowContext(
				t.Context(),
				`SELECT pg_catalog.current_setting(
				     'server_version_num'
				 )::pg_catalog.int4`,
			).Scan(&serverVersion))
			if serverVersion < 170000 {
				t.Skip("MAINTAIN privilege requires PostgreSQL 17+")
			}
			helper := createA3ProtectedOwnerRole(t, db, role)
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`GRANT MAINTAIN ON TABLE public.schema_migrations TO %s`,
					quoteA3Role(helper),
				),
			)
			require.NoError(t, err)
			grantA3SetOnlyMembership(t, db, helper, role)
		},
		"schema migrations column update": func(
			t *testing.T,
			db *sql.DB,
			role string,
		) {
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`GRANT UPDATE (dirty)
					 ON TABLE public.schema_migrations TO %s`,
					quoteA3Role(role),
				),
			)
			require.NoError(t, err)
		},
		"set-only schema migrations column update": func(
			t *testing.T,
			db *sql.DB,
			role string,
		) {
			helper := createA3ProtectedOwnerRole(t, db, role)
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`GRANT UPDATE (version)
					 ON TABLE public.schema_migrations TO %s`,
					quoteA3Role(helper),
				),
			)
			require.NoError(t, err)
			grantA3SetOnlyMembership(t, db, helper, role)
		},
		"schema migrations inheritance": func(
			t *testing.T,
			db *sql.DB,
			_ string,
		) {
			_, err := db.ExecContext(
				t.Context(),
				`CREATE TABLE public.a3_migration_parent (
				     version BIGINT,
				     dirty BOOLEAN
				 );
				 ALTER TABLE public.schema_migrations
				 INHERIT public.a3_migration_parent`,
			)
			require.NoError(t, err)
		},
		"schema migrations foreign key": func(
			t *testing.T,
			db *sql.DB,
			_ string,
		) {
			_, err := db.ExecContext(
				t.Context(),
				`CREATE TABLE public.a3_migration_parent (
				     version BIGINT PRIMARY KEY
				 );
				 INSERT INTO public.a3_migration_parent (version)
				 SELECT version FROM public.schema_migrations;
				 ALTER TABLE public.schema_migrations
				 ADD CONSTRAINT a3_migration_parent_fkey
				 FOREIGN KEY (version)
				 REFERENCES public.a3_migration_parent(version)
				 ON DELETE CASCADE`,
			)
			require.NoError(t, err)
		},
		"logical subscription": func(t *testing.T, db *sql.DB, _ string) {
			name := fmt.Sprintf("a3_subscription_%d", time.Now().UnixNano())
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`CREATE SUBSCRIPTION %s
					 CONNECTION 'host=127.0.0.1 port=1 dbname=unused'
					 PUBLICATION unused_publication
					 WITH (connect = false, create_slot = false, enabled = false)`,
					quoteA3Role(name),
				),
			)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, _ = db.ExecContext(
					context.Background(),
					fmt.Sprintf(`DROP SUBSCRIPTION IF EXISTS %s`, quoteA3Role(name)),
				)
			})
		},
		"disabled trigger": func(t *testing.T, db *sql.DB, _ string) {
			_, err := db.ExecContext(
				t.Context(),
				`ALTER TABLE hytch_push_vault.a3_directory_witness_heads
				 DISABLE TRIGGER hytch_a3_witness_delete_guard`,
			)
			require.NoError(t, err)
		},
		"narrowed update trigger": func(t *testing.T, db *sql.DB, _ string) {
			_, err := db.ExecContext(
				t.Context(),
				`DROP TRIGGER hytch_a3_witness_update_guard
				     ON hytch_push_vault.a3_directory_witness_heads;
				 CREATE TRIGGER hytch_a3_witness_update_guard
				 BEFORE UPDATE OF timestamp_ms
				     ON hytch_push_vault.a3_directory_witness_heads
				 FOR EACH STATEMENT
				 EXECUTE FUNCTION
				     hytch_push_vault.reject_a3_witness_mutation();
				 ALTER TABLE hytch_push_vault.a3_directory_witness_heads
				 ENABLE ALWAYS TRIGGER hytch_a3_witness_update_guard`,
			)
			require.NoError(t, err)
		},
		"weakened signature check": func(t *testing.T, db *sql.DB, _ string) {
			_, err := db.ExecContext(
				t.Context(),
				`ALTER TABLE hytch_push_vault.a3_directory_witness_heads
				 DROP CONSTRAINT a3_witness_signature_check;
				 ALTER TABLE hytch_push_vault.a3_directory_witness_heads
				 ADD CONSTRAINT a3_witness_signature_check
				 CHECK (pg_catalog.octet_length(witness_signature) > 0)`,
			)
			require.NoError(t, err)
		},
		"changed primary index shape": func(t *testing.T, db *sql.DB, _ string) {
			_, err := db.ExecContext(
				t.Context(),
				`ALTER INDEX
				     hytch_push_vault.a3_directory_witness_heads_pkey
				 SET (fillfactor = 70)`,
			)
			require.NoError(t, err)
		},
		"changed mutation function": func(t *testing.T, db *sql.DB, _ string) {
			_, err := db.ExecContext(
				t.Context(),
				`CREATE OR REPLACE FUNCTION
				     hytch_push_vault.reject_a3_witness_mutation()
				 RETURNS TRIGGER
				 LANGUAGE plpgsql
				 SET search_path = pg_catalog
				 AS $function$
				 BEGIN
				     RETURN NULL;
				 END;
				 $function$`,
			)
			require.NoError(t, err)
		},
		"schema owner mismatch": func(t *testing.T, db *sql.DB, role string) {
			owner := createA3ProtectedOwnerRole(t, db, role)
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`ALTER SCHEMA hytch_push_vault OWNER TO %s`,
					quoteA3Role(owner),
				),
			)
			require.NoError(t, err)
		},
		"set-only witness owner membership": func(
			t *testing.T,
			db *sql.DB,
			role string,
		) {
			owner := createA3ProtectedOwnerRole(t, db, role)
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`ALTER SCHEMA hytch_push_vault OWNER TO %[1]s;
					 ALTER TABLE
					     hytch_push_vault.a3_directory_witness_heads
					 OWNER TO %[1]s;
					 ALTER FUNCTION
					     hytch_push_vault.reject_a3_witness_mutation()
					 OWNER TO %[1]s`,
					quoteA3Role(owner),
				),
			)
			require.NoError(t, err)
			grantA3SetOnlyMembership(t, db, owner, role)
		},
		"set-only database owner membership": func(
			t *testing.T,
			db *sql.DB,
			role string,
		) {
			owner := createA3ProtectedOwnerRole(t, db, role)
			var databaseName string
			require.NoError(t, db.QueryRowContext(
				t.Context(),
				`SELECT pg_catalog.current_database()`,
			).Scan(&databaseName))
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`ALTER DATABASE %s OWNER TO %s`,
					quoteA3Role(databaseName),
					quoteA3Role(owner),
				),
			)
			require.NoError(t, err)
			grantA3SetOnlyMembership(t, db, owner, role)
		},
		"select grant option": func(t *testing.T, db *sql.DB, role string) {
			_, err := db.ExecContext(
				t.Context(),
				fmt.Sprintf(
					`GRANT SELECT ON TABLE
					     hytch_push_vault.a3_directory_witness_heads
					 TO %s WITH GRANT OPTION`,
					quoteA3Role(role),
				),
			)
			require.NoError(t, err)
		},
	} {
		t.Run(name, func(t *testing.T) {
			db := testdb.CreateTestDb(t)
			role := createA3WitnessRuntimeRole(t, db)
			tamper(t, db, role)
			runtimeDB := openA3WitnessRuntimeDB(t, db, role)
			require.ErrorIs(
				t,
				database.NewA3WitnessStore(runtimeDB).
					RequireActivationBarrier(t.Context()),
				database.ErrA3WitnessBarrierInvalid,
			)
		})
	}
}

func TestA3WitnessMigrationDowngradeAndPublicBoundary(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	require.NoError(t, database.MigrateUpTo(t.Context(), db, 13))
	var missing bool
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT pg_catalog.to_regclass('hytch_push_vault.a3_directory_witness_heads') IS NULL`).Scan(&missing))
	require.True(t, missing)
	require.NoError(t, database.Migrate(t.Context(), db))

	var publicAccessAbsent bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
		     NOT EXISTS (
		         SELECT 1
		           FROM pg_catalog.pg_class AS relation
		           JOIN pg_catalog.pg_namespace AS namespace
		             ON namespace.oid = relation.relnamespace
		           CROSS JOIN LATERAL pg_catalog.aclexplode(
		               COALESCE(
		                   relation.relacl,
		                   pg_catalog.acldefault('r', relation.relowner)
		               )
		           ) AS privilege
		          WHERE namespace.nspname = 'hytch_push_vault'
		            AND relation.relname = 'a3_directory_witness_heads'
		            AND privilege.grantee = 0
		     ) AND
		     NOT EXISTS (
		         SELECT 1
		           FROM pg_catalog.pg_proc AS routine
		           JOIN pg_catalog.pg_namespace AS namespace
		             ON namespace.oid = routine.pronamespace
		           CROSS JOIN LATERAL pg_catalog.aclexplode(
		               COALESCE(
		                   routine.proacl,
		                   pg_catalog.acldefault('f', routine.proowner)
		               )
		           ) AS privilege
		          WHERE namespace.nspname = 'hytch_push_vault'
		            AND routine.proname = 'reject_a3_witness_mutation'
		            AND routine.pronargs = 0
		            AND privilege.grantee = 0
		     )`,
	).Scan(&publicAccessAbsent))
	require.True(t, publicAccessAbsent)

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	keyID := a3trust.WitnessKeyID(privateKey.Public().(ed25519.PublicKey))
	proposal, _, _ := firstA3Proposal(t, 1750000000123)
	_, err := database.NewA3WitnessStore(db).AcceptDirectoryTreeHead(t.Context(), proposal, privateKey, keyID)
	require.NoError(t, err)
	err = database.MigrateUpTo(t.Context(), db, 13)
	require.Error(t, err)
	require.Contains(t, err.Error(), "SQLSTATE 55000")
}

func TestA3WitnessMigrationLocksBeforeDormancyCheck(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	blocker, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback() }()
	_, err = blocker.ExecContext(
		t.Context(),
		`LOCK TABLE hytch_push_vault.a3_directory_witness_heads
		 IN ROW EXCLUSIVE MODE`,
	)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- database.MigrateUpTo(t.Context(), db, 13) }()
	require.Eventually(t, func() bool {
		var waiting bool
		queryErr := db.QueryRowContext(
			t.Context(),
			`SELECT EXISTS (
			     SELECT 1
			       FROM pg_catalog.pg_locks
			      WHERE relation =
			            'hytch_push_vault.a3_directory_witness_heads'
			                ::pg_catalog.regclass
			        AND mode = 'AccessExclusiveLock'
			        AND NOT granted
			 )`,
		).Scan(&waiting)
		return queryErr == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)

	emptyRoot := sha256.Sum256(nil)
	_, err = blocker.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a3_directory_witness_heads
		 (environment, tree_size, root_hash, prior_tree_size, prior_root_hash,
		  timestamp_ms, canonical_head, consistency_proof, witness_key_id,
		  witness_signature)
		 VALUES (1, 1, $1, 0, $2, 1, $3, $4, $5, $6)`,
		bytes.Repeat([]byte{1}, sha256.Size),
		emptyRoot[:],
		[]byte{1},
		[]byte{},
		"ed25519-sha256:"+strings.Repeat("a", 64),
		bytes.Repeat([]byte{2}, ed25519.SignatureSize),
	)
	require.NoError(t, err)
	require.NoError(t, blocker.Commit())
	select {
	case migrateErr := <-done:
		require.Error(t, migrateErr)
		require.Contains(t, migrateErr.Error(), "SQLSTATE 55000")
	case <-time.After(5 * time.Second):
		t.Fatal("A3 downgrade did not resume after the concurrent writer")
	}
}

func firstA3Proposal(t *testing.T, timestamp uint64) (a3trust.WitnessProposal, [32]byte, [32]byte) {
	t.Helper()
	leafZero := a3LeafHash([]byte("zero"))
	leafOne := a3LeafHash([]byte("one"))
	empty := sha256.Sum256(nil)
	proposal := a3trust.WitnessProposal{Head: a3trust.TreeHead{
		Domain: "hytch.directory.tree-head/v1", Environment: "dev",
		PriorRootHash: hex.EncodeToString(empty[:]), PriorTreeSize: 0,
		Protocol: 1, RootHash: hex.EncodeToString(leafZero[:]),
		TimestampMS: timestamp, TreeSize: 1,
	}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	var err error
	proposal.CanonicalHead, err = a3trust.CanonicalTreeHead(proposal.Head)
	require.NoError(t, err)
	return proposal, leafZero, leafOne
}

func a3LeafHash(value []byte) [32]byte {
	return sha256.Sum256(append([]byte{0}, value...))
}

func a3NodeHash(left, right [32]byte) [32]byte {
	input := make([]byte, 1+sha256.Size*2)
	input[0] = 1
	copy(input[1:], left[:])
	copy(input[1+sha256.Size:], right[:])
	return sha256.Sum256(input)
}

func createA3WitnessRuntimeRole(t *testing.T, db *sql.DB) string {
	t.Helper()
	role := fmt.Sprintf("a3_witness_runtime_%d", time.Now().UnixNano())
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`CREATE ROLE %s LOGIN PASSWORD 'a3-runtime-test-password'`,
			quoteA3Role(role),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(
			context.Background(),
			fmt.Sprintf(
				`DROP OWNED BY %[1]s; DROP ROLE IF EXISTS %[1]s`,
				quoteA3Role(role),
			),
		)
	})
	_, err = db.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`REVOKE CREATE ON SCHEMA public FROM PUBLIC;
			 GRANT USAGE ON SCHEMA hytch_push_vault TO %[1]s;
			 GRANT SELECT, INSERT ON TABLE
			     hytch_push_vault.a3_directory_witness_heads
			 TO %[1]s;
			 GRANT SELECT ON TABLE public.schema_migrations TO %[1]s`,
			quoteA3Role(role),
		),
	)
	require.NoError(t, err)
	return role
}

func createA3ProtectedOwnerRole(
	t *testing.T,
	db *sql.DB,
	runtimeRole string,
) string {
	t.Helper()
	ownerRole := fmt.Sprintf("a3_protected_owner_%d", time.Now().UnixNano())
	_, err := db.ExecContext(
		t.Context(),
		fmt.Sprintf(`CREATE ROLE %s NOLOGIN`, quoteA3Role(ownerRole)),
	)
	require.NoError(t, err)
	var databaseName, sessionUser string
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.current_database(), session_user`,
	).Scan(&databaseName, &sessionUser))
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.ExecContext(
			ctx,
			fmt.Sprintf(
				`REVOKE %[1]s FROM %[2]s;
				 ALTER DATABASE %[3]s OWNER TO %[4]s;
				 REASSIGN OWNED BY %[1]s TO %[4]s;
				 DROP OWNED BY %[1]s;
				 DROP ROLE IF EXISTS %[1]s`,
				quoteA3Role(ownerRole),
				quoteA3Role(runtimeRole),
				quoteA3Role(databaseName),
				quoteA3Role(sessionUser),
			),
		)
	})
	return ownerRole
}

func grantA3SetOnlyMembership(
	t *testing.T,
	db *sql.DB,
	ownerRole string,
	runtimeRole string,
) {
	t.Helper()
	var serverVersion int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.current_setting('server_version_num')::pg_catalog.int4`,
	).Scan(&serverVersion))
	var grantSQL string
	if serverVersion >= 160000 {
		grantSQL = fmt.Sprintf(
			`GRANT %s TO %s WITH INHERIT FALSE, SET TRUE`,
			quoteA3Role(ownerRole),
			quoteA3Role(runtimeRole),
		)
	} else {
		grantSQL = fmt.Sprintf(
			`ALTER ROLE %s NOINHERIT; GRANT %s TO %s`,
			quoteA3Role(runtimeRole),
			quoteA3Role(ownerRole),
			quoteA3Role(runtimeRole),
		)
	}
	_, err := db.ExecContext(t.Context(), grantSQL)
	require.NoError(t, err)
	var member, inherited bool
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
		     pg_catalog.pg_has_role($1, $2, 'MEMBER'),
		     pg_catalog.pg_has_role($1, $2, 'USAGE')`,
		runtimeRole,
		ownerRole,
	).Scan(&member, &inherited))
	require.True(t, member)
	require.False(t, inherited)
}

func openA3WitnessRuntimeDB(
	t *testing.T,
	ownerDB *sql.DB,
	role string,
) *sql.DB {
	t.Helper()
	var databaseName string
	require.NoError(t, ownerDB.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.current_database()`,
	).Scan(&databaseName))
	dsn, err := url.Parse(testdb.TEST_DSN)
	require.NoError(t, err)
	dsn.User = url.UserPassword(role, "a3-runtime-test-password")
	dsn.Path = "/" + databaseName
	runtimeDB, err := database.CreateDB(dsn.String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = runtimeDB.Close() })
	return runtimeDB
}

func quoteA3Role(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
