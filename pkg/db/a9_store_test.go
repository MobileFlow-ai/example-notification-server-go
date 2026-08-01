package db_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a9auth"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

var (
	_ a9trust.KeysetStore = database.NewA9KeysetStore(nil)
	_ a9auth.ReplayStore  = database.NewA9ReplayStore(nil)
)

func TestA9PostgresKeysetStoreAcceptsAtomicallyAndReadsExactState(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	store := database.NewA9KeysetStore(db)
	issuedAt := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	candidate := a9StoreCandidate(
		t,
		1,
		issuedAt,
		defaultA9OnlineKeys(t, issuedAt),
		0x70,
	)

	state, err := store.AcceptKeyset(t.Context(), candidate)
	require.NoError(t, err)
	require.Equal(t, candidate.Environment, state.Environment)
	require.Equal(t, candidate.Sequence, state.Sequence)
	require.Equal(t, candidate.ObjectHash, state.ObjectHash)
	require.True(t, candidate.ExpiresAt.Equal(state.ExpiresAt))
	require.False(t, state.Uncertain)

	current, err := store.CurrentKeysetState(
		t.Context(),
		candidate.Environment,
	)
	require.NoError(t, err)
	require.Equal(t, state, current)

	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.a9_keyset_state
		    SET refreshed_at = TIMESTAMPTZ '2000-01-01 00:00:00Z'
		  WHERE environment = 1`,
	)
	require.NoError(t, err)
	var validationStartedAt time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.clock_timestamp()`,
	).Scan(&validationStartedAt))

	replayed, err := store.AcceptKeyset(t.Context(), candidate)
	require.NoError(t, err)
	require.Equal(t, state, replayed)
	var (
		refreshedAt          time.Time
		validationFinishedAt time.Time
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT refreshed_at, pg_catalog.clock_timestamp()
		   FROM hytch_push_vault.a9_keyset_state
		  WHERE environment = 1`,
	).Scan(&refreshedAt, &validationFinishedAt))
	require.False(t, refreshedAt.Before(validationStartedAt))
	require.False(t, refreshedAt.After(validationFinishedAt))

	var (
		keysets        int
		onlineKeys     int
		commitmentKeys int
		storedJCS      []byte
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_accepted_keysets`,
	).Scan(&keysets))
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT signed_keyset_jcs
		   FROM hytch_push_vault.a9_accepted_keysets
		  LIMIT 1`,
	).Scan(&storedJCS))
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_online_key_descriptors`,
	).Scan(&onlineKeys))
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_commitment_key_descriptors`,
	).Scan(&commitmentKeys))
	require.Equal(t, 1, keysets)
	require.Equal(t, len(candidate.OnlineKeys), onlineKeys)
	require.Equal(t, len(candidate.CommitmentKeys), commitmentKeys)
	require.Equal(t, candidate.CanonicalSignedObject, storedJCS)
}

func TestA9PostgresKeysetStoreLatchesRollbackAndEqualConflict(
	t *testing.T,
) {
	t.Run("rollback", func(t *testing.T) {
		db := testdb.CreateEmptyTestDb(t)
		require.NoError(t, database.Migrate(t.Context(), db))
		store := database.NewA9KeysetStore(db)
		issuedAt := time.Date(
			2026,
			7,
			29,
			0,
			0,
			0,
			0,
			time.UTC,
		)
		accepted := a9StoreCandidate(
			t,
			2,
			issuedAt.Add(time.Hour),
			defaultA9OnlineKeys(t, issuedAt.Add(time.Hour)),
			0x71,
		)
		_, err := store.AcceptKeyset(t.Context(), accepted)
		require.NoError(t, err)
		rollback := a9StoreCandidate(
			t,
			1,
			issuedAt,
			defaultA9OnlineKeys(t, issuedAt),
			0x72,
		)

		rejectedState, err := store.AcceptKeyset(
			t.Context(),
			rollback,
		)
		require.ErrorIs(t, err, a9trust.ErrKeysetRejected)
		require.True(t, rejectedState.Uncertain)
		require.Equal(t, accepted.Sequence, rejectedState.Sequence)
		require.Equal(t, accepted.ObjectHash, rejectedState.ObjectHash)

		durable, err := database.NewA9KeysetStore(db).
			CurrentKeysetState(t.Context(), "dev")
		require.NoError(t, err)
		require.Equal(t, rejectedState, durable)
		assertA9KeysetHistoryCount(t, db, 1)

		higher := a9StoreCandidate(
			t,
			3,
			issuedAt.Add(2*time.Hour),
			defaultA9OnlineKeys(t, issuedAt.Add(2*time.Hour)),
			0x73,
		)
		_, err = store.AcceptKeyset(t.Context(), higher)
		require.ErrorIs(t, err, a9trust.ErrKeysetRejected)
		assertA9KeysetHistoryCount(t, db, 1)
	})

	t.Run("equal sequence different bytes", func(t *testing.T) {
		db := testdb.CreateEmptyTestDb(t)
		require.NoError(t, database.Migrate(t.Context(), db))
		store := database.NewA9KeysetStore(db)
		issuedAt := time.Date(
			2026,
			7,
			29,
			0,
			0,
			0,
			0,
			time.UTC,
		)
		accepted := a9StoreCandidate(
			t,
			1,
			issuedAt,
			defaultA9OnlineKeys(t, issuedAt),
			0x74,
		)
		_, err := store.AcceptKeyset(t.Context(), accepted)
		require.NoError(t, err)
		conflict := a9StoreCandidate(
			t,
			1,
			issuedAt,
			defaultA9OnlineKeys(t, issuedAt),
			0x75,
		)

		_, err = store.AcceptKeyset(t.Context(), conflict)
		require.ErrorIs(t, err, a9trust.ErrKeysetRejected)
		current, err := store.CurrentKeysetState(t.Context(), "dev")
		require.NoError(t, err)
		require.True(t, current.Uncertain)
		require.Equal(t, accepted.ObjectHash, current.ObjectHash)
		assertA9KeysetHistoryCount(t, db, 1)
	})
}

func TestA9PostgresKeysetStoreValidatesRotationForBothUses(
	t *testing.T,
) {
	for _, test := range []struct {
		name       string
		changedUse string
	}{
		{name: "A9 control", changedUse: "A9_CONTROL"},
		{name: "service auth", changedUse: "SERVICE_AUTH"},
	} {
		t.Run(test.name+" unstaged", func(t *testing.T) {
			db := testdb.CreateEmptyTestDb(t)
			require.NoError(t, database.Migrate(t.Context(), db))
			store := database.NewA9KeysetStore(db)
			issuedAt := time.Date(
				2026,
				7,
				29,
				0,
				0,
				0,
				0,
				time.UTC,
			)
			beforeKeys := defaultA9OnlineKeys(t, issuedAt)
			before := a9StoreCandidate(
				t,
				1,
				issuedAt,
				beforeKeys,
				0x76,
			)
			_, err := store.AcceptKeyset(t.Context(), before)
			require.NoError(t, err)

			afterKeys := make(
				[]a9trust.OnlineKey,
				0,
				len(beforeKeys)+1,
			)
			for _, key := range beforeKeys {
				if key.Use != test.changedUse {
					afterKeys = append(afterKeys, key)
					continue
				}
				replacement := a9TestOnlineKey(
					t,
					keyMarkerForA9Use(test.changedUse)+0x10,
					key.Use,
					"SIGN",
					issuedAt.Add(24*time.Hour),
					issuedAt.Add(72*time.Hour),
				)
				retired := key
				retired.State = "VERIFY_ONLY"
				afterKeys = append(
					afterKeys,
					replacement,
					retired,
				)
			}
			after := a9StoreCandidate(
				t,
				2,
				issuedAt.Add(24*time.Hour),
				afterKeys,
				0x77,
			)
			_, err = store.AcceptKeyset(t.Context(), after)
			require.ErrorIs(t, err, a9trust.ErrKeysetRejected)
			current, err := store.CurrentKeysetState(
				t.Context(),
				"dev",
			)
			require.NoError(t, err)
			require.True(t, current.Uncertain)
			require.Equal(t, before.ObjectHash, current.ObjectHash)
			assertA9KeysetHistoryCount(t, db, 1)
		})
	}

	t.Run("staged cutover", func(t *testing.T) {
		db := testdb.CreateEmptyTestDb(t)
		require.NoError(t, database.Migrate(t.Context(), db))
		store := database.NewA9KeysetStore(db)
		issuedAt := time.Date(
			2026,
			7,
			29,
			0,
			0,
			0,
			0,
			time.UTC,
		)
		cutover := issuedAt.Add(24 * time.Hour)
		controlOld := a9TestOnlineKey(
			t,
			0x31,
			"A9_CONTROL",
			"SIGN",
			issuedAt.Add(-time.Hour),
			cutover.Add(24*time.Hour),
		)
		controlNew := a9TestOnlineKey(
			t,
			0x41,
			"A9_CONTROL",
			"VERIFY_ONLY",
			cutover,
			cutover.Add(48*time.Hour),
		)
		serviceOld := a9TestOnlineKey(
			t,
			0x32,
			"SERVICE_AUTH",
			"SIGN",
			issuedAt.Add(-time.Hour),
			cutover.Add(24*time.Hour),
		)
		serviceNew := a9TestOnlineKey(
			t,
			0x42,
			"SERVICE_AUTH",
			"VERIFY_ONLY",
			cutover,
			cutover.Add(48*time.Hour),
		)
		transition := a9StoreCandidate(
			t,
			1,
			issuedAt,
			[]a9trust.OnlineKey{
				controlOld,
				controlNew,
				serviceOld,
				serviceNew,
			},
			0x78,
		)
		_, err := store.AcceptKeyset(t.Context(), transition)
		require.NoError(t, err)

		controlNew.State = "SIGN"
		controlOld.State = "VERIFY_ONLY"
		serviceNew.State = "SIGN"
		serviceOld.State = "VERIFY_ONLY"
		cutoverCandidate := a9StoreCandidate(
			t,
			2,
			cutover,
			[]a9trust.OnlineKey{
				controlNew,
				controlOld,
				serviceNew,
				serviceOld,
			},
			0x79,
		)
		state, err := store.AcceptKeyset(
			t.Context(),
			cutoverCandidate,
		)
		require.NoError(t, err)
		require.False(t, state.Uncertain)
		require.Equal(t, uint64(2), state.Sequence)
		require.Equal(t, cutoverCandidate.ObjectHash, state.ObjectHash)
		assertA9KeysetHistoryCount(t, db, 2)
	})
}

func TestA9PostgresKeysetStoreBootstrapLatchIsIdempotent(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	store := database.NewA9KeysetStore(db)

	require.NoError(t, store.LatchKeysetUncertainty(
		t.Context(),
		"dev",
		"KEY_STATE",
	))
	var firstRefreshed time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT refreshed_at
		   FROM hytch_push_vault.a9_keyset_state
		  WHERE environment = 1`,
	).Scan(&firstRefreshed))

	require.NoError(t, store.LatchKeysetUncertainty(
		t.Context(),
		"dev",
		"KEYSET_ROLLBACK",
	))
	var (
		secondRefreshed time.Time
		reasonCode      int16
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT refreshed_at, uncertainty_reason
		   FROM hytch_push_vault.a9_keyset_state
		  WHERE environment = 1`,
	).Scan(&secondRefreshed, &reasonCode))
	require.True(t, firstRefreshed.Equal(secondRefreshed))
	require.Equal(t, int16(1), reasonCode)

	current, err := store.CurrentKeysetState(t.Context(), "dev")
	require.NoError(t, err)
	require.Equal(t, "dev", current.Environment)
	require.Zero(t, current.Sequence)
	require.Empty(t, current.ObjectHash)
	require.True(t, current.ExpiresAt.IsZero())
	require.True(t, current.Uncertain)

	candidate := a9StoreCandidate(
		t,
		1,
		time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC),
		defaultA9OnlineKeys(
			t,
			time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC),
		),
		0x7a,
	)
	_, err = store.AcceptKeyset(t.Context(), candidate)
	require.ErrorIs(t, err, a9trust.ErrKeysetRejected)
	assertA9KeysetHistoryCount(t, db, 0)
}

func TestA9PostgresKeysetStoreSerializesBootstrapLatch(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	start := make(chan struct{})
	errs := make(chan error, 12)
	var wait sync.WaitGroup
	for range 12 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- database.NewA9KeysetStore(db).LatchKeysetUncertainty(
				context.Background(),
				"dev",
				"KEY_STATE",
			)
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	var stateRows int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_keyset_state
		  WHERE environment = 1
		    AND keyset_sequence = 0
		    AND state = 2
		    AND uncertainty_reason = 1`,
	).Scan(&stateRows))
	require.Equal(t, 1, stateRows)
}

func TestA9PostgresKeysetStoreSerializesFirstAcceptance(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	issuedAt := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	candidates := []a9trust.AcceptedKeyset{
		a9StoreCandidate(
			t,
			1,
			issuedAt,
			defaultA9OnlineKeys(t, issuedAt),
			0x7b,
		),
		a9StoreCandidate(
			t,
			1,
			issuedAt,
			defaultA9OnlineKeys(t, issuedAt),
			0x7c,
		),
	}
	start := make(chan struct{})
	errs := make(chan error, len(candidates))
	var wait sync.WaitGroup
	for index := range candidates {
		wait.Add(1)
		go func(candidate a9trust.AcceptedKeyset) {
			defer wait.Done()
			<-start
			_, err := database.NewA9KeysetStore(db).AcceptKeyset(
				context.Background(),
				candidate,
			)
			errs <- err
		}(candidates[index])
	}
	close(start)
	wait.Wait()
	close(errs)

	var accepted int
	var rejected int
	for err := range errs {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, a9trust.ErrKeysetRejected):
			rejected++
		default:
			t.Fatalf("unexpected accept result: %v", err)
		}
	}
	require.Equal(t, 1, accepted)
	require.Equal(t, 1, rejected)
	current, err := database.NewA9KeysetStore(db).
		CurrentKeysetState(t.Context(), "dev")
	require.NoError(t, err)
	require.True(t, current.Uncertain)
	assertA9KeysetHistoryCount(t, db, 1)
}

func TestA9PostgresKeysetStoreSerializesIdenticalFirstAcceptance(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	issuedAt := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	candidate := a9StoreCandidate(
		t,
		1,
		issuedAt,
		defaultA9OnlineKeys(t, issuedAt),
		0x7d,
	)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := database.NewA9KeysetStore(db).AcceptKeyset(
				context.Background(),
				candidate,
			)
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	current, err := database.NewA9KeysetStore(db).
		CurrentKeysetState(t.Context(), "dev")
	require.NoError(t, err)
	require.False(t, current.Uncertain)
	require.Equal(t, candidate.ObjectHash, current.ObjectHash)
	assertA9KeysetHistoryCount(t, db, 1)
}

func TestA9PostgresKeysetStoreRejectsInconsistentCandidateAtomically(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	store := database.NewA9KeysetStore(db)
	issuedAt := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	candidate := a9StoreCandidate(
		t,
		1,
		issuedAt,
		defaultA9OnlineKeys(t, issuedAt),
		0x7e,
	)
	candidate.OnlineKeys[0].PublicKey[0] ^= 0xff

	_, err := store.AcceptKeyset(t.Context(), candidate)
	require.ErrorIs(t, err, a9trust.ErrKeysetRejected)
	current, err := store.CurrentKeysetState(t.Context(), "dev")
	require.NoError(t, err)
	require.True(t, current.Uncertain)
	require.Zero(t, current.Sequence)
	assertA9KeysetHistoryCount(t, db, 0)
}

func TestA9PostgresReplayStoreIsOneUseAcrossReplicas(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	const jti = "11111111-1111-4111-8111-111111111111"
	var now time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.clock_timestamp()`,
	).Scan(&now))
	now = now.UTC()
	retainUntil := now.Add(65 * time.Second)
	start := make(chan struct{})
	results := make(chan bool, 24)
	errs := make(chan error, 24)
	var wait sync.WaitGroup
	for range 24 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			consumed, err := database.NewA9ReplayStore(db).Consume(
				context.Background(),
				"dev",
				jti,
				retainUntil,
				now,
			)
			results <- consumed
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errs)

	var consumedCount int
	for consumed := range results {
		if consumed {
			consumedCount++
		}
	}
	require.Equal(t, 1, consumedCount)
	for err := range errs {
		require.NoError(t, err)
	}

	var (
		receipts     int
		jwtExpiresAt time.Time
		deleteAfter  time.Time
		consumedAt   time.Time
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
		     COUNT(*),
		     pg_catalog.min(jwt_expires_at),
		     pg_catalog.min(delete_after),
		     pg_catalog.min(consumed_at)
		   FROM hytch_push_vault.a9_service_jti_receipts
		  WHERE environment = 1
		    AND jti = $1`,
		jti,
	).Scan(
		&receipts,
		&jwtExpiresAt,
		&deleteAfter,
		&consumedAt,
	))
	require.Equal(t, 1, receipts)
	require.True(t, retainUntil.Add(-5*time.Second).Equal(jwtExpiresAt))
	require.True(t, retainUntil.Equal(deleteAfter))
	require.False(t, consumedAt.Before(now))
	require.False(t, consumedAt.After(retainUntil))

	productionConsumed, err := database.NewA9ReplayStore(db).Consume(
		t.Context(),
		"production",
		jti,
		retainUntil,
		now,
	)
	require.NoError(t, err)
	require.True(t, productionConsumed)

	invalid, err := database.NewA9ReplayStore(db).Consume(
		t.Context(),
		"dev",
		"NOT-"+jti,
		retainUntil,
		now,
	)
	require.False(t, invalid)
	require.EqualError(t, err, "a9 database store unavailable")
}

func TestA9PostgresReplayStorePurgesOnlyExpiredReceipts(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	store := database.NewA9ReplayStore(db)
	var databaseNow time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.clock_timestamp()`,
	).Scan(&databaseNow))
	databaseNow = databaseNow.UTC()
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_service_jti_receipts (
		     environment, jti, jwt_expires_at, delete_after, consumed_at
		 ) VALUES ($1,$2,$3,$4,$5)`,
		int16(1),
		"22222222-2222-4222-8222-222222222222",
		databaseNow.Add(-10*time.Second),
		databaseNow.Add(-5*time.Second),
		databaseNow.Add(-20*time.Second),
	)
	require.NoError(t, err)
	futureNow := databaseNow
	future, err := store.Consume(
		t.Context(),
		"dev",
		"33333333-3333-4333-8333-333333333333",
		futureNow.Add(65*time.Second),
		futureNow,
	)
	require.NoError(t, err)
	require.True(t, future)

	purged, err := store.PurgeExpired(t.Context())
	require.NoError(t, err)
	require.Equal(t, int64(1), purged)
	var remaining int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_service_jti_receipts`,
	).Scan(&remaining))
	require.Equal(t, 1, remaining)
}

func TestA9PostgresReplayStoreUsesDatabaseClockForExpiry(
	t *testing.T,
) {
	db := testdb.CreateEmptyTestDb(t)
	require.NoError(t, database.Migrate(t.Context(), db))
	store := database.NewA9ReplayStore(db)
	var databaseNow time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.clock_timestamp()`,
	).Scan(&databaseNow))
	databaseNow = databaseNow.UTC()

	// A lagging caller clock cannot recreate a JTI after the database-owned
	// retention deadline has elapsed.
	consumed, err := store.Consume(
		t.Context(),
		"dev",
		"44444444-4444-4444-8444-444444444444",
		databaseNow.Add(-time.Second),
		databaseNow.Add(-time.Hour),
	)
	require.False(t, consumed)
	require.EqualError(t, err, "a9 database store unavailable")

	callerNow := databaseNow.Add(-time.Hour)
	retainUntil := databaseNow.Add(time.Minute)
	consumed, err = store.Consume(
		t.Context(),
		"dev",
		"55555555-5555-4555-8555-555555555555",
		retainUntil,
		callerNow,
	)
	require.NoError(t, err)
	require.True(t, consumed)
	var consumedAt time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT consumed_at
		   FROM hytch_push_vault.a9_service_jti_receipts
		  WHERE environment = 1
		    AND jti = $1`,
		"55555555-5555-4555-8555-555555555555",
	).Scan(&consumedAt))
	require.False(t, consumedAt.Before(databaseNow))
	require.False(t, consumedAt.Equal(callerNow))
}

func assertA9KeysetHistoryCount(
	t *testing.T,
	db interface {
		QueryRowContext(
			context.Context,
			string,
			...any,
		) *sql.Row
	},
	expected int,
) {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_accepted_keysets`,
	).Scan(&count))
	require.Equal(t, expected, count)
}

func defaultA9OnlineKeys(
	t *testing.T,
	issuedAt time.Time,
) []a9trust.OnlineKey {
	t.Helper()
	return []a9trust.OnlineKey{
		a9TestOnlineKey(
			t,
			0x31,
			"A9_CONTROL",
			"SIGN",
			issuedAt.Add(-time.Hour),
			issuedAt.Add(48*time.Hour),
		),
		a9TestOnlineKey(
			t,
			0x32,
			"SERVICE_AUTH",
			"SIGN",
			issuedAt.Add(-time.Hour),
			issuedAt.Add(48*time.Hour),
		),
	}
}

func keyMarkerForA9Use(use string) byte {
	if use == "A9_CONTROL" {
		return 0x31
	}
	return 0x32
}

func a9TestOnlineKey(
	t *testing.T,
	marker byte,
	use string,
	state string,
	notBefore time.Time,
	notAfter time.Time,
) a9trust.OnlineKey {
	t.Helper()
	publicKey := bytes.Repeat([]byte{marker}, 32)
	keyID, err := a9trust.Ed25519KeyID(publicKey)
	require.NoError(t, err)
	return a9trust.OnlineKey{
		KeyID:     keyID,
		Use:       use,
		PublicKey: publicKey,
		NotBefore: notBefore.UTC(),
		NotAfter:  notAfter.UTC(),
		State:     state,
	}
}

func a9StoreCandidate(
	t *testing.T,
	sequence uint64,
	issuedAt time.Time,
	onlineKeys []a9trust.OnlineKey,
	signatureMarker byte,
) a9trust.AcceptedKeyset {
	t.Helper()
	issuedAt = issuedAt.UTC()
	expiresAt := issuedAt.Add(24 * time.Hour)
	rootKeyID, err := a9trust.Ed25519KeyID(
		bytes.Repeat([]byte{0x51}, 32),
	)
	require.NoError(t, err)
	topicEpoch := a9trust.TopicEpoch(issuedAt)
	rosterKeyID, err := a9trust.HMACKeyID(
		bytes.Repeat([]byte{0x61}, 32),
	)
	require.NoError(t, err)
	topicKeyID, err := a9trust.HMACKeyID(
		bytes.Repeat([]byte{0x62}, 32),
	)
	require.NoError(t, err)
	tupleKeyID, err := a9trust.HMACKeyID(
		bytes.Repeat([]byte{0x63}, 32),
	)
	require.NoError(t, err)
	commitments := []a9trust.CommitmentKey{
		{
			Purpose:   "ROSTER",
			KeyID:     rosterKeyID,
			NotBefore: issuedAt.Add(-time.Hour),
			NotAfter:  expiresAt.Add(time.Hour),
		},
		{
			Purpose:       "TOPIC",
			KeyID:         topicKeyID,
			TopicKeyEpoch: &topicEpoch,
			NotBefore:     issuedAt.Add(-time.Hour),
			NotAfter:      expiresAt.Add(time.Hour),
		},
		{
			Purpose:   "TUPLE",
			KeyID:     tupleKeyID,
			NotBefore: issuedAt.Add(-time.Hour),
			NotAfter:  expiresAt.Add(time.Hour),
		},
	}
	rawOnline := make([]any, 0, len(onlineKeys))
	for _, key := range onlineKeys {
		rawOnline = append(rawOnline, map[string]any{
			"key_id":               key.KeyID,
			"use":                  key.Use,
			"public_key_base64url": base64.RawURLEncoding.EncodeToString(key.PublicKey),
			"not_before":           formatA9TestTime(key.NotBefore),
			"not_after":            formatA9TestTime(key.NotAfter),
			"state":                key.State,
		})
	}
	rawCommitments := make([]any, 0, len(commitments))
	for _, key := range commitments {
		var epoch any
		if key.TopicKeyEpoch != nil {
			epoch = json.Number(
				strconv.FormatUint(
					uint64(*key.TopicKeyEpoch),
					10,
				),
			)
		}
		rawCommitments = append(rawCommitments, map[string]any{
			"purpose":         key.Purpose,
			"key_id":          key.KeyID,
			"topic_key_epoch": epoch,
			"not_before":      formatA9TestTime(key.NotBefore),
			"not_after":       formatA9TestTime(key.NotAfter),
		})
	}
	object := map[string]any{
		"protocol":                 "hytch.a9-bridge-keyset",
		"schema_version":           json.Number("1"),
		"environment":              "dev",
		"keyset_sequence":          json.Number(strconv.FormatUint(sequence, 10)),
		"issued_at":                formatA9TestTime(issuedAt),
		"expires_at":               formatA9TestTime(expiresAt),
		"keys":                     rawOnline,
		"commitment_keys":          rawCommitments,
		"root_signing_key_id":      rootKeyID,
		"root_signature_algorithm": "Ed25519",
		"root_signature_base64url": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{signatureMarker}, 64)),
	}
	canonical, err := a9trust.Canonicalize(object)
	require.NoError(t, err)
	return a9trust.AcceptedKeyset{
		Environment:           "dev",
		Sequence:              sequence,
		ObjectHash:            a9trust.SHA256LowerHex(canonical),
		CanonicalSignedObject: canonical,
		IssuedAt:              issuedAt,
		ExpiresAt:             expiresAt,
		RootKeyID:             rootKeyID,
		OnlineKeys:            cloneA9TestOnlineKeys(onlineKeys),
		CommitmentKeys:        commitments,
	}
}

func cloneA9TestOnlineKeys(
	source []a9trust.OnlineKey,
) []a9trust.OnlineKey {
	cloned := make([]a9trust.OnlineKey, len(source))
	for index := range source {
		cloned[index] = source[index]
		cloned[index].PublicKey = append(
			[]byte(nil),
			source[index].PublicKey...,
		)
	}
	return cloned
}

func formatA9TestTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000Z")
}
