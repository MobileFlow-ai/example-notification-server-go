package db

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"time"
)

const (
	LegacyRetirementPreflightFailureOutput = "preflight=fail\n"

	legacyRetirementPreflightRetryInterval = 3 * time.Second

	legacyRetirementPreflightSuccessTail = "transaction_read_only=true\n" +
		"schema_migrations_ready=true\n" +
		"only_client_session=true\n" +
		"no_logical_subscription=true\n" +
		"no_enabled_event_trigger=true\n" +
		"legacy_relations_ready=true\n" +
		"activation_marker_empty=true\n" +
		"activation_functions_ready=true\n" +
		"activation_triggers_ready=true\n" +
		"no_named_non_owner_public_create=true\n" +
		"preflight=pass\n"
)

//go:embed legacy_retirement_preflight.sql
var legacyRetirementPreflightQuery string

// RunLegacyRetirementPreflight opens the owner connection without running
// migrations, executes the read-only catalog preflight, and returns only a
// fixed safe result. Driver and query errors never cross this boundary.
func RunLegacyRetirementPreflight(
	ctx context.Context,
	dsn string,
	waitForDB time.Duration,
) (output string, passed bool) {
	output = LegacyRetirementPreflightFailureOutput
	defer func() {
		if recover() != nil {
			output = LegacyRetirementPreflightFailureOutput
			passed = false
		}
	}()

	if dsn == "" {
		return output, false
	}
	db, err := openLegacyRetirementPreflightDB(ctx, dsn, waitForDB)
	if err != nil {
		return output, false
	}

	output, passed = CheckLegacyRetirementPreflight(ctx, db)
	if closeErr := db.Close(); closeErr != nil {
		return LegacyRetirementPreflightFailureOutput, false
	}
	return output, passed
}

func openLegacyRetirementPreflightDB(
	ctx context.Context,
	dsn string,
	waitForDB time.Duration,
) (*sql.DB, error) {
	if ctx == nil {
		return nil, errors.New("preflight context missing")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, errors.New("preflight database unavailable")
	}
	// The catalog query proves this process is the database's only client.
	// A one-connection pool prevents PingContext and the transaction from
	// creating two sessions and invalidating or masking that proof.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	waitUntil := time.Now().Add(waitForDB)
	for {
		if err = db.PingContext(ctx); err == nil {
			return db, nil
		}
		if ctx.Err() != nil || waitForDB <= 0 {
			_ = db.Close()
			return nil, errors.New("preflight database unavailable")
		}

		remaining := time.Until(waitUntil)
		if remaining <= 0 {
			_ = db.Close()
			return nil, errors.New("preflight database unavailable")
		}
		retryAfter := legacyRetirementPreflightRetryInterval
		if remaining < retryAfter {
			retryAfter = remaining
		}

		timer := time.NewTimer(retryAfter)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			_ = db.Close()
			return nil, errors.New("preflight database unavailable")
		case <-timer.C:
		}
	}
}

// CheckLegacyRetirementPreflight owns a SERIALIZABLE READ ONLY transaction.
// It commits only after every fixed catalog invariant passes; every other path
// rolls back and returns the same fixed failure result.
func CheckLegacyRetirementPreflight(
	ctx context.Context,
	db *sql.DB,
) (output string, passed bool) {
	output = LegacyRetirementPreflightFailureOutput
	defer func() {
		if recover() != nil {
			output = LegacyRetirementPreflightFailureOutput
			passed = false
		}
	}()

	tx, err := db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
		ReadOnly:  true,
	})
	if err != nil {
		return output, false
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var (
		databaseName                string
		transactionReadOnly         bool
		schemaMigrationsReady       bool
		onlyClientSession           bool
		noLogicalSubscription       bool
		noEnabledEventTrigger       bool
		legacyRelationsReady        bool
		activationMarkerEmpty       bool
		activationFunctionsReady    bool
		activationTriggersReady     bool
		noNamedNonOwnerPublicCreate bool
		allReady                    bool
	)
	err = tx.QueryRowContext(
		ctx,
		legacyRetirementPreflightQuery,
	).Scan(
		&databaseName,
		&transactionReadOnly,
		&schemaMigrationsReady,
		&onlyClientSession,
		&noLogicalSubscription,
		&noEnabledEventTrigger,
		&legacyRelationsReady,
		&activationMarkerEmpty,
		&activationFunctionsReady,
		&activationTriggersReady,
		&noNamedNonOwnerPublicCreate,
		&allReady,
	)
	if err != nil ||
		!transactionReadOnly ||
		!schemaMigrationsReady ||
		!onlyClientSession ||
		!noLogicalSubscription ||
		!noEnabledEventTrigger ||
		!legacyRelationsReady ||
		!activationMarkerEmpty ||
		!activationFunctionsReady ||
		!activationTriggersReady ||
		!noNamedNonOwnerPublicCreate ||
		!allReady {
		return output, false
	}

	encodedDatabaseName, err := json.Marshal(databaseName)
	if err != nil {
		return output, false
	}
	if err = tx.Commit(); err != nil {
		return output, false
	}

	return "database=" + string(encodedDatabaseName) + "\n" +
		legacyRetirementPreflightSuccessTail, true
}
