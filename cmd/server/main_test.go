package main

import (
	"bytes"
	"context"
	"log"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestCheckedSecureLeaseTTLRejectsOverflowBeforeConversion(t *testing.T) {
	for _, hours := range []int{-1, 0, maxSecureLeaseTTLHours + 1, math.MaxInt} {
		duration, valid := checkedSecureLeaseTTL(hours)
		require.False(t, valid)
		require.Zero(t, duration)
	}
}

func TestCheckedSecureLeaseTTLAcceptsBoundedHours(t *testing.T) {
	duration, valid := checkedSecureLeaseTTL(maxSecureLeaseTTLHours)
	require.True(t, valid)
	require.Equal(t, 7*24*time.Hour, duration)
}

func TestWelcomeRuntimeConfigurationIsHardClosed(t *testing.T) {
	require.True(t, welcomeRuntimeConfigurationValid(false))
	require.False(t, welcomeRuntimeConfigurationValid(true))
}

func TestAPNSRuntimeConfigurationIsHardClosed(t *testing.T) {
	require.True(t, apnsRuntimeConfigurationValid(false))
	require.False(t, apnsRuntimeConfigurationValid(true))
}

func TestCheckedXMTPWorkerCountRejectsInvalidAndOverflowValues(t *testing.T) {
	for _, workers := range []int{
		-math.MaxInt - 1,
		-1,
		0,
		maxXMTPListenerWorkers + 1,
		math.MaxInt,
	} {
		checked, valid := checkedXMTPWorkerCount(workers)
		require.False(t, valid)
		require.Zero(t, checked)
	}
}

func TestCheckedXMTPWorkerCountAcceptsInclusiveBounds(t *testing.T) {
	for _, workers := range []int{1, maxXMTPListenerWorkers} {
		checked, valid := checkedXMTPWorkerCount(workers)
		require.True(t, valid)
		require.Equal(t, workers, checked)
	}
}

func TestCheckedIncidentDurationsRejectOverflowBeforeConversion(
	t *testing.T,
) {
	invalid := [][3]int{
		{0, 1, 1},
		{maxIncidentRoleTTLMinutes + 1, 1, 1},
		{1, 0, 1},
		{1, maxIncidentRequestTimeoutSeconds + 1, 1},
		{1, 1, 0},
		{1, 1, maxIncidentOversightTimeoutSeconds + 1},
		{math.MaxInt, math.MaxInt, math.MaxInt},
	}
	for _, values := range invalid {
		roleTTL, requestTimeout, oversightTimeout, valid :=
			checkedIncidentDurations(
				values[0],
				values[1],
				values[2],
			)
		require.False(t, valid)
		require.Zero(t, roleTTL)
		require.Zero(t, requestTimeout)
		require.Zero(t, oversightTimeout)
	}
}

func TestCheckedIncidentDurationsAcceptInclusiveBounds(t *testing.T) {
	roleTTL, requestTimeout, oversightTimeout, valid :=
		checkedIncidentDurations(
			maxIncidentRoleTTLMinutes,
			maxIncidentRequestTimeoutSeconds,
			maxIncidentOversightTimeoutSeconds,
		)
	require.True(t, valid)
	require.Equal(t, 2*time.Hour, roleTTL)
	require.Equal(t, 30*time.Second, requestTimeout)
	require.Equal(t, 15*time.Second, oversightTimeout)
}

func TestProcessPanicBoundaryEmitsOnlyFixedMessage(t *testing.T) {
	var output bytes.Buffer
	originalWriter := log.Writer()
	originalFlags := log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
	})

	completed := runWithFixedPanicBoundary(func() {
		panic("sensitive-envelope-topic")
	})

	require.False(t, completed)
	require.Equal(t, "fatal runtime failure\n", output.String())
	require.NotContains(t, output.String(), "sensitive-envelope-topic")
}

func TestMonitorXMTPListenerFailureCancelsRuntimeWithFixedLog(t *testing.T) {
	core, observed := observer.New(zap.ErrorLevel)
	runtimeLogger := zap.New(core)
	ctx, cancel := context.WithCancel(t.Context())
	failed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		monitorXMTPListenerFailure(ctx, failed, runtimeLogger, cancel)
		close(done)
	}()

	close(failed)

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return ctx.Err() != nil && observed.Len() == 1
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
	entries := observed.All()
	require.Len(t, entries, 1)
	require.Equal(t, "XMTP listener stopped", entries[0].Message)
	require.Empty(t, entries[0].Context)
}

func TestMonitorXMTPListenerNormalShutdownDoesNotLogFailure(t *testing.T) {
	core, observed := observer.New(zap.ErrorLevel)
	ctx, cancel := context.WithCancel(t.Context())
	failed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		monitorXMTPListenerFailure(
			ctx,
			failed,
			zap.New(core),
			cancel,
		)
		close(done)
	}()

	cancel()

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
	require.Empty(t, observed.All())
}

func TestRetentionWorkerPanicCancelsRuntimeWithoutLoggingPanicValue(t *testing.T) {
	const canary = "RETENTION_PANIC_CANARY_RAW_DATABASE_VALUE"
	core, observed := observer.New(zap.ErrorLevel)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		runRetentionWorker(
			ctx,
			func(context.Context) error {
				panic(canary)
			},
			zap.New(core),
			cancel,
		)
		close(done)
	}()

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return ctx.Err() != nil && observed.Len() == 1
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
	entries := observed.All()
	require.Len(t, entries, 1)
	require.Equal(t, "retention worker stopped", entries[0].Message)
	require.Empty(t, entries[0].Context)
	require.NotContains(t, entries[0].Message, canary)
}

func TestRailwayDevConfigPinsDevelopmentEnvironments(t *testing.T) {
	config, err := os.ReadFile("../../railway.toml")
	require.NoError(t, err)
	startCommand := string(config)

	require.Contains(
		t,
		startCommand,
		"--bridge-environment=dev",
	)
	require.Contains(t, startCommand, "--apns-mode=development")
	require.Contains(
		t,
		startCommand,
		"--bridge-teen-conversation-mode=disabled",
	)
	require.NotContains(t, strings.ToLower(startCommand), "production")
}

func TestSecureRuntimeSchemaGateNeverAppliesPendingMigration(t *testing.T) {
	db := testdb.CreateEmptyTestDb(t)
	latest, err := database.LatestMigrationVersion()
	require.NoError(t, err)
	require.Greater(t, latest, 1)
	require.NoError(
		t,
		database.MigrateUpTo(t.Context(), db, uint(latest-1)),
	)

	require.Error(t, prepareRuntimeDatabase(t.Context(), db, true))
	var version int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT version FROM public.schema_migrations`,
	).Scan(&version))
	require.Equal(t, latest-1, version)

	require.NoError(t, prepareRuntimeDatabase(t.Context(), db, false))
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT version FROM public.schema_migrations`,
	).Scan(&version))
	require.Equal(t, latest, version)
}
