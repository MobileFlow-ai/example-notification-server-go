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
	"github.com/xmtp/example-notification-server-go/pkg/options"
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

func TestA9RuntimeConfigurationRejectsDisabledMaterialAndDowngrades(
	t *testing.T,
) {
	require.True(t, a9RuntimeConfigurationValid(options.Options{}))

	disabledWithMaterial := options.Options{}
	disabledWithMaterial.A9.PinnedRootKeyID = "latent-key"
	require.False(t, a9RuntimeConfigurationValid(disabledWithMaterial))
	disabledWithInlineSecret := options.Options{}
	disabledWithInlineSecret.A9.TopicCommitmentKeysJSON =
		"inline-secret"
	require.False(
		t,
		a9RuntimeConfigurationValid(disabledWithInlineSecret),
	)

	valid := validA9RuntimeOptions(t)
	require.True(t, a9RuntimeConfigurationValid(valid))

	for name, mutate := range map[string]func(*options.Options){
		"vault off": func(config *options.Options) {
			config.Vault.Enabled = false
		},
		"api off": func(config *options.Options) {
			config.Api.Enabled = false
		},
		"listener off": func(config *options.Options) {
			config.Xmtp.ListenerEnabled = false
		},
		"v3 listener": func(config *options.Options) {
			config.Xmtp.ListenerType = "v3"
		},
		"legacy bearer downgrade": func(config *options.Options) {
			config.Vault.APIBearerToken = "legacy-static-bearer"
		},
		"missing origin": func(config *options.Options) {
			config.A9.KeysetOrigin = ""
		},
		"missing root public key": func(config *options.Options) {
			config.A9.PinnedRootPublicKeyBase64URL = ""
		},
		"missing root key id": func(config *options.Options) {
			config.A9.PinnedRootKeyID = ""
		},
		"missing topic key source": func(config *options.Options) {
			config.A9.TopicCommitmentKeysFilePath = ""
		},
		"inline topic key downgrade": func(config *options.Options) {
			config.A9.TopicCommitmentKeysJSON = "inline-secret"
		},
		"relative topic key source": func(config *options.Options) {
			config.A9.TopicCommitmentKeysFilePath =
				"topic-keys.json"
		},
		"zero timeout": func(config *options.Options) {
			config.A9.KeysetRequestTimeoutSeconds = 0
		},
		"oversized timeout": func(config *options.Options) {
			config.A9.KeysetRequestTimeoutSeconds =
				maxA9KeysetRequestTimeoutSeconds + 1
		},
		"missing private bind": func(config *options.Options) {
			config.A9.PrivateBindAddress = ""
		},
		"public private bind": func(config *options.Options) {
			config.A9.PrivateBindAddress =
				"203.0.113.8:9443"
		},
		"wildcard without isolation opt-in": func(config *options.Options) {
			config.A9.PrivateBindAddress = "0.0.0.0:9443"
		},
		"misplaced wildcard isolation opt-in": func(config *options.Options) {
			config.A9.AllowWildcardPrivateBind = true
		},
		"missing TLS certificate": func(config *options.Options) {
			config.A9.TLSCertificateFilePath = ""
		},
		"missing TLS private key": func(config *options.Options) {
			config.A9.TLSPrivateKeyFilePath = ""
		},
		"zero header timeout": func(config *options.Options) {
			config.A9.ReadHeaderTimeoutSeconds = 0
		},
		"read below header timeout": func(config *options.Options) {
			config.A9.ReadTimeoutSeconds =
				config.A9.ReadHeaderTimeoutSeconds - 1
		},
		"oversized read timeout": func(config *options.Options) {
			config.A9.ReadTimeoutSeconds =
				maxA9RequestTimeoutSeconds + 1
		},
		"zero write timeout": func(config *options.Options) {
			config.A9.WriteTimeoutSeconds = 0
		},
		"oversized idle timeout": func(config *options.Options) {
			config.A9.IdleTimeoutSeconds =
				maxA9IdleTimeoutSeconds + 1
		},
		"small header bound": func(config *options.Options) {
			config.A9.MaxHeaderBytes = minA9HeaderBytes - 1
		},
		"large header bound": func(config *options.Options) {
			config.A9.MaxHeaderBytes = maxA9HeaderBytes + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			require.False(t, a9RuntimeConfigurationValid(candidate))
		})
	}

	wildcard := valid
	wildcard.A9.PrivateBindAddress = "0.0.0.0:9443"
	wildcard.A9.AllowWildcardPrivateBind = true
	require.True(t, a9RuntimeConfigurationValid(wildcard))
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
