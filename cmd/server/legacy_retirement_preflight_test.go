package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	"github.com/xmtp/example-notification-server-go/pkg/options"
)

func TestLegacyRetirementPreflightModeIsMutuallyExclusive(t *testing.T) {
	valid := options.Options{
		MigrationDbConnectionString: "owner-connection",
		PreflightLegacyRetirement:   true,
	}
	require.True(t, legacyRetirementPreflightModeValid(valid))

	invalid := []options.Options{
		{},
		func() options.Options {
			config := valid
			config.DbConnectionString = "runtime-connection"
			return config
		}(),
		func() options.Options {
			config := valid
			config.CreateMigration = "unexpected"
			return config
		}(),
		func() options.Options {
			config := valid
			config.MigrateOnly = true
			return config
		}(),
		func() options.Options {
			config := valid
			config.Api.Enabled = true
			return config
		}(),
		func() options.Options {
			config := valid
			config.Xmtp.ListenerEnabled = true
			return config
		}(),
		func() options.Options {
			config := valid
			config.Apns.Enabled = true
			return config
		}(),
		func() options.Options {
			config := valid
			config.Fcm.Enabled = true
			return config
		}(),
		func() options.Options {
			config := valid
			config.HttpDelivery.Enabled = true
			return config
		}(),
		func() options.Options {
			config := valid
			config.Vault.Enabled = true
			return config
		}(),
		func() options.Options {
			config := valid
			config.A9.Enabled = true
			return config
		}(),
		func() options.Options {
			config := valid
			config.Incident.Enabled = true
			return config
		}(),
		func() options.Options {
			config := valid
			config.Apns.P8CertificateBase64 = "runtime-secret"
			return config
		}(),
		func() options.Options {
			config := valid
			config.Fcm.CredentialsJson = "runtime-secret"
			return config
		}(),
		func() options.Options {
			config := valid
			config.HttpDelivery.AuthHeader = "runtime-secret"
			return config
		}(),
		func() options.Options {
			config := valid
			config.Vault.MasterKeysJSON = "runtime-secret"
			return config
		}(),
		func() options.Options {
			config := valid
			config.A9.KeysetOrigin = "https://runtime-service"
			return config
		}(),
		func() options.Options {
			config := valid
			config.A9.PinnedRootPublicKeyBase64URL = "runtime-key"
			return config
		}(),
		func() options.Options {
			config := valid
			config.A9.PinnedRootKeyID = "runtime-key-id"
			return config
		}(),
		func() options.Options {
			config := valid
			config.A9.TopicCommitmentKeysJSON = "runtime-secret"
			return config
		}(),
		func() options.Options {
			config := valid
			config.Incident.OversightWebhookBearer = "runtime-secret"
			return config
		}(),
	}
	for _, config := range invalid {
		require.False(t, legacyRetirementPreflightModeValid(config))
	}
}

func TestRunLegacyRetirementPreflightModeWritesOnlyFixedResults(t *testing.T) {
	config := options.Options{
		MigrationDbConnectionString: "owner-connection",
		PreflightLegacyRetirement:   true,
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false
	completed := runLegacyRetirementPreflightMode(
		t.Context(),
		config,
		&stdout,
		&stderr,
		func(
			ctx context.Context,
			dsn string,
			wait time.Duration,
		) (string, bool) {
			called = true
			deadline, hasDeadline := ctx.Deadline()
			require.True(t, hasDeadline)
			require.WithinDuration(
				t,
				time.Now().Add(legacyRetirementPreflightTimeout),
				deadline,
				time.Second,
			)
			require.Equal(t, config.MigrationDbConnectionString, dsn)
			require.Equal(t, legacyRetirementPreflightDBWait, wait)
			return "database=\"safe\"\npreflight=pass\n", true
		},
	)
	require.True(t, completed)
	require.True(t, called)
	require.Equal(t, "database=\"safe\"\npreflight=pass\n", stdout.String())
	require.Empty(t, stderr.String())

	stdout.Reset()
	stderr.Reset()
	const unsafeRunnerOutput = "preflight=fail secret=must-not-escape\n"
	completed = runLegacyRetirementPreflightMode(
		t.Context(),
		config,
		&stdout,
		&stderr,
		func(
			context.Context,
			string,
			time.Duration,
		) (string, bool) {
			return unsafeRunnerOutput, false
		},
	)
	require.False(t, completed)
	require.Empty(t, stdout.String())
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		stderr.String(),
	)
	require.NotContains(t, stderr.String(), unsafeRunnerOutput)

	stdout.Reset()
	stderr.Reset()
	completed = runLegacyRetirementPreflightMode(
		t.Context(),
		config,
		alwaysFailWriter{},
		&stderr,
		func(
			context.Context,
			string,
			time.Duration,
		) (string, bool) {
			return "database=\"safe\"\npreflight=pass\n", true
		},
	)
	require.False(t, completed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		stderr.String(),
	)
}

func TestRunLegacyRetirementPreflightModeRejectsBeforeRunner(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false
	completed := runLegacyRetirementPreflightMode(
		t.Context(),
		options.Options{PreflightLegacyRetirement: true},
		&stdout,
		&stderr,
		func(
			context.Context,
			string,
			time.Duration,
		) (string, bool) {
			called = true
			return "unexpected", true
		},
	)
	require.False(t, completed)
	require.False(t, called)
	require.Empty(t, stdout.String())
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		stderr.String(),
	)
}

func TestLegacyRetirementPreflightRawArgumentDetection(t *testing.T) {
	testCases := []struct {
		name            string
		args            []string
		requested       bool
		migrationDSNCLI bool
	}{
		{
			name:      "standalone preflight flag",
			args:      []string{"--preflight-legacy-retirement"},
			requested: true,
		},
		{
			name: "preflight assignment is still a raw request",
			args: []string{
				"--preflight-legacy-retirement=false",
			},
			requested: true,
		},
		{
			name: "migration DSN separate value",
			args: []string{
				"--preflight-legacy-retirement",
				"--migration-db-connection-string",
				"postgres://owner:secret@database/vault",
			},
			requested:       true,
			migrationDSNCLI: true,
		},
		{
			name: "migration DSN assignment",
			args: []string{
				"--preflight-legacy-retirement",
				"--migration-db-connection-string=" +
					"postgres://owner:secret@database/vault",
			},
			requested:       true,
			migrationDSNCLI: true,
		},
		{
			name: "double dash terminates option scan",
			args: []string{
				"--",
				"--preflight-legacy-retirement",
				"--migration-db-connection-string=secret",
			},
		},
		{
			name: "ordinary runtime",
			args: []string{"--api"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(
				t,
				testCase.requested,
				legacyRetirementPreflightRequested(testCase.args),
			)
			require.Equal(
				t,
				testCase.migrationDSNCLI,
				legacyRetirementPreflightMigrationDSNOnCLI(
					testCase.args,
				),
			)
		})
	}
}

func TestLegacyRetirementPreflightParseBoundaryEmitsOneFixedLine(
	t *testing.T,
) {
	if helperCase := os.Getenv(
		"LEGACY_RETIREMENT_PREFLIGHT_HELPER_CASE",
	); helperCase != "" {
		switch helperCase {
		case "invalid_choice":
			os.Args = []string{
				"server",
				"--preflight-legacy-retirement",
				"--log-encoding=not-valid",
			}
		case "unknown_flag":
			os.Args = []string{
				"server",
				"--preflight-legacy-retirement",
				"--not-a-server-option",
			}
		case "help":
			os.Args = []string{
				"server",
				"--preflight-legacy-retirement",
				"--help",
			}
		case "cli_dsn":
			os.Args = []string{
				"server",
				"--preflight-legacy-retirement",
				"--migration-db-connection-string",
				"postgres://owner:must-not-escape@database/vault",
			}
		case "cli_dsn_assignment":
			os.Args = []string{
				"server",
				"--preflight-legacy-retirement",
				"--migration-db-connection-string=" +
					"postgres://owner:must-not-escape@database/vault",
			}
		default:
			panic("unknown helper case")
		}
		runServer()
		return
	}

	for _, helperCase := range []string{
		"invalid_choice",
		"unknown_flag",
		"help",
		"cli_dsn",
		"cli_dsn_assignment",
	} {
		t.Run(helperCase, func(t *testing.T) {
			commandContext, cancel := context.WithTimeout(
				t.Context(),
				5*time.Second,
			)
			defer cancel()
			command := exec.CommandContext(
				commandContext,
				os.Args[0],
				"-test.run=^"+
					"TestLegacyRetirementPreflightParseBoundary"+
					"EmitsOneFixedLine$",
			)
			command.Env = append(
				os.Environ(),
				"LEGACY_RETIREMENT_PREFLIGHT_HELPER_CASE="+
					helperCase,
			)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr

			err := command.Run()
			require.Error(t, err)
			require.NoError(t, commandContext.Err())
			require.Empty(t, stdout.String())
			require.Equal(
				t,
				database.LegacyRetirementPreflightFailureOutput,
				stderr.String(),
			)
			require.NotContains(t, stderr.String(), "must-not-escape")
		})
	}
}

func TestPreflightPanicBoundaryEmitsOnlyFixedFailure(t *testing.T) {
	var stderr bytes.Buffer
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() {
		log.SetOutput(originalWriter)
	})

	completed := runWithModeAwareFixedPanicBoundary(
		func() {
			panic("must-not-escape")
		},
		true,
		&stderr,
	)

	require.False(t, completed)
	require.Equal(
		t,
		database.LegacyRetirementPreflightFailureOutput,
		stderr.String(),
	)
	require.Empty(t, logs.String())
}

type alwaysFailWriter struct{}

func (alwaysFailWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
