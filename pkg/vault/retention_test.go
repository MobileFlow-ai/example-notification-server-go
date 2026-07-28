package vault

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRetentionRunRecoversFromTransientFailuresWithBoundedBackoff(
	t *testing.T,
) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(t.Context())
	var (
		attempts int
		delays   []time.Duration
	)
	sweeper := &RetentionSweeper{
		db:            &sql.DB{},
		sweepInterval: 15 * time.Minute,
		now:           func() time.Time { return now },
		retryInitial:  time.Millisecond,
		retryMaximum:  2 * time.Millisecond,
		wait: func(ctx context.Context, delay time.Duration) bool {
			delays = append(delays, delay)
			return ctx.Err() == nil
		},
		healthOverride: func(
			context.Context,
		) (*RetentionHealth, error) {
			return nil, ErrRetentionUnavailable
		},
		sweepOverride: func(
			context.Context,
		) (*RetentionResult, error) {
			attempts++
			if attempts <= 3 {
				return nil, ErrRetentionUnavailable
			}
			cancel()
			return &RetentionResult{
				CompletedAt: now,
				NextDueAt:   now.Add(15 * time.Minute),
			}, nil
		},
	}

	require.NoError(t, sweeper.Run(ctx))
	require.Equal(t, 4, attempts)
	require.Equal(
		t,
		[]time.Duration{
			0,
			time.Millisecond,
			2 * time.Millisecond,
			2 * time.Millisecond,
		},
		delays,
	)
}

func TestRetentionEnsureReadyAcceptsHealthyLockOwner(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(15 * time.Minute)
	var (
		healthChecks int
		sweepCalls   int
		waitCalls    int
	)
	sweeper := &RetentionSweeper{
		db:            &sql.DB{},
		sweepInterval: 15 * time.Minute,
		now:           func() time.Time { return now },
		wait: func(context.Context, time.Duration) bool {
			waitCalls++
			return true
		},
		healthOverride: func(
			context.Context,
		) (*RetentionHealth, error) {
			healthChecks++
			if healthChecks == 1 {
				return &RetentionHealth{Safe: false}, nil
			}
			return &RetentionHealth{
				Safe:           true,
				NextDeadlineAt: &deadline,
			}, nil
		},
		sweepOverride: func(
			context.Context,
		) (*RetentionResult, error) {
			sweepCalls++
			return nil, ErrRetentionBusy
		},
	}

	require.NoError(t, sweeper.EnsureReady(t.Context()))
	require.Equal(t, 2, healthChecks)
	require.Equal(t, 1, sweepCalls)
	require.Zero(t, waitCalls)
}

func TestRetentionRunSchedulesBeforeHardDeadline(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(15 * time.Minute)
	ctx, cancel := context.WithCancel(t.Context())
	var delays []time.Duration
	sweeper := &RetentionSweeper{
		db:            &sql.DB{},
		sweepInterval: 15 * time.Minute,
		now:           func() time.Time { return now },
		wait: func(_ context.Context, delay time.Duration) bool {
			delays = append(delays, delay)
			cancel()
			return false
		},
		healthOverride: func(
			context.Context,
		) (*RetentionHealth, error) {
			return &RetentionHealth{
				Safe:           true,
				NextDeadlineAt: &deadline,
			}, nil
		},
		sweepOverride: func(
			context.Context,
		) (*RetentionResult, error) {
			t.Fatal("worker swept before its scheduled margin")
			return nil, ErrRetentionUnavailable
		},
	}

	require.NoError(t, sweeper.Run(ctx))
	require.Equal(
		t,
		[]time.Duration{15*time.Minute - retentionDeadlineMargin},
		delays,
	)
}

func TestNewRetentionSweeperRejectsInvalidConfiguration(t *testing.T) {
	sweeper, err := NewRetentionSweeper(nil, RetentionOptions{})
	require.Nil(t, sweeper)
	require.ErrorIs(t, err, ErrRetentionInvalid)

	db := &sql.DB{}
	lookup, err := NewLookupKey(make([]byte, 32))
	require.NoError(t, err)
	sweeper, err = NewRetentionSweeper(
		db,
		RetentionOptions{
			SweepInterval:        30 * time.Second,
			Environment:          "development",
			Lookup:               lookup,
			EncryptionKeyVersion: 1,
		},
	)
	require.Nil(t, sweeper)
	require.ErrorIs(t, err, ErrRetentionInvalid)

	sweeper, err = NewRetentionSweeper(
		db,
		RetentionOptions{
			SweepInterval:        2 * time.Hour,
			Environment:          "development",
			Lookup:               lookup,
			EncryptionKeyVersion: 1,
		},
	)
	require.Nil(t, sweeper)
	require.ErrorIs(t, err, ErrRetentionInvalid)
}

func TestRetentionHealthRequiresCompletedCurrentSweep(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	started := now.Add(-time.Minute)
	completed := now.Add(-30 * time.Second)
	deadline := now.Add(time.Minute)

	health := retentionHealthFromState(
		now,
		sql.NullTime{Time: started, Valid: true},
		sql.NullTime{Time: completed, Valid: true},
		sql.NullTime{Time: deadline, Valid: true},
		true,
		retentionOutcomeComplete,
	)
	require.True(t, health.Safe)
	require.Equal(t, started, *health.LastStartedAt)
	require.Equal(t, completed, *health.LastCompletedAt)
	require.Equal(t, deadline, *health.NextDeadlineAt)

	testCases := []struct {
		name          string
		lastStarted   sql.NullTime
		lastCompleted sql.NullTime
		nextDeadline  sql.NullTime
		storedSafe    bool
		fixedOutcome  int16
	}{
		{
			name:          "not marked safe",
			lastStarted:   sql.NullTime{Time: started, Valid: true},
			lastCompleted: sql.NullTime{Time: completed, Valid: true},
			nextDeadline:  sql.NullTime{Time: deadline, Valid: true},
			storedSafe:    false,
			fixedOutcome:  retentionOutcomeComplete,
		},
		{
			name:         "never completed",
			lastStarted:  sql.NullTime{Time: started, Valid: true},
			nextDeadline: sql.NullTime{Time: deadline, Valid: true},
			storedSafe:   true,
			fixedOutcome: retentionOutcomeComplete,
		},
		{
			name:          "deadline stale",
			lastStarted:   sql.NullTime{Time: started, Valid: true},
			lastCompleted: sql.NullTime{Time: completed, Valid: true},
			nextDeadline: sql.NullTime{
				Time:  now.Add(-time.Nanosecond),
				Valid: true,
			},
			storedSafe:   true,
			fixedOutcome: retentionOutcomeComplete,
		},
		{
			name:          "sweep still in progress",
			lastStarted:   sql.NullTime{Time: now, Valid: true},
			lastCompleted: sql.NullTime{Time: completed, Valid: true},
			nextDeadline:  sql.NullTime{Time: deadline, Valid: true},
			storedSafe:    true,
			fixedOutcome:  retentionOutcomeComplete,
		},
		{
			name:          "deadline reached",
			lastStarted:   sql.NullTime{Time: started, Valid: true},
			lastCompleted: sql.NullTime{Time: completed, Valid: true},
			nextDeadline:  sql.NullTime{Time: now, Valid: true},
			storedSafe:    true,
			fixedOutcome:  retentionOutcomeComplete,
		},
		{
			name:          "fixed failure outcome",
			lastStarted:   sql.NullTime{Time: started, Valid: true},
			lastCompleted: sql.NullTime{Time: completed, Valid: true},
			nextDeadline:  sql.NullTime{Time: deadline, Valid: true},
			storedSafe:    true,
			fixedOutcome:  retentionOutcomeUnsafe,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := retentionHealthFromState(
				now,
				testCase.lastStarted,
				testCase.lastCompleted,
				testCase.nextDeadline,
				testCase.storedSafe,
				testCase.fixedOutcome,
			)
			require.False(t, actual.Safe)
		})
	}
}
