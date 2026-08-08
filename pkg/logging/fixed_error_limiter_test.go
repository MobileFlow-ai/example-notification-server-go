package logging

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestFixedErrorLimiterBoundsRepeatedRecords(t *testing.T) {
	core, observed := observer.New(zapcore.ErrorLevel)
	logger := zap.New(core)
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	var limiter FixedErrorLimiter

	limiter.Log(logger, now, "fixed worker error")
	limiter.Log(logger, now.Add(time.Minute), "fixed worker error")
	require.Len(t, observed.All(), 1)

	limiter.Log(
		logger,
		now.Add(FixedErrorLogInterval),
		"fixed worker error",
	)
	require.Len(t, observed.All(), 2)
}
