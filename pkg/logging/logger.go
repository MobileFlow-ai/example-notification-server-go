package logging

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func CreateLogger(encoding string, level string) *zap.Logger {
	cfg := zap.Config{
		Level:            getLevel(level),
		Encoding:         encoding,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:  "message",
			LevelKey:    "level",
			EncodeLevel: zapcore.CapitalLevelEncoder,
			TimeKey:     "time",
			EncodeTime: func(value time.Time, encoder zapcore.PrimitiveArrayEncoder) {
				encoder.AppendString(coarseLogTime(value))
			},
			NameKey:      "caller",
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}

	logger := zap.Must(cfg.Build())
	return logger.Named("notifications-server")
}

func coarseLogTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15Z")
}

func getLevel(levelString string) zap.AtomicLevel {
	level := zap.NewAtomicLevel()
	switch levelString {
	case "debug":
		level.SetLevel(zapcore.DebugLevel)
	case "error":
		level.SetLevel(zapcore.ErrorLevel)
	case "info":
		level.SetLevel(zapcore.InfoLevel)
	default:
		panic(fmt.Sprintf("unknown log level %s", levelString))
	}

	return level
}
