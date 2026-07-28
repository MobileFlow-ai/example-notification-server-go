package delivery

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

const fixedErrorLogInterval = time.Hour

// privacySafeErrorLimiter bounds fixed operational error records to one per
// replica and component per hour. Repeated per-job failures must not become an
// event-count or timing side channel in runtime logs.
type privacySafeErrorLimiter struct {
	mu        sync.Mutex
	nextLogAt time.Time
}

func (l *privacySafeErrorLimiter) Log(
	logger *zap.Logger,
	now time.Time,
	message string,
) {
	if l == nil || logger == nil || message == "" {
		return
	}
	now = now.UTC()
	l.mu.Lock()
	if !l.nextLogAt.IsZero() && now.Before(l.nextLogAt) {
		l.mu.Unlock()
		return
	}
	l.nextLogAt = now.Add(fixedErrorLogInterval)
	l.mu.Unlock()
	logger.Error(message)
}
