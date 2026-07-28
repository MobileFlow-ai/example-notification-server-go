package logging

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

const FixedErrorLogInterval = time.Hour

// FixedErrorLimiter bounds fixed operational error records to one per replica
// and component per hour. Repeated failures must not become an exact event
// count or timing side channel in runtime logs.
type FixedErrorLimiter struct {
	mu        sync.Mutex
	nextLogAt time.Time
}

func (l *FixedErrorLimiter) Log(
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
	l.nextLogAt = now.Add(FixedErrorLogInterval)
	l.mu.Unlock()
	logger.Error(message)
}
