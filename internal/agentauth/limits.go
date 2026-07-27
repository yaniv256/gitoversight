package agentauth

import (
	"errors"
	"strings"
	"sync"
	"time"
)

type FixedWindowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	now     func() time.Time
	sources map[string]sourceWindow
}

type sourceWindow struct {
	startsAt time.Time
	count    int
}

func NewFixedWindowLimiter(limit int, window time.Duration, now func() time.Time) (*FixedWindowLimiter, error) {
	if limit <= 0 || window <= 0 {
		return nil, errors.New("positive rate limit and window are required")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &FixedWindowLimiter{limit: limit, window: window, now: now, sources: make(map[string]sourceWindow)}, nil
}

func (limiter *FixedWindowLimiter) Allow(source string) bool {
	if limiter == nil || strings.TrimSpace(source) == "" {
		return false
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now().UTC()
	current := limiter.sources[source]
	if current.startsAt.IsZero() || !now.Before(current.startsAt.Add(limiter.window)) {
		current = sourceWindow{startsAt: now}
	}
	if current.count >= limiter.limit {
		return false
	}
	current.count++
	limiter.sources[source] = current
	return true
}
