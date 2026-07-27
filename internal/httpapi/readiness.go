package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

type Check interface {
	Name() string
	Check(context.Context) error
}

type CheckFunc struct {
	CheckName string
	Run       func(context.Context) error
}

func (check CheckFunc) Name() string { return check.CheckName }

func (check CheckFunc) Check(ctx context.Context) error {
	if check.Run == nil {
		return context.Canceled
	}
	return check.Run(ctx)
}

type ReadinessStatus struct {
	Ready  bool     `json:"ready"`
	Failed []string `json:"failed,omitempty"`
}

type Readiness struct {
	checks       []Check
	cacheTTL     time.Duration
	checkTimeout time.Duration
	now          func() time.Time
	mu           sync.Mutex
	cached       ReadinessStatus
	expires      time.Time
	initialized  bool
	refreshing   bool
	refreshDone  chan struct{}
}

func NewReadiness(checks []Check) *Readiness {
	return NewCachedReadiness(checks, 0)

}

func NewCachedReadiness(checks []Check, cacheTTL time.Duration) *Readiness {
	return &Readiness{checks: append([]Check(nil), checks...), cacheTTL: cacheTTL, checkTimeout: 2 * time.Second, now: time.Now}
}

func (readiness *Readiness) Status(ctx context.Context) ReadinessStatus {
	if readiness == nil {
		return ReadinessStatus{Ready: false, Failed: []string{"configuration"}}
	}
	if readiness.cacheTTL <= 0 {
		return readiness.evaluate(ctx)
	}
	for {
		readiness.mu.Lock()
		now := readiness.now()
		if readiness.initialized && now.Before(readiness.expires) {
			status := cloneStatus(readiness.cached)
			readiness.mu.Unlock()
			return status
		}
		if readiness.refreshing {
			done := readiness.refreshDone
			readiness.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return ReadinessStatus{Ready: false, Failed: []string{"readiness_refresh"}}
			}
		}
		readiness.refreshing = true
		readiness.refreshDone = make(chan struct{})
		done := readiness.refreshDone
		readiness.mu.Unlock()

		status := readiness.evaluate(ctx)
		readiness.mu.Lock()
		readiness.cached = cloneStatus(status)
		readiness.expires = readiness.now().Add(readiness.cacheTTL)
		readiness.initialized = true
		readiness.refreshing = false
		close(done)
		readiness.mu.Unlock()
		return cloneStatus(status)
	}
}

func (readiness *Readiness) evaluate(ctx context.Context) ReadinessStatus {
	status := ReadinessStatus{Ready: true}
	if len(readiness.checks) == 0 {
		return ReadinessStatus{Ready: false, Failed: []string{"configuration"}}
	}
	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(readiness.checks))
	pending := make(map[string]int, len(readiness.checks))
	checkCtx, cancel := context.WithTimeout(ctx, readiness.checkTimeout)
	defer cancel()
	for _, candidate := range readiness.checks {
		check := candidate
		if check == nil || check.Name() == "" {
			pending["configuration"]++
			results <- result{name: "configuration", err: context.Canceled}
			continue
		}
		pending[check.Name()]++
		go func() { results <- result{name: check.Name(), err: check.Check(checkCtx)} }()
	}
	for received := 0; received < len(readiness.checks); received++ {
		select {
		case item := <-results:
			pending[item.name]--
			if item.err != nil {
				status.Ready = false
				status.Failed = append(status.Failed, item.name)
			}
		case <-checkCtx.Done():
			status.Ready = false
			for name, count := range pending {
				for range count {
					status.Failed = append(status.Failed, name)
				}
			}
			sort.Strings(status.Failed)
			return status
		}
	}
	sort.Strings(status.Failed)
	return status
}

func cloneStatus(status ReadinessStatus) ReadinessStatus {
	status.Failed = append([]string(nil), status.Failed...)
	return status
}

func (readiness *Readiness) Handler() http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.NotFound(response, request)
			return
		}
		status := readiness.Status(request.Context())
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		code := http.StatusOK
		if !status.Ready {
			code = http.StatusServiceUnavailable
		}
		response.WriteHeader(code)
		_ = json.NewEncoder(response).Encode(status)
	})
}

func (readiness *Readiness) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !readiness.Status(request.Context()).Ready {
			http.Error(response, "service not ready", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(response, request)
	})
}
