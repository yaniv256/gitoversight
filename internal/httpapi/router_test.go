package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRouterKeepsLivenessSeparateAndGatesMutationsOnReadiness(t *testing.T) {
	readiness := NewReadiness([]Check{CheckFunc{CheckName: "worker", Run: func(context.Context) error { return errors.New("offline") }}})
	called := false
	authority := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		called = true
		response.WriteHeader(http.StatusCreated)
	})
	router := NewRouter(RouterConfig{
		Readiness: readiness,
		AgentAuth: func(next http.Handler) http.Handler { return next },
		HumanAuth: func(_ bool, next http.Handler) http.Handler { return next },
		Authority: authority,
	})

	for path, want := range map[string]int{"/livez": http.StatusOK, "/readyz": http.StatusServiceUnavailable, "/v1/operations": http.StatusServiceUnavailable} {
		request := httptest.NewRequest(http.MethodPost, "https://gitoversight.test"+path, nil)
		if path != "/v1/operations" {
			request.Method = http.MethodGet
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != want {
			t.Errorf("%s status = %d, want %d", path, response.Code, want)
		}
	}
	if called {
		t.Fatal("unready authority handler was called")
	}
}

func TestRouterBypassesBodyBufferingAgentAuthOnlyForExactRawAssetRoute(t *testing.T) {
	var agentCalls int
	var bodyReads int
	releaseAssets := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		buffer := make([]byte, 1)
		if strings.HasSuffix(request.URL.Path, "/content") {
			_, _ = request.Body.Read(buffer)
		}
		response.WriteHeader(http.StatusNoContent)
	})
	router := NewRouter(RouterConfig{
		Readiness: NewReadiness([]Check{CheckFunc{CheckName: "ok", Run: func(context.Context) error { return nil }}}),
		AgentAuth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				agentCalls++
				next.ServeHTTP(response, request)
			})
		},
		ReleaseAssets: releaseAssets,
		MaxConcurrent: 2,
	})
	issue := httptest.NewRequest(http.MethodPost, "/v1/release-assets", nil)
	router.ServeHTTP(httptest.NewRecorder(), issue)
	if agentCalls != 1 {
		t.Fatalf("metadata agent auth calls = %d", agentCalls)
	}
	raw := httptest.NewRequest(http.MethodPut, "/v1/release-assets/0123456789abcdef0123456789abcdef/content", &routerCountingReader{reads: &bodyReads})
	router.ServeHTTP(httptest.NewRecorder(), raw)
	if agentCalls != 1 {
		t.Fatalf("raw upload invoked body-signing auth: calls=%d", agentCalls)
	}
	if bodyReads != 1 {
		t.Fatalf("raw handler body reads = %d", bodyReads)
	}
	status := httptest.NewRequest(http.MethodGet, "/v1/release-assets/0123456789abcdef0123456789abcdef?repository=yaniv256/private", nil)
	router.ServeHTTP(httptest.NewRecorder(), status)
	if agentCalls != 2 {
		t.Fatalf("status did not use agent auth: calls=%d", agentCalls)
	}
}

type routerCountingReader struct {
	reads *int
}

func (reader *routerCountingReader) Read([]byte) (int, error) {
	(*reader.reads)++
	return 0, io.EOF
}

func TestRouterUsesHumanAuthForPolicyPromotionAndAgentAuthForPolicyRead(t *testing.T) {
	readiness := NewReadiness([]Check{CheckFunc{CheckName: "ready", Run: func(context.Context) error { return nil }}})
	var agentCalls, humanCalls int
	router := NewRouter(RouterConfig{
		Readiness: readiness,
		AgentAuth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				agentCalls++
				next.ServeHTTP(response, request)
			})
		},
		HumanAuth: func(recent bool, next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if !recent {
					t.Fatal("policy promotion did not require recent authentication")
				}
				humanCalls++
				next.ServeHTTP(response, request)
			})
		},
		Authority: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) }),
	})
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(method, "https://gitoversight.test/v1/policy", nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s policy status = %d", method, response.Code)
		}
	}
	scopedResponse := httptest.NewRecorder()
	router.ServeHTTP(scopedResponse, httptest.NewRequest(http.MethodPost, "https://gitoversight.test/v1/policy/private-owner-additions", nil))
	if scopedResponse.Code != http.StatusNoContent {
		t.Fatalf("scoped policy promotion = %d", scopedResponse.Code)
	}
	orchestratorResponse := httptest.NewRecorder()
	router.ServeHTTP(orchestratorResponse, httptest.NewRequest(http.MethodPost, "https://gitoversight.test/v1/policy/orchestrator", nil))
	if orchestratorResponse.Code != http.StatusNoContent {
		t.Fatalf("orchestrator policy promotion = %d", orchestratorResponse.Code)
	}
	if agentCalls != 3 || humanCalls != 1 {
		t.Fatalf("auth calls: agent=%d human=%d", agentCalls, humanCalls)
	}
}

func TestRouterAppliesMethodSpecificWorkOAuthAndMCPBoundaries(t *testing.T) {
	readiness := NewReadiness([]Check{CheckFunc{CheckName: "ready", Run: func(context.Context) error { return nil }}})
	var humanCalls, pageCalls, agentCalls int
	oauth := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) })
	mcp := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusAccepted) })
	router := NewRouter(RouterConfig{
		Readiness: readiness,
		AgentAuth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				agentCalls++
				next.ServeHTTP(response, request)
			})
		},
		HumanAuth: func(_ bool, next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				humanCalls++
				next.ServeHTTP(response, request)
			})
		},
		UIAuth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				pageCalls++
				next.ServeHTTP(response, request)
			})
		},
		WorkOAuth: oauth, MCP: mcp,
	})
	for _, test := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/.well-known/oauth-authorization-server", http.StatusNoContent},
		{http.MethodGet, "/oauth/authorize", http.StatusNoContent},
		{http.MethodPost, "/oauth/authorize", http.StatusNoContent},
		{http.MethodPost, "/oauth/token", http.StatusNoContent},
		{http.MethodPost, "/mcp", http.StatusAccepted},
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(test.method, "https://gitoversight.test"+test.path, nil))
		if response.Code != test.want {
			t.Fatalf("%s %s = %d", test.method, test.path, response.Code)
		}
	}
	if pageCalls != 1 || humanCalls != 1 || agentCalls != 0 {
		t.Fatalf("auth calls page=%d human=%d agent=%d", pageCalls, humanCalls, agentCalls)
	}
}

// Approving publishes something irreversible to a public repository and demands
// a fresh step-up. Declining publishes NOTHING, so it must not carry the same
// friction — otherwise, once the step-up window lapses, refusing an agent's
// action costs the reviewer exactly as much as consenting to it.
//
// Found by declining on the deployed page and watching it refuse with "needs a
// fresh sign-in" (2026-07-26). No handler test could catch it: the gate lives
// here in the router, above the handler's test scope — the same
// test-enters-below-the-layer shape this project keeps hitting.
func TestRouterDoesNotMakeDecliningHarderThanApproving(t *testing.T) {
	readiness := NewReadiness([]Check{CheckFunc{CheckName: "ready", Run: func(context.Context) error { return nil }}})
	recentByPath := map[string]bool{}
	router := NewRouter(RouterConfig{
		Readiness: readiness,
		AgentAuth: func(next http.Handler) http.Handler { return next },
		HumanAuth: func(recent bool, next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				recentByPath[request.URL.Path] = recent
				next.ServeHTTP(response, request)
			})
		},
		Authority: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) }),
	})
	for _, path := range []string{"/v1/reviews/op-1/approve", "/v1/reviews/op-1/decline"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://gitoversight.test"+path, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s = %d", path, response.Code)
		}
	}
	if !recentByPath["/v1/reviews/op-1/approve"] {
		t.Fatal("approve no longer requires recent authentication — the step-up gate regressed")
	}
	if recentByPath["/v1/reviews/op-1/decline"] {
		t.Fatal("decline requires a fresh step-up: saying no is harder than saying yes")
	}
	// Declining still requires an authenticated human session; only the
	// recent-auth requirement is dropped.
	if _, gated := recentByPath["/v1/reviews/op-1/decline"]; !gated {
		t.Fatal("decline bypassed human authentication entirely")
	}
}

// The stylesheet and script must reach a LOGGED-OUT browser. They were behind
// UIAuth, so a signed-out visitor got a redirect instead of CSS/JS.
//
// This test lives at the ROUTER, not the UI handler, because that is where the
// gate actually is. An equivalent test inside internal/ui passed the whole time
// — it calls Handler.ServeHTTP directly, below this middleware, so it could not
// see the wrapper at all. Only the post-deploy smoke caught the real behaviour
// (2026-07-26). Test the layer that serves the request.
func TestRouterServesStaticAssetsWithoutHumanAuth(t *testing.T) {
	readiness := NewReadiness([]Check{CheckFunc{CheckName: "ready", Run: func(context.Context) error { return nil }}})
	uiAuthCalls := 0
	router := NewRouter(RouterConfig{
		Readiness: readiness,
		UI: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusOK)
		}),
		UIAuth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				uiAuthCalls++
				// Stand in for a logged-out visitor.
				http.Redirect(response, request, "/login/github", http.StatusFound)
			})
		},
	})

	for _, path := range []string{"/ui/static/styles.css", "/ui/static/app.js"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://gitoversight.test"+path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200 for a logged-out browser", path, response.Code)
		}
	}
	if uiAuthCalls != 0 {
		t.Fatalf("UIAuth ran %d times for static assets; they must bypass it", uiAuthCalls)
	}

	// The authenticated subtree must STILL be gated — the bypass is narrow.
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://gitoversight.test/ui/now", nil))
	if response.Code != http.StatusFound || uiAuthCalls != 1 {
		t.Fatalf("/ui/now status=%d uiAuthCalls=%d, want 302 and exactly one gate call", response.Code, uiAuthCalls)
	}
}

func TestRouterRegistersSearchBehindAgentAuthAndReadiness(t *testing.T) {
	readiness := NewReadiness([]Check{CheckFunc{CheckName: "ready", Run: func(context.Context) error { return nil }}})
	var agentCalls int
	router := NewRouter(RouterConfig{
		Readiness: readiness,
		AgentAuth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				agentCalls++
				next.ServeHTTP(response, request)
			})
		},
		HumanAuth: func(_ bool, next http.Handler) http.Handler { return next },
		Search:    http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) }),
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://gitoversight.test/v1/search?q=x", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("search status = %d", response.Code)
	}
	if agentCalls != 1 {
		t.Fatalf("agent auth calls = %d, want 1", agentCalls)
	}
}

func TestRouterOmitsSearchWhenUnconfigured(t *testing.T) {
	readiness := NewReadiness([]Check{CheckFunc{CheckName: "ready", Run: func(context.Context) error { return nil }}})
	router := NewRouter(RouterConfig{
		Readiness: readiness,
		AgentAuth: func(next http.Handler) http.Handler { return next },
		HumanAuth: func(_ bool, next http.Handler) http.Handler { return next },
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://gitoversight.test/v1/search?q=x", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("search status = %d, want 404", response.Code)
	}
	// The readiness endpoint stays healthy with search disabled.
	ready := httptest.NewRecorder()
	router.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "https://gitoversight.test/readyz", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("readyz status = %d", ready.Code)
	}
}

func TestCachedReadinessBoundsDeepChecks(t *testing.T) {
	var calls atomic.Int32
	readiness := NewCachedReadiness([]Check{CheckFunc{CheckName: "sqlite", Run: func(context.Context) error {
		calls.Add(1)
		return nil
	}}}, time.Minute)
	if !readiness.Status(context.Background()).Ready || !readiness.Status(context.Background()).Ready {
		t.Fatal("readiness unexpectedly failed")
	}
	if calls.Load() != 1 {
		t.Fatalf("deep check calls = %d", calls.Load())
	}
}

func TestCachedReadinessHealthyRefreshDoesNotManufactureUnavailableResponse(t *testing.T) {
	var calls atomic.Int32
	now := time.Unix(1000, 0)
	readiness := NewCachedReadiness([]Check{CheckFunc{CheckName: "sqlite", Run: func(context.Context) error {
		calls.Add(1)
		return nil
	}}}, time.Second)
	readiness.now = func() time.Time { return now }
	if !readiness.Status(context.Background()).Ready {
		t.Fatal("initial readiness failed")
	}
	now = now.Add(2 * time.Second)
	if !readiness.Status(context.Background()).Ready {
		t.Fatal("healthy refresh manufactured an unavailable response")
	}
	if calls.Load() != 2 {
		t.Fatalf("check calls = %d, want 2", calls.Load())
	}
}

func TestCachedReadinessCoalescesOneBoundedRefreshWithoutServingStaleSuccess(t *testing.T) {
	var calls atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	readiness := NewCachedReadiness([]Check{CheckFunc{CheckName: "audit", Run: func(context.Context) error {
		if calls.Add(1) == 2 {
			close(refreshStarted)
			<-releaseRefresh
			return errors.New("audit unavailable")
		}
		return nil
	}}}, time.Second)
	now := time.Unix(1000, 0)
	readiness.now = func() time.Time { return now }
	if !readiness.Status(context.Background()).Ready {
		t.Fatal("initial readiness failed")
	}
	now = now.Add(2 * time.Second)
	results := make(chan ReadinessStatus, 2)
	go func() { results <- readiness.Status(context.Background()) }()
	<-refreshStarted
	go func() { results <- readiness.Status(context.Background()) }()
	if got := calls.Load(); got != 2 {
		t.Fatalf("refresh calls = %d, want 2", got)
	}
	close(releaseRefresh)
	for range 2 {
		status := <-results
		if status.Ready || len(status.Failed) != 1 || status.Failed[0] != "audit" {
			t.Fatalf("refresh status = %+v", status)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("concurrent stale read launched another refresh: calls=%d", calls.Load())
	}
}

func TestReadinessTimeoutNamesTheDependencyThatDidNotAnswer(t *testing.T) {
	readiness := NewReadiness([]Check{
		CheckFunc{CheckName: "sqlite", Run: func(context.Context) error { return nil }},
		CheckFunc{CheckName: "checkpoint", Run: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }},
	})
	readiness.checkTimeout = time.Millisecond
	status := readiness.Status(context.Background())
	if status.Ready || len(status.Failed) != 1 || status.Failed[0] != "checkpoint" {
		t.Fatalf("status = %#v", status)
	}
}

func TestLimitConcurrentRejectsBeforeCallingHandler(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	handler := LimitConcurrent(1, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		response.WriteHeader(http.StatusNoContent)
	}))
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://gitoversight.test", nil))
		close(done)
	}()
	<-entered
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "https://gitoversight.test", nil))
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second status = %d", second.Code)
	}
	close(release)
	<-done
}

func TestSecurityHeadersAllowSameOriginApprovalRequests(t *testing.T) {
	response := httptest.NewRecorder()
	SecurityHeaders(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://gitoversight.test", nil))

	const want = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'"
	if got := response.Header().Get("Content-Security-Policy"); got != want {
		t.Fatalf("Content-Security-Policy = %q, want %q", got, want)
	}
}

func TestRouterRoutesSearchRefreshToSearchHumanHandler(t *testing.T) {
	readiness := NewReadiness([]Check{CheckFunc{CheckName: "ready", Run: func(context.Context) error { return nil }}})
	var syncCalls, refreshCalls int
	router := NewRouter(RouterConfig{
		Readiness: readiness,
		HumanAuth: func(recent bool, next http.Handler) http.Handler {
			if !recent {
				t.Fatal("human search refresh did not require recent authentication")
			}
			return next
		},
		SyncHuman: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { syncCalls++; response.WriteHeader(http.StatusOK) }),
		SearchHuman: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			refreshCalls++
			response.WriteHeader(http.StatusAccepted)
		}),
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://gitoversight.test/v1/human/search/refresh", nil))
	if response.Code != http.StatusAccepted {
		t.Fatalf("refresh status = %d", response.Code)
	}
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://gitoversight.test/v1/human/sync/s1/authorize", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("sync status = %d", response.Code)
	}
	if syncCalls != 1 || refreshCalls != 1 {
		t.Fatalf("calls: sync=%d refresh=%d", syncCalls, refreshCalls)
	}
}

// The twin of TestRouterDoesNotMakeDecliningHarderThanApproving. The step-up
// gate belongs on routes that PUBLISH to a public repository — not on every
// mutation. Gating the corrective actions the same way blocks a reviewer who
// cannot re-authenticate from resolving anything, while the queue keeps
// insisting they act.
//
// Found by tapping Done on a real stranded sync and watching it refuse. The
// principle was already written one route group above; it simply had not been
// applied here.
func TestRouterStepsUpOnlyForRoutesThatPublish(t *testing.T) {
	readiness := NewReadiness([]Check{CheckFunc{CheckName: "ready", Run: func(context.Context) error { return nil }}})
	recentByPath := map[string]bool{}
	router := NewRouter(RouterConfig{
		Readiness: readiness,
		AgentAuth: func(next http.Handler) http.Handler { return next },
		HumanAuth: func(recent bool, next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				recentByPath[request.URL.Path] = recent
				next.ServeHTTP(response, request)
			})
		},
		SyncHuman: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) }),
	})
	for _, path := range []string{
		"/v1/human/sync/s1/authorize",
		"/v1/human/sync/s1/done",
		"/v1/human/sync/s1/request-changes",
		"/v1/human/queue/q1/defer",
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://gitoversight.test"+path, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s = %d", path, response.Code)
		}
	}
	if !recentByPath["/v1/human/sync/s1/authorize"] {
		t.Fatal("authorize no longer requires a step-up — it publishes to a public repository")
	}
	for _, path := range []string{
		"/v1/human/sync/s1/done",
		"/v1/human/sync/s1/request-changes",
		"/v1/human/queue/q1/defer",
	} {
		if recentByPath[path] {
			t.Fatalf("%s requires a fresh step-up but publishes nothing", path)
		}
		if _, gated := recentByPath[path]; !gated {
			t.Fatalf("%s bypassed human authentication entirely", path)
		}
	}
}
