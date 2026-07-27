package httpapi

import (
	"net/http"
	"strings"
)

type RouterConfig struct {
	Readiness     *Readiness
	AgentAuth     func(http.Handler) http.Handler
	HumanAuth     func(bool, http.Handler) http.Handler
	Authority     http.Handler
	Enrollment    http.Handler
	OAuth         http.Handler
	Webhook       http.Handler
	Subscriptions http.Handler
	Read          http.Handler
	Pulls         http.Handler
	Search        http.Handler
	Sync          http.Handler
	Queue         http.Handler
	SyncHuman     http.Handler
	SearchHuman   http.Handler
	UI            http.Handler
	UIAuth        func(http.Handler) http.Handler
	MaxConcurrent int
}

func NewRouter(config RouterConfig) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/livez", http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("{\"live\":true}\n"))
	}))
	if config.Readiness != nil {
		mux.Handle("/readyz", config.Readiness.Handler())
	}

	ready := func(handler http.Handler) http.Handler {
		if config.Readiness == nil {
			return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				http.Error(response, "service not ready", http.StatusServiceUnavailable)
			})
		}
		return config.Readiness.Require(handler)
	}
	agent := func(handler http.Handler) http.Handler {
		if config.AgentAuth == nil {
			return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				http.Error(response, "agent authentication unavailable", http.StatusServiceUnavailable)
			})
		}
		return config.AgentAuth(handler)
	}
	human := func(recent bool, handler http.Handler) http.Handler {
		if config.HumanAuth == nil {
			return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				http.Error(response, "human authentication unavailable", http.StatusServiceUnavailable)
			})
		}
		return config.HumanAuth(recent, handler)
	}

	if config.Webhook != nil {
		mux.Handle("/webhooks/github", ready(config.Webhook))
	}
	if config.OAuth != nil {
		mux.Handle("/login/github", ready(config.OAuth))
		mux.Handle("/oauth/github/callback", ready(config.OAuth))
		mux.Handle("/v1/oauth/github/begin", ready(human(true, config.OAuth)))
	}
	if config.Enrollment != nil {
		mux.Handle("/v1/enrollments/challenge", ready(config.Enrollment))
		mux.Handle("/v1/enrollments/", ready(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if strings.HasSuffix(request.URL.Path, "/approve") {
				human(true, config.Enrollment).ServeHTTP(response, request)
				return
			}
			config.Enrollment.ServeHTTP(response, request)
		})))
	}
	if config.Authority != nil {
		// Approving publishes something irreversible to a public repository, so
		// it demands a fresh step-up. DECLINING PUBLISHES NOTHING — it stops a
		// publication — and gating it the same way means that once the
		// step-up window lapses, refusing costs the reviewer exactly as much
		// friction as consenting. Saying no must never be harder than saying
		// yes; the same rule governs DurableBroker.Decline, which deliberately
		// does not re-verify the approval binding.
		//
		// Decline still requires an authenticated human session and CSRF —
		// human(false, ...) drops only the recent-auth requirement.
		//
		// Found by declining on the deployed page and watching it refuse
		// (2026-07-26). No handler test could see this: the gate lives in the
		// router, above the handler's test scope.
		mux.Handle("/v1/reviews/", ready(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if strings.HasSuffix(strings.TrimRight(request.URL.Path, "/"), "/decline") {
				human(false, config.Authority).ServeHTTP(response, request)
				return
			}
			human(true, config.Authority).ServeHTTP(response, request)
		})))
		mux.Handle("/v1/operations", ready(agent(config.Authority)))
		mux.Handle("/v1/operations/", ready(agent(config.Authority)))
		mux.Handle("/v1/policy", http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodPost {
				ready(human(true, config.Authority)).ServeHTTP(response, request)
				return
			}
			agent(config.Authority).ServeHTTP(response, request)
		}))
	}
	if config.Subscriptions != nil {
		mux.Handle("/v1/subscriptions", ready(agent(config.Subscriptions)))
		mux.Handle("/v1/subscriptions/", ready(agent(config.Subscriptions)))
		mux.Handle("/v1/notifications/", agent(config.Subscriptions))
	}
	if config.Read != nil {
		mux.Handle("/v1/read-sessions", ready(agent(config.Read)))
		mux.Handle("/git/", ready(config.Read))
	}
	if config.Pulls != nil {
		mux.Handle("/v1/pulls", ready(agent(config.Pulls)))
	}
	if config.Search != nil {
		mux.Handle("/v1/search", ready(agent(config.Search)))
	}
	if config.Sync != nil {
		mux.Handle("/v1/sync", ready(agent(config.Sync)))
		mux.Handle("/v1/sync/", ready(agent(config.Sync)))
	}
	if config.Queue != nil {
		mux.Handle("/v1/queue/", ready(agent(config.Queue)))
	}
	if config.SyncHuman != nil {
		// Same rule as /v1/reviews/ above, applied to its twin. The step-up
		// exists because a route PUBLISHES something irreversible to a public
		// repository — not because it is a mutation.
		//
		// Only /authorize does that. `request-changes` sends the agent a note,
		// `done` confirms a merge that already happened on GitHub (or abandons
		// a sync whose pull request is dead), and `defer` reorders a private
		// queue. Gating those the same way means the reviewer who cannot
		// re-authenticate right now is blocked from every corrective action
		// while the queue keeps insisting they act.
		//
		// Found by tapping Done on the stranded PR #9 sync and watching it
		// refuse (2026-07-26) — the SAME defect fixed for /v1/reviews/decline
		// an hour earlier, in a sibling group I did not check. When you find a
		// gate, look for its twin.
		mux.Handle("/v1/human/", ready(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if strings.HasSuffix(strings.TrimRight(request.URL.Path, "/"), "/authorize") {
				human(true, config.SyncHuman).ServeHTTP(response, request)
				return
			}
			human(false, config.SyncHuman).ServeHTTP(response, request)
		})))
	}
	if config.SearchHuman != nil {
		// Exact path beats the /v1/human/ prefix in ServeMux matching, so this
		// coexists with the SyncHuman catch-all above.
		mux.Handle("/v1/human/search/refresh", ready(human(true, config.SearchHuman)))
	}
	if config.UI != nil && config.UIAuth != nil {
		// The apex proxies / to this service; a bare domain visit should land
		// in the app, not a 404.
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				http.Redirect(w, r, "/ui/now", http.StatusFound)
				return
			}
			http.NotFound(w, r)
		}))
		// Stylesheet and script are registered UNWRAPPED, ahead of the
		// authenticated subtree. They carry no tenant data, and http.ServeMux
		// prefers the longer pattern, so these win over "/ui/".
		//
		// The gate lives HERE, not in the UI handler: moving the static case
		// above the session check inside Handler.ServeHTTP changed nothing in
		// production, because UIAuth wraps the whole subtree and the handler
		// never runs for a logged-out request. The unit test still passed — it
		// calls Handler.ServeHTTP directly, below this middleware. Only the
		// post-deploy smoke caught it (2026-07-26). Fix the layer that actually
		// serves the request, not the one that is easiest to test.
		mux.Handle("/ui/static/styles.css", ready(config.UI))
		mux.Handle("/ui/static/app.js", ready(config.UI))
		mux.Handle("/ui", ready(config.UIAuth(config.UI)))
		mux.Handle("/ui/", ready(config.UIAuth(config.UI)))
	}

	return SecurityHeaders(RejectForwardingAmbiguity(LimitConcurrent(config.MaxConcurrent, mux)))
}
