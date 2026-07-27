package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type GitHubOAuthConfig struct {
	MaxBodyBytes   int64
	TenantID       string
	HumanApprovers map[string]string
	HumanSessions  *HumanSessionManager
}

type GitHubOAuthWorker interface {
	BeginOAuth(workerrpc.OAuthBeginRequest) (string, error)
	CompleteOAuth(workerrpc.OAuthCallbackRequest) (workerrpc.OAuthCompletion, error)
}

type GitHubOAuthHandler struct {
	worker         GitHubOAuthWorker
	maxBody        int64
	tenantID       string
	humanApprovers map[string]string
	humanSessions  *HumanSessionManager
}

func NewGitHubOAuthHandler(worker GitHubOAuthWorker, config GitHubOAuthConfig) *GitHubOAuthHandler {
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 16 << 10
	}
	return &GitHubOAuthHandler{
		worker: worker, maxBody: config.MaxBodyBytes, tenantID: config.TenantID,
		humanApprovers: config.HumanApprovers, humanSessions: config.HumanSessions,
	}
}

func (handler *GitHubOAuthHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/login/github":
		handler.login(response, request)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/oauth/github/begin":
		handler.begin(response, request)
	case request.Method == http.MethodGet && request.URL.Path == "/oauth/github/callback":
		handler.callback(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (handler *GitHubOAuthHandler) login(response http.ResponseWriter, request *http.Request) {
	humanID := request.URL.Query().Get("human_id")
	// Browser redirects from the UI cannot know the approver id. With exactly
	// one configured approver there is no ambiguity — default to it so the
	// login link works without a query parameter.
	if humanID == "" && len(handler.humanApprovers) == 1 {
		for id := range handler.humanApprovers {
			humanID = id
		}
	}
	githubLogin, allowed := handler.humanApprovers[humanID]
	if handler.worker == nil || handler.humanSessions == nil || handler.tenantID == "" || !allowed || githubLogin == "" {
		writeError(response, http.StatusForbidden, "human_login_rejected")
		return
	}
	pending, err := handler.humanSessions.Begin(request.Context(), handler.tenantID)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "human_login_unavailable")
		return
	}
	authorizationURL, err := handler.worker.BeginOAuth(workerrpc.OAuthBeginRequest{
		Purpose: "human_login", Session: pending.Token, Subject: humanID, GitHubLogin: githubLogin,
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	})
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "oauth_unavailable")
		return
	}
	// Remember where to come back to. Re-authenticating is never the thing the
	// human set out to do — it interrupts something. Losing that destination is
	// what turned a routine step-up into a dead end (2026-07-26). A cookie
	// carries it across the GitHub round-trip without putting it in a URL GitHub
	// would have to echo back.
	http.SetCookie(response, returnCookie(safeReturnPath(request.URL.Query().Get("return_to"))))
	http.Redirect(response, request, authorizationURL, http.StatusSeeOther)
}

// returnCookieName holds the in-app path to resume after a login round-trip.
const returnCookieName = "gitoversight_return_to"

func returnCookie(path string) *http.Cookie {
	return &http.Cookie{
		Name: returnCookieName, Value: path, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 600,
	}
}

// safeReturnPath admits ONLY a same-site absolute path. An open redirect on a
// login endpoint is a phishing primitive: an attacker who can choose where
// "sign in" lands can bounce a freshly-authenticated approver anywhere. Anything
// that is not a plain "/path" — a scheme, a host, a protocol-relative "//evil" —
// collapses to the queue.
func safeReturnPath(candidate string) string {
	if len(candidate) < 2 || candidate[0] != '/' || candidate[1] == '/' || candidate[1] == '\\' {
		return "/ui/now"
	}
	if strings.ContainsAny(candidate, "\r\n") || strings.Contains(candidate, "://") {
		return "/ui/now"
	}
	// Only paths this app actually serves. An allow-list beats a deny-list here:
	// a deny-list has to anticipate every encoding a browser might normalise
	// (the cookie layer alone silently strips backslashes), while an allow-list
	// fails closed on anything unforeseen.
	if !strings.HasPrefix(candidate, "/ui/") {
		return "/ui/now"
	}
	// Validate the survivor as a URL. Intermediaries normalise before this code
	// runs — Go's cookie encoder silently drops backslashes and CRLF — so a
	// hostile value can arrive already mangled into something that merely LOOKS
	// like a path. Parsing rejects the residue instead of forwarding it.
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.Path != candidate {
		return "/ui/now"
	}
	// A real in-app path contains no spaces or control characters. Header-
	// injection probes arrive here already flattened by the cookie layer
	// ("/ui/now\r\nSet-Cookie: x=y" becomes "/ui/nowSet-Cookie: x=y"), which
	// still parses as a path — so reject on character class, not on the escape
	// sequence that no longer survives to be matched.
	for _, r := range candidate {
		if r <= ' ' || r == 0x7f {
			return "/ui/now"
		}
	}
	return candidate
}

func (handler *GitHubOAuthHandler) begin(response http.ResponseWriter, request *http.Request) {
	approver, ok := HumanApproverFromContext(request.Context())
	if handler.worker == nil || !ok || approver.SessionID == "" {
		writeError(response, http.StatusUnauthorized, "human_authentication_required")
		return
	}
	var input struct {
		Repository string    `json:"repository"`
		ExpiresAt  time.Time `json:"expires_at"`
	}
	now := time.Now().UTC()
	if err := handler.decode(request, &input); err != nil || input.Repository == "" || !input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(10*time.Minute)) {
		writeError(response, http.StatusBadRequest, "oauth_begin_rejected")
		return
	}
	githubLogin, allowed := handler.humanApprovers[approver.ID]
	if !allowed || githubLogin == "" {
		writeError(response, http.StatusForbidden, "human_not_allowlisted")
		return
	}
	authorizationURL, err := handler.worker.BeginOAuth(workerrpc.OAuthBeginRequest{
		Repository: input.Repository, Session: approver.TenantID + ":" + approver.SessionID,
		Purpose: "public_actor", Subject: approver.ID, GitHubLogin: githubLogin, ExpiresAt: input.ExpiresAt,
	})
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "oauth_unavailable")
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"authorization_url": authorizationURL})
}

func (handler *GitHubOAuthHandler) callback(response http.ResponseWriter, request *http.Request) {
	if handler.worker == nil {
		writeError(response, http.StatusServiceUnavailable, "oauth_unavailable")
		return
	}
	state, code := request.URL.Query().Get("state"), request.URL.Query().Get("code")
	if state == "" || code == "" || len(state) > 512 || len(code) > 512 {
		writeError(response, http.StatusBadRequest, "oauth_callback_rejected")
		return
	}
	completion, err := handler.worker.CompleteOAuth(workerrpc.OAuthCallbackRequest{State: state, Code: code})
	if err != nil {
		writeError(response, http.StatusForbidden, "oauth_callback_rejected")
		return
	}
	switch completion.Purpose {
	case "human_login":
		if handler.humanSessions == nil {
			writeError(response, http.StatusServiceUnavailable, "human_login_unavailable")
			return
		}
		if _, allowed := handler.humanApprovers[completion.Subject]; !allowed {
			writeError(response, http.StatusForbidden, "human_login_rejected")
			return
		}
		session, err := handler.humanSessions.Authenticate(request.Context(), completion.Session, completion.Subject)
		if err != nil {
			writeError(response, http.StatusForbidden, "human_login_rejected")
			return
		}
		http.SetCookie(response, handler.humanSessions.Cookie(session.Token))
		http.SetCookie(response, handler.humanSessions.CSRFCookie(session.CSRF))
		// A human who logged in is IN THE APP, not in a popup. Sending them back
		// to the queue is the only ending that lets them finish what they came to
		// do. The terminal "you may close this window" text was written for a
		// popup that closes itself; in a normal tab it is a dead end with no link
		// and no back-path — Yaniv hit it mid-authorization on 2026-07-26, having
		// been bounced here by an expired session, and was left believing he had
		// published when nothing had run.
		destination := "/ui/now"
		if cookie, err := request.Cookie(returnCookieName); err == nil {
			destination = safeReturnPath(cookie.Value)
		}
		// Clear it either way: a stale destination must not hijack a later login.
		expired := returnCookie("")
		expired.MaxAge = -1
		http.SetCookie(response, expired)
		http.Redirect(response, request, destination, http.StatusFound)
		return
	case "public_actor":
	default:
		writeError(response, http.StatusForbidden, "oauth_callback_rejected")
		return
	}
	// public_actor is a step-up for a specific write and genuinely may be a
	// popup, so it keeps the terminal text — but it must still offer a way back
	// rather than a bare sentence.
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(response, oauthCompletePage)
}

// oauthCompletePage ends the public_actor step-up. It states what happened and
// ALWAYS offers a route back into the app: a window that cannot self-close must
// never leave the reader without a next step.
const oauthCompletePage = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorization complete · GitOversight</title>
<style>
  body { font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         margin: 0; padding: 2.5rem 1.25rem; display: flex; justify-content: center; }
  main { max-width: 30rem; }
  h1 { font-size: 1.25rem; margin: 0 0 .5rem; }
  p { margin: 0 0 1.25rem; }
  a.btn { display: inline-block; padding: .7rem 1.1rem; border-radius: .5rem;
          background: #1f6feb; color: #fff; text-decoration: none; font-weight: 600; }
  @media (prefers-color-scheme: dark) { body { background: #0d1117; color: #e6edf3; } }
</style>
<main>
  <h1>Authorization complete</h1>
  <p>You can close this window, or return to your queue to finish the review.</p>
  <p><a class="btn" href="/ui/now">Back to my queue</a></p>
</main>
`

func (handler *GitHubOAuthHandler) decode(request *http.Request, destination any) error {
	if request.Header.Get("Content-Type") != "application/json" {
		return errors.New("application/json is required")
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, handler.maxBody+1))
	if err != nil || int64(len(payload)) > handler.maxBody {
		return errors.New("request body exceeds configured limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(string(payload)) == "" {
		return errors.New("exactly one JSON value is required")
	}
	return nil
}
