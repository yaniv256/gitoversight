package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type oauthWorker struct {
	begin    workerrpc.OAuthBeginRequest
	callback workerrpc.OAuthCallbackRequest
	complete workerrpc.OAuthCompletion
	url      string
}

func (worker *oauthWorker) BeginOAuth(request workerrpc.OAuthBeginRequest) (string, error) {
	worker.begin = request
	return worker.url, nil
}

func (worker *oauthWorker) CompleteOAuth(request workerrpc.OAuthCallbackRequest) (workerrpc.OAuthCompletion, error) {
	worker.callback = request
	return worker.complete, nil
}

func TestGitHubOAuthPublicSurfaceKeepsExchangeInsideWorker(t *testing.T) {
	worker := &oauthWorker{url: "https://github.test/login/oauth/authorize?state=opaque", complete: workerrpc.OAuthCompletion{Purpose: "public_actor"}}
	handler := NewGitHubOAuthHandler(worker, GitHubOAuthConfig{MaxBodyBytes: 4096, HumanApprovers: map[string]string{"yaniv": "Yaniv256"}})
	expiresAt := time.Now().UTC().Add(time.Minute)

	begin := httptest.NewRequest(http.MethodPost, "/v1/oauth/github/begin", jsonBody(t, map[string]any{
		"repository": "yaniv256/public", "expires_at": expiresAt.Format(time.RFC3339Nano),
	}))
	begin.Header.Set("Content-Type", "application/json")
	begin = begin.WithContext(WithHumanApprover(begin.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv", SessionID: "session-hash"}))
	beginResponse := httptest.NewRecorder()
	handler.ServeHTTP(beginResponse, begin)
	if beginResponse.Code != http.StatusOK {
		t.Fatalf("begin = %d: %s", beginResponse.Code, beginResponse.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(beginResponse.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["authorization_url"] != worker.url || worker.begin.Repository != "yaniv256/public" || worker.begin.Subject != "yaniv" || worker.begin.GitHubLogin != "Yaniv256" || worker.begin.Session != "tenant-a:session-hash" || worker.begin.Purpose != "public_actor" {
		t.Fatalf("body = %#v, worker request = %#v", body, worker.begin)
	}

	callback := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state=opaque&code=one-time-code", nil)
	callbackResponse := httptest.NewRecorder()
	handler.ServeHTTP(callbackResponse, callback)
	if callbackResponse.Code != http.StatusOK || worker.callback.State != "opaque" || worker.callback.Code != "one-time-code" {
		t.Fatalf("callback = %d: %s, worker = %#v", callbackResponse.Code, callbackResponse.Body.String(), worker.callback)
	}
	if body := callbackResponse.Body.String(); body == "" || containsGitHubCredential(body) {
		t.Fatalf("unsafe callback body = %q", body)
	}
}

func TestGitHubOAuthBeginRequiresDerivedHumanSession(t *testing.T) {
	handler := NewGitHubOAuthHandler(&oauthWorker{}, GitHubOAuthConfig{MaxBodyBytes: 4096})
	request := httptest.NewRequest(http.MethodPost, "/v1/oauth/github/begin", jsonBody(t, map[string]any{
		"repository": "yaniv256/public", "expires_at": time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano),
	}))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestGitHubOAuthLoginEstablishesRotatedHumanSession(t *testing.T) {
	manager := humanSessionManager(t, func() time.Time { return time.Unix(1000, 0).UTC() })
	worker := &oauthWorker{url: "https://github.test/login/oauth/authorize?state=opaque"}
	handler := NewGitHubOAuthHandler(worker, GitHubOAuthConfig{
		MaxBodyBytes: 4096, TenantID: "tenant-a", HumanApprovers: map[string]string{"yaniv": "Yaniv256"}, HumanSessions: manager,
	})

	begin := httptest.NewRequest(http.MethodGet, "/login/github?human_id=yaniv", nil)
	beginResponse := httptest.NewRecorder()
	handler.ServeHTTP(beginResponse, begin)
	if beginResponse.Code != http.StatusSeeOther || beginResponse.Header().Get("Location") != worker.url {
		t.Fatalf("login begin = %d, location = %q", beginResponse.Code, beginResponse.Header().Get("Location"))
	}
	if worker.begin.Purpose != "human_login" || worker.begin.Subject != "yaniv" || worker.begin.GitHubLogin != "Yaniv256" || worker.begin.Session == "" {
		t.Fatalf("worker begin = %#v", worker.begin)
	}
	worker.complete = workerrpc.OAuthCompletion{Purpose: "human_login", Session: worker.begin.Session, Subject: "yaniv"}

	callback := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state=opaque&code=one-time-code", nil)
	callbackResponse := httptest.NewRecorder()
	handler.ServeHTTP(callbackResponse, callback)
	// A logged-in human is returned to the app. See
	// TestGitHubOAuthLoginReturnsTheHumanToTheirQueue for why this must not be a
	// terminal page.
	if callbackResponse.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", callbackResponse.Code, callbackResponse.Body.String())
	}
	var sessionCookie, csrfCookie *http.Cookie
	for _, cookie := range callbackResponse.Result().Cookies() {
		switch cookie.Name {
		case "gitoversight_session":
			sessionCookie = cookie
		case "gitoversight_csrf":
			csrfCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.Secure || !sessionCookie.HttpOnly || csrfCookie == nil || !csrfCookie.Secure || csrfCookie.HttpOnly {
		t.Fatalf("unsafe or missing login cookies: session=%+v csrf=%+v", sessionCookie, csrfCookie)
	}
	if _, err := manager.Authorize(context.Background(), sessionCookie.Value, csrfCookie.Value); err != nil {
		t.Fatalf("callback did not establish an authenticated session: %v", err)
	}
}

// A human who signs in is IN THE APP, not in a popup. The callback used to end
// on "GitHub authorization complete. You may close this window." — a full stop
// with no link and no back-path.
//
// That is how it failed for real (2026-07-26): an expired session bounced Yaniv
// out of a sync authorization into login, login succeeded, and he landed on the
// terminal page. He had confirmed "publish this to the public repo", the page
// moved on, and he concluded a pull request existed. None had been requested.
// A dead end after a destructive-looking confirmation reads as success.
func TestGitHubOAuthLoginReturnsTheHumanToTheirQueue(t *testing.T) {
	manager := humanSessionManager(t, func() time.Time { return time.Unix(1000, 0).UTC() })
	worker := &oauthWorker{url: "https://github.test/login/oauth/authorize?state=opaque"}
	handler := NewGitHubOAuthHandler(worker, GitHubOAuthConfig{
		MaxBodyBytes: 4096, TenantID: "tenant-a", HumanApprovers: map[string]string{"yaniv": "Yaniv256"}, HumanSessions: manager,
	})
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/login/github?human_id=yaniv", nil))
	worker.complete = workerrpc.OAuthCompletion{Purpose: "human_login", Session: worker.begin.Session, Subject: "yaniv"}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state=opaque&code=one-time-code", nil))

	if response.Code != http.StatusFound {
		t.Fatalf("callback = %d, want a redirect back into the app; body: %s", response.Code, response.Body.String())
	}
	if location := response.Header().Get("Location"); location != "/ui/now" {
		t.Fatalf("Location = %q, want /ui/now", location)
	}
	if strings.Contains(response.Body.String(), "may close this window") {
		t.Fatal("logged-in human was left on the terminal close-window page")
	}
}

// The public_actor step-up may genuinely run in a popup, so it keeps a terminal
// page — but a window that cannot close itself must still offer a way back.
func TestGitHubOAuthPublicActorCompletionOffersAWayBack(t *testing.T) {
	manager := humanSessionManager(t, func() time.Time { return time.Unix(1000, 0).UTC() })
	worker := &oauthWorker{url: "https://github.test/login/oauth/authorize?state=opaque"}
	handler := NewGitHubOAuthHandler(worker, GitHubOAuthConfig{
		MaxBodyBytes: 4096, TenantID: "tenant-a", HumanApprovers: map[string]string{"yaniv": "Yaniv256"}, HumanSessions: manager,
	})
	worker.complete = workerrpc.OAuthCompletion{Purpose: "public_actor", Subject: "yaniv"}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state=opaque&code=one-time-code", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("callback = %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `href="/ui/now"`) {
		t.Fatalf("step-up completion has no route back into the app:\n%s", response.Body.String())
	}
}

// Publishing requires a RECENT sign-in that lapses ~10 minutes after login,
// while the session stays valid for hours. Before this, a lapsed step-up left
// the reviewer permanently stuck: signed in, button enabled, every tap 403.
// Re-authenticating has to return them to the page they were working on, or the
// round-trip loses the task that prompted it.
func TestGitHubOAuthLoginReturnsToTheInterruptedPage(t *testing.T) {
	manager := humanSessionManager(t, func() time.Time { return time.Unix(1000, 0).UTC() })
	worker := &oauthWorker{url: "https://github.test/login/oauth/authorize?state=opaque"}
	handler := NewGitHubOAuthHandler(worker, GitHubOAuthConfig{
		MaxBodyBytes: 4096, TenantID: "tenant-a", HumanApprovers: map[string]string{"yaniv": "Yaniv256"}, HumanSessions: manager,
	})
	target := "/ui/sync/agent-kanban-ready-for-review"

	begin := httptest.NewRecorder()
	handler.ServeHTTP(begin, httptest.NewRequest(http.MethodGet, "/login/github?return_to="+target, nil))
	var carried *http.Cookie
	for _, cookie := range begin.Result().Cookies() {
		if cookie.Name == "gitoversight_return_to" {
			carried = cookie
		}
	}
	if carried == nil || carried.Value != target {
		t.Fatalf("login did not carry the return path: %+v", carried)
	}

	worker.complete = workerrpc.OAuthCompletion{Purpose: "human_login", Session: worker.begin.Session, Subject: "yaniv"}
	callback := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state=opaque&code=one-time-code", nil)
	callback.AddCookie(carried)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, callback)

	if location := response.Header().Get("Location"); location != target {
		t.Fatalf("Location = %q, want the interrupted page %q", location, target)
	}
}

// A login endpoint that redirects anywhere the caller names is a phishing
// primitive: it bounces a freshly-authenticated approver off-site.
func TestGitHubOAuthLoginRefusesOffSiteReturnPaths(t *testing.T) {
	for _, hostile := range []string{
		"https://evil.test/steal",
		"//evil.test/steal",
		"/\\evil.test",
		"javascript:alert(1)",
		"/ui/now\r\nSet-Cookie: x=y",
		"",
	} {
		manager := humanSessionManager(t, func() time.Time { return time.Unix(1000, 0).UTC() })
		worker := &oauthWorker{url: "https://github.test/login/oauth/authorize?state=opaque"}
		handler := NewGitHubOAuthHandler(worker, GitHubOAuthConfig{
			MaxBodyBytes: 4096, TenantID: "tenant-a", HumanApprovers: map[string]string{"yaniv": "Yaniv256"}, HumanSessions: manager,
		})
		worker.complete = workerrpc.OAuthCompletion{Purpose: "human_login", Subject: "yaniv"}
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/login/github", nil))
		worker.complete.Session = worker.begin.Session

		callback := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state=opaque&code=one-time-code", nil)
		callback.AddCookie(&http.Cookie{Name: "gitoversight_return_to", Value: hostile})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, callback)

		if location := response.Header().Get("Location"); location != "/ui/now" {
			t.Fatalf("return_to %q redirected to %q, want /ui/now", hostile, location)
		}
	}
}

func TestGitHubOAuthLoginRejectsUnknownHumanBeforeWorker(t *testing.T) {
	manager := humanSessionManager(t, func() time.Time { return time.Unix(1000, 0).UTC() })
	worker := &oauthWorker{url: "https://github.test/login/oauth/authorize?state=opaque"}
	handler := NewGitHubOAuthHandler(worker, GitHubOAuthConfig{
		TenantID: "tenant-a", HumanApprovers: map[string]string{"yaniv": "Yaniv256"}, HumanSessions: manager,
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login/github?human_id=attacker", nil))
	if response.Code != http.StatusForbidden || worker.begin.Session != "" {
		t.Fatalf("unknown human reached worker: status=%d request=%#v", response.Code, worker.begin)
	}
}

func TestGitHubOAuthLoginRejectsHumanRemovedBeforeCallback(t *testing.T) {
	manager := humanSessionManager(t, func() time.Time { return time.Unix(1000, 0).UTC() })
	approvers := map[string]string{"yaniv": "Yaniv256"}
	worker := &oauthWorker{url: "https://github.test/login/oauth/authorize?state=opaque"}
	handler := NewGitHubOAuthHandler(worker, GitHubOAuthConfig{
		TenantID: "tenant-a", HumanApprovers: approvers, HumanSessions: manager,
	})
	beginResponse := httptest.NewRecorder()
	handler.ServeHTTP(beginResponse, httptest.NewRequest(http.MethodGet, "/login/github?human_id=yaniv", nil))
	delete(approvers, "yaniv")
	worker.complete = workerrpc.OAuthCompletion{Purpose: "human_login", Session: worker.begin.Session, Subject: "yaniv"}
	callbackResponse := httptest.NewRecorder()
	handler.ServeHTTP(callbackResponse, httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state=opaque&code=one-time-code", nil))
	if callbackResponse.Code != http.StatusForbidden || len(callbackResponse.Result().Cookies()) != 0 {
		t.Fatalf("removed human authenticated: status=%d cookies=%v", callbackResponse.Code, callbackResponse.Result().Cookies())
	}
}

func TestGitHubOAuthCallbackRejectsUnknownPurpose(t *testing.T) {
	worker := &oauthWorker{complete: workerrpc.OAuthCompletion{Purpose: "unexpected"}}
	handler := NewGitHubOAuthHandler(worker, GitHubOAuthConfig{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state=opaque&code=one-time-code", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("unknown purpose status = %d", response.Code)
	}
}

func containsGitHubCredential(value string) bool {
	for _, prefix := range []string{"ghu_", "ghr_", "ghs_", "github_pat_"} {
		if len(value) >= len(prefix) {
			for index := 0; index+len(prefix) <= len(value); index++ {
				if value[index:index+len(prefix)] == prefix {
					return true
				}
			}
		}
	}
	return false
}
