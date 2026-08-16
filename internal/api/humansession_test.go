package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func TestHumanSessionRotatesAtAuthenticationAndUsesSecureCookie(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager := humanSessionManager(t, func() time.Time { return now })
	pending, err := manager.Begin(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := manager.Authenticate(context.Background(), pending.Token, "yaniv")
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.Token == pending.Token || authenticated.CSRF == pending.CSRF {
		t.Fatal("authentication did not rotate session and CSRF tokens")
	}
	if _, err := manager.Authorize(context.Background(), pending.Token, pending.CSRF); err == nil {
		t.Fatal("fixated pre-authentication session remained valid")
	}
	approver, err := manager.Authorize(context.Background(), authenticated.Token, authenticated.CSRF)
	if err != nil || approver.TenantID != "tenant-a" || approver.ID != "yaniv" || approver.SessionID == "" {
		t.Fatalf("authorized approver = %+v, %v", approver, err)
	}
	cookie := manager.Cookie(authenticated.Token)
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" {
		t.Fatalf("unsafe session cookie: %+v", cookie)
	}
	csrfCookie := manager.CSRFCookie(authenticated.CSRF)
	if !csrfCookie.Secure || csrfCookie.HttpOnly || csrfCookie.Path != "/" {
		t.Fatalf("unsafe CSRF cookie: %+v", csrfCookie)
	}
}

// The session cookie has to survive the redirect that arrives FROM github.com
// at the end of OAuth. SameSite=Strict withholds it on exactly that navigation,
// so the callback sets a session the browser then refuses to send back,
// ProtectPage bounces to /login/github, and login becomes unreachable —
// ERR_TOO_MANY_REDIRECTS, observed live on iOS Safari 2026-07-27.
//
// The previous version of this file asserted Strict on both cookies, so it
// PINNED that bug: the test named "UsesSecureCookie" passed for as long as no
// human could log in at all. Strictness is not the property worth asserting on
// a cookie that must cross an identity provider; reachability is.
//
// This test originally asserted the CSRF cookie stays Strict, on the reasoning
// that it guards mutations and is not needed during login. That reasoning was
// WRONG and the assertion pinned a second loop: the UI READS that cookie at
// render time to populate the page's csrf-token meta tag, so withholding it on
// the OAuth return produced a page with an empty token whose every POST 403s.
// TestBothCookiesSurviveTheLoginRoundTrip now covers both.
func TestSessionCookieSurvivesTheLoginRoundTrip(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager := humanSessionManager(t, func() time.Time { return now })

	session := manager.Cookie("token")
	if session.SameSite == http.SameSiteStrictMode {
		t.Fatal("session cookie is SameSite=Strict: the browser will withhold it on the redirect back from GitHub, making login an infinite redirect loop")
	}
	if session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie SameSite = %v, want Lax — Lax still blocks cross-site POSTs while allowing the OAuth return navigation", session.SameSite)
	}
	if !session.Secure || !session.HttpOnly {
		t.Fatalf("session cookie lost Secure/HttpOnly while fixing SameSite: %+v", session)
	}

}

func TestProtectPagePreservesDirectReviewDestinationWhenLoginIsRequired(t *testing.T) {
	manager := humanSessionManager(t, time.Now)
	next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		t.Fatal("unauthenticated request reached protected page")
	})

	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{"sync review", "/ui/sync/review-123?section=files", "/login/github?return_to=%2Fui%2Fsync%2Freview-123%3Fsection%3Dfiles"},
		{"queue", "/ui/now", "/login/github?return_to=%2Fui%2Fnow"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			manager.ProtectPage(next).ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != http.StatusFound || response.Header().Get("Location") != test.want {
				t.Fatalf("status=%d location=%q want=%q", response.Code, response.Header().Get("Location"), test.want)
			}
		})
	}
}

func TestHumanSessionMiddlewareDerivesApproverFromServerState(t *testing.T) {
	manager := humanSessionManager(t, func() time.Time { return time.Unix(1000, 0).UTC() })
	pending, err := manager.Begin(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.Authenticate(context.Background(), pending.Token, "yaniv")
	if err != nil {
		t.Fatal(err)
	}
	protected := manager.Protect(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		approver, ok := HumanApproverFromContext(request.Context())
		if !ok || approver.ID != "yaniv" {
			t.Fatalf("missing derived approver: %+v", approver)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/reviews/1/approve", nil)
	request.AddCookie(manager.Cookie(session.Token))
	request.Header.Set("X-CSRF-Token", session.CSRF)
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("protected response = %d", response.Code)
	}
}

func TestHumanSessionRejectsStaleCSRFAndRecentAuthentication(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager := humanSessionManager(t, func() time.Time { return now })
	pending, err := manager.Begin(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.Authenticate(context.Background(), pending.Token, "yaniv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Authorize(context.Background(), session.Token, "wrong-csrf"); err == nil {
		t.Fatal("wrong CSRF token authorized sensitive action")
	}
	// The recent-auth step-up is GONE (see Authorize). It was never requested,
	// bought no property the session and packet binding did not already
	// provide, and made publication impossible for a whole evening. A session
	// that is valid stays valid until it expires.
	now = now.Add(6 * time.Minute)
	if _, err := manager.Authorize(context.Background(), session.Token, session.CSRF); err != nil {
		t.Fatalf("a valid session must keep working: the publish-time step-up was invented and is removed: %v", err)
	}
	if _, err := manager.Authorize(context.Background(), session.Token, session.CSRF); err != nil {
		t.Fatalf("ordinary session expired too early: %v", err)
	}
}

// This test used to prove the invented publish-time step-up could be REOPENED
// after it lapsed. The step-up itself is now gone — it was never requested, and
// its only measured effect was making publication impossible while presenting
// every other failure as "you need a fresh sign-in".
//
// What remains worth asserting is the property that actually protects a
// publish: a session is bound to ONE approver and one CSRF token, and stays
// usable for its whole lifetime without re-proving anything.
func TestAuthenticatedSessionStaysUsableWithoutReAuthenticating(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager := humanSessionManager(t, func() time.Time { return now })
	pending, err := manager.Begin(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.Authenticate(context.Background(), pending.Token, "yaniv")
	if err != nil {
		t.Fatal(err)
	}
	// Well past the old ten-minute step-up window, but inside the session's own
	// one-hour lifetime — the distinction the removed gate erased. A session
	// expiring is legitimate; a session refusing to act while still valid is
	// the defect.
	for _, elapsed := range []time.Duration{0, 6 * time.Minute, 30 * time.Minute, 59 * time.Minute} {
		now = time.Unix(1000, 0).UTC().Add(elapsed)
		approver, err := manager.Authorize(context.Background(), session.Token, session.CSRF)
		if err != nil {
			t.Fatalf("after %v the reviewer could not act: %v — a publish-time step-up has been reintroduced", elapsed, err)
		}
		if approver.ID != "yaniv" {
			t.Fatalf("approver = %q, want yaniv", approver.ID)
		}
	}
	// The session is still bound: a wrong CSRF token is still refused.
	if _, err := manager.Authorize(context.Background(), session.Token, "wrong-csrf"); err == nil {
		t.Fatal("wrong CSRF token authorized an action")
	}
}

func humanSessionManager(t *testing.T, now func() time.Time) *HumanSessionManager {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	createdAt := now()
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		if err := tx.EnsureTenant(context.Background(), "tenant-a", createdAt); err != nil {
			return err
		}
		return tx.EnsureHuman(context.Background(), "tenant-a", "yaniv", "yaniv256", createdAt)
	}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewHumanSessionManager(db, HumanSessionConfig{SessionTTL: time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

// Both cookies must survive the OAuth return, not just the session one.
//
// The UI reads gitoversight_csrf at render time to populate the page's
// csrf-token meta tag. Under SameSite=Strict the browser withheld it on the
// redirect from github.com, so the reviewer arrived with a valid session and an
// EMPTY csrf token, every POST answered 403, and the client — unable to tell
// that from a lapsed step-up — sent them back to sign in again. Live
// 2026-07-27: three cycles, publication impossible.
//
// Making only the session cookie Lax is what turned a clean failure into a
// loop: with both Strict the page redirected to login and failed honestly.
// They travel together or the login round trip is broken.
func TestBothCookiesSurviveTheLoginRoundTrip(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager := humanSessionManager(t, func() time.Time { return now })
	for _, c := range []struct {
		name   string
		cookie *http.Cookie
	}{
		{"session", manager.Cookie("token")},
		{"csrf", manager.CSRFCookie("csrf")},
	} {
		if c.cookie.SameSite == http.SameSiteStrictMode {
			t.Fatalf("%s cookie is SameSite=Strict: the browser withholds it on the redirect back from GitHub, so the reviewer returns to a page that cannot publish", c.name)
		}
		if c.cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("%s cookie SameSite = %v, want Lax", c.name, c.cookie.SameSite)
		}
		if !c.cookie.Secure {
			t.Fatalf("%s cookie lost Secure", c.name)
		}
	}
}
