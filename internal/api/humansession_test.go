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
	if _, err := manager.Authorize(context.Background(), pending.Token, pending.CSRF, true); err == nil {
		t.Fatal("fixated pre-authentication session remained valid")
	}
	approver, err := manager.Authorize(context.Background(), authenticated.Token, authenticated.CSRF, true)
	if err != nil || approver.TenantID != "tenant-a" || approver.ID != "yaniv" || approver.SessionID == "" {
		t.Fatalf("authorized approver = %+v, %v", approver, err)
	}
	cookie := manager.Cookie(authenticated.Token)
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" {
		t.Fatalf("unsafe session cookie: %+v", cookie)
	}
	csrfCookie := manager.CSRFCookie(authenticated.CSRF)
	if !csrfCookie.Secure || csrfCookie.HttpOnly || csrfCookie.SameSite != http.SameSiteStrictMode || csrfCookie.Path != "/" {
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
// The CSRF cookie keeps Strict deliberately. It guards mutations, not page
// loads, and nothing needs it during the login round trip — so the two cookies
// differ on purpose, and this test records which is which.
func TestSessionCookieSurvivesTheLoginRoundTripAndCSRFStaysStrict(t *testing.T) {
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

	csrf := manager.CSRFCookie("csrf")
	if csrf.SameSite != http.SameSiteStrictMode {
		t.Fatalf("CSRF cookie SameSite = %v, want Strict — it guards mutations and is not needed during login", csrf.SameSite)
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
	protected := manager.Protect(true, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
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
	if _, err := manager.Authorize(context.Background(), session.Token, "wrong-csrf", true); err == nil {
		t.Fatal("wrong CSRF token authorized sensitive action")
	}
	now = now.Add(6 * time.Minute)
	if _, err := manager.Authorize(context.Background(), session.Token, session.CSRF, true); err == nil {
		t.Fatal("stale recent authentication authorized sensitive action")
	}
	if _, err := manager.Authorize(context.Background(), session.Token, session.CSRF, false); err != nil {
		t.Fatalf("ordinary session expired too early: %v", err)
	}
}

// The twin of TestHumanSessionRejectsStaleCSRFAndRecentAuthentication above.
// That test proves the step-up gate CLOSES; it passed all day while the product
// was unusable, because closing is only half a gate. This one proves the gate
// can be REOPENED — that a lapsed step-up is recoverable rather than terminal.
//
// Without it, a 10-minute window silently became a permanent deadlock: signed
// in, Authorize enabled, every tap 403 forever, because login was the only
// writer of recent_auth_until and nothing routed the human back to it
// (2026-07-26 — Yaniv could not publish at all).
//
// Whenever a gate's closing is asserted, assert its reopening in the same
// breath, and check the exit has a CALLER — not merely an implementation.
func TestHumanSessionRecentAuthenticationIsRecoverableAfterItLapses(t *testing.T) {
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
	if _, err := manager.Authorize(context.Background(), session.Token, session.CSRF, true); err != nil {
		t.Fatalf("fresh step-up should authorize: %v", err)
	}

	// Let the step-up lapse while the session itself stays valid — the exact
	// state Yaniv sat in.
	now = now.Add(6 * time.Minute)
	if _, err := manager.Authorize(context.Background(), session.Token, session.CSRF, true); err == nil {
		t.Fatal("lapsed step-up must not authorize")
	}
	if _, err := manager.Authorize(context.Background(), session.Token, session.CSRF, false); err != nil {
		t.Fatalf("ordinary session must remain valid: %v", err)
	}

	// THE POINT: re-authenticating restores it. If this cannot be done, the
	// reviewer is stuck forever with no path forward.
	repeat, err := manager.Begin(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := manager.Authenticate(context.Background(), repeat.Token, "yaniv")
	if err != nil {
		t.Fatalf("re-authentication must be possible after a lapsed step-up: %v", err)
	}
	if _, err := manager.Authorize(context.Background(), refreshed.Token, refreshed.CSRF, true); err != nil {
		t.Fatalf("re-authentication did not restore the step-up — the gate has no key: %v", err)
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
	manager, err := NewHumanSessionManager(db, HumanSessionConfig{SessionTTL: time.Hour, RecentAuthTTL: 5 * time.Minute, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}
