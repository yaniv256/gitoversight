package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

var ErrHumanSessionRejected = errors.New("human session rejected")

type HumanSessionConfig struct {
	SessionTTL    time.Duration
	RecentAuthTTL time.Duration
	Now           func() time.Time
}

type HumanSessionManager struct {
	db            *sqlite.DB
	sessionTTL    time.Duration
	recentAuthTTL time.Duration
	now           func() time.Time
}

type HumanSessionCredentials struct {
	Token     string
	CSRF      string
	ExpiresAt time.Time
}

func NewHumanSessionManager(db *sqlite.DB, config HumanSessionConfig) (*HumanSessionManager, error) {
	if db == nil || config.SessionTTL <= 0 || config.RecentAuthTTL <= 0 || config.RecentAuthTTL > config.SessionTTL {
		return nil, errors.New("database and valid human session lifetimes are required")
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &HumanSessionManager{db: db, sessionTTL: config.SessionTTL, recentAuthTTL: config.RecentAuthTTL, now: config.Now}, nil
}

func (manager *HumanSessionManager) Begin(ctx context.Context, tenantID string) (HumanSessionCredentials, error) {
	if strings.TrimSpace(tenantID) == "" {
		return HumanSessionCredentials{}, ErrHumanSessionRejected
	}
	credentials, err := newSessionCredentials(tenantID, manager.now().UTC().Add(manager.sessionTTL))
	if err != nil {
		return HumanSessionCredentials{}, err
	}
	now := manager.now().UTC()
	record := storage.HumanSession{TenantID: tenantID, IDHash: hashSecret(credentials.Token), CSRFHash: hashSecret(credentials.CSRF), CreatedAt: now, ExpiresAt: credentials.ExpiresAt}
	if err := manager.db.WithTx(ctx, func(tx *sqlite.Tx) error { return tx.PutHumanSession(ctx, record) }); err != nil {
		return HumanSessionCredentials{}, err
	}
	return credentials, nil
}

func (manager *HumanSessionManager) Authenticate(ctx context.Context, pendingToken, humanID string) (HumanSessionCredentials, error) {
	tenantID, err := tenantFromSessionToken(pendingToken)
	if err != nil || strings.TrimSpace(humanID) == "" {
		return HumanSessionCredentials{}, ErrHumanSessionRejected
	}
	pending, err := manager.db.HumanSession(ctx, tenantID, hashSecret(pendingToken))
	if err != nil || pending.HumanID != "" || pending.RevokedAt != nil || !manager.now().Before(pending.ExpiresAt) {
		return HumanSessionCredentials{}, ErrHumanSessionRejected
	}
	now := manager.now().UTC()
	replacement, err := newSessionCredentials(tenantID, now.Add(manager.sessionTTL))
	if err != nil {
		return HumanSessionCredentials{}, err
	}
	recentUntil := now.Add(manager.recentAuthTTL)
	record := storage.HumanSession{
		TenantID: tenantID, IDHash: hashSecret(replacement.Token), HumanID: humanID,
		CSRFHash: hashSecret(replacement.CSRF), CreatedAt: now, AuthenticatedAt: &now,
		RecentAuthUntil: &recentUntil, ExpiresAt: replacement.ExpiresAt,
	}
	if err := manager.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		return tx.RotateHumanSession(ctx, tenantID, hashSecret(pendingToken), record, now)
	}); err != nil {
		return HumanSessionCredentials{}, ErrHumanSessionRejected
	}
	return replacement, nil
}

func (manager *HumanSessionManager) Authorize(ctx context.Context, token, csrf string, requireRecent bool) (HumanApprover, error) {
	tenantID, err := tenantFromSessionToken(token)
	if err != nil || token == "" || csrf == "" {
		return HumanApprover{}, ErrHumanSessionRejected
	}
	record, err := manager.db.HumanSession(ctx, tenantID, hashSecret(token))
	now := manager.now().UTC()
	if err != nil || record.HumanID == "" || record.AuthenticatedAt == nil || record.RevokedAt != nil || !now.Before(record.ExpiresAt) || subtle.ConstantTimeCompare([]byte(record.CSRFHash), []byte(hashSecret(csrf))) != 1 {
		return HumanApprover{}, ErrHumanSessionRejected
	}
	if requireRecent && (record.RecentAuthUntil == nil || !now.Before(*record.RecentAuthUntil)) {
		return HumanApprover{}, ErrHumanSessionRejected
	}
	return HumanApprover{TenantID: record.TenantID, ID: record.HumanID, SessionID: record.IDHash}, nil
}

// Cookie carries the session across the GitHub login round trip, so it is Lax
// and NOT Strict.
//
// Strict withholds the cookie on every cross-site navigation — including the
// redirect that arrives FROM github.com at the end of OAuth. The callback would
// set the session, redirect to the requested page, the browser would decline to
// send the cookie it had just been given, ProtectPage would bounce back to
// /login/github, and the loop ends in ERR_TOO_MANY_REDIRECTS. Observed live on
// iOS Safari (2026-07-27): login was completely unreachable, so no human could
// approve anything.
//
// Lax is not a weakening here. It still withholds the cookie on cross-site
// POSTs — the CSRF case — while allowing top-level GET navigations, which is
// exactly what returning from an identity provider is. The CSRF cookie below
// stays Strict because it guards mutations rather than page loads, and the
// return-to cookie in github_oauth.go was already Lax for this same reason.
func (manager *HumanSessionManager) Cookie(token string) *http.Cookie {
	return &http.Cookie{
		Name: "gitoversight_session", Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(manager.sessionTTL.Seconds()),
	}
}

func (manager *HumanSessionManager) CSRFCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name: "gitoversight_csrf", Value: token, Path: "/", Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(manager.sessionTTL.Seconds()),
	}
}

func (manager *HumanSessionManager) Protect(requireRecent bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie("gitoversight_session")
		if err != nil {
			writeError(response, http.StatusUnauthorized, "human_authentication_required")
			return
		}
		approver, err := manager.Authorize(request.Context(), cookie.Value, request.Header.Get("X-CSRF-Token"), requireRecent)
		if err != nil {
			writeError(response, http.StatusForbidden, "human_session_rejected")
			return
		}
		next.ServeHTTP(response, request.WithContext(WithHumanApprover(request.Context(), approver)))
	})
}

func newSessionCredentials(tenantID string, expiresAt time.Time) (HumanSessionCredentials, error) {
	tokenBytes := make([]byte, 32)
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return HumanSessionCredentials{}, err
	}
	if _, err := rand.Read(csrfBytes); err != nil {
		return HumanSessionCredentials{}, err
	}
	tenant := base64.RawURLEncoding.EncodeToString([]byte(tenantID))
	return HumanSessionCredentials{
		Token: tenant + "." + base64.RawURLEncoding.EncodeToString(tokenBytes),
		CSRF:  base64.RawURLEncoding.EncodeToString(csrfBytes), ExpiresAt: expiresAt,
	}, nil
}

func tenantFromSessionToken(token string) (string, error) {
	encoded, secret, ok := strings.Cut(token, ".")
	if !ok || encoded == "" || secret == "" {
		return "", ErrHumanSessionRejected
	}
	tenant, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(tenant) == 0 {
		return "", ErrHumanSessionRejected
	}
	return string(tenant), nil
}

func hashSecret(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// AuthorizeSession validates the session cookie alone — authenticated,
// unexpired, unrevoked — with no CSRF requirement and no recent-auth
// requirement. It exists ONLY for safe-method HTML page loads (browser
// navigations cannot send X-CSRF-Token). Every mutating route must keep
// using Authorize/Protect; weakening those to accommodate page loads is
// forbidden (review finding, 3x code-verified).
func (manager *HumanSessionManager) AuthorizeSession(ctx context.Context, token string) (HumanApprover, error) {
	tenantID, err := tenantFromSessionToken(token)
	if err != nil || token == "" {
		return HumanApprover{}, ErrHumanSessionRejected
	}
	record, err := manager.db.HumanSession(ctx, tenantID, hashSecret(token))
	now := manager.now().UTC()
	if err != nil || record.HumanID == "" || record.AuthenticatedAt == nil || record.RevokedAt != nil || !now.Before(record.ExpiresAt) {
		return HumanApprover{}, ErrHumanSessionRejected
	}
	return HumanApprover{TenantID: record.TenantID, ID: record.HumanID, SessionID: record.IDHash}, nil
}

// ProtectPage authenticates GET/HEAD page loads by session cookie alone and
// redirects to the GitHub login on failure. Never use it for mutations.
func (manager *HumanSessionManager) ProtectPage(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.NotFound(response, request)
			return
		}
		cookie, err := request.Cookie("gitoversight_session")
		if err != nil {
			http.Redirect(response, request, "/login/github", http.StatusFound)
			return
		}
		approver, err := manager.AuthorizeSession(request.Context(), cookie.Value)
		if err != nil {
			http.Redirect(response, request, "/login/github", http.StatusFound)
			return
		}
		next.ServeHTTP(response, request.WithContext(WithHumanApprover(request.Context(), approver)))
	})
}
