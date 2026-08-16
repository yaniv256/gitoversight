package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/appauth"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type oauthTestWriteGate struct{}

func (oauthTestWriteGate) Verify() error                        { return nil }
func (oauthTestWriteGate) Commit(context.Context, string) error { return nil }

func newOAuthHandler(t *testing.T) (*WorkOAuthHandler, *server.DurableBroker, appauth.Client) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "oauth.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(oauthTestWriteGate{})
	snapshot := policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}}, Repositories: map[string]policy.Repository{
		"org/private": {Visibility: "private", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
		"org/public":  {Visibility: "public", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
	}}
	if err := broker.InstallPolicy(ctx, "tenant-a", snapshot); err != nil {
		t.Fatal(err)
	}
	client := appauth.Client{Issuer: "https://gitoversight.test", Audience: "https://gitoversight.test/mcp", ID: "chatgpt-work", Name: "ChatGPT Work", RedirectURIs: []string{"https://chatgpt.com/oauth/callback"}}
	service := appauth.NewService(db)
	if err := service.RegisterClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	handler, err := NewWorkOAuthHandler(service, broker, WorkOAuthConfig{Client: client, CodeLifetime: time.Minute, AccessLifetime: time.Hour, RefreshLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return handler, broker, client
}

func TestWorkOAuthMetadataAndReviewExposeExactSecurityBoundary(t *testing.T) {
	handler, _, client := newOAuthHandler(t)
	metadata := httptest.NewRecorder()
	handler.ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	if metadata.Code != http.StatusOK || !strings.Contains(metadata.Body.String(), `"code_challenge_methods_supported":["S256"]`) {
		t.Fatalf("metadata = %d %s", metadata.Code, metadata.Body.String())
	}
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	request := httptest.NewRequest(http.MethodGet, "/oauth/authorize?response_type=code&client_id=chatgpt-work&redirect_uri="+url.QueryEscape(client.RedirectURIs[0])+"&state=opaque&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	request.AddCookie(&http.Cookie{Name: "gitoversight_csrf", Value: "csrf"})
	request = request.WithContext(WithHumanApprover(request.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv"}))
	review := httptest.NewRecorder()
	handler.ServeHTTP(review, request)
	body := review.Body.String()
	if review.Code != http.StatusOK || !strings.Contains(body, "org/private") || strings.Contains(body, "org/public") || !strings.Contains(body, client.RedirectURIs[0]) || !strings.Contains(body, "does not receive your GitHub credentials") {
		t.Fatalf("review = %d %s", review.Code, body)
	}
	if strings.Contains(body, "<script>") || !strings.Contains(body, `src="/v1/work/oauth/static/authorize.js"`) {
		t.Fatalf("authorization page is not external-script CSP compatible: %s", body)
	}
	asset := httptest.NewRecorder()
	handler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/v1/work/oauth/static/authorize.js", nil))
	if asset.Code != http.StatusOK || !strings.Contains(asset.Body.String(), "oauth/authorize") {
		t.Fatalf("authorization asset = %d %s", asset.Code, asset.Body.String())
	}
}

func TestWorkOAuthAuthorizationCodeIsPKCEBoundAndOneTime(t *testing.T) {
	handler, broker, client := newOAuthHandler(t)
	verifier := "correct-verifier-with-enough-entropy-123456789"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	input := oauthAuthorizationInput{ResponseType: "code", ClientID: client.ID, RedirectURI: client.RedirectURIs[0], State: "state-1", CodeChallenge: challenge, ChallengeType: "S256", AgentID: "mobile-work", DisplayName: "Mobile Work", Repositories: []string{"org/private"}}
	payload, _ := json.Marshal(input)
	request := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(WithHumanApprover(request.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("authorize = %d %s", response.Code, response.Body.String())
	}
	var approved map[string]string
	_ = json.Unmarshal(response.Body.Bytes(), &approved)
	redirect, _ := url.Parse(approved["redirect_uri"])
	code := redirect.Query().Get("code")
	if code == "" || redirect.Query().Get("state") != "state-1" {
		t.Fatalf("redirect = %s", approved["redirect_uri"])
	}
	snapshot, _ := broker.PolicySnapshot(context.Background(), "tenant-a")
	if !snapshot.Agents["mobile-work"].IsRemote() {
		t.Fatal("authorization did not register a remote policy identity")
	}

	exchange := func(candidate string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"authorization_code"}, "client_id": {client.ID}, "code": {code}, "redirect_uri": {client.RedirectURIs[0]}, "code_verifier": {candidate}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if wrong := exchange("wrong-verifier"); wrong.Code != http.StatusBadRequest {
		t.Fatalf("wrong verifier = %d %s", wrong.Code, wrong.Body.String())
	}
	good := exchange(verifier)
	if good.Code != http.StatusOK || !strings.Contains(good.Body.String(), `"access_token"`) || !strings.Contains(good.Body.String(), `"refresh_token"`) {
		t.Fatalf("correct verifier = %d %s", good.Code, good.Body.String())
	}
	if replay := exchange(verifier); replay.Code != http.StatusBadRequest {
		t.Fatalf("code replay = %d %s", replay.Code, replay.Body.String())
	}
	var tokens map[string]any
	_ = json.Unmarshal(good.Body.Bytes(), &tokens)
	refresh, _ := tokens["refresh_token"].(string)
	revokeForm := url.Values{"client_id": {client.ID}, "token": {refresh}, "token_type_hint": {"refresh_token"}}
	revokeRequest := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(revokeForm.Encode()))
	revokeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revoked := httptest.NewRecorder()
	handler.ServeHTTP(revoked, revokeRequest)
	if revoked.Code != http.StatusOK {
		t.Fatalf("refresh revoke = %d %s", revoked.Code, revoked.Body.String())
	}
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "client_id": {client.ID}, "refresh_token": {refresh}}
	refreshRequest := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	refreshRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshResponse := httptest.NewRecorder()
	handler.ServeHTTP(refreshResponse, refreshRequest)
	if refreshResponse.Code != http.StatusBadRequest {
		t.Fatalf("revoked refresh rotated = %d %s", refreshResponse.Code, refreshResponse.Body.String())
	}
}

func TestWorkOAuthReauthorizationPreservesActiveIdentityAndRequiresExplicitRevokedReplacement(t *testing.T) {
	handler, _, client := newOAuthHandler(t)
	verifier := "reauthorization-verifier-with-enough-length-123"
	digest := sha256.Sum256([]byte(verifier))
	input := oauthAuthorizationInput{ResponseType: "code", ClientID: client.ID, RedirectURI: client.RedirectURIs[0], State: "state", CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]), ChallengeType: "S256", AgentID: "work", DisplayName: "Work", Repositories: []string{"org/private"}}
	authorize := func(value oauthAuthorizationInput) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(value)
		request := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(string(payload)))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(WithHumanApprover(request.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv"}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	first := authorize(input)
	if first.Code != http.StatusCreated {
		t.Fatalf("first authorization = %d %s", first.Code, first.Body.String())
	}
	// No family exists yet: this is the safe recovery path when enrollment
	// succeeded but code issuance/return failed.
	second := authorize(input)
	if second.Code != http.StatusCreated {
		t.Fatalf("orphan recovery authorization = %d %s", second.Code, second.Body.String())
	}
	var issued map[string]string
	_ = json.Unmarshal(first.Body.Bytes(), &issued)
	redirect, _ := url.Parse(issued["redirect_uri"])
	exchangeForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {client.ID}, "code": {redirect.Query().Get("code")}, "redirect_uri": {client.RedirectURIs[0]}, "code_verifier": {verifier}}
	exchangeRequest := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(exchangeForm.Encode()))
	exchangeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	exchangeResponse := httptest.NewRecorder()
	handler.ServeHTTP(exchangeResponse, exchangeRequest)
	if exchangeResponse.Code != http.StatusOK {
		t.Fatalf("exchange = %d %s", exchangeResponse.Code, exchangeResponse.Body.String())
	}
	if active := authorize(input); active.Code != http.StatusCreated {
		t.Fatalf("active reauthorization = %d %s", active.Code, active.Body.String())
	}
	htmlRequest := httptest.NewRequest(http.MethodGet, "/v1/work/oauth/credentials?agent_id=work", nil)
	htmlRequest.Header.Set("Accept", "text/html")
	htmlRequest.AddCookie(&http.Cookie{Name: "gitoversight_csrf", Value: "csrf-token"})
	htmlRequest = htmlRequest.WithContext(WithHumanApprover(htmlRequest.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv"}))
	htmlResponse := httptest.NewRecorder()
	handler.ServeHTTP(htmlResponse, htmlRequest)
	html := htmlResponse.Body.String()
	for _, required := range []string{"<!doctype html>", "Work credentials", "ChatGPT Work", "work", "org/private", "Created", "Last used", "Not recorded", "Active", "Revoke this credential", "csrf-token", "width=device-width", `role="status"`, `aria-live="polite"`} {
		if !strings.Contains(html, required) {
			t.Fatalf("credential HTML missing %q: %s", required, html)
		}
	}
	if strings.Contains(html, "access_token") || strings.Contains(html, "refresh_token") {
		t.Fatalf("credential HTML leaked a token field: %s", html)
	}
	credentialRequest := httptest.NewRequest(http.MethodGet, "/v1/work/oauth/credentials?agent_id=work", nil)
	credentialRequest.Header.Set("Accept", "application/json")
	credentialRequest = credentialRequest.WithContext(WithHumanApprover(credentialRequest.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv"}))
	credentialResponse := httptest.NewRecorder()
	handler.ServeHTTP(credentialResponse, credentialRequest)
	if credentialResponse.Code != http.StatusOK || strings.Contains(credentialResponse.Body.String(), "access_token") || strings.Contains(credentialResponse.Body.String(), "refresh_token") {
		t.Fatalf("credential list = %d %s", credentialResponse.Code, credentialResponse.Body.String())
	}
	var credentials struct {
		Credentials []appauth.TokenFamily `json:"credentials"`
	}
	_ = json.Unmarshal(credentialResponse.Body.Bytes(), &credentials)
	if len(credentials.Credentials) != 1 {
		t.Fatalf("credentials = %+v", credentials.Credentials)
	}
	revokeRequest := httptest.NewRequest(http.MethodPost, "/v1/work/oauth/credentials/"+credentials.Credentials[0].ID+"/revoke?agent_id=work", nil)
	revokeRequest = revokeRequest.WithContext(WithHumanApprover(revokeRequest.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv"}))
	revokeResponse := httptest.NewRecorder()
	handler.ServeHTTP(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("human credential revoke = %d %s", revokeResponse.Code, revokeResponse.Body.String())
	}
	revokedPageRequest := httptest.NewRequest(http.MethodGet, "/v1/work/oauth/credentials?agent_id=work", nil)
	revokedPageRequest.Header.Set("Accept", "text/html")
	revokedPageRequest = revokedPageRequest.WithContext(WithHumanApprover(revokedPageRequest.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv"}))
	revokedPage := httptest.NewRecorder()
	handler.ServeHTTP(revokedPage, revokedPageRequest)
	if revokedPage.Code != http.StatusOK || !strings.Contains(revokedPage.Body.String(), "A new authorization must explicitly replace the revoked identity") || strings.Contains(revokedPage.Body.String(), ">Revoke this credential</button>") {
		t.Fatalf("revoked credential page = %d %s", revokedPage.Code, revokedPage.Body.String())
	}
	if implicit := authorize(input); implicit.Code != http.StatusConflict || !strings.Contains(implicit.Body.String(), "revoked_identity_replacement_required") {
		t.Fatalf("implicit revoked replacement = %d %s", implicit.Code, implicit.Body.String())
	}
	input.ReplaceRevokedIdentity = true
	if replacement := authorize(input); replacement.Code != http.StatusCreated {
		t.Fatalf("explicit revoked replacement = %d %s", replacement.Code, replacement.Body.String())
	}
}

func TestWorkOAuthApprovalRejectsPublicRepositoryAndTenantlessHuman(t *testing.T) {
	handler, _, client := newOAuthHandler(t)
	digest := sha256.Sum256([]byte("verifier"))
	input := oauthAuthorizationInput{ResponseType: "code", ClientID: client.ID, RedirectURI: client.RedirectURIs[0], State: "state", CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]), ChallengeType: "S256", AgentID: "work", DisplayName: "Work", Repositories: []string{"org/public"}}
	payload, _ := json.Marshal(input)
	for _, test := range []struct {
		name    string
		context context.Context
		want    int
	}{
		{name: "missing human", context: context.Background(), want: http.StatusUnauthorized},
		{name: "public scope", context: WithHumanApprover(context.Background(), HumanApprover{TenantID: "tenant-a", ID: "yaniv"}), want: http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(string(payload))).WithContext(test.context)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestWorkOAuthReauthorizationRejectsLatentAndDuplicateRepositoryScopes(t *testing.T) {
	handler, _, client := newOAuthHandler(t)
	digest := sha256.Sum256([]byte("scope-verifier"))
	base := oauthAuthorizationInput{ResponseType: "code", ClientID: client.ID, RedirectURI: client.RedirectURIs[0], State: "state", CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]), ChallengeType: "S256", AgentID: "work", DisplayName: "Work", Repositories: []string{"org/private"}}
	authorize := func(input oauthAuthorizationInput) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(input)
		request := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(string(payload)))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(WithHumanApprover(request.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv"}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if got := authorize(base); got.Code != http.StatusCreated {
		t.Fatalf("initial authorization = %d %s", got.Code, got.Body.String())
	}
	for name, repositories := range map[string][]string{
		"unknown":   {"org/future-private"},
		"public":    {"org/public"},
		"duplicate": {"org/private", "org/private"},
	} {
		t.Run(name, func(t *testing.T) {
			input := base
			input.Repositories = repositories
			got := authorize(input)
			if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "repository_scope_rejected") {
				t.Fatalf("reauthorization = %d %s", got.Code, got.Body.String())
			}
		})
	}
}
