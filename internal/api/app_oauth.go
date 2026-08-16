package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/appauth"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
)

type WorkOAuthAuthority interface {
	PolicyStatus(context.Context, string) (server.DurablePolicyStatus, error)
	PolicySnapshot(context.Context, string) (policy.Snapshot, error)
	EnrollWorkAgent(context.Context, string, string, server.WorkAgentEnrollment) (server.DurablePolicyStatus, error)
}

type WorkOAuthConfig struct {
	Client          appauth.Client
	CodeLifetime    time.Duration
	AccessLifetime  time.Duration
	RefreshLifetime time.Duration
	MaxBodyBytes    int64
}

type WorkOAuthHandler struct {
	service         *appauth.Service
	authority       WorkOAuthAuthority
	client          appauth.Client
	codeLifetime    time.Duration
	accessLifetime  time.Duration
	refreshLifetime time.Duration
	maxBodyBytes    int64
}

func NewWorkOAuthHandler(service *appauth.Service, authority WorkOAuthAuthority, config WorkOAuthConfig) (*WorkOAuthHandler, error) {
	if service == nil || authority == nil || config.Client.Issuer == "" || config.Client.Audience == "" || config.Client.ID == "" || config.Client.Name == "" || len(config.Client.RedirectURIs) == 0 {
		return nil, errors.New("work oauth handler configuration is incomplete")
	}
	issuer, issuerErr := url.Parse(config.Client.Issuer)
	audience, audienceErr := url.Parse(config.Client.Audience)
	if issuerErr != nil || audienceErr != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" || audience.Scheme != "https" || audience.Host == "" {
		return nil, errors.New("work oauth issuer and audience must be absolute https URLs")
	}
	for _, redirectURI := range config.Client.RedirectURIs {
		redirect, err := url.Parse(redirectURI)
		if err != nil || redirect.Scheme != "https" || redirect.Host == "" || redirect.Fragment != "" {
			return nil, errors.New("work oauth redirect URIs must be absolute https URLs without fragments")
		}
	}
	if config.CodeLifetime <= 0 {
		config.CodeLifetime = 5 * time.Minute
	}
	if config.AccessLifetime <= 0 {
		config.AccessLifetime = time.Hour
	}
	if config.RefreshLifetime <= 0 {
		config.RefreshLifetime = 30 * 24 * time.Hour
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 32 << 10
	}
	return &WorkOAuthHandler{service: service, authority: authority, client: config.Client, codeLifetime: config.CodeLifetime, accessLifetime: config.AccessLifetime, refreshLifetime: config.RefreshLifetime, maxBodyBytes: config.MaxBodyBytes}, nil
}

func (handler *WorkOAuthHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/.well-known/oauth-authorization-server":
		handler.authorizationMetadata(response, request)
	case "/.well-known/oauth-protected-resource":
		handler.resourceMetadata(response, request)
	case "/oauth/authorize":
		if request.Method == http.MethodGet {
			handler.reviewAuthorization(response, request)
		} else if request.Method == http.MethodPost {
			handler.approveAuthorization(response, request)
		} else {
			http.NotFound(response, request)
		}
	case "/oauth/token":
		handler.token(response, request)
	case "/oauth/revoke":
		handler.revoke(response, request)
	case "/v1/work/oauth/static/authorize.js":
		handler.staticAsset(response, request, "application/javascript; charset=utf-8", workAuthorizationScript)
	case "/v1/work/oauth/static/credentials.js":
		handler.staticAsset(response, request, "application/javascript; charset=utf-8", workCredentialsScript)
	case "/v1/work/oauth/static/credentials.css":
		handler.staticAsset(response, request, "text/css; charset=utf-8", workCredentialsStyle)
	case "/v1/work/oauth/credentials":
		handler.credentials(response, request)
	default:
		if strings.HasPrefix(request.URL.Path, "/v1/work/oauth/credentials/") && strings.HasSuffix(request.URL.Path, "/revoke") {
			handler.revokeCredential(response, request)
			return
		}
		http.NotFound(response, request)
	}
}

func (handler *WorkOAuthHandler) staticAsset(response http.ResponseWriter, request *http.Request, contentType, body string) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.NotFound(response, request)
		return
	}
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Cache-Control", "public, max-age=300")
	if request.Method == http.MethodGet {
		_, _ = io.WriteString(response, body)
	}
}

func (handler *WorkOAuthHandler) credentials(response http.ResponseWriter, request *http.Request) {
	approver, ok := HumanApproverFromContext(request.Context())
	if request.Method != http.MethodGet || !ok {
		http.NotFound(response, request)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	agentID := request.URL.Query().Get("agent_id")
	families, err := handler.service.TokenFamilies(request.Context(), approver.TenantID, agentID)
	if err != nil {
		writeError(response, http.StatusBadRequest, "credentials_unavailable")
		return
	}
	if strings.Contains(request.Header.Get("Accept"), "text/html") {
		snapshot, policyErr := handler.authority.PolicySnapshot(request.Context(), approver.TenantID)
		if policyErr != nil {
			writeError(response, http.StatusServiceUnavailable, "policy_unavailable")
			return
		}
		displayName := agentID
		if agent, exists := snapshot.Agents[agentID]; exists {
			displayName = agent.FirstName
		}
		csrf := ""
		if cookie, cookieErr := request.Cookie("gitoversight_csrf"); cookieErr == nil {
			csrf = cookie.Value
		}
		views := make([]workCredentialView, 0, len(families))
		for _, family := range families {
			view := workCredentialView{
				ID: family.ID, ClientID: family.ClientID, ClientName: family.ClientID,
				AgentID: agentID, DisplayName: displayName, Created: family.CreatedAt.UTC().Format(time.RFC3339),
				LastUsed: "Not recorded", Repositories: append([]string(nil), family.Repositories...),
			}
			if family.ClientID == handler.client.ID {
				view.ClientName = handler.client.Name
			}
			if family.AllPrivate {
				view.ScopeSummary = "All current and future registered private repositories"
			} else {
				view.ScopeSummary = "Selected private repositories"
			}
			if family.RevokedAt == nil {
				view.Status = "Active"
			} else {
				view.Status = "Revoked"
				view.Revoked = true
				view.RevokedAt = family.RevokedAt.UTC().Format(time.RFC3339)
				view.RevocationReason = family.RevocationReason
			}
			views = append(views, view)
		}
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = workCredentialsTemplate.Execute(response, map[string]any{"AgentID": agentID, "DisplayName": displayName, "Credentials": views, "CSRF": csrf})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"agent_id": agentID, "credentials": families})
}

type workCredentialView struct {
	ID, ClientID, ClientName, AgentID, DisplayName string
	ScopeSummary, Created, LastUsed, Status        string
	Repositories                                   []string
	Revoked                                        bool
	RevokedAt, RevocationReason                    string
}

func (handler *WorkOAuthHandler) revokeCredential(response http.ResponseWriter, request *http.Request) {
	approver, ok := HumanApproverFromContext(request.Context())
	if request.Method != http.MethodPost || !ok {
		http.NotFound(response, request)
		return
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) != 6 || parts[4] == "" || parts[5] != "revoke" {
		http.NotFound(response, request)
		return
	}
	agentID := request.URL.Query().Get("agent_id")
	families, err := handler.service.TokenFamilies(request.Context(), approver.TenantID, agentID)
	if err != nil {
		writeError(response, http.StatusBadRequest, "credentials_unavailable")
		return
	}
	owned := false
	for _, family := range families {
		owned = owned || family.ID == parts[4]
	}
	if !owned {
		writeError(response, http.StatusNotFound, "credential_not_found")
		return
	}
	if err := handler.service.RevokeFamily(request.Context(), parts[4], "human revoked Work credential"); err != nil {
		writeError(response, http.StatusConflict, "credential_revoke_failed")
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (handler *WorkOAuthHandler) authorizationMetadata(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.NotFound(response, request)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"issuer": handler.client.Issuer, "authorization_endpoint": handler.client.Issuer + "/oauth/authorize",
		"token_endpoint": handler.client.Issuer + "/oauth/token", "revocation_endpoint": handler.client.Issuer + "/oauth/revoke",
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"},
	})
}

func (handler *WorkOAuthHandler) resourceMetadata(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.NotFound(response, request)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"resource": handler.client.Audience, "authorization_servers": []string{handler.client.Issuer}, "bearer_methods_supported": []string{"header"}})
}

type oauthAuthorizationInput struct {
	ResponseType           string   `json:"response_type"`
	ClientID               string   `json:"client_id"`
	RedirectURI            string   `json:"redirect_uri"`
	State                  string   `json:"state"`
	CodeChallenge          string   `json:"code_challenge"`
	ChallengeType          string   `json:"code_challenge_method"`
	AgentID                string   `json:"agent_id"`
	DisplayName            string   `json:"display_name"`
	Repositories           []string `json:"repositories"`
	AllPrivate             bool     `json:"all_private"`
	ReplaceRevokedIdentity bool     `json:"replace_revoked_identity,omitempty"`
}

func (handler *WorkOAuthHandler) validateProtocol(input oauthAuthorizationInput) error {
	challenge, challengeErr := base64.RawURLEncoding.DecodeString(input.CodeChallenge)
	if input.ResponseType != "code" || input.ClientID != handler.client.ID || !containsExact(handler.client.RedirectURIs, input.RedirectURI) || input.State == "" || len(input.State) > 512 || challengeErr != nil || len(challenge) != sha256.Size || input.ChallengeType != "S256" {
		return errors.New("invalid oauth authorization request")
	}
	return nil
}

func (handler *WorkOAuthHandler) reviewAuthorization(response http.ResponseWriter, request *http.Request) {
	approver, ok := HumanApproverFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "human_authentication_required")
		return
	}
	input := oauthAuthorizationInput{ResponseType: request.URL.Query().Get("response_type"), ClientID: request.URL.Query().Get("client_id"), RedirectURI: request.URL.Query().Get("redirect_uri"), State: request.URL.Query().Get("state"), CodeChallenge: request.URL.Query().Get("code_challenge"), ChallengeType: request.URL.Query().Get("code_challenge_method")}
	if err := handler.validateProtocol(input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_authorization_request")
		return
	}
	snapshot, err := handler.authority.PolicySnapshot(request.Context(), approver.TenantID)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "policy_unavailable")
		return
	}
	repositories := make([]string, 0)
	for name, repository := range snapshot.Repositories {
		if repository.Visibility == "private" {
			repositories = append(repositories, name)
		}
	}
	sort.Strings(repositories)
	csrf := ""
	if cookie, err := request.Cookie("gitoversight_csrf"); err == nil {
		csrf = cookie.Value
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = workAuthorizationTemplate.Execute(response, map[string]any{"Client": handler.client, "Input": input, "Repositories": repositories, "CSRF": csrf})
}

func (handler *WorkOAuthHandler) approveAuthorization(response http.ResponseWriter, request *http.Request) {
	approver, ok := HumanApproverFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "human_authentication_required")
		return
	}
	var input oauthAuthorizationInput
	if err := decodeBoundedJSON(request, handler.maxBodyBytes, &input); err != nil || handler.validateProtocol(input) != nil {
		writeError(response, http.StatusBadRequest, "invalid_authorization_request")
		return
	}
	snapshot, err := handler.authority.PolicySnapshot(request.Context(), approver.TenantID)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "policy_unavailable")
		return
	}
	if err := validateRequestedRepositoryScope(snapshot, input.Repositories, input.AllPrivate); err != nil {
		writeError(response, http.StatusConflict, "repository_scope_rejected")
		return
	}
	if existing, exists := snapshot.Agents[input.AgentID]; exists {
		if !existing.IsRemote() || existing.FirstName != input.DisplayName {
			writeError(response, http.StatusConflict, "agent_identity_conflict")
			return
		}
		families, familyErr := handler.service.TokenFamilies(request.Context(), approver.TenantID, input.AgentID)
		if familyErr != nil {
			writeError(response, http.StatusServiceUnavailable, "credentials_unavailable")
			return
		}
		hasActive, hasRevoked := false, false
		for _, family := range families {
			hasActive = hasActive || family.RevokedAt == nil
			hasRevoked = hasRevoked || family.RevokedAt != nil
		}
		if !hasActive && hasRevoked && !input.ReplaceRevokedIdentity {
			writeError(response, http.StatusConflict, "revoked_identity_replacement_required")
			return
		}
	} else {
		status, statusErr := handler.authority.PolicyStatus(request.Context(), approver.TenantID)
		if statusErr != nil {
			writeError(response, http.StatusServiceUnavailable, "policy_unavailable")
			return
		}
		_, err = handler.authority.EnrollWorkAgent(request.Context(), approver.TenantID, approver.ID, server.WorkAgentEnrollment{
			AgentID: input.AgentID, DisplayName: input.DisplayName, RepositoryScope: input.Repositories, AllPrivate: input.AllPrivate,
			ExpectedGeneration: status.Generation, ExpectedPolicyHash: status.PolicyHash,
		})
		if err != nil {
			writeError(response, http.StatusConflict, "enrollment_rejected")
			return
		}
	}
	code, err := handler.service.IssueAuthorizationCode(request.Context(), appauth.AuthorizationRequest{Binding: appauth.Binding{
		Issuer: handler.client.Issuer, Audience: handler.client.Audience, ClientID: handler.client.ID,
		TenantID: approver.TenantID, AgentID: input.AgentID, Repositories: input.Repositories, AllPrivate: input.AllPrivate,
	}, RedirectURI: input.RedirectURI, PKCEChallenge: input.CodeChallenge, Lifetime: handler.codeLifetime})
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "authorization_unavailable")
		return
	}
	redirect, _ := url.Parse(input.RedirectURI)
	query := redirect.Query()
	query.Set("code", code)
	query.Set("state", input.State)
	redirect.RawQuery = query.Encode()
	writeJSON(response, http.StatusCreated, map[string]string{"redirect_uri": redirect.String()})
}

func validateRequestedRepositoryScope(snapshot policy.Snapshot, repositories []string, allPrivate bool) error {
	if allPrivate == (len(repositories) > 0) {
		return errors.New("choose all private or selected repositories")
	}
	seen := make(map[string]struct{}, len(repositories))
	for _, name := range repositories {
		if name == "" || name != strings.TrimSpace(name) {
			return errors.New("repository names must be exact")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("repository scope contains duplicates")
		}
		seen[name] = struct{}{}
		repository, exists := snapshot.Repositories[name]
		if !exists || repository.Visibility != "private" {
			return errors.New("selected repository is not registered private")
		}
	}
	return nil
}

func (handler *WorkOAuthHandler) token(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	if request.Method != http.MethodPost || !parseBoundedForm(response, request, handler.maxBodyBytes) {
		return
	}
	if request.Form.Get("client_id") != handler.client.ID {
		handler.oauthError(response, http.StatusBadRequest, "invalid_client")
		return
	}
	var pair appauth.TokenPair
	var grant appauth.AccessGrant
	var err error
	switch request.Form.Get("grant_type") {
	case "authorization_code":
		pair, grant, err = handler.service.ExchangeAuthorizationCode(request.Context(), appauth.ExchangeRequest{
			Code: request.Form.Get("code"), Issuer: handler.client.Issuer, Audience: handler.client.Audience,
			ClientID: handler.client.ID, RedirectURI: request.Form.Get("redirect_uri"), PKCEVerifier: request.Form.Get("code_verifier"),
			AccessLifetime: handler.accessLifetime, RefreshLifetime: handler.refreshLifetime,
		})
	case "refresh_token":
		pair, grant, err = handler.service.RotateRefreshToken(request.Context(), request.Form.Get("refresh_token"), handler.accessLifetime, handler.refreshLifetime)
	default:
		handler.oauthError(response, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	if err != nil || grant.Issuer != handler.client.Issuer || grant.Audience != handler.client.Audience || grant.ClientID != handler.client.ID {
		if err == nil && grant.ID != "" {
			_ = handler.service.RevokeFamily(request.Context(), grant.ID, "oauth binding mismatch")
		}
		handler.oauthError(response, http.StatusBadRequest, "invalid_grant")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"access_token": pair.AccessToken, "refresh_token": pair.RefreshToken, "token_type": "Bearer", "expires_in": int64(time.Until(pair.AccessExpiry).Seconds())})
}

func (handler *WorkOAuthHandler) revoke(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || !parseBoundedForm(response, request, handler.maxBodyBytes) {
		return
	}
	if request.Form.Get("client_id") != handler.client.ID {
		handler.oauthError(response, http.StatusBadRequest, "invalid_client")
		return
	}
	// RFC 7009 deliberately returns success for unknown tokens. The service
	// hashes and looks up both access and refresh forms without logging either.
	_ = handler.service.RevokeToken(request.Context(), request.Form.Get("token"), handler.client.Issuer, handler.client.ID, "oauth client revocation")
	response.WriteHeader(http.StatusOK)
}

func (handler *WorkOAuthHandler) oauthError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]string{"error": code})
}

func parseBoundedForm(response http.ResponseWriter, request *http.Request, limit int64) bool {
	if request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		writeError(response, http.StatusUnsupportedMediaType, "form_encoding_required")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, limit)
	if err := request.ParseForm(); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func decodeBoundedJSON(request *http.Request, limit int64, destination any) error {
	if request.Header.Get("Content-Type") != "application/json" {
		return errors.New("application/json required")
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, limit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("exactly one JSON object is required")
	}
	return nil
}

func containsExact(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

var workAuthorizationTemplate = template.Must(template.New("work-oauth").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="csrf-token" content="{{.CSRF}}"><title>Authorize {{.Client.Name}}</title><script src="/v1/work/oauth/static/authorize.js" defer></script></head><body><main id="oauth-authorization" data-response-type="{{.Input.ResponseType}}" data-client-id="{{.Input.ClientID}}" data-redirect-uri="{{.Input.RedirectURI}}" data-state="{{.Input.State}}" data-code-challenge="{{.Input.CodeChallenge}}" data-challenge-type="{{.Input.ChallengeType}}"><h1>Connect {{.Client.Name}}</h1><p>This creates a separate remote agent. It does not receive your GitHub credentials.</p><p><strong>Callback:</strong> {{.Input.RedirectURI}}</p><label>Agent ID <input id="agent" autocomplete="off" required></label><label>Display name <input id="display" autocomplete="off" required></label><fieldset><legend>Private repository access</legend><label><input id="all" type="checkbox"> All current and future registered private repositories</label>{{range .Repositories}}<label><input class="repo" type="checkbox" value="{{.}}"> {{.}}</label>{{end}}</fieldset><label><input id="replace" type="checkbox"> Explicitly replace a previously revoked identity with this same agent ID</label><p id="status" role="status" aria-live="polite"></p><button id="approve" type="button">Authorize exact access</button><button id="decline" type="button">Decline</button></main></body></html>`))

var workCredentialsTemplate = template.Must(template.New("work-credentials").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="csrf-token" content="{{.CSRF}}"><title>Work credentials</title><link rel="stylesheet" href="/v1/work/oauth/static/credentials.css"><script src="/v1/work/oauth/static/credentials.js" defer></script></head><body><main id="work-credentials" data-agent-id="{{.AgentID}}"><h1>Work credentials</h1><p>Remote agent <strong>{{.DisplayName}}</strong> (<code>{{.AgentID}}</code>). Tokens are never displayed.</p>{{if .Credentials}}{{range .Credentials}}<article aria-labelledby="credential-{{.ID}}"><h2 id="credential-{{.ID}}">{{.ClientName}}</h2><dl><dt>Client ID</dt><dd><code>{{.ClientID}}</code></dd><dt>Agent</dt><dd>{{.DisplayName}} (<code>{{.AgentID}}</code>)</dd><dt>Scope</dt><dd>{{.ScopeSummary}}{{if .Repositories}}<ul>{{range .Repositories}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}</dd><dt>Created</dt><dd><time>{{.Created}}</time></dd><dt>Last used</dt><dd>{{.LastUsed}}</dd><dt>Status</dt><dd class="credential-status {{if .Revoked}}revoked{{end}}">{{.Status}}{{if .RevokedAt}} at <time>{{.RevokedAt}}</time>{{end}}{{if .RevocationReason}} — {{.RevocationReason}}{{end}}</dd></dl>{{if .Revoked}}<p>This credential cannot connect. A new authorization must explicitly replace the revoked identity.</p>{{else}}<button type="button" class="revoke" data-id="{{.ID}}" aria-label="Revoke this credential for {{.ClientName}}">Revoke this credential</button>{{end}}</article>{{end}}{{else}}<p>No credentials exist for this agent.</p>{{end}}<p id="status" role="status" aria-live="polite"></p></main></body></html>`))

const workAuthorizationScript = `(()=>{const root=document.getElementById('oauth-authorization'),status=document.getElementById('status'),callback=root.dataset.redirectUri,state=root.dataset.state;document.getElementById('decline').onclick=()=>{const u=new URL(callback);u.searchParams.set('error','access_denied');u.searchParams.set('state',state);status.textContent='Access declined. Returning to the app.';location.assign(u)};document.getElementById('approve').onclick=async()=>{const all=document.getElementById('all').checked,repositories=all?[]:[...document.querySelectorAll('.repo:checked')].map(x=>x.value);if(!all&&repositories.length===0){status.textContent='Choose at least one private repository or all private repositories.';return}status.textContent='Creating the scoped connection…';const body={response_type:root.dataset.responseType,client_id:root.dataset.clientId,redirect_uri:callback,state,code_challenge:root.dataset.codeChallenge,code_challenge_method:root.dataset.challengeType,agent_id:document.getElementById('agent').value,display_name:document.getElementById('display').value,repositories,all_private:all,replace_revoked_identity:document.getElementById('replace').checked};const r=await fetch('/oauth/authorize',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name=csrf-token]').content},body:JSON.stringify(body)}),v=await r.json();if(r.ok){status.textContent='Connected. Returning to the app; you may close this window if it does not return.';setTimeout(()=>location.assign(v.redirect_uri),500)}else if(v.error==='revoked_identity_replacement_required'){status.textContent='This identity was revoked. Select the explicit replacement checkbox to create a new credential.'}else{status.textContent='Connection failed: '+v.error+'. Review the fields and try again.'}}})();`

const workCredentialsScript = `(()=>{const root=document.getElementById('work-credentials'),csrf=document.querySelector('meta[name=csrf-token]').content,status=document.getElementById('status'),agent=root.dataset.agentId;document.querySelectorAll('.revoke').forEach(button=>button.onclick=async()=>{button.disabled=true;status.textContent='Revoking credential…';const r=await fetch('/v1/work/oauth/credentials/'+encodeURIComponent(button.dataset.id)+'/revoke?agent_id='+encodeURIComponent(agent),{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':csrf}});if(r.ok){status.textContent='Credential revoked. It can no longer connect. You may close this page.';button.closest('article').querySelector('.credential-status').textContent='Revoked';button.remove()}else{status.textContent='Revocation failed. Refresh the page and try again.';button.disabled=false}})})();`

const workCredentialsStyle = `body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#f6f7f8;color:#17202a}main{max-width:52rem;margin:auto;padding:1rem}article{background:white;border:1px solid #d9dee3;border-radius:.75rem;padding:1rem;margin:1rem 0;overflow-wrap:anywhere}dl{display:grid;grid-template-columns:minmax(7rem,auto) 1fr;gap:.5rem 1rem}dt{font-weight:650}dd{margin:0}button{min-height:44px;padding:.65rem 1rem;border-radius:.5rem;border:1px solid #9b1c1c;background:#fff;color:#8a1111;font:inherit}button:focus-visible{outline:3px solid #1769aa;outline-offset:2px}.revoked{color:#6b7280}@media(max-width:32rem){dl{grid-template-columns:1fr;gap:.15rem}dd{margin-bottom:.6rem}}`
