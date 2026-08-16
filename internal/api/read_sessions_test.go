package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/api"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

func TestReadSessionAuthorizesFallbackReadAndProxiesOnlyBoundRepository(t *testing.T) {
	t.Parallel()
	snapshot := policy.Snapshot{
		Generation:          1,
		FallbackPermissions: policy.PermissionSet{Read: true},
		Agents:              map[string]policy.Agent{"tomas": {UID: 1005, FirstName: "Tomas"}},
		Repositories: map[string]policy.Repository{
			"ActionsJson/actions.json.dev": {Visibility: "private", Owners: []string{"zara"}},
			"yaniv256/other":               {Visibility: "private", Owners: []string{"zara"}},
		},
	}
	proxied := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Proxied-Repository", request.Header.Get("X-GitOversight-Repository"))
		response.WriteHeader(http.StatusOK)
	})
	handler, err := api.NewReadHandler(api.ReadHandlerConfig{
		Policy: snapshot, SessionTTL: 5 * time.Minute, GitBaseURL: "https://gitoversight.test/git", GitProxy: proxied,
		Random: bytes.NewReader(bytes.Repeat([]byte{7}, 64)), Now: func() time.Time { return time.Unix(1000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{"repository": "ActionsJson/actions.json.dev"})
	request := httptest.NewRequest(http.MethodPost, "/v1/read-sessions", bytes.NewReader(body))
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "tomas", CredentialID: "tomas-1"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", response.Code, response.Body.String())
	}
	var session struct {
		Token    string `json:"token"`
		CloneURL string `json:"clone_url"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil || session.Token == "" || session.CloneURL != "https://gitoversight.test/git/ActionsJson/actions.json.dev.git" {
		t.Fatalf("session = %#v, err=%v", session, err)
	}

	read := httptest.NewRequest(http.MethodGet, "/git/ActionsJson/actions.json.dev.git/info/refs?service=git-upload-pack", nil)
	read.Header.Set("Authorization", "Bearer "+session.Token)
	readResponse := httptest.NewRecorder()
	handler.ServeHTTP(readResponse, read)
	if readResponse.Code != http.StatusOK || readResponse.Header().Get("X-Proxied-Repository") != "ActionsJson/actions.json.dev" {
		t.Fatalf("read = %d headers=%v", readResponse.Code, readResponse.Header())
	}

	other := httptest.NewRequest(http.MethodGet, "/git/yaniv256/other.git/info/refs?service=git-upload-pack", nil)
	other.Header.Set("Authorization", "Bearer "+session.Token)
	otherResponse := httptest.NewRecorder()
	handler.ServeHTTP(otherResponse, other)
	if otherResponse.Code != http.StatusUnauthorized {
		t.Fatalf("cross-repository token = %d", otherResponse.Code)
	}
}

func TestReadSessionHonorsExplicitRepositoryDenial(t *testing.T) {
	t.Parallel()
	deny := policy.PermissionSet{Read: false}
	snapshot := policy.Snapshot{
		Generation: 1, FallbackPermissions: policy.PermissionSet{Read: true},
		Agents:       map[string]policy.Agent{"tomas": {UID: 1005, FirstName: "Tomas"}},
		Repositories: map[string]policy.Repository{"yaniv256/restricted": {Visibility: "private", Owners: []string{"zara"}, Permissions: &deny}},
	}
	handler, err := api.NewReadHandler(api.ReadHandlerConfig{Policy: snapshot, SessionTTL: time.Minute, GitBaseURL: "https://gitoversight.test/git", GitProxy: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"repository": "yaniv256/restricted"})
	request := httptest.NewRequest(http.MethodPost, "/v1/read-sessions", bytes.NewReader(body))
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "tomas", CredentialID: "tomas-1"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("denied read = %d: %s", response.Code, response.Body.String())
	}
}

func TestReadSessionUsesLivePolicyResolver(t *testing.T) {
	snapshot := policy.Snapshot{
		Generation:   1,
		Agents:       map[string]policy.Agent{"tomas": {UID: 1005, FirstName: "Tomas"}},
		Repositories: map[string]policy.Repository{},
	}
	handler, err := api.NewReadHandler(api.ReadHandlerConfig{
		PolicyResolver: func(context.Context) (policy.Snapshot, error) { return snapshot, nil },
		SessionTTL:     time.Minute, GitBaseURL: "https://gitoversight.test/git", GitProxy: http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Repositories["yaniv256/new-private"] = policy.Repository{Visibility: "private", Owners: []string{"tomas"}, Derived: true}
	body, _ := json.Marshal(map[string]string{"repository": "yaniv256/new-private"})
	request := httptest.NewRequest(http.MethodPost, "/v1/read-sessions", bytes.NewReader(body))
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "tomas"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", response.Code, response.Body.String())
	}
}
