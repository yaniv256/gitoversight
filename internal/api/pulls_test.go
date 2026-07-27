package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/api"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

type fakePullLister struct {
	repository string
	summaries  []githubapp.PullRequestSummary
	err        error
}

func (f *fakePullLister) List(request worker.Request) ([]githubapp.PullRequestSummary, error) {
	f.repository = request.Repository
	return f.summaries, f.err
}

func pullsSnapshot(read bool) policy.Snapshot {
	return policy.Snapshot{
		Generation:          1,
		FallbackPermissions: policy.PermissionSet{Read: read},
		Agents:              map[string]policy.Agent{"tomas": {UID: 1005, FirstName: "Tomas"}},
		Repositories: map[string]policy.Repository{
			"ActionsJson/actions.json.dev": {Visibility: "private", Owners: []string{"zara"}},
		},
	}
}

func TestPullsHandlerRequiresAgentIdentity(t *testing.T) {
	t.Parallel()
	handler, err := api.NewPullsHandler(api.PullsHandlerConfig{Policy: pullsSnapshot(true), Worker: &fakePullLister{}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/pulls?repository=ActionsJson/actions.json.dev", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
}

func TestPullsHandlerDeniesUnauthorizedRead(t *testing.T) {
	t.Parallel()
	handler, err := api.NewPullsHandler(api.PullsHandlerConfig{Policy: pullsSnapshot(false), Worker: &fakePullLister{}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/pulls?repository=ActionsJson/actions.json.dev", nil)
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "tomas", CredentialID: "tomas-1"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
}

func TestPullsHandlerReturnsOpenPullRequestsWhenAllowed(t *testing.T) {
	t.Parallel()
	worker := &fakePullLister{summaries: []githubapp.PullRequestSummary{
		{Number: 7, Title: "first", State: "open", HeadRef: "feature", BaseRef: "main", Author: "zara"},
		{Number: 9, Title: "second", State: "open", HeadRef: "fix", BaseRef: "main", Author: "tomas"},
	}}
	handler, err := api.NewPullsHandler(api.PullsHandlerConfig{Policy: pullsSnapshot(true), Worker: worker})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/pulls?repository=ActionsJson/actions.json.dev", nil)
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "tomas", CredentialID: "tomas-1"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
	if worker.repository != "ActionsJson/actions.json.dev" {
		t.Fatalf("worker repository = %q", worker.repository)
	}
	var payload struct {
		PullRequests []githubapp.PullRequestSummary `json:"pull_requests"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.PullRequests) != 2 || payload.PullRequests[0].Number != 7 || payload.PullRequests[1].Number != 9 {
		t.Fatalf("pull_requests = %#v", payload.PullRequests)
	}
}

func TestPullsHandlerRejectsMalformedRepository(t *testing.T) {
	t.Parallel()
	handler, err := api.NewPullsHandler(api.PullsHandlerConfig{Policy: pullsSnapshot(true), Worker: &fakePullLister{}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/pulls?repository=ActionsJson/*", nil)
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "tomas", CredentialID: "tomas-1"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
}

func TestPullsHandlerSurfacesWorkerFailure(t *testing.T) {
	t.Parallel()
	handler, err := api.NewPullsHandler(api.PullsHandlerConfig{Policy: pullsSnapshot(true), Worker: &fakePullLister{err: errors.New("worker unavailable")}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/pulls?repository=ActionsJson/actions.json.dev", nil)
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "tomas", CredentialID: "tomas-1"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
}
