package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

type PullLister interface {
	List(worker.Request) ([]githubapp.PullRequestSummary, error)
}

type PullsHandlerConfig struct {
	Policy policy.Snapshot
	Worker PullLister
}

type PullsHandler struct {
	policy policy.Snapshot
	worker PullLister
}

func NewPullsHandler(config PullsHandlerConfig) (*PullsHandler, error) {
	if config.Worker == nil {
		return nil, errors.New("pulls handler configuration is incomplete")
	}
	if err := config.Policy.Validate(); err != nil {
		return nil, err
	}
	return &PullsHandler{policy: config.Policy, worker: config.Worker}, nil
}

func (handler *PullsHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.Path != "/v1/pulls" {
		http.NotFound(response, request)
		return
	}
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok || identity.AgentID == "" {
		http.Error(response, "agent authentication required", http.StatusUnauthorized)
		return
	}
	repository := request.URL.Query().Get("repository")
	if strings.Count(repository, "/") != 1 || strings.ContainsAny(repository, "*?[]") {
		http.Error(response, "invalid pull list request", http.StatusBadRequest)
		return
	}
	decision := policy.Evaluate(handler.policy, policy.Request{Caller: identity.AgentID, Repository: repository, Operation: "repository.read"})
	if decision.Code != policy.AllowedRead {
		http.Error(response, "repository read denied", http.StatusForbidden)
		return
	}
	summaries, err := handler.worker.List(worker.Request{Repository: repository})
	if err != nil {
		http.Error(response, "pull list unavailable", http.StatusBadGateway)
		return
	}
	if summaries == nil {
		summaries = []githubapp.PullRequestSummary{}
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(response).Encode(map[string]any{"pull_requests": summaries})
}
