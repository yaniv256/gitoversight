package githubapp

import (
	"errors"
	"fmt"

	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

type pullRequestAPI interface {
	CreatePullRequest(CreatePullRequest) (PullRequest, error)
	VerifyPullRequest(repository, head, sha string, mode TokenMode, subject string) (PullRequest, bool, error)
	ListPullRequests(repository string, mode TokenMode, subject string) ([]PullRequestSummary, error)
	PullRequestState(repository string, number int64, mode TokenMode, subject string) (PullState, error)
}

type mutationAPI interface {
	ExecuteMutation(worker.Request, TokenMode, string) (string, error)
	ReconcileMutation(worker.Request, TokenMode, string) (worker.Reconciliation, error)
}

type Executor struct {
	client pullRequestAPI
}

func NewExecutor(client pullRequestAPI) *Executor {
	return &Executor{client: client}
}

func (e *Executor) Execute(request worker.Request) (worker.Result, error) {
	mode, subject, err := tokenIdentity(request)
	if err != nil {
		return worker.Result{}, err
	}
	if request.Operation != "pull_request.create" {
		client, ok := e.client.(mutationAPI)
		if !ok {
			return worker.Result{}, errors.New("operation has no privileged executor")
		}
		resourceID, err := client.ExecuteMutation(request, mode, subject)
		return worker.Result{ResourceID: resourceID}, err
	}
	base, ok := stringValue(request.Payload, "base")
	if !ok || base == "" || request.Branch == "" || request.Title == "" {
		return worker.Result{}, errors.New("pull request packet is incomplete")
	}
	result, err := e.client.CreatePullRequest(CreatePullRequest{
		Repository: request.Repository,
		Head:       request.Branch,
		Base:       base,
		Title:      request.Title,
		Body:       request.Body,
		Mode:       mode,
		Subject:    subject,
	})
	if err != nil {
		return worker.Result{}, err
	}
	resourceID := result.HTMLURL
	if resourceID == "" && result.Number > 0 {
		resourceID = fmt.Sprintf("pull_request:%d", result.Number)
	}
	return worker.Result{ResourceID: resourceID}, nil
}

func (e *Executor) Reconcile(request worker.Request) (worker.Reconciliation, error) {
	mode, subject, err := tokenIdentity(request)
	if err != nil {
		return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
	}
	if request.Operation != "pull_request.create" {
		client, ok := e.client.(mutationAPI)
		if !ok {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, errors.New("operation has no reconciliation adapter")
		}
		return client.ReconcileMutation(request, mode, subject)
	}
	headSHA, ok := stringValue(request.Payload, "head_sha")
	if !ok || headSHA == "" || request.Branch == "" {
		return worker.Reconciliation{State: worker.ReconciliationUnknown}, errors.New("pull request reconciliation packet is incomplete")
	}
	result, found, err := e.client.VerifyPullRequest(request.Repository, request.Branch, headSHA, mode, subject)
	if err != nil {
		return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
	}
	if !found {
		return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
	}
	resourceID := result.HTMLURL
	if resourceID == "" && result.Number > 0 {
		resourceID = fmt.Sprintf("pull_request:%d", result.Number)
	}
	return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: resourceID}, nil
}

func (e *Executor) ListPullRequests(request worker.Request) ([]PullRequestSummary, error) {
	if request.Repository == "" {
		return nil, errors.New("pull request list request is incomplete")
	}
	return e.client.ListPullRequests(request.Repository, AppInstallation, request.Repository+"\x00"+"pull_request.list")
}

func (e *Executor) PullRequestState(request worker.Request, number int64) (PullState, error) {
	if request.Repository == "" || number <= 0 {
		return PullState{Outcome: PullOutcomeIndeterminate}, errors.New("pull request state check is incomplete")
	}
	return e.client.PullRequestState(request.Repository, number, AppInstallation, request.Repository+"\x00"+"pull_request.list")
}

func tokenIdentity(request worker.Request) (TokenMode, string, error) {
	switch TokenMode(request.ActorMode) {
	case AppInstallation:
		if request.ActorSubject != "" {
			return "", "", errors.New("app installation actor subject must be empty")
		}
		return AppInstallation, "", nil
	case HumanUser:
		if request.ActorSubject == "" {
			return "", "", errors.New("human token subject is required")
		}
		return HumanUser, request.ActorSubject, nil
	default:
		return "", "", errors.New("token mode is invalid")
	}
}

func stringValue(payload map[string]any, key string) (string, bool) {
	value, exists := payload[key]
	if !exists {
		return "", false
	}
	result, ok := value.(string)
	return result, ok
}
