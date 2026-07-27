package githubapp_test

import (
	"errors"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

type pullRequestAPI struct {
	createInput githubapp.CreatePullRequest
	createErr   error
	verify      githubapp.PullRequest
	found       bool
	verifyErr   error
	listRepo    string
	listMode    githubapp.TokenMode
	listSubject string
	list        []githubapp.PullRequestSummary
	listErr     error
}

func (f *pullRequestAPI) CreatePullRequest(input githubapp.CreatePullRequest) (githubapp.PullRequest, error) {
	f.createInput = input
	return githubapp.PullRequest{Number: 42, HTMLURL: "https://github.test/private/pull/42"}, f.createErr
}

func (f *pullRequestAPI) VerifyPullRequest(string, string, string, githubapp.TokenMode, string) (githubapp.PullRequest, bool, error) {
	return f.verify, f.found, f.verifyErr
}

func (f *pullRequestAPI) PullRequestState(repository string, number int64, mode githubapp.TokenMode, subject string) (githubapp.PullState, error) {
	return githubapp.PullState{Outcome: githubapp.PullOutcomeMerged, MergeSHA: "fake-merge-sha"}, nil
}

func (f *pullRequestAPI) ListPullRequests(repository string, mode githubapp.TokenMode, subject string) ([]githubapp.PullRequestSummary, error) {
	f.listRepo, f.listMode, f.listSubject = repository, mode, subject
	return f.list, f.listErr
}

func TestExecutorCreatesPrivatePullRequestFromExactWorkerPacket(t *testing.T) {
	api := &pullRequestAPI{}
	executor := githubapp.NewExecutor(api)
	result, err := executor.Execute(worker.Request{
		RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create",
		Branch: "agent/zara/change", Title: "Private review", Body: "Review body",
		ActorMode: "app_installation",
		Payload:   map[string]any{"base": "main", "head_sha": "abc123", "token_mode": "human_user", "token_subject": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ResourceID != "https://github.test/private/pull/42" {
		t.Fatalf("result = %#v", result)
	}
	if api.createInput.Repository != "yaniv256/private" || api.createInput.Head != "agent/zara/change" || api.createInput.Base != "main" || api.createInput.Mode != githubapp.AppInstallation {
		t.Fatalf("input = %#v", api.createInput)
	}
}

func TestExecutorUsesBrokerBoundHumanActorInsteadOfPayload(t *testing.T) {
	api := &pullRequestAPI{}
	executor := githubapp.NewExecutor(api)
	_, err := executor.Execute(worker.Request{
		RequestID: "request-public", Repository: "yaniv256/public", Operation: "pull_request.create",
		Branch: "export", Title: "Public review", ActorMode: "human_user", ActorSubject: "yaniv",
		Payload: map[string]any{"base": "main", "head_sha": "abc123", "token_mode": "app_installation", "token_subject": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if api.createInput.Mode != githubapp.HumanUser || api.createInput.Subject != "yaniv" {
		t.Fatalf("input = %#v", api.createInput)
	}
}

func TestExecutorListsOpenPullRequestsWithAppInstallationScope(t *testing.T) {
	api := &pullRequestAPI{list: []githubapp.PullRequestSummary{{Number: 7, Title: "first", State: "open"}}}
	executor := githubapp.NewExecutor(api)
	summaries, err := executor.ListPullRequests(worker.Request{Repository: "yaniv256/private"})
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].Number != 7 {
		t.Fatalf("summaries = %#v", summaries)
	}
	if api.listRepo != "yaniv256/private" || api.listMode != githubapp.AppInstallation || api.listSubject != "yaniv256/private\x00pull_request.list" {
		t.Fatalf("repo = %q, mode = %q, subject = %q", api.listRepo, api.listMode, api.listSubject)
	}
	if _, err := executor.ListPullRequests(worker.Request{}); err == nil {
		t.Fatal("empty repository was accepted")
	}
}

func TestExecutorReconcilesCommittedAndAbsentPullRequest(t *testing.T) {
	api := &pullRequestAPI{verify: githubapp.PullRequest{Number: 42, HTMLURL: "https://github.test/private/pull/42"}, found: true}
	executor := githubapp.NewExecutor(api)
	request := worker.Request{RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "yaniv256:feature", ActorMode: "app_installation", Payload: map[string]any{"base": "main", "head_sha": "abc123"}}
	result, err := executor.Reconcile(request)
	if err != nil || result.State != worker.ReconciliationCommitted || result.ResourceID == "" {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
	api.found = false
	result, err = executor.Reconcile(request)
	if err != nil || result.State != worker.ReconciliationAbsent {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
}

func TestExecutorFailsClosedForUnsupportedOrIncompleteOperation(t *testing.T) {
	executor := githubapp.NewExecutor(&pullRequestAPI{})
	for _, request := range []worker.Request{
		{RequestID: "request-1", Repository: "yaniv256/private", Operation: "issue.create"},
		{RequestID: "request-2", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "feature", Payload: map[string]any{"base": 7}},
	} {
		if _, err := executor.Execute(request); err == nil {
			t.Fatalf("request unexpectedly accepted: %#v", request)
		}
	}
}

func TestExecutorReportsUnknownWhenIndependentReadFails(t *testing.T) {
	api := &pullRequestAPI{verifyErr: errors.New("read failed")}
	result, err := githubapp.NewExecutor(api).Reconcile(worker.Request{RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "feature", ActorMode: "app_installation", Payload: map[string]any{"head_sha": "abc123"}})
	if err == nil || result.State != worker.ReconciliationUnknown {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
}
