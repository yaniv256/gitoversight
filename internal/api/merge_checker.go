package api

import (
	"context"
	"fmt"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

// WorkerPullStateReader is the workerrpc surface the Done gate needs.
type WorkerPullStateReader interface {
	PullState(value worker.Request, number int64) (githubapp.PullState, error)
}

// WorkerPullStateChecker answers Done-gate verification through the privileged
// worker's single-PR read.
//
// It returns the pull request's whole resolved outcome rather than a boolean.
// The boolean was the defect: "closed without merging" and "not merged yet"
// collapsed into the same false, so a sync whose PR was closed unmerged was
// stranded forever behind a Done button that could never succeed.
type WorkerPullStateChecker struct {
	Worker WorkerPullStateReader
}

func (checker *WorkerPullStateChecker) PullState(_ context.Context, tenantID, repository string, number int64) (githubapp.PullState, error) {
	if checker.Worker == nil {
		// Unavailable is indeterminate, not a verdict: the caller must block
		// rather than conclude anything about the pull request.
		return githubapp.PullState{Outcome: githubapp.PullOutcomeIndeterminate}, fmt.Errorf("pull request verification unavailable")
	}
	return checker.Worker.PullState(worker.Request{
		RequestID: fmt.Sprintf("pull-state-%s-%d", tenantID, number), TenantID: tenantID,
		Repository: repository, Operation: "pull_request.list",
	}, number)
}
