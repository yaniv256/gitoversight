package githubapp_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

// livenessServer stands in for GitHub. It records every request so a test can
// assert what was NOT issued — the load-bearing assertion for a guard, since a
// refusal that still sent the mutation has refused nothing.
type livenessServer struct {
	pullState string
	merged    bool
	title     string
	body      string
	requests  []string
}

func (s *livenessServer) start(t *testing.T) *githubapp.Client {
	return s.startWithVisibility(t, "public")
}

func (s *livenessServer) startWithVisibility(t *testing.T, visibility string) *githubapp.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			merged := "false"
			if s.merged {
				merged = "true"
			}
			title, body := s.title, s.body
			if title == "" {
				title, body = "t", "b"
			}
			io.WriteString(w, `{"number":9,"state":"`+s.pullState+`","merged":`+merged+
				`,"merge_commit_sha":"msha","html_url":"https://github.test/pull/9","title":"`+title+`","body":"`+body+`"}`)
			return
		}
		io.WriteString(w, `{"id":1,"number":9,"html_url":"https://github.test/c/1","state":"`+s.pullState+`","title":"t","body":"b"}`)
	}))
	t.Cleanup(server.Close)
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	client, err := githubapp.New(server.URL, httpClient,
		func(githubapp.TokenMode, string) (string, error) { return "installation-token", nil },
		func(string) (string, error) { return visibility, nil })
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (s *livenessServer) mutated() bool {
	for _, request := range s.requests {
		if strings.HasPrefix(request, "PATCH") || strings.HasPrefix(request, "POST") || strings.HasPrefix(request, "PUT") {
			return true
		}
	}
	return false
}

func commentRequest(operation string) worker.Request {
	return worker.Request{
		RequestID: "live-1", Repository: "yaniv256/public", Operation: operation,
		Title: "New title", Body: "text <!-- gitoversight-request:live-1 -->",
		ActorMode: string(githubapp.HumanUser), ActorSubject: "yaniv",
		Payload: map[string]any{"number": float64(9), "head_sha": "abc1234", "event": "COMMENT", "merge_method": "squash"},
	}
}

// The defect: GitHub accepts a PATCH on a CLOSED pull request and returns 200,
// so the write lands somewhere nobody will ever merge — and reconciliation then
// re-reads it, sees the title matches, and reports success. Silence would be
// better; a confident-wrong success ends the investigation before it starts.
func TestGuardedOperationsRefuseAClosedPullRequest(t *testing.T) {
	t.Parallel()
	// Comments are NOT in this list. An update vanishes into a closed PR; a
	// comment is visible and wanting it is ordinary. See TestCommentsAreAllowed.
	for _, operation := range []string{"pull_request.update", "pull_request.review"} {
		server := &livenessServer{pullState: "closed"}
		client := server.start(t)
		executor := githubapp.NewExecutor(client)
		_, err := executor.Execute(commentRequest(operation))
		if err == nil {
			t.Fatalf("%s: executed against a closed pull request", operation)
		}
		// Pin WHY it refused. Asserting only "an error" would pass on a token
		// or payload failure that never reached the guard at all.
		if !strings.Contains(err.Error(), "closed") {
			t.Fatalf("%s: refused for the wrong reason: %v", operation, err)
		}
		if server.mutated() {
			t.Fatalf("%s: refused but STILL issued the mutation — %v", operation, server.requests)
		}
	}
}

// A merged pull request is equally unwritable for an UPDATE: the branch is in,
// so editing the proposal changes nothing anyone will act on.
func TestGuardedOperationsRefuseAMergedPullRequest(t *testing.T) {
	t.Parallel()
	server := &livenessServer{pullState: "closed", merged: true}
	client := server.start(t)
	_, err := githubapp.NewExecutor(client).Execute(commentRequest("pull_request.update"))
	if err == nil {
		t.Fatal("commented on a merged pull request")
	}
	if !strings.Contains(err.Error(), "merged") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if server.mutated() {
		t.Fatalf("refused but still issued the mutation — %v", server.requests)
	}
}

// Comments reach a pull request in EVERY state. This is the rule Yaniv stated
// and the first table got backwards: an update into a closed PR vanishes
// unnoticed, which is a GitHub misfeature worth closing, while a comment is
// visible and often exactly what someone needs — a reviewer closes the PR and
// you still want to explain, ask why, or link the replacement.
//
// Guarding comments made the system LESS useful than GitHub while claiming to
// reimplement it, and it contradicted this codebase's own pre-PR behaviour,
// where a closed pre-PR deliberately keeps its discussion thread (U8).
func TestCommentsAreAllowedOnClosedAndMergedPullRequests(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"issue.comment", "pull_request.reply"} {
		for _, state := range []struct {
			name   string
			server *livenessServer
		}{
			{"closed", &livenessServer{pullState: "closed"}},
			{"merged", &livenessServer{pullState: "closed", merged: true}},
			{"open", &livenessServer{pullState: "open"}},
		} {
			client := state.server.start(t)
			if _, err := githubapp.NewExecutor(client).Execute(commentRequest(operation)); err != nil {
				t.Fatalf("%s on a %s pull request was refused: %v", operation, state.name, err)
			}
			if !state.server.mutated() {
				t.Fatalf("%s on a %s pull request reported success without issuing the write", operation, state.name)
			}
		}
	}
}

// The guard must not break the ordinary path. Every refusal test above needs
// this twin, or "refuses everything" would pass them all.
func TestGuardedOperationsProceedOnAnOpenPullRequest(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"pull_request.update", "pull_request.review", "pull_request.reply", "issue.comment"} {
		server := &livenessServer{pullState: "open"}
		client := server.start(t)
		if _, err := githubapp.NewExecutor(client).Execute(commentRequest(operation)); err != nil {
			t.Fatalf("%s on an OPEN pull request failed: %v", operation, err)
		}
		if !server.mutated() {
			t.Fatalf("%s: no mutation issued for an open pull request — %v", operation, server.requests)
		}
	}
}

// KTD3's effect rule, and the case that settles what the rule IS.
//
// Closing an already-closed pull request is a correct idempotent no-op, so a
// blanket "refuse when not open" would BREAK a working operation. The rule this
// codebase adopts is "refuse a write that cannot achieve its intent": for close
// that means merged-only.
func TestCloseStaysIdempotentButRefusesAMergedPullRequest(t *testing.T) {
	t.Parallel()
	closeRequest := worker.Request{
		RequestID: "live-close", Repository: "yaniv256/public", Operation: "pull_request.close",
		ActorMode: string(githubapp.HumanUser), ActorSubject: "yaniv", Payload: map[string]any{"number": float64(9)},
	}
	alreadyClosed := &livenessServer{pullState: "closed"}
	if _, err := githubapp.NewExecutor(alreadyClosed.start(t)).Execute(closeRequest); err != nil {
		t.Fatalf("closing an already-closed pull request must stay a no-op success: %v", err)
	}
	merged := &livenessServer{pullState: "closed", merged: true}
	if _, err := githubapp.NewExecutor(merged.start(t)).Execute(closeRequest); err == nil {
		t.Fatal("closed a MERGED pull request — closing cannot achieve its intent there")
	}
	if merged.mutated() {
		t.Fatalf("refused but still issued the mutation — %v", merged.requests)
	}
}

// merge is MAPPED, not guarded. It already fails informatively via GitHub's own
// message, so a pre-flight read would only add an API call and a TOCTOU window
// between the read and the PUT. Asserting the absent GET is the point.
func TestMergeIssuesNoPreflightLivenessRead(t *testing.T) {
	t.Parallel()
	server := &livenessServer{pullState: "open"}
	client := server.start(t)
	mergeRequest := worker.Request{
		RequestID: "live-merge", Repository: "yaniv256/public", Operation: "pull_request.merge",
		ActorMode: string(githubapp.HumanUser), ActorSubject: "yaniv",
		Payload: map[string]any{"number": float64(9), "merge_method": "squash"},
	}
	_, _ = githubapp.NewExecutor(client).Execute(mergeRequest)
	for _, request := range server.requests {
		if strings.HasPrefix(request, "GET") {
			t.Fatalf("merge issued a pre-flight liveness read (%v) — it must map its own failure instead", server.requests)
		}
	}
}

// R5 — the refusal must not be undone by the reconciler.
//
// pull_request.update's reconciler compares the stored title and body against
// the live pull request. On a CLOSED pull request those match, because the
// update was refused and the values were never different — so without this the
// operation is blocked and then recorded as successful. That is the original
// defect wearing a different hat: the system confirming a write it did not make.
func TestRefusedOperationReconcilesAbsentNotPresent(t *testing.T) {
	t.Parallel()
	// The fixture must echo the REQUEST's title and body. With mismatched
	// values the reconciler returns absent for a content difference and the
	// test passes without the guard ever running — measuring a coincidence
	// instead of the rule. On a real closed pull request the values DO match,
	// because the update was refused and nothing changed.
	server := &livenessServer{pullState: "closed", title: "New title", body: "text <!-- gitoversight-request:live-1 -->"}
	client := server.start(t)
	result, err := githubapp.NewExecutor(client).Reconcile(commentRequest("pull_request.update"))
	if err != nil {
		t.Fatalf("reconcile returned an error rather than a verdict: %v", err)
	}
	if result.State == worker.ReconciliationCommitted {
		t.Fatal("a REFUSED update reconciled as present — the guard is undone one layer down")
	}
	if result.State != worker.ReconciliationAbsent {
		t.Fatalf("reconciliation = %q, want absent", result.State)
	}
}

// The mirror of the above: an indeterminate liveness read is a statement about
// our instrument, not the pull request, so it must reconcile UNKNOWN
// (retryable) — never Absent, which is terminal and would permanently mark a
// live operation as never-happened.
func TestIndeterminateLivenessReconcilesUnknownNotAbsent(t *testing.T) {
	t.Parallel()
	// An empty `state` is what a payload without the field looks like: the read
	// succeeded but could not decide.
	server := &livenessServer{pullState: ""}
	client := server.start(t)
	result, _ := githubapp.NewExecutor(client).Reconcile(commentRequest("pull_request.update"))
	if result.State == worker.ReconciliationAbsent {
		t.Fatal("an indeterminate read reconciled ABSENT — a transient blip would become terminal")
	}
	if result.State != worker.ReconciliationUnknown {
		t.Fatalf("reconciliation = %q, want unknown (retryable)", result.State)
	}
}

// The guard is scoped to PUBLIC repositories, and that scoping is a decision,
// not an accident — so it is pinned.
//
// The harm is a write landing unread on someone else's public pull request
// while we report success; on a not-owned repo it is visible to a third party
// and cannot be quietly undone. A private mirror is cheap to notice and cheap
// to redo, so charging every private mutation an extra GitHub read is the wrong
// trade. Removing the scope regresses TestApprovedPrivateOperationAdapters...
// which is how this was found.
func TestLivenessGuardDoesNotChargePrivateRepositories(t *testing.T) {
	t.Parallel()
	server := &livenessServer{pullState: "closed"}
	privateClient := server.startWithVisibility(t, "private")
	if _, err := githubapp.NewExecutor(privateClient).Execute(commentRequest("issue.comment")); err != nil {
		t.Fatalf("a private-repo comment was refused by the public-only guard: %v", err)
	}
	for _, request := range server.requests {
		if strings.HasPrefix(request, "GET") {
			t.Fatalf("the guard issued a liveness read against a PRIVATE repository — %v", server.requests)
		}
	}
}
