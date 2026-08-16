package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type fakeAuthority struct {
	submitted      []server.DurableOperationRequest
	approved       []server.DurableApprovalRequest
	executed       []string
	reconciled     []string
	failStage      string
	resource       string
	reconcileState server.DurableState
}

// Reconcile makes fakeAuthority an OperationReconciler. With reconcileState
// unset it fails (preserving pre-fallback failure tests); set it to a durable
// state to simulate an independent reconcile outcome.
func (f *fakeAuthority) Reconcile(_ context.Context, _ server.DurableIdentity, operationID string) (server.DurableResult, error) {
	f.reconciled = append(f.reconciled, operationID)
	if f.reconcileState == "" {
		return server.DurableResult{ID: operationID}, fmt.Errorf("no reconciliation available")
	}
	return server.DurableResult{ID: operationID, State: f.reconcileState, ResourceID: f.resource}, nil
}

func (f *fakeAuthority) Submit(_ context.Context, _ server.DurableIdentity, request server.DurableOperationRequest) (server.DurableResult, error) {
	f.submitted = append(f.submitted, request)
	if f.failStage == "submit" {
		return server.DurableResult{ID: request.ID, State: server.DurableDenied, Reason: "denied"}, nil
	}
	return server.DurableResult{ID: request.ID, State: server.DurableAwaitingApproval, PacketHash: "packet-" + request.ID}, nil
}

func (f *fakeAuthority) Approve(_ context.Context, request server.DurableApprovalRequest) (server.DurableResult, error) {
	f.approved = append(f.approved, request)
	return server.DurableResult{ID: request.OperationID, State: server.DurableAuthorized}, nil
}

func (f *fakeAuthority) Execute(_ context.Context, _ server.DurableIdentity, operationID string) (server.DurableResult, error) {
	f.executed = append(f.executed, operationID)
	if f.failStage == "execute" && strings.HasSuffix(operationID, "-pr") {
		return server.DurableResult{ID: operationID, State: server.DurableIndeterminate, Reason: "worker failed"}, nil
	}
	return server.DurableResult{ID: operationID, State: server.DurableVerified, ResourceID: f.resource}, nil
}

// fakePullState replaces a `{merged bool}` fake that could not express "closed
// without merging" — which is exactly why TestDoneRequiresRealMerge passed for
// weeks against a Done gate that stranded every closed pull request. A fake
// narrower than reality makes the missing case untestable, not merely untested.
type fakePullState struct {
	outcome githubapp.PullOutcome
	sha     string
	err     error
}

func (f *fakePullState) PullState(context.Context, string, string, int64) (githubapp.PullState, error) {
	if f.err != nil {
		return githubapp.PullState{Outcome: githubapp.PullOutcomeIndeterminate}, f.err
	}
	outcome := f.outcome
	if outcome == "" {
		outcome = githubapp.PullOutcomeOpen
	}
	return githubapp.PullState{Outcome: outcome, MergeSHA: f.sha}, nil
}

func humanSyncDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "human.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.EnsureTenant(context.Background(), "default", time.Unix(1_700_000_000, 0).UTC())
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return db
}

func seedProposal(t *testing.T, db *sqlite.DB, id string) sqlite.SyncRequest {
	t.Helper()
	req := sqlite.SyncRequest{
		TenantID: "default", ID: id,
		PrivateRepository: "yaniv256/mirror.dev", PublicRepository: "yaniv256/mirror",
		ProposalText: "Release the rules\n\nDetails.", FileManifest: []string{"SKILL.md"},
		CommitPacketJSON: `{"sha":"abc123","commit":{"sha":"abc123"}}`, PacketHeadSHA: "abc123",
		CreatedBy: "zara",
	}
	if err := db.CreateSyncProposal(context.Background(), req, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return req
}

func humanPolicy() policy.Snapshot {
	return policy.Snapshot{Generation: 1, QueueCurator: "zara",
		Agents: map[string]policy.Agent{"zara": {UID: 1002, FirstName: "Zara"}}}
}

func humanPost(path, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	return request.WithContext(WithHumanApprover(request.Context(), HumanApprover{TenantID: "default", ID: "yaniv"}))
}

func TestAuthorizeRunsFullChain(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	req := seedProposal(t, db, "s1")
	authority := &fakeAuthority{resource: "pull_request:41"}
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: authority, Executor: authority})
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s1/authorize", `{"packet_hash":"`+hash+`"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("authorize = %d body=%s", response.Code, response.Body.String())
	}
	if len(authority.submitted) != 2 || authority.submitted[0].Operation != "branch.push" || authority.submitted[1].Operation != "pull_request.create" {
		t.Fatalf("submitted = %+v", authority.submitted)
	}
	if authority.submitted[0].Branch != "sync/"+shortSHA(hash) || strings.Contains(authority.submitted[0].Branch, req.CreatedBy) {
		t.Fatalf("public branch = %q, want content-derived branch without private agent attribution", authority.submitted[0].Branch)
	}
	if authority.submitted[1].Body != req.ProposalText {
		t.Fatalf("public PR body = %q, want authorized text", authority.submitted[1].Body)
	}
	if len(authority.approved) != 2 || authority.approved[0].PacketHash != "packet-s1-push" {
		t.Fatalf("approvals did not bind submit packet hash: %+v", authority.approved)
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "s1")
	if got.State != "public_pr_created" || got.PublicPRNumber != 41 {
		t.Fatalf("state=%q pr=%d", got.State, got.PublicPRNumber)
	}
}

func TestAuthorizeStaleHashRejected(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	seedProposal(t, db, "s2")
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: &fakeAuthority{}, Executor: &fakeAuthority{}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s2/authorize", `{"packet_hash":"stale"}`))
	if response.Code != http.StatusConflict {
		t.Fatalf("stale hash = %d", response.Code)
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "s2")
	if got.State != "proposed" {
		t.Fatalf("state = %q, want proposed", got.State)
	}
}

func TestAuthorizePublishFailureStaysAuthorized(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	req := seedProposal(t, db, "s3")
	authority := &fakeAuthority{failStage: "execute", resource: "pull/7"}
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: authority, Executor: authority})
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s3/authorize", `{"packet_hash":"`+hash+`"}`))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("failed publish = %d body=%s", response.Code, response.Body.String())
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "s3")
	if got.State != "authorized" {
		t.Fatalf("state = %q, want authorized (retryable)", got.State)
	}
}

func TestDoneRequiresRealMerge(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	req := seedProposal(t, db, "s4")
	authority := &fakeAuthority{resource: "pull/9"}
	merges := &fakePullState{outcome: githubapp.PullOutcomeOpen}
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: authority, Executor: authority, Merges: merges})
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	auth := httptest.NewRecorder()
	handler.ServeHTTP(auth, humanPost("/v1/human/sync/s4/authorize", `{"packet_hash":"`+hash+`"}`))
	if auth.Code != http.StatusOK {
		t.Fatalf("authorize = %d", auth.Code)
	}
	// unmerged → 409
	unmerged := httptest.NewRecorder()
	handler.ServeHTTP(unmerged, humanPost("/v1/human/sync/s4/done", `{}`))
	if unmerged.Code != http.StatusConflict {
		t.Fatalf("unmerged done = %d", unmerged.Code)
	}
	// merged → done with SHA
	merges.outcome, merges.sha = githubapp.PullOutcomeMerged, "mergesha1"
	done := httptest.NewRecorder()
	handler.ServeHTTP(done, humanPost("/v1/human/sync/s4/done", `{}`))
	if done.Code != http.StatusOK {
		t.Fatalf("done = %d body=%s", done.Code, done.Body.String())
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "s4")
	if got.State != "done" {
		t.Fatalf("state = %q, want done", got.State)
	}
}

func TestRequestChangesTransitions(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	seedProposal(t, db, "s5")
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: &fakeAuthority{}, Executor: &fakeAuthority{}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s5/request-changes", `{"note":"tighten the text"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("request-changes = %d body=%s", response.Code, response.Body.String())
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "s5")
	if got.State != "changes_requested" {
		t.Fatalf("state = %q", got.State)
	}
}

func TestHumanEndpointsRequireHumanSession(t *testing.T) {
	t.Parallel()
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: humanSyncDB(t), Broker: &fakeAuthority{}, Executor: &fakeAuthority{}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/human/sync/s1/authorize", strings.NewReader(`{"packet_hash":"x"}`)))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("no session = %d", response.Code)
	}
}

func TestParsePRNumberFormats(t *testing.T) {
	t.Parallel()
	// pull_request:41 is the REAL format the worker's reconciler emits
	// (githubapp executor: fmt.Sprintf("pull_request:%d", result.Number)).
	for input, want := range map[string]int64{
		"pull_request:41": 41,
		"pull/9":          9,
		"#7":              7,
		"12":              12,
		"garbage":         0,
	} {
		if got := parsePRNumber(input); got != want {
			t.Fatalf("parsePRNumber(%q) = %d, want %d", input, got, want)
		}
	}
}

// TestAuthorizeResumesStrandedPublishViaReconcile reproduces the
// agent-kanban-wip-limit incident (2026-07-24): the push executed on GitHub
// but its immediate read-back parked indeterminate, the coordinator gave up,
// and the sync stranded at "authorized" with the human's retry tap drawing
// authorization_stale. The fix: re-authorize is idempotent, and a failed chain
// falls back to an independent reconcile whose VERIFIED outcome resumes the
// publish.
func TestAuthorizeResumesStrandedPublishViaReconcile(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	req := seedProposal(t, db, "s9")
	authority := &fakeAuthority{failStage: "execute", resource: "pull_request:77"}
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: authority, Executor: authority})
	handler.reconcileDelay = time.Millisecond
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)

	// First tap: publish fails (PR execute indeterminate, reconcile unavailable)
	// and the sync strands at authorized — the incident state.
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s9/authorize", `{"packet_hash":"`+hash+`"}`))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("first tap = %d body=%s", response.Code, response.Body.String())
	}
	if got, _ := db.GetSyncRequest(context.Background(), "default", "s9"); got.State != "authorized" {
		t.Fatalf("state after failure = %q, want authorized", got.State)
	}

	// Retry tap: the re-authorize must NOT be rejected as stale, and the
	// reconcile fallback (now answering verified) must complete the publish.
	authority.reconcileState = server.DurableVerified
	retry := httptest.NewRecorder()
	handler.ServeHTTP(retry, humanPost("/v1/human/sync/s9/authorize", `{"packet_hash":"`+hash+`"}`))
	if retry.Code != http.StatusOK {
		t.Fatalf("retry tap = %d body=%s", retry.Code, retry.Body.String())
	}
	if len(authority.reconciled) == 0 {
		t.Fatal("reconcile fallback never ran")
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "s9")
	if got.State != "public_pr_created" || got.PublicPRNumber != 77 {
		t.Fatalf("state=%q pr=%d, want public_pr_created/77", got.State, got.PublicPRNumber)
	}
}

// A reconcile that truthfully finds the object ABSENT must not be treated as
// success — the publish fails honestly.
func TestAuthorizeReconcileAbsentIsNotSuccess(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	req := seedProposal(t, db, "s10")
	authority := &fakeAuthority{failStage: "execute", resource: "pull_request:5", reconcileState: server.DurableAbsent}
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: authority, Executor: authority})
	handler.reconcileDelay = time.Millisecond
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s10/authorize", `{"packet_hash":"`+hash+`"}`))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("absent reconcile = %d body=%s", response.Code, response.Body.String())
	}
	if got, _ := db.GetSyncRequest(context.Background(), "default", "s10"); got.State != "authorized" {
		t.Fatalf("state = %q, want authorized (retryable)", got.State)
	}
}

// staleBases returns a base tree SHA the caller chooses, so a test can simulate
// the public repository moving between review and approval.
type staleBases struct {
	treeSHA string
	err     error
}

func (b staleBases) ReadBase(workerrpc.BaseReadRequest) (workerrpc.BaseRead, error) {
	if b.err != nil {
		return workerrpc.BaseRead{}, b.err
	}
	return workerrpc.BaseRead{CommitSHA: "3333333333333333333333333333333333333333", TreeSHA: b.treeSHA}, nil
}

// seedRebasedProposal stores a proposal whose packet was rebased onto a known
// public tree, so the authorization-time base check has something to compare.
func seedRebasedProposal(t *testing.T, db *sqlite.DB, id, baseTree string) sqlite.SyncRequest {
	t.Helper()
	content := "# Skill\n"
	blobSHA := "50860bb5e14f44f3916a2b1f2976f009c1580b65"
	packet := map[string]any{
		"blobs": []map[string]any{{"sha": blobSHA, "content": "IyBTa2lsbAo=", "encoding": "base64"}},
		"tree": map[string]any{"sha": "9ff4fc377ca2fdf571913c2f2abeb30655ea91a8", "base_tree": baseTree,
			"entries": []map[string]any{{"path": "SKILL.md", "mode": "100644", "type": "blob", "sha": blobSHA}}},
		"commit": map[string]any{"sha": "68d273daa52639af3825a0e4c2d0a5ab82bd40a0", "message": "Release\n",
			"tree": "9ff4fc377ca2fdf571913c2f2abeb30655ea91a8", "parents": []string{},
			"author":    map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2023-11-14T22:13:20Z"},
			"committer": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2023-11-14T22:13:20Z"}},
	}
	encoded, err := json.Marshal(map[string]any{"sha": "68d273daa52639af3825a0e4c2d0a5ab82bd40a0", "object_package": packet})
	if err != nil {
		t.Fatal(err)
	}
	_ = content
	req := sqlite.SyncRequest{TenantID: "default", ID: id,
		PrivateRepository: "yaniv256/mirror.dev", PublicRepository: "yaniv256/mirror",
		ProposalText: "Release\n\nDetails.", FileManifest: []string{"SKILL.md"},
		CommitPacketJSON: string(encoded), PacketHeadSHA: "68d273daa52639af3825a0e4c2d0a5ab82bd40a0",
		CreatedBy: "zara"}
	if err := db.CreateSyncProposal(context.Background(), req, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, _ := db.GetSyncRequest(context.Background(), "default", id)
	return out
}

// If the public repository moved between review and approval, the diff the
// human read is not the diff that would publish. Authorization must refuse.
func TestAuthorizeRefusesWhenThePublicBaseMoved(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	reviewedBase := "2222222222222222222222222222222222222222"
	sync := seedRebasedProposal(t, db, "s-moved", reviewedBase)
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{
		Policy: humanPolicy(), Store: db, Broker: &fakeAuthority{resource: "pull_request:41"}, Executor: &fakeAuthority{resource: "pull_request:41"},
		Bases: staleBases{treeSHA: "9999999999999999999999999999999999999999"},
	})
	response := httptest.NewRecorder()
	body := `{"packet_hash":"` + sync.ProposalHash + `"}`
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s-moved/authorize", body))

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 when the base moved", response.Code)
	}
	if !strings.Contains(response.Body.String(), "base_moved") {
		t.Fatalf("body = %s, want base_moved", response.Body.String())
	}
	// The proposal must NOT have advanced: a refused authorization leaves it
	// reviewable, so the agent can resubmit against the current base.
	after, _ := db.GetSyncRequest(context.Background(), "default", "s-moved")
	if after.State != "proposed" {
		t.Fatalf("state = %q, want proposed — a refused authorization must not advance", after.State)
	}
}

// An unchanged base authorizes normally: the check must not block the ordinary
// path, or reviewers learn to route around it.
func TestAuthorizeProceedsWhenTheBaseIsUnchanged(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	reviewedBase := "2222222222222222222222222222222222222222"
	sync := seedRebasedProposal(t, db, "s-current", reviewedBase)
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{
		Policy: humanPolicy(), Store: db, Broker: &fakeAuthority{resource: "pull_request:41"}, Executor: &fakeAuthority{resource: "pull_request:41"},
		Bases: staleBases{treeSHA: reviewedBase},
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s-current/authorize",
		`{"packet_hash":"`+sync.ProposalHash+`"}`))
	if response.Code == http.StatusConflict && strings.Contains(response.Body.String(), "base_moved") {
		t.Fatalf("an unchanged base must not be refused: %s", response.Body.String())
	}
}

// An unreadable base fails CLOSED. It cannot prove the reviewed diff is still
// current, and authorizing on an unproven base is the failure this prevents.
func TestAuthorizeFailsClosedWhenTheBaseCannotBeRead(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	sync := seedRebasedProposal(t, db, "s-unreadable", "2222222222222222222222222222222222222222")
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{
		Policy: humanPolicy(), Store: db, Broker: &fakeAuthority{resource: "pull_request:41"}, Executor: &fakeAuthority{resource: "pull_request:41"},
		Bases: staleBases{err: errors.New("github unreachable")},
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s-unreadable/authorize",
		`{"packet_hash":"`+sync.ProposalHash+`"}`))
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 — an unreadable base must fail closed", response.Code)
	}
}

// The defect this whole track exists to fix: a closed-unmerged PR left the sync
// in public_pr_created forever behind a Done button that returned 409 on every
// tap — a control offered to a human that could never succeed.
func TestDoneAbandonsWhenThePublicPRWasClosedUnmerged(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	req := seedProposal(t, db, "s-abandon")
	authority := &fakeAuthority{resource: "pull/42"}
	merges := &fakePullState{outcome: githubapp.PullOutcomeClosedUnmerged}
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: authority, Executor: authority, Merges: merges})
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	auth := httptest.NewRecorder()
	handler.ServeHTTP(auth, humanPost("/v1/human/sync/s-abandon/authorize", `{"packet_hash":"`+hash+`"}`))
	if auth.Code != http.StatusOK {
		t.Fatalf("authorize = %d", auth.Code)
	}
	done := httptest.NewRecorder()
	handler.ServeHTTP(done, humanPost("/v1/human/sync/s-abandon/done", `{}`))
	if done.Code != http.StatusOK {
		t.Fatalf("done on a closed-unmerged PR = %d body=%s", done.Code, done.Body.String())
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "s-abandon")
	if got.State != "abandoned" {
		t.Fatalf("state = %q, want abandoned", got.State)
	}
	// R2: the row must stop being reported as awaiting merge in EVERY view,
	// including list filters that select by negation.
	open, err := db.ListOpenSyncRequests(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range open {
		if item.ID == "s-abandon" {
			t.Fatal("an abandoned sync is still listed as open — the negation filter still selects it")
		}
	}
}

// KTD1a: an indeterminate read must NEVER produce a terminal transition. A
// lagging or failed read that abandoned a genuinely merged pull request would be
// irreversible, and strictly worse than the bug being fixed.
func TestDoneNeverTransitionsOnAnIndeterminateRead(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	req := seedProposal(t, db, "s-unknown")
	authority := &fakeAuthority{resource: "pull/43"}
	merges := &fakePullState{outcome: githubapp.PullOutcomeIndeterminate}
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: authority, Executor: authority, Merges: merges})
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	auth := httptest.NewRecorder()
	handler.ServeHTTP(auth, humanPost("/v1/human/sync/s-unknown/authorize", `{"packet_hash":"`+hash+`"}`))
	if auth.Code != http.StatusOK {
		t.Fatalf("authorize = %d", auth.Code)
	}
	done := httptest.NewRecorder()
	handler.ServeHTTP(done, humanPost("/v1/human/sync/s-unknown/done", `{}`))
	if done.Code != http.StatusServiceUnavailable {
		t.Fatalf("indeterminate done = %d, want 503 (retryable), not a verdict", done.Code)
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "s-unknown")
	if got.State != "public_pr_created" {
		t.Fatalf("state = %q — an indeterminate read moved the sync", got.State)
	}
}

// Open and closed used to collapse into the same 409 "not merged". They are
// different situations with different recoveries, so they get different codes.
func TestDoneOnAnOpenPRIsRetryableAndDistinctFromClosed(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	req := seedProposal(t, db, "s-open")
	authority := &fakeAuthority{resource: "pull/44"}
	merges := &fakePullState{outcome: githubapp.PullOutcomeOpen}
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: authority, Executor: authority, Merges: merges})
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	auth := httptest.NewRecorder()
	handler.ServeHTTP(auth, humanPost("/v1/human/sync/s-open/authorize", `{"packet_hash":"`+hash+`"}`))
	if auth.Code != http.StatusOK {
		t.Fatalf("authorize = %d", auth.Code)
	}
	done := httptest.NewRecorder()
	handler.ServeHTTP(done, humanPost("/v1/human/sync/s-open/done", `{}`))
	if done.Code != http.StatusConflict {
		t.Fatalf("open done = %d", done.Code)
	}
	if !strings.Contains(done.Body.String(), "public_pr_still_open") {
		t.Fatalf("open PR reported as %q — must not reuse the closed vocabulary", done.Body.String())
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "s-open")
	if got.State != "public_pr_created" {
		t.Fatalf("state = %q, want public_pr_created (retryable)", got.State)
	}
}

// A human's comment must be attributed to the authenticated approver and never
// to anything the request body claims — otherwise an agent could post words
// carrying a human's authority, and the reviewer would weigh a publication on
// text nobody wrote.
func TestHumanCommentIsAttributedToTheAuthenticatedApprover(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	seedProposal(t, db, "s-comment")
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db})

	created := httptest.NewRecorder()
	handler.ServeHTTP(created, humanPost("/v1/human/sync/s-comment/comment", `{"body":"Looks right to me."}`))
	if created.Code != http.StatusCreated {
		t.Fatalf("comment = %d body=%s", created.Code, created.Body.String())
	}
	thread, err := db.SyncCommentsFor(context.Background(), "default", sqlite.SyncCommentSubjectSync, "s-comment")
	if err != nil {
		t.Fatal(err)
	}
	if len(thread) != 1 || thread[0].AuthorKind != sqlite.CommentAuthorHuman || thread[0].AuthorID != "yaniv" {
		t.Fatalf("comment misattributed: %+v", thread)
	}

	// An attempt to supply the author is rejected outright by
	// DisallowUnknownFields rather than silently ignored.
	spoofed := httptest.NewRecorder()
	handler.ServeHTTP(spoofed, humanPost("/v1/human/sync/s-comment/comment",
		`{"body":"as yaniv","author_id":"mallory","author_kind":"human"}`))
	if spoofed.Code != http.StatusBadRequest {
		t.Fatalf("a body carrying author fields was accepted: %d", spoofed.Code)
	}
}

// Commenting must not move the sync. A discussion surface that mutated
// lifecycle state would make every comment a governance action.
func TestCommentingDoesNotChangeSyncState(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	seedProposal(t, db, "s-nostate")
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db})
	before, _ := db.GetSyncRequest(context.Background(), "default", "s-nostate")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s-nostate/comment", `{"body":"a note"}`))
	if response.Code != http.StatusCreated {
		t.Fatalf("comment = %d", response.Code)
	}
	after, _ := db.GetSyncRequest(context.Background(), "default", "s-nostate")
	if before.State != after.State {
		t.Fatalf("commenting moved the sync from %q to %q", before.State, after.State)
	}
}

// Commenting on a sync that does not exist is a 404, not a silently stored row
// pointing at nothing.
func TestCommentOnMissingSyncIsRefused(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/no-such-sync/comment", `{"body":"hello"}`))
	if response.Code != http.StatusNotFound {
		t.Fatalf("comment on a missing sync = %d, want 404", response.Code)
	}
}

// app.js wraps EVERY typed field as {"note": ...} — one convention for every
// data-body-id control. The comment handler read only {"body": ...}, so with
// DisallowUnknownFields the browser's payload was rejected outright: the button
// resolved, clicked, and could never succeed.
//
// Found by clicking Comment on the deployed page (400 invalid_comment). No API
// test could see it — they post the Go-shaped body directly and never exercise
// the script that builds the real one. The seam between template and JS is
// where handler tests stop.
func TestCommentAcceptsTheBodyShapeTheBrowserActuallySends(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	seedProposal(t, db, "s-jsonshape")
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db})

	// The exact shape app.js emits for a textarea.
	browser := httptest.NewRecorder()
	handler.ServeHTTP(browser, humanPost("/v1/human/sync/s-jsonshape/comment", `{"note":"typed in the browser"}`))
	if browser.Code != http.StatusCreated {
		t.Fatalf("the browser's own payload was rejected: %d body=%s", browser.Code, browser.Body.String())
	}
	thread, err := db.SyncCommentsFor(context.Background(), "default", sqlite.SyncCommentSubjectSync, "s-jsonshape")
	if err != nil {
		t.Fatal(err)
	}
	if len(thread) != 1 || thread[0].Body != "typed in the browser" {
		t.Fatalf("comment body lost in translation: %+v", thread)
	}
}

// A push that already succeeded must be SKIPPED on retry, not re-submitted.
//
// The publication of 302 files outran GitHub's read replica: the immediate
// reconcile said "absent", KTD1a correctly parked the operation indeterminate
// rather than calling a negative read terminal, and the chain treated "cannot
// confirm yet" as "failed" — aborting before the pull request existed.
//
// Retrying then hit the replay guard: "operation id was already submitted".
// That guard is CORRECT — re-submitting an executed public write is exactly
// what it prevents. The defect was asking to re-run a completed step at all.
//
// Live 2026-07-27: branch pushed with all 302 files, push reconciled VERIFIED,
// no pull request, and every retry denied. Publication was complete except for
// its final step and unreachable by any route the reviewer had.
func TestAuthorizeResumesPastAnAlreadyVerifiedPush(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	req := seedProposal(t, db, "s-resume")
	// Seed a REAL verified push operation. The earlier version of this test
	// stubbed the reconciler instead, which is why it passed against a check
	// that consulted the wrong source: production reads the operation's stored
	// state, and Reconcile REFUSES a verified operation ("not indeterminate").
	// A fixture that fakes the probe cannot detect the probe being wrong.
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		if err := tx.EnsureAgent(context.Background(), "default", "zara", time.Unix(1_800_000_000, 0)); err != nil {
			return err
		}
		return tx.PutOperation(context.Background(), storage.Operation{
			TenantID: "default", ID: "s-resume-push", AgentID: "zara",
			Repository: "yaniv256/mirror", Kind: "branch.push", PacketHash: "seeded-resume-packet",
			State: string(server.DurableVerified), PolicyGeneration: 1,
			CreatedAt: time.Unix(1_800_000_000, 0), ExpiresAt: time.Unix(1_900_000_000, 0),
			UpdatedAt: time.Unix(1_800_000_000, 0),
		})
	}); err != nil {
		t.Fatalf("seed verified push: %v", err)
	}
	authority := &fakeAuthority{resource: "pull_request:77"}
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: authority, Executor: authority})
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s-resume/authorize", `{"packet_hash":"`+hash+`"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("authorize = %d body=%s", response.Code, response.Body.String())
	}
	for _, submitted := range authority.submitted {
		if submitted.Operation == "branch.push" {
			t.Fatal("re-submitted a push that had already been verified — the replay guard will deny this and publication stalls one step from done")
		}
	}
	if len(authority.submitted) != 1 || authority.submitted[0].Operation != "pull_request.create" {
		t.Fatalf("expected the chain to resume at pull_request.create, submitted = %+v", authority.submitted)
	}
}

func TestAuthorizeRetriesTerminalDeniedPushWithFreshOperationID(t *testing.T) {
	t.Parallel()
	db := humanSyncDB(t)
	req := seedProposal(t, db, "s-denied-retry")
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		if err := tx.EnsureAgent(context.Background(), "default", "zara", time.Unix(1_800_000_000, 0)); err != nil {
			return err
		}
		return tx.PutOperation(context.Background(), storage.Operation{
			TenantID: "default", ID: "s-denied-retry-push", AgentID: "zara",
			Repository: "yaniv256/mirror", Kind: "branch.push", PacketHash: "denied-packet",
			State: string(server.DurableDenied), PolicyGeneration: 1, Reason: "policy defect",
			CreatedAt: time.Unix(1_800_000_000, 0), ExpiresAt: time.Unix(1_900_000_000, 0),
			UpdatedAt: time.Unix(1_800_000_000, 0),
		})
	}); err != nil {
		t.Fatalf("seed denied push: %v", err)
	}
	authority := &fakeAuthority{resource: "pull_request:78"}
	handler := NewSyncHumanHandler(SyncHumanHandlerConfig{Policy: humanPolicy(), Store: db, Broker: authority, Executor: authority})
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/sync/s-denied-retry/authorize", `{"packet_hash":"`+hash+`"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("authorize = %d body=%s", response.Code, response.Body.String())
	}
	if len(authority.submitted) != 2 || authority.submitted[0].ID != "s-denied-retry-push-retry-1" {
		t.Fatalf("submitted = %+v, want fresh retry push followed by PR", authority.submitted)
	}
}
