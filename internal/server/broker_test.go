package server_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/approval"
	"github.com/yaniv256/gitoversight.dev/internal/audit"
	"github.com/yaniv256/gitoversight.dev/internal/mutation"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
)

type failingRecorder struct{}

func (failingRecorder) Append(audit.Event) (audit.Event, error) {
	return audit.Event{}, errors.New("disk unavailable")
}

func brokerForTest(t *testing.T) (*server.Broker, *approval.Store) {
	t.Helper()
	j, err := audit.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	approvals := approval.NewStore()
	b := server.New(policy.Snapshot{
		Generation: 1,
		Agents: map[string]policy.Agent{
			"zara": {UID: 1002, FirstName: "Zara", Emails: []string{"zara@example.com"}},
		},
		Repositories: map[string]policy.Repository{
			"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}},
			"yaniv256/public":  {Visibility: "public", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
		},
	}, approvals, j, time.Minute)
	return b, approvals
}

func TestBrokerIgnoresCallerClaimAndUsesAuthenticatedCaller(t *testing.T) {
	t.Parallel()
	b, _ := brokerForTest(t)
	result := b.Authorize("zara", server.MutationRequest{
		RequestID: "request-1", CallerClaim: "elena", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature",
	}, "", time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC))
	if result.Code != policy.Allowed || result.Caller != "zara" || result.Capability == "" || result.ActorMode != "app_installation" || result.ActorSubject != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestBrokerRejectsReplay(t *testing.T) {
	t.Parallel()
	b, _ := brokerForTest(t)
	req := server.MutationRequest{RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature"}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	if got := b.Authorize("zara", req, "", now); got.Code != policy.Allowed {
		t.Fatalf("first = %#v", got)
	}
	if got := b.Authorize("zara", req, "", now); got.Code != server.ReplayDenied {
		t.Fatalf("replay = %#v", got)
	}
}

func TestBrokerRejectsReplayAfterRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1002, FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}}}
	req := server.MutationRequest{RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature"}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	if got := server.New(snapshot, approval.NewStore(), j, time.Minute).Authorize("zara", req, "", now); got.Code != policy.Allowed {
		t.Fatalf("first = %#v", got)
	}
	reopened, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := server.New(snapshot, approval.NewStore(), reopened, time.Minute).Authorize("zara", req, "", now); got.Code != server.ReplayDenied {
		t.Fatalf("after restart = %#v", got)
	}
}

func TestPublicMutationNeedsExactApproval(t *testing.T) {
	t.Parallel()
	b, approvals := brokerForTest(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	req := server.MutationRequest{RequestID: "request-1", Repository: "yaniv256/public", Operation: "pull_request.create", Branch: "export"}
	if got := b.Authorize("zara", req, "manifest", now); got.Code != policy.ApprovalRequired {
		t.Fatalf("without approval = %#v", got)
	}
	if err := approvals.Put(approval.Packet{ID: "approval-1", ManifestHash: "manifest", Repository: "yaniv256/public", Operations: []string{"pull_request.create"}, Approver: "yaniv", Nonce: "0123456789abcdef", ExpiresAt: now.Add(time.Hour), PolicyGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	req.RequestID = "request-2"
	req.ApprovalID = "approval-1"
	if got := b.Authorize("zara", req, "manifest", now); got.Code != server.AllowedByApproval || got.Capability == "" || got.ActorMode != "human_user" || got.ActorSubject != "yaniv" {
		t.Fatalf("with approval = %#v", got)
	}
}

func TestPrepareApprovalAcceptsOnlyExactApprovalGatedMutation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	request := server.MutationRequest{RequestID: "expect-1", Repository: "yaniv256/public", Operation: "pull_request.create", Branch: "export"}

	t.Run("exact public request", func(t *testing.T) {
		b, _ := brokerForTest(t)
		packet, err := b.PrepareApproval("zara", request, "expect-1", "manifest", "approval-1", "yaniv", "abc123", now.Add(time.Hour), now)
		if err != nil || packet.Repository != request.Repository || packet.Nonce == "" || packet.PolicyGeneration != 1 {
			t.Fatalf("packet = %#v, err = %v", packet, err)
		}
	})

	for _, test := range []struct {
		name      string
		request   server.MutationRequest
		requestID string
		approver  string
		expires   time.Time
	}{
		{"mismatched request id", request, "other", "yaniv", now.Add(time.Hour)},
		{"unlisted approver", request, "expect-1", "other", now.Add(time.Hour)},
		{"excessive lifetime", request, "expect-1", "yaniv", now.Add(25 * time.Hour)},
		{"non-gated private operation", server.MutationRequest{RequestID: "expect-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature"}, "expect-1", "yaniv", now.Add(time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, _ := brokerForTest(t)
			if _, err := b.PrepareApproval("zara", test.request, test.requestID, "manifest", "approval-1", test.approver, "abc123", test.expires, now); err != server.ErrApprovalExpectation {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestCapabilityIsShortLivedAndSingleUse(t *testing.T) {
	t.Parallel()
	b, _ := brokerForTest(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	got := b.Authorize("zara", server.MutationRequest{RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature"}, "", now)
	binding, err := mutation.Hash(mutation.Packet{RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature", ActorMode: "app_installation"})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := b.ConsumeCapability(got.Capability, "yaniv256/private", "branch.push", binding, now.Add(30*time.Second))
	if err != nil || packet.RequestID != "request-1" {
		t.Fatalf("consume: %#v, %v", packet, err)
	}
	if _, err := b.ConsumeCapability(got.Capability, "yaniv256/private", "branch.push", binding, now.Add(31*time.Second)); err != server.ErrCapabilityConsumed {
		t.Fatalf("second consume = %v", err)
	}
}

func TestCapabilityRejectsChangedBranch(t *testing.T) {
	t.Parallel()
	b, _ := brokerForTest(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	got := b.Authorize("zara", server.MutationRequest{RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature"}, "", now)
	changed, err := mutation.Hash(mutation.Packet{RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "main", ActorMode: "app_installation"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ConsumeCapability(got.Capability, "yaniv256/private", "branch.push", changed, now); err != server.ErrCapabilityBinding {
		t.Fatalf("changed branch = %v", err)
	}
}

func TestAuditFailureIssuesNoCapability(t *testing.T) {
	t.Parallel()
	snapshot := policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1002, FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}}}
	b := server.New(snapshot, approval.NewStore(), failingRecorder{}, time.Minute)
	got := b.Authorize("zara", server.MutationRequest{RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature"}, "", time.Now())
	if got.Code != server.AuditUnavailable || got.Capability != "" {
		t.Fatalf("authorization = %#v", got)
	}
}

func TestReceiptStatusIsScopedToAuthenticatedCaller(t *testing.T) {
	t.Parallel()
	b, _ := brokerForTest(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	b.Authorize("zara", server.MutationRequest{RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature"}, "", now)
	events, err := b.Receipt("zara", "request-1")
	if err != nil || len(events) == 0 {
		t.Fatalf("events = %#v, err = %v", events, err)
	}
	if _, err := b.Receipt("tomas", "request-1"); err != server.ErrReceiptForbidden {
		t.Fatalf("cross-caller receipt = %v", err)
	}
}

func TestCapabilityRevocationReleasesUnexecutedApproval(t *testing.T) {
	t.Parallel()
	b, approvals := brokerForTest(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	if err := approvals.Put(approval.Packet{ID: "approval-1", ManifestHash: "manifest", Repository: "yaniv256/public", Operations: []string{"pull_request.create"}, Approver: "yaniv", Nonce: "0123456789abcdef", ExpiresAt: now.Add(time.Hour), PolicyGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	request := server.MutationRequest{RequestID: "request-1", Repository: "yaniv256/public", Operation: "pull_request.create", ApprovalID: "approval-1"}
	authorized := b.Authorize("zara", request, "manifest", now)
	if err := b.RevokeCapability("zara", authorized.Capability, now); err != nil {
		t.Fatal(err)
	}
	request.RequestID = "request-2"
	if got := b.Authorize("zara", request, "manifest", now); got.Code != server.AllowedByApproval {
		t.Fatalf("reuse after safe revocation = %#v", got)
	}
}

func TestOAuthBeginIsExactApproverBoundAndReplayResistant(t *testing.T) {
	b, _ := brokerForTest(t)
	now := time.Now()
	if err := b.BeginOAuth("zara", "oauth-1", "yaniv256/public", "yaniv", now); err != nil {
		t.Fatal(err)
	}
	if err := b.BeginOAuth("zara", "oauth-1", "yaniv256/public", "yaniv", now); err == nil {
		t.Fatal("oauth begin request replay was accepted")
	}
	if err := b.BeginOAuth("zara", "oauth-2", "yaniv256/public", "mallory", now); err == nil {
		t.Fatal("unlisted human approver was accepted")
	}
}

func TestStatusAndVerificationAreScopedAndJournalBacked(t *testing.T) {
	b, _ := brokerForTest(t)
	now := time.Now()
	authorization := b.Authorize("zara", server.MutationRequest{RequestID: "status-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature"}, "", now)
	if authorization.Capability == "" {
		t.Fatalf("authorization = %#v", authorization)
	}
	status, err := b.Status("zara", "status-1")
	if err != nil || status.RequestID != "status-1" || status.State != "authorized" {
		t.Fatalf("status = %#v, err = %v", status, err)
	}
	if err := b.VerifyReceipt("zara", "status-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Status("tomas", "status-1"); err == nil {
		t.Fatal("cross-agent status read was accepted")
	}
}
