package server

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type testDurableWriteGate struct{}

func (testDurableWriteGate) Verify() error                        { return nil }
func (testDurableWriteGate) Commit(context.Context, string) error { return nil }

func newTestDurableBroker(db *sqlite.DB) *DurableBroker {
	broker := NewDurableBroker(db)
	broker.SetWriteGate(testDurableWriteGate{})
	return broker
}

func TestDurableBrokerPreservesPolicyDecisionsAndReplayAcrossRestart(t *testing.T) {
	ctx := context.Background()
	db := openDurableDB(t)
	broker := newTestDurableBroker(db)
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}

	result, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, DurableOperationRequest{
		ID: "operation-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "refs/heads/feat/one", ManifestHash: "manifest-1", Payload: map[string]any{"sha": "abc123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != DurableAuthorized || result.Decision != policy.Allowed || result.ActorMode != ActorAppInstallation {
		t.Fatalf("unexpected private decision: %+v", result)
	}
	stored, err := broker.db.Operation(ctx, "tenant-a", "operation-1")
	if err != nil || stored.Branch != "feat/one" {
		t.Fatalf("stored branch = %q, err = %v", stored.Branch, err)
	}

	restarted := newTestDurableBroker(db)
	replay, err := restarted.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, DurableOperationRequest{
		ID: "operation-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feat/one", ManifestHash: "manifest-1", Payload: map[string]any{"sha": "abc123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if replay.State != DurableDenied || replay.Decision != ReplayDenied {
		t.Fatalf("replay = %+v", replay)
	}
	status, err := restarted.Status(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, "operation-1")
	if err != nil || status.State != DurableAuthorized {
		t.Fatalf("status = %+v, %v", status, err)
	}
	if _, err := restarted.Status(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "elena"}, "operation-1"); err == nil {
		t.Fatal("another agent read an operation it does not own")
	}
}

func TestDurableBrokerRejectsAmbiguousQualifiedRefBeforePersistence(t *testing.T) {
	ctx := context.Background()
	db := openDurableDB(t)
	broker := newTestDurableBroker(db)
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}

	_, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, DurableOperationRequest{
		ID: "ambiguous-ref", Repository: "yaniv256/private", Operation: "branch.push", Branch: "refs/heads/refs/heads/main", ManifestHash: "manifest", Payload: map[string]any{"sha": "abc123"},
	})
	if err == nil {
		t.Fatal("ambiguous qualified ref was accepted")
	}
	if _, err := broker.db.Operation(ctx, "tenant-a", "ambiguous-ref"); err == nil {
		t.Fatal("rejected ambiguous ref was persisted")
	}
}

func TestDurableBrokerPinsExactReadyReleaseAssetInSubmissionTransaction(t *testing.T) {
	ctx := context.Background()
	db := openDurableDB(t)
	broker := newTestDurableBroker(db)
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error {
		return tx.PutAgentCredential(ctx, storage.AgentCredential{
			TenantID: "tenant-a", AgentID: "zara", ID: "zara-1",
			PublicKey: make([]byte, 32), CreatedAt: now, ApprovedAt: now, ApprovedBy: "yaniv",
		})
	}); err != nil {
		t.Fatal(err)
	}
	stage := releaseasset.Stage{
		TenantID: "tenant-a", ID: "0123456789abcdef0123456789abcdef",
		AgentID: "zara", CredentialID: "zara-1", Repository: "yaniv256/private",
		Name: "bridge.zip", ContentType: "application/zip", ExpectedSHA256: strings.Repeat("a", 64),
		ExpectedSize: 42, ReservedSize: 42, State: releaseasset.StateCreated,
		CapabilityHash: strings.Repeat("b", 64), CapabilityExpiresAt: now.Add(time.Minute),
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := broker.CreateStagedAsset(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.BeginStagedAssetUpload(ctx, stage.TenantID, stage.ID, "temp", now.Add(time.Second)); err != nil {
			return err
		}
		return tx.MarkStagedAssetReady(ctx, stage.TenantID, stage.ID, "object", now.Add(2*time.Second))
	}); err != nil {
		t.Fatal(err)
	}
	request := DurableOperationRequest{
		ID: "asset-operation", Repository: stage.Repository, Operation: "release.asset.upload",
		ManifestHash: "asset-manifest", ApprovalID: "asset-approval", ApprovalNonce: "asset-nonce",
		ApprovalExpiresAt: now.Add(30 * time.Minute), Approver: "yaniv", HeadSHA: "release-v1",
		Payload: map[string]any{
			"tag_name": "v1", "name": stage.Name, "content_type": stage.ContentType,
			"asset": map[string]any{"stage_id": stage.ID, "sha256": stage.ExpectedSHA256, "size": float64(stage.ExpectedSize)},
		},
	}
	result, err := broker.Submit(ctx, DurableIdentity{
		TenantID: stage.TenantID, AgentID: stage.AgentID, CredentialID: stage.CredentialID,
	}, request)
	if err != nil || result.State != DurableAuthorized {
		t.Fatalf("submit = %+v, %v", result, err)
	}
	pinned, err := db.StagedAssetForOwner(ctx, stage.TenantID, stage.ID, stage.AgentID, stage.CredentialID, stage.Repository)
	if err != nil || pinned.State != releaseasset.StatePinned || pinned.OperationID != request.ID {
		t.Fatalf("pinned = %+v, %v", pinned, err)
	}

	other := stage
	other.ID = "fedcba9876543210fedcba9876543210"
	other.CapabilityHash = strings.Repeat("c", 64)
	if err := broker.CreateStagedAsset(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.BeginStagedAssetUpload(ctx, other.TenantID, other.ID, "temp-2", now.Add(time.Second)); err != nil {
			return err
		}
		return tx.MarkStagedAssetReady(ctx, other.TenantID, other.ID, "object-2", now.Add(2*time.Second))
	}); err != nil {
		t.Fatal(err)
	}
	request.ID = "asset-mismatch"
	request.ApprovalID = "asset-mismatch-approval"
	request.ApprovalNonce = "asset-mismatch-nonce"
	request.ManifestHash = "asset-mismatch-manifest"
	request.HeadSHA = "release-v2"
	request.Payload["asset"].(map[string]any)["stage_id"] = other.ID
	request.Payload["asset"].(map[string]any)["size"] = float64(other.ExpectedSize + 1)
	if _, err := broker.Submit(ctx, DurableIdentity{
		TenantID: other.TenantID, AgentID: other.AgentID, CredentialID: other.CredentialID,
	}, request); !errors.Is(err, ErrDurableInvalid) {
		t.Fatalf("mismatch error = %v", err)
	}
	if _, err := db.Operation(ctx, other.TenantID, request.ID); !errors.Is(err, sqlite.ErrNotFound) {
		t.Fatalf("mismatched operation persisted: %v", err)
	}
}

func TestDurableBrokerInstallsFirstPolicyIntoFreshTenant(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	broker := newTestDurableBroker(db)
	if err := broker.InstallPolicy(ctx, "new-tenant", durablePolicy()); err != nil {
		t.Fatalf("install first policy: %v", err)
	}
	status, err := broker.PolicyStatus(ctx, "new-tenant")
	if err != nil || status.Generation != durablePolicy().Generation {
		t.Fatalf("policy status = %+v, err = %v", status, err)
	}
}

func TestDurableBrokerPromotesExactReviewedPolicyGeneration(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	current, err := broker.PolicyStatus(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	next := durablePolicy()
	next.Generation = 2
	next.Repositories["yaniv256/migrated"] = policy.Repository{Visibility: "private", Owners: []string{"zara"}, Approvers: []string{"yaniv"}}
	if err := broker.PromotePolicy(ctx, "tenant-a", "yaniv", 1, "wrong-hash", next); err == nil {
		t.Fatal("promotion accepted a policy that was not bound to the active predecessor")
	}
	if err := broker.PromotePolicy(ctx, "tenant-a", "yaniv", current.Generation, current.PolicyHash, next); err != nil {
		t.Fatal(err)
	}
	promoted, err := broker.PolicyStatus(ctx, "tenant-a")
	if err != nil || promoted.Generation != 2 || promoted.PolicyHash == current.PolicyHash {
		t.Fatalf("promoted policy = %+v, err = %v", promoted, err)
	}
	if err := broker.PromotePolicy(ctx, "tenant-a", "yaniv", current.Generation, current.PolicyHash, next); err == nil {
		t.Fatal("replayed policy promotion succeeded")
	}
	events, err := broker.db.AuthorityAuditEvents(ctx, "tenant-a", "policy:2")
	if err != nil || len(events) != 1 || !strings.Contains(string(events[0].PayloadJSON), `"approver":"yaniv"`) {
		t.Fatalf("policy audit events = %+v, err = %v", events, err)
	}
}

func TestDurableBrokerBindsPublicApprovalToExactPacketAndHuman(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	approvalExpiresAt := time.Now().UTC().Add(time.Hour)
	request := DurableOperationRequest{
		ID: "public-1", Repository: "yaniv256/public", Operation: "pull_request.create",
		Branch: "feat/public", Title: "Public change", Body: "Reviewed content",
		ManifestHash: "manifest-public", ApprovalID: "approval-public", ApprovalNonce: "approval-nonce-exact",
		ApprovalExpiresAt: approvalExpiresAt, Approver: "yaniv", HeadSHA: "abc1234", Payload: map[string]any{"base": "main", "head_sha": "abc1234"},
	}
	result, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != DurableAwaitingApproval || result.Decision != policy.ApprovalRequired {
		t.Fatalf("public submit = %+v", result)
	}

	wrong := DurableApprovalRequest{
		TenantID: "tenant-a", OperationID: request.ID, ApprovalID: request.ApprovalID,
		PacketHash: result.PacketHash, ManifestHash: request.ManifestHash, HeadSHA: request.HeadSHA,
		Approver: "mallory", ExpiresAt: approvalExpiresAt, Nonce: request.ApprovalNonce,
	}
	if _, err := broker.Approve(ctx, wrong); err == nil {
		t.Fatal("unlisted human approved public operation")
	}
	modified := wrong
	modified.Approver = "yaniv"
	modified.ManifestHash = "modified"
	if _, err := broker.Approve(ctx, modified); err == nil {
		t.Fatal("modified packet was approved")
	}

	exact := wrong
	exact.Approver = "yaniv"
	exact.Nonce = "approval-nonce-exact"
	authorized, err := broker.Approve(ctx, exact)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.State != DurableAuthorized || authorized.ActorMode != ActorHumanUser || authorized.ActorSubject != "yaniv" {
		t.Fatalf("approved operation = %+v", authorized)
	}
	if _, err := broker.Approve(ctx, exact); err == nil {
		t.Fatal("approval replay succeeded")
	}
	receipt, err := broker.Receipt(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID)
	if err != nil || len(receipt) != 2 || receipt[0].Kind != "operation_submitted" || receipt[1].Kind != "operation_approved" {
		t.Fatalf("receipt = %+v, %v", receipt, err)
	}
}

// submitAwaitingOperation seeds one public operation parked at
// awaiting_approval — the state a human reviewer actually meets.
func submitAwaitingOperation(t *testing.T, broker *DurableBroker, id string) DurableOperationRequest {
	t.Helper()
	ctx := context.Background()
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	request := DurableOperationRequest{
		ID: id, Repository: "yaniv256/public", Operation: "pull_request.create",
		Branch: "feat/public", Title: "Public change", Body: "Reviewed content",
		ManifestHash: "manifest-" + id, ApprovalID: "approval-" + id, ApprovalNonce: "nonce-" + id,
		ApprovalExpiresAt: time.Now().UTC().Add(time.Hour), Approver: "yaniv", HeadSHA: "abc1234",
		Payload: map[string]any{"base": "main", "head_sha": "abc1234"},
	}
	result, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request)
	if err != nil || result.State != DurableAwaitingApproval {
		t.Fatalf("submit = %+v, %v", result, err)
	}
	return request
}

// Declining is the reviewer's "no". Before this existed the only way to refuse
// was to let the approval lapse, which the audit trail cannot distinguish from
// never having looked.
func TestDurableDeclineIsTerminalAndBlocksLaterApproval(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	request := submitAwaitingOperation(t, broker, "decline-1")

	declined, err := broker.Decline(ctx, "tenant-a", request.ID, "yaniv", "not ready for the public repo")
	if err != nil {
		t.Fatalf("decline: %v", err)
	}
	if declined.State != DurableDenied {
		t.Fatalf("state after decline = %q, want denied", declined.State)
	}

	// The decisive assertion: a refused action must not be executable by
	// approving it afterward. Proving a state can be ENTERED says nothing
	// about what it forbids.
	approval := DurableApprovalRequest{
		TenantID: "tenant-a", OperationID: request.ID, ApprovalID: request.ApprovalID,
		PacketHash: declined.PacketHash, ManifestHash: request.ManifestHash, HeadSHA: request.HeadSHA,
		Approver: "yaniv", ExpiresAt: request.ApprovalExpiresAt, Nonce: request.ApprovalNonce,
	}
	if _, err := broker.Approve(ctx, approval); err == nil {
		t.Fatal("a declined operation was approved afterward")
	}

	if _, err := broker.Decline(ctx, "tenant-a", request.ID, "yaniv", "again"); err == nil {
		t.Fatal("second decline succeeded — the state is not terminal")
	}

	receipt, err := broker.Receipt(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt) != 2 || receipt[1].Kind != "operation_declined" {
		t.Fatalf("decline not receipted: %+v", receipt)
	}
	if !strings.Contains(string(receipt[1].PayloadJSON), "yaniv") {
		t.Fatal("receipt does not name who declined")
	}
}

// Refusing an agent's public action is a governance decision, so it carries the
// same approver authority as allowing one.
func TestDurableDeclineRequiresAnApproverForTheRepository(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	request := submitAwaitingOperation(t, broker, "decline-2")

	if _, err := broker.Decline(ctx, "tenant-a", request.ID, "mallory", "nope"); !errors.Is(err, ErrDurableForbidden) {
		t.Fatalf("unlisted human declined the operation: %v", err)
	}
	// And the operation is still reviewable by someone who may.
	if _, err := broker.Decline(ctx, "tenant-a", request.ID, "yaniv", ""); err != nil {
		t.Fatalf("listed approver could not decline: %v", err)
	}
}

// Decline covers the pre-execution window only. Once authorized the agent may
// already have published, and revoke is the verb for that.
func TestDurableDeclineRejectsNonPendingStates(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	request := submitAwaitingOperation(t, broker, "decline-3")

	if _, err := broker.Decline(ctx, "tenant-a", "no-such-operation", "yaniv", ""); !errors.Is(err, ErrDurableNotFound) {
		t.Fatalf("missing operation = %v, want not-found", err)
	}
	approved, err := broker.Approve(ctx, DurableApprovalRequest{
		TenantID: "tenant-a", OperationID: request.ID, ApprovalID: request.ApprovalID,
		PacketHash: mustPacketHash(t, broker, request.ID), ManifestHash: request.ManifestHash,
		HeadSHA: request.HeadSHA, Approver: "yaniv", ExpiresAt: request.ApprovalExpiresAt, Nonce: request.ApprovalNonce,
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.State != DurableAuthorized {
		t.Fatalf("approved state = %q", approved.State)
	}
	if _, err := broker.Decline(ctx, "tenant-a", request.ID, "yaniv", ""); !errors.Is(err, ErrDurableState) {
		t.Fatalf("declining an authorized operation = %v, want state error", err)
	}
}

func mustPacketHash(t *testing.T, broker *DurableBroker, operationID string) string {
	t.Helper()
	status, err := broker.Status(context.Background(), DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, operationID)
	if err != nil {
		t.Fatal(err)
	}
	return status.PacketHash
}

func TestDurableBrokerDistinguishesApprovalExpectationConflictFromReplay(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	first := DurableOperationRequest{ID: "approval-first", Repository: "yaniv256/public", Operation: "pull_request.create", Branch: "feat/first", Title: "First", Body: "First", ManifestHash: "manifest-first", ApprovalID: "approval-first", ApprovalNonce: "approval-first-nonce", ApprovalExpiresAt: expires, Approver: "yaniv", HeadSHA: "abc1234", Payload: map[string]any{"base": "main", "head_sha": "abc1234"}}
	if result, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, first); err != nil || result.State != DurableAwaitingApproval {
		t.Fatalf("first approval = %+v, %v", result, err)
	}
	second := first
	second.ID, second.Branch, second.Title, second.Body = "approval-second", "feat/second", "Second", "Second"
	second.ManifestHash, second.ApprovalID, second.ApprovalNonce = "manifest-second", "approval-second", "approval-second-nonce"
	conflict, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, second)
	if err != nil || conflict.State != DurableDenied || conflict.Decision != ApprovalConflict || conflict.ResourceID != first.ID || conflict.NextAction != "approve_or_revoke_existing_approval" {
		t.Fatalf("approval conflict = %+v, %v", conflict, err)
	}
	if _, err := broker.Status(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, second.ID); !errors.Is(err, ErrDurableNotFound) {
		t.Fatalf("conflicting operation unexpectedly persisted: %v", err)
	}
	replay, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, first)
	if err != nil || replay.Decision != ReplayDenied || replay.NextAction != "status" {
		t.Fatalf("true replay = %+v, %v", replay, err)
	}
}

func TestDurableApprovalHasOneConcurrentWinner(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	approvalExpiresAt := time.Now().UTC().Add(time.Hour)
	request := DurableOperationRequest{ID: "public-race", Repository: "yaniv256/public", Operation: "pull_request.create", Branch: "feat/public", Title: "Public", Body: "Body", ManifestHash: "manifest", ApprovalID: "approval-race", ApprovalNonce: "one-concurrent-nonce", ApprovalExpiresAt: approvalExpiresAt, Approver: "yaniv", HeadSHA: "abc1234", Payload: map[string]any{"base": "main", "head_sha": "abc1234"}}
	pending, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request)
	if err != nil {
		t.Fatal(err)
	}
	approvalRequest := DurableApprovalRequest{TenantID: "tenant-a", OperationID: request.ID, ApprovalID: request.ApprovalID, PacketHash: pending.PacketHash, ManifestHash: request.ManifestHash, HeadSHA: request.HeadSHA, Approver: "yaniv", Nonce: request.ApprovalNonce, ExpiresAt: approvalExpiresAt}
	var winners atomic.Int32
	var group sync.WaitGroup
	for range 10 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := broker.Approve(ctx, approvalRequest); err == nil {
				winners.Add(1)
			}
		}()
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("approval winners = %d, want 1", winners.Load())
	}
}

func TestDurableOperationRevocationPersistsAndIsOwnerScoped(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	request := DurableOperationRequest{ID: "revoke-1", Repository: "yaniv256/public", Operation: "pull_request.create", Branch: "feat/public", Title: "Public", Body: "Body", ManifestHash: "manifest", ApprovalID: "approval-revoke", ApprovalNonce: "approval-revoke-nonce", ApprovalExpiresAt: time.Now().UTC().Add(time.Hour), Approver: "yaniv", HeadSHA: "abc1234", Payload: map[string]any{"base": "main", "head_sha": "abc1234"}}
	if _, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Revoke(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "elena"}, request.ID); err == nil {
		t.Fatal("another agent revoked the operation")
	}
	revoked, err := broker.Revoke(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID)
	if err != nil || revoked.State != DurableRevoked {
		t.Fatalf("revoked = %+v, %v", revoked, err)
	}
	restarted := newTestDurableBroker(broker.db)
	status, err := restarted.Status(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID)
	if err != nil || status.State != DurableRevoked {
		t.Fatalf("restart status = %+v, %v", status, err)
	}
}

func TestDurableStatusPersistsExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0).UTC()
	broker := newTestDurableBroker(openDurableDB(t))
	broker.now = func() time.Time { return now }
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	request := DurableOperationRequest{ID: "expiry-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feat/expiry", ManifestHash: "manifest", Payload: map[string]any{"sha": "abc123"}}
	if _, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request); err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	status, err := broker.Status(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID)
	if err != nil || status.State != DurableExpired {
		t.Fatalf("expired status = %+v, %v", status, err)
	}
}

func openDurableDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.EnsureTenant(context.Background(), "tenant-a", time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestDurableSubmitGrantsHumanOwnerActorForPrivateRepositoryCreate(t *testing.T) {
	ctx := context.Background()
	db := openDurableDB(t)
	broker := newTestDurableBroker(db)
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}

	broker.SetHumanLogins(map[string]string{"yaniv": "yaniv256"})

	private, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "elena"}, DurableOperationRequest{
		ID: "create-private-1", Repository: "yaniv256/brand-new-private", Operation: "repository.create",
		ManifestHash: "manifest-1", Payload: map[string]any{"visibility": "private"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if private.State != DurableAuthorized || private.Decision != policy.Allowed {
		t.Fatalf("private create decision = %+v", private)
	}
	stored, err := broker.db.Operation(ctx, "tenant-a", "create-private-1")
	if err != nil || stored.ActorMode != ActorHumanUser || stored.ActorSubject != "yaniv" {
		t.Fatalf("stored actor = %q/%q, err = %v", stored.ActorMode, stored.ActorSubject, err)
	}

	unmapped, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "elena"}, DurableOperationRequest{
		ID: "create-private-2", Repository: "stranger/brand-new-private", Operation: "repository.create",
		ManifestHash: "manifest-3", Payload: map[string]any{"visibility": "private"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if unmapped.State == DurableAuthorized || !strings.Contains(unmapped.Reason, "no enrolled human owns") {
		t.Fatalf("unmapped namespace create = %+v", unmapped)
	}

	public, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, DurableOperationRequest{
		ID: "create-public-1", Repository: "yaniv256/brand-new-public", Operation: "repository.create",
		ManifestHash: "manifest-2", Payload: map[string]any{"visibility": "public"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if public.State == DurableAuthorized || public.Decision != policy.ApprovalRequired {
		t.Fatalf("public create must stay human-gated: %+v", public)
	}
}

func TestDurableSubmitUsesEnrolledNamespaceOwnerForPrivateOwnerMutation(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	broker.SetHumanLogins(map[string]string{"yaniv": "yaniv256"})

	result, err := broker.Submit(ctx, DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, DurableOperationRequest{
		ID: "private-owner-push-1", Repository: "yaniv256/private", Operation: "branch.push",
		Branch: "main", ManifestHash: "manifest-private", Payload: map[string]any{"sha": "abc123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != DurableAuthorized || result.Decision != policy.Allowed {
		t.Fatalf("private owner mutation = %+v", result)
	}
	stored, err := broker.db.Operation(ctx, "tenant-a", "private-owner-push-1")
	if err != nil || stored.ActorMode != ActorHumanUser || stored.ActorSubject != "yaniv" {
		t.Fatalf("stored actor = %q/%q, err = %v", stored.ActorMode, stored.ActorSubject, err)
	}
}

func durablePolicy() policy.Snapshot {
	return policy.Snapshot{
		Generation: 1,
		Agents: map[string]policy.Agent{
			"zara":  {UID: 1000, FirstName: "Zara"},
			"elena": {UID: 1001, FirstName: "Elena"},
		},
		Repositories: map[string]policy.Repository{
			"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
			"yaniv256/public":  {Visibility: "public", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
		},
	}
}
