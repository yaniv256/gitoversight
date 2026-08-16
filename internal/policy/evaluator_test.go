package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

func TestZeroFallbackPermissionsPreserveLegacySnapshotEncoding(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "fallback_permissions") {
		t.Fatalf("zero fallback permissions changed durable snapshot encoding: %s", payload)
	}
}

func testPolicy() policy.Snapshot {
	return policy.Snapshot{
		Generation: 1,
		Agents: map[string]policy.Agent{
			"zara":  {UID: 1002, FirstName: "Zara", Emails: []string{"zara@example.com"}},
			"tomas": {UID: 1005, FirstName: "Tomas", Emails: []string{"tomas@example.com"}},
		},
		Repositories: map[string]policy.Repository{
			"yaniv256/private": {
				Visibility: "private", Owners: []string{"zara"}, Writers: []string{"zara"}, Approvers: []string{"yaniv"},
			},
			"yaniv256/public": {
				Visibility: "public", Owners: []string{"zara"}, Writers: []string{"zara"}, Approvers: []string{"yaniv"}, Standing: []string{"branch.push", "pull_request.merge"},
			},
			// A public repo with no standing exceptions at all. Its presence is what
			// makes the standing-exception tests meaningful: without it, a bug that
			// allowed every public write would still pass the suite.
			"yaniv256/public.bare": {
				Visibility: "public", Owners: []string{"zara"}, Writers: []string{"zara"}, Approvers: []string{"yaniv"},
			},
			"yaniv256/gitoversight.authorization": {
				Visibility: "private", Owners: []string{"yaniv"}, Approvers: []string{"yaniv"}, ProtectedPolicy: true,
			},
			"yaniv256/storage": {
				Visibility: "private", Owners: []string{"zara"}, Writers: []string{"zara"}, Standing: []string{"branch.push"},
			},
		},
		BranchGrants: []policy.BranchGrant{{Repository: "yaniv256/private", Agent: "tomas", Branch: "agent/tomas/change", Active: true}},
	}
}

func TestDocumentCompilesToRuntimeSnapshot(t *testing.T) {
	t.Parallel()
	document := policy.Document{SchemaVersion: 1, Generation: 7, Repositories: []policy.RepositoryDocument{{Name: "yaniv256/private", Visibility: "private", Owners: []string{"zara"}, AuthorizedWriters: []string{"tomas"}, HumanApprovers: []string{"yaniv"}}}}
	snapshot, err := document.Compile(map[string]policy.Agent{"zara": {UID: 1002, FirstName: "Zara"}, "tomas": {UID: 1005, FirstName: "Tomas"}})
	if err != nil {
		t.Fatal(err)
	}
	repo := snapshot.Repositories["yaniv256/private"]
	if snapshot.Generation != 7 || len(repo.Writers) != 1 || repo.Writers[0] != "tomas" || len(repo.Approvers) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestDocumentAppliesConfiguredFallbackOwner(t *testing.T) {
	t.Parallel()
	document := policy.Document{
		SchemaVersion: 1,
		Generation:    7,
		FallbackOwner: "zara",
		Repositories: []policy.RepositoryDocument{{
			Name: "yaniv256/unassigned", Visibility: "private",
			Owners: []string{}, HumanApprovers: []string{"yaniv"},
		}},
	}
	snapshot, err := document.Compile(map[string]policy.Agent{
		"zara": {UID: 1002, FirstName: "Zara"},
	})
	if err != nil {
		t.Fatal(err)
	}
	repo := snapshot.Repositories["yaniv256/unassigned"]
	if snapshot.FallbackOwner != "zara" || len(repo.Owners) != 0 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	decision := policy.Evaluate(snapshot, policy.Request{Caller: "zara", Repository: "yaniv256/unassigned", Operation: "branch.push", Branch: "feature"})
	if decision.Code != policy.Allowed {
		t.Fatalf("code = %s, want %s (%s)", decision.Code, policy.Allowed, decision.Reason)
	}
}

func TestExplicitRepositoryOwnerOverridesFallback(t *testing.T) {
	t.Parallel()
	document := policy.Document{
		SchemaVersion: 1,
		Generation:    7,
		FallbackOwner: "zara",
		Repositories: []policy.RepositoryDocument{{
			Name: "yaniv256/assigned", Visibility: "private",
			Owners: []string{"tomas"}, HumanApprovers: []string{"yaniv"},
		}},
	}
	snapshot, err := document.Compile(map[string]policy.Agent{
		"zara":  {UID: 1002, FirstName: "Zara"},
		"tomas": {UID: 1005, FirstName: "Tomas"},
	})
	if err != nil {
		t.Fatal(err)
	}
	repo := snapshot.Repositories["yaniv256/assigned"]
	if len(repo.Owners) != 1 || repo.Owners[0] != "tomas" {
		t.Fatalf("owners = %#v", repo.Owners)
	}
}

func TestFallbackOwnerMustReferenceRegisteredAgent(t *testing.T) {
	t.Parallel()
	snapshot := testPolicy()
	snapshot.FallbackOwner = "missing"
	if err := snapshot.Validate(); err == nil {
		t.Fatal("expected unknown fallback owner rejection")
	}
}

func TestFallbackPermissionsAllowEveryRegisteredAgentToReadPrivateRepositories(t *testing.T) {
	t.Parallel()
	document := policy.Document{
		SchemaVersion:       1,
		Generation:          8,
		FallbackOwner:       "zara",
		FallbackPermissions: policy.PermissionSet{Read: true},
		Repositories: []policy.RepositoryDocument{{
			Name: "ActionsJson/actions.json.dev", Visibility: "private",
			Owners: []string{}, HumanApprovers: []string{"yaniv"},
		}},
	}
	snapshot, err := document.Compile(map[string]policy.Agent{
		"zara":   {UID: 1002, FirstName: "Zara"},
		"dakota": {UID: 1007, FirstName: "Dakota"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, caller := range []string{"zara", "dakota"} {
		decision := policy.Evaluate(snapshot, policy.Request{Caller: caller, Repository: "ActionsJson/actions.json.dev", Operation: "repository.read"})
		if decision.Code != policy.AllowedRead {
			t.Fatalf("caller %s: code = %s, want %s (%s)", caller, decision.Code, policy.AllowedRead, decision.Reason)
		}
	}
}

func TestRepositoryPermissionsOverrideFallbackRead(t *testing.T) {
	t.Parallel()
	deny := policy.PermissionSet{Read: false}
	document := policy.Document{
		SchemaVersion:       1,
		Generation:          8,
		FallbackOwner:       "zara",
		FallbackPermissions: policy.PermissionSet{Read: true},
		Repositories: []policy.RepositoryDocument{{
			Name: "yaniv256/restricted", Visibility: "private", Permissions: &deny,
			Owners: []string{}, HumanApprovers: []string{"yaniv"},
		}},
	}
	snapshot, err := document.Compile(map[string]policy.Agent{
		"zara":   {UID: 1002, FirstName: "Zara"},
		"dakota": {UID: 1007, FirstName: "Dakota"},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision := policy.Evaluate(snapshot, policy.Request{Caller: "dakota", Repository: "yaniv256/restricted", Operation: "repository.read"})
	if decision.Code != policy.ReadDenied {
		t.Fatalf("code = %s, want %s (%s)", decision.Code, policy.ReadDenied, decision.Reason)
	}
}

func TestDerivedRepositoryOwnerReadsWithoutBroadeningOtherAgents(t *testing.T) {
	snapshot := testPolicy()
	// The broad fallback for configured repositories must not leak across the
	// ownership boundary of repositories created dynamically at runtime.
	snapshot.FallbackPermissions.Read = true
	snapshot.Repositories["yaniv256/derived"] = policy.Repository{Visibility: "private", Owners: []string{"tomas"}, Derived: true}
	if decision := policy.Evaluate(snapshot, policy.Request{Caller: "tomas", Repository: "yaniv256/derived", Operation: "repository.read"}); decision.Code != policy.AllowedRead {
		t.Fatalf("owner read = %s (%s)", decision.Code, decision.Reason)
	}
	if decision := policy.Evaluate(snapshot, policy.Request{Caller: "zara", Repository: "yaniv256/derived", Operation: "repository.read"}); decision.Code != policy.ReadDenied {
		t.Fatalf("unrelated read = %s (%s)", decision.Code, decision.Reason)
	}
}

func TestFallbackReadPermissionDoesNotGrantPrivateReleaseWrite(t *testing.T) {
	t.Parallel()
	// Read-only fallback permission must not grant release publication to a caller
	// who is neither an owner nor an authorized writer.
	snapshot := testPolicy()
	snapshot.FallbackPermissions = policy.PermissionSet{Read: true}
	decision := policy.Evaluate(snapshot, policy.Request{Caller: "tomas", Repository: "yaniv256/storage", Operation: "release.publish", Title: "v1", Payload: map[string]any{"tag_name": "v1", "target_commitish": "main", "prerelease": false}})
	if decision.Code != policy.BranchGrantRequired {
		t.Fatalf("code = %s, want %s (%s)", decision.Code, policy.BranchGrantRequired, decision.Reason)
	}
}

func TestPrivateOwnerMayPublishReleaseAndAssetsWithoutApproval(t *testing.T) {
	t.Parallel()
	snapshot := testPolicy()
	for _, operation := range []string{"release.publish", "release.asset.upload"} {
		decision := policy.Evaluate(snapshot, policy.Request{
			Caller: "zara", Repository: "yaniv256/private", Operation: operation,
		})
		if decision.Code != policy.Allowed {
			t.Fatalf("%s private code = %s, want %s (%s)", operation, decision.Code, policy.Allowed, decision.Reason)
		}
		decision = policy.Evaluate(snapshot, policy.Request{
			Caller: "zara", Repository: "yaniv256/public.bare", Operation: operation,
		})
		if decision.Code != policy.ApprovalRequired {
			t.Fatalf("%s public code = %s, want %s (%s)", operation, decision.Code, policy.ApprovalRequired, decision.Reason)
		}
	}
}

func TestRegisteredAgentMayOpenBranchOnPrivateRepo(t *testing.T) {
	t.Parallel()
	// Yaniv's policy directive (2026-07-21): everybody should be able to open a
	// branch on a private repo. A registered non-owner with no branch grant is
	// allowed for branch/PR ops on a private, non-protected repo.
	snapshot := testPolicy()
	for _, op := range []struct {
		operation string
		branch    string
	}{
		{"branch.push", "tomas/change"},
		{"pull_request.create", "tomas/change"},
		{"pull_request.update", ""},
	} {
		decision := policy.Evaluate(snapshot, policy.Request{Caller: "tomas", Repository: "yaniv256/private", Operation: op.operation, Branch: op.branch, Title: "x"})
		if decision.Code != policy.AllowedPrivateContributor {
			t.Fatalf("op %s: code = %s, want %s (%s)", op.operation, decision.Code, policy.AllowedPrivateContributor, decision.Reason)
		}
	}
}

func TestEvaluatePolicyMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  policy.Request
		want policy.Code
	}{
		{"private owner write", policy.Request{Caller: "zara", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature"}, policy.Allowed},
		{"public standing exception is honored for an eligible caller", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "branch.push", Branch: "feature"}, policy.AllowedStanding},
		{"public standing does not cover an unlisted operation", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "repository.settings.update"}, policy.ApprovalRequired},
		{"public repo with no standing still requires approval", policy.Request{Caller: "zara", Repository: "yaniv256/public.bare", Operation: "branch.push", Branch: "feature"}, policy.ApprovalRequired},
		{"standing exact operation", policy.Request{Caller: "zara", Repository: "yaniv256/storage", Operation: "branch.push", Branch: "feature"}, policy.AllowedStanding},
		{"standing does not broaden operation", policy.Request{Caller: "zara", Repository: "yaniv256/storage", Operation: "repository.settings.update"}, policy.ApprovalRequired},
		{"installation expansion always requires approval", policy.Request{Caller: "zara", Repository: "yaniv256/private", Operation: "installation.repository.add"}, policy.ApprovalRequired},
		{"non-owner exact branch", policy.Request{Caller: "tomas", Repository: "yaniv256/private", Operation: "branch.push", Branch: "agent/tomas/change"}, policy.AllowedBranchGrant},
		{"non-owner any branch on private repo", policy.Request{Caller: "tomas", Repository: "yaniv256/private", Operation: "branch.push", Branch: "main"}, policy.AllowedPrivateContributor},
		{"non-owner opens PR on private repo", policy.Request{Caller: "tomas", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "tomas/feature", Title: "Add feature"}, policy.AllowedPrivateContributor},
		{"non-owner cannot merge on private repo", policy.Request{Caller: "tomas", Repository: "yaniv256/private", Operation: "pull_request.merge", Payload: map[string]any{"number": float64(1), "merge_method": "squash"}}, policy.BranchGrantRequired},
		{"OWNER merges private PR independently (no approval)", policy.Request{Caller: "zara", Repository: "yaniv256/private", Operation: "pull_request.merge", Payload: map[string]any{"number": float64(1), "merge_method": "squash"}}, policy.Allowed},
		// Merge is destructive AND public, so it clears two guards at once — it is
		// only reachable because the policy lists it as an exact standing exception.
		{"public standing covers merge when listed", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "pull_request.merge", Payload: map[string]any{"number": float64(1), "merge_method": "squash"}}, policy.AllowedStanding},
		{"merge on a public repo WITHOUT standing needs approval", policy.Request{Caller: "zara", Repository: "yaniv256/public.bare", Operation: "pull_request.merge", Payload: map[string]any{"number": float64(1), "merge_method": "squash"}}, policy.ApprovalRequired},
		{"OWNER deletes a branch on private repo independently", policy.Request{Caller: "zara", Repository: "yaniv256/private", Operation: "branch.delete", Branch: "stale-ref"}, policy.Allowed},
		{"non-owner cannot auto-delete a branch on private repo", policy.Request{Caller: "tomas", Repository: "yaniv256/private", Operation: "branch.delete", Branch: "stale-ref"}, policy.BranchGrantRequired},
		{"branch.delete on PUBLIC repo needs approval", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "branch.delete", Branch: "stale-ref"}, policy.ApprovalRequired},
		{"non-owner branch on PUBLIC repo still needs approval", policy.Request{Caller: "tomas", Repository: "yaniv256/public", Operation: "branch.push", Branch: "feature/change"}, policy.ApprovalRequired},
		{"non-owner branch on protected-policy repo still needs approval", policy.Request{Caller: "tomas", Repository: "yaniv256/gitoversight.authorization", Operation: "branch.push", Branch: "feature/change"}, policy.ApprovalRequired},
		{"private review by registered agent", policy.Request{Caller: "tomas", Repository: "yaniv256/private", Operation: "pull_request.review", Body: "Looks good.\n\n— Tomas"}, policy.AllowedPrivateReview},
		{"private review missing signature", policy.Request{Caller: "tomas", Repository: "yaniv256/private", Operation: "pull_request.review", Body: "Looks good."}, policy.PrivateAttributionRequired},
		{"public agent signature denied", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "pull_request.create", Title: "Docs", Body: "Ready.\n\n— Zara"}, policy.PublicIdentityLeak},
		{"public payload agent identity denied", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "pull_request.create", Title: "Docs", Payload: map[string]any{"commit_message": "Co-authored-by: Zara <zara@example.com>"}}, policy.PublicIdentityLeak},
		{"public packet encoded blob coincidence is not attribution", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "branch.push", Branch: "feature/change", Payload: map[string]any{"object_package": map[string]any{"blobs": []any{map[string]any{"sha": "d7c6b25ea1bc0028201ab05b2e84044f6f294566", "encoding": "base64", "content": "/9j/4AAQZarAAB"}}}}}, policy.AllowedStanding},
		{"public packet commit attribution still denied", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "branch.push", Branch: "feature/change", Payload: map[string]any{"object_package": map[string]any{"commit": map[string]any{"committer": map[string]any{"name": "Zara", "email": "zara@example.com"}}}}}, policy.PublicIdentityLeak},
		{"public non-base64 content attribution still denied", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "branch.push", Branch: "feature/change", Payload: map[string]any{"sha": "d7c6b25ea1bc0028201ab05b2e84044f6f294566", "encoding": "utf-8", "content": "Authored by Zara"}}, policy.PublicIdentityLeak},
		{"public branch agent identity denied", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "pull_request.create", Branch: "zara/feature", Title: "Docs"}, policy.PublicIdentityLeak},
		{"public prose agent identity denied", policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "pull_request.create", Title: "Authored by Zara"}, policy.PublicIdentityLeak},
		{"protected policy always approval", policy.Request{Caller: "zara", Repository: "yaniv256/gitoversight.authorization", Operation: "branch.push", Branch: "policy"}, policy.ApprovalRequired},
		{"protected policy discussion requires approval", policy.Request{Caller: "zara", Repository: "yaniv256/gitoversight.authorization", Operation: "pull_request.reply", Body: "Internal.\n\n— Zara"}, policy.ApprovalRequired},
		{"unknown repository", policy.Request{Caller: "zara", Repository: "yaniv256/missing", Operation: "branch.push"}, policy.RepositoryUnknown},
		{"unknown caller", policy.Request{Caller: "elena", Repository: "yaniv256/private", Operation: "branch.push"}, policy.CallerUnknown},
		{"unknown operation", policy.Request{Caller: "zara", Repository: "yaniv256/private", Operation: "raw.admin"}, policy.OperationUnknown},
		// repository.create bootstrap exception: the target repo cannot be pre-registered.
		// The gate keys on public exposure — a private create by a registered agent is
		// allowed (execution still needs the namespace owner's stored human credential);
		// a public create is externally visible and stays human-gated.
		{"create new private repo allowed for registered agent", policy.Request{Caller: "zara", Repository: "yaniv256/agent-kanban.dev", Operation: "repository.create", Payload: map[string]any{"visibility": "private"}}, policy.Allowed},
		{"create new public repo needs approval", policy.Request{Caller: "zara", Repository: "yaniv256/brand-new-public", Operation: "repository.create", Payload: map[string]any{"visibility": "public"}}, policy.ApprovalRequired},
		{"create without declared visibility needs approval", policy.Request{Caller: "zara", Repository: "yaniv256/brand-new-unspecified", Operation: "repository.create"}, policy.ApprovalRequired},
		{"create by unknown caller still CallerUnknown", policy.Request{Caller: "elena", Repository: "yaniv256/agent-kanban.dev", Operation: "repository.create", Payload: map[string]any{"visibility": "private"}}, policy.CallerUnknown},
		{"non-create op on unregistered repo still RepositoryUnknown", policy.Request{Caller: "zara", Repository: "yaniv256/missing", Operation: "pull_request.create", Title: "x"}, policy.RepositoryUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policy.Evaluate(testPolicy(), tt.req)
			if got.Code != tt.want {
				t.Fatalf("code = %s, want %s (%s)", got.Code, tt.want, got.Reason)
			}
		})
	}
}

func TestDuplicateUIDsRejected(t *testing.T) {
	t.Parallel()
	snapshot := testPolicy()
	snapshot.Agents["tomas"] = policy.Agent{UID: 1002, FirstName: "Tomas"}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("expected duplicate UID rejection")
	}
}

func TestLegacyAndExplicitLocalAgentsRetainUniqueUIDSemantics(t *testing.T) {
	t.Parallel()
	snapshot := testPolicy()
	snapshot.Agents["tomas"] = policy.Agent{Kind: policy.AgentKindLocal, UID: 1002, FirstName: "Tomas"}
	if err := snapshot.Validate(); err == nil || !strings.Contains(err.Error(), "share uid") {
		t.Fatalf("expected local uid collision, got %v", err)
	}
}

func TestRemoteAgentsHaveNoUnixUIDAndDoNotCollide(t *testing.T) {
	t.Parallel()
	snapshot := testPolicy()
	snapshot.Agents["work-one"] = policy.Agent{Kind: policy.AgentKindRemote, FirstName: "Work One"}
	snapshot.Agents["work-two"] = policy.Agent{Kind: policy.AgentKindRemote, FirstName: "Work Two"}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("remote agents with uid zero should validate: %v", err)
	}
	snapshot.Agents["work-two"] = policy.Agent{Kind: policy.AgentKindRemote, UID: 2000, FirstName: "Work Two"}
	if err := snapshot.Validate(); err == nil || !strings.Contains(err.Error(), "must not declare a unix uid") {
		t.Fatalf("expected remote unix uid rejection, got %v", err)
	}
}

func TestUnknownAgentKindRejected(t *testing.T) {
	t.Parallel()
	snapshot := testPolicy()
	snapshot.Agents["work"] = policy.Agent{Kind: policy.AgentKind("browser"), FirstName: "Work"}
	if err := snapshot.Validate(); err == nil || !strings.Contains(err.Error(), "invalid kind") {
		t.Fatalf("expected invalid kind rejection, got %v", err)
	}
}

func TestClosedBranchGrantIrrelevantOnPrivateRepo(t *testing.T) {
	t.Parallel()
	// Since any registered agent may open a branch on a private repo
	// (AllowedPrivateContributor), the state of a branch grant no longer gates a
	// private-repo branch/PR op — a closed grant neither blocks nor is needed. The
	// grant mechanism remains meaningful only where a non-owner is otherwise denied
	// (it is not exercised for private repos under the current policy).
	snapshot := testPolicy()
	snapshot.BranchGrants[0].Active = false
	decision := policy.Evaluate(snapshot, policy.Request{Caller: "tomas", Repository: "yaniv256/private", Operation: "branch.push", Branch: "agent/tomas/change"})
	if decision.Code != policy.AllowedPrivateContributor {
		t.Fatalf("code = %s, want %s (%s)", decision.Code, policy.AllowedPrivateContributor, decision.Reason)
	}
}

func TestSyncsToValidation(t *testing.T) {
	t.Parallel()
	base := func(syncsTo, visibility string) policy.Document {
		return policy.Document{SchemaVersion: 1, Generation: 7, Repositories: []policy.RepositoryDocument{{
			Name: "yaniv256/agent-kanban.dev", Visibility: visibility,
			Owners: []string{"zara"}, SyncsTo: syncsTo,
		}}}
	}
	agents := map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}}

	if snap, err := base("yaniv256/agent-kanban", "private").Compile(agents); err != nil {
		t.Fatalf("valid syncs_to rejected: %v", err)
	} else if got := snap.Repositories["yaniv256/agent-kanban.dev"].SyncsTo; got != "yaniv256/agent-kanban" {
		t.Fatalf("SyncsTo = %q, want yaniv256/agent-kanban", got)
	}
	if _, err := base("yaniv256/*", "private").Compile(agents); err == nil {
		t.Fatal("wildcard syncs_to accepted")
	}
	if _, err := base("not-a-repo", "private").Compile(agents); err == nil {
		t.Fatal("non owner/name syncs_to accepted")
	}
	if _, err := base("yaniv256/agent-kanban", "public").Compile(agents); err == nil {
		t.Fatal("syncs_to on a public repo accepted")
	}
}

func TestQueueCuratorValidation(t *testing.T) {
	t.Parallel()
	agents := map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}}
	doc := policy.Document{SchemaVersion: 1, Generation: 7, QueueCurator: "zara"}
	snap, err := doc.Compile(agents)
	if err != nil {
		t.Fatalf("valid queue_curator rejected: %v", err)
	}
	if snap.QueueCurator != "zara" {
		t.Fatalf("QueueCurator = %q, want zara", snap.QueueCurator)
	}
	doc.QueueCurator = "ghost"
	if _, err := doc.Compile(agents); err == nil {
		t.Fatal("unregistered queue_curator accepted")
	}
}

func syncTestPolicy() policy.Snapshot {
	snap := testPolicy()
	snap.QueueCurator = "zara"
	snap.Repositories["yaniv256/mirror.dev"] = policy.Repository{
		Visibility: "private", Owners: []string{"zara"}, Writers: []string{"zara", "tomas"},
		Approvers: []string{"yaniv"}, SyncsTo: "yaniv256/mirror",
	}
	snap.Repositories["yaniv256/mirror"] = policy.Repository{
		Visibility: "public", Owners: []string{"zara"}, Writers: []string{"zara"}, Approvers: []string{"yaniv"},
	}
	return snap
}

func TestSyncOperationsRegistered(t *testing.T) {
	t.Parallel()
	for _, op := range []string{"sync.propose", "sync.update", "queue.set_order"} {
		decision := policy.Evaluate(syncTestPolicy(), policy.Request{Caller: "zara", Repository: "yaniv256/mirror.dev", Operation: op})
		if decision.Code == policy.OperationUnknown {
			t.Fatalf("%s is operation_unknown", op)
		}
	}
}

func TestSyncProposeRequiresLinkedMirrorAndStanding(t *testing.T) {
	t.Parallel()
	snap := syncTestPolicy()
	// owner on mirror AND on linked public target -> allowed
	if d := policy.Evaluate(snap, policy.Request{Caller: "zara", Repository: "yaniv256/mirror.dev", Operation: "sync.propose"}); d.Code != policy.Allowed {
		t.Fatalf("owner propose = %s (%s), want allowed", d.Code, d.Reason)
	}
	if d := policy.Evaluate(snap, policy.Request{Caller: "zara", Repository: "yaniv256/mirror.dev", Operation: "sync.update"}); d.Code != policy.Allowed {
		t.Fatalf("owner update = %s (%s), want allowed", d.Code, d.Reason)
	}
	// repo without syncs_to -> sync_mirror_required
	if d := policy.Evaluate(snap, policy.Request{Caller: "zara", Repository: "yaniv256/private", Operation: "sync.propose"}); d.Code != policy.SyncMirrorRequired {
		t.Fatalf("unlinked repo = %s, want sync_mirror_required", d.Code)
	}
	// public repo -> sync_mirror_required
	if d := policy.Evaluate(snap, policy.Request{Caller: "zara", Repository: "yaniv256/public", Operation: "sync.propose"}); d.Code != policy.SyncMirrorRequired {
		t.Fatalf("public repo = %s, want sync_mirror_required", d.Code)
	}
	// writer on mirror but NO standing on the linked public target -> denied
	if d := policy.Evaluate(snap, policy.Request{Caller: "tomas", Repository: "yaniv256/mirror.dev", Operation: "sync.propose"}); d.Code == policy.Allowed {
		t.Fatalf("caller without public-target standing was allowed (%s)", d.Reason)
	}
}

func TestQueueSetOrderCuratorOnly(t *testing.T) {
	t.Parallel()
	snap := syncTestPolicy()
	if d := policy.Evaluate(snap, policy.Request{Caller: "zara", Operation: "queue.set_order"}); d.Code != policy.Allowed {
		t.Fatalf("curator = %s (%s), want allowed", d.Code, d.Reason)
	}
	if d := policy.Evaluate(snap, policy.Request{Caller: "tomas", Operation: "queue.set_order"}); d.Code != policy.QueueCuratorRequired {
		t.Fatalf("non-curator = %s, want queue_curator_required", d.Code)
	}
	snap.QueueCurator = ""
	if d := policy.Evaluate(snap, policy.Request{Caller: "zara", Operation: "queue.set_order"}); d.Code != policy.QueueCuratorRequired {
		t.Fatalf("no curator configured = %s, want queue_curator_required", d.Code)
	}
}
