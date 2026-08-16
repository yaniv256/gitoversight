package brokerapp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/syncproposal"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

const syncShapePacketJSON = `{"sha": "68d273daa52639af3825a0e4c2d0a5ab82bd40a0", "object_package": {"blobs": [{"sha": "50860bb5e14f44f3916a2b1f2976f009c1580b65", "content": "IyBTa2lsbAo=", "encoding": "base64"}], "tree": {"sha": "9ff4fc377ca2fdf571913c2f2abeb30655ea91a8", "entries": [{"path": "SKILL.md", "mode": "100644", "type": "blob", "sha": "50860bb5e14f44f3916a2b1f2976f009c1580b65"}]}, "commit": {"sha": "68d273daa52639af3825a0e4c2d0a5ab82bd40a0", "message": "Release\n", "tree": "9ff4fc377ca2fdf571913c2f2abeb30655ea91a8", "parents": [], "author": {"name": "Zara", "email": "zara@example.com", "date": "2023-11-14T22:13:20Z"}, "committer": {"name": "Zara", "email": "zara@example.com", "date": "2023-11-14T22:13:20Z"}}}}`

type syncProposalStoreStub struct {
	record      SyncProposalRecord
	notifyAgent string
	now         time.Time
	err         error
	calls       int
}

func (stub *syncProposalStoreStub) CreateSyncProposal(_ context.Context, record SyncProposalRecord, notifyAgent string, now time.Time) error {
	stub.calls++
	stub.record, stub.notifyAgent, stub.now = record, notifyAgent, now
	return stub.err
}

type syncProposalBasesStub struct {
	result workerrpc.BaseRead
	err    error
	input  workerrpc.BaseReadRequest
	calls  int
}

type syncPolicySourceStub struct {
	snapshot policy.Snapshot
	calls    int
}

func (stub *syncPolicySourceStub) PolicySnapshot(context.Context, string) (policy.Snapshot, error) {
	stub.calls++
	return stub.snapshot, nil
}

func (stub *syncProposalBasesStub) ReadBase(request workerrpc.BaseReadRequest) (workerrpc.BaseRead, error) {
	stub.calls++
	stub.input = request
	return stub.result, stub.err
}

func TestSyncProposalServiceDerivesAndBindsExactReviewArtifact(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store := &syncProposalStoreStub{}
	bases := &syncProposalBasesStub{result: workerrpc.BaseRead{
		CommitSHA: strings.Repeat("e", 40), TreeSHA: strings.Repeat("f", 40),
	}}
	service := NewSyncProposalService(SyncProposalConfig{Policy: syncProposalPolicy(), Store: store, Bases: bases, Now: func() time.Time { return now }})
	request := SyncProposalRequest{
		ID: "sync-1", Repository: "yaniv256/product.dev", Text: "Public release\n\nExact features.",
		CommitPacketJSON: decodedSyncShapePacket(), PacketHeadSHA: "68d273daa52639af3825a0e4c2d0a5ab82bd40a0",
	}
	result, err := service.Propose(context.Background(), Identity{TenantID: "tenant-a", AgentID: "zara"}, request)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || bases.calls != 1 || bases.input.Repository != "yaniv256/product" || bases.input.Branch != "main" {
		t.Fatalf("store calls=%d base=%+v calls=%d", store.calls, bases.input, bases.calls)
	}
	if store.record.ProposalText != request.Text || store.record.PrivateRepository != request.Repository || store.record.PublicRepository != "yaniv256/product" || store.notifyAgent != "zara" {
		t.Fatalf("record=%+v notify=%q", store.record, store.notifyAgent)
	}
	if len(store.record.FileManifest) != 1 || store.record.FileManifest[0] != "SKILL.md" {
		t.Fatalf("derived manifest=%v", store.record.FileManifest)
	}
	if result.PacketHeadSHA != store.record.PacketHeadSHA || result.ProposalHash != syncproposal.Hash(request.Text, result.Files, result.PacketHeadSHA, store.record.CommitPacketJSON) {
		t.Fatalf("result=%+v record head=%q", result, store.record.PacketHeadSHA)
	}
	if result.PacketHeadSHA == request.PacketHeadSHA {
		t.Fatal("reparented public commit incorrectly kept the submitted private head")
	}
	if result.State != "proposed" || result.PublicRepository != "yaniv256/product" {
		t.Fatalf("result=%+v", result)
	}
	var stored map[string]any
	if err := json.Unmarshal([]byte(store.record.CommitPacketJSON), &stored); err != nil {
		t.Fatal(err)
	}
	if stored["sha"] != result.PacketHeadSHA {
		t.Fatalf("packet sha=%v result=%s", stored["sha"], result.PacketHeadSHA)
	}
}

func TestSyncProposalServiceDeniesBeforeBaseReadAndStore(t *testing.T) {
	store := &syncProposalStoreStub{}
	bases := &syncProposalBasesStub{}
	service := NewSyncProposalService(SyncProposalConfig{Policy: syncProposalPolicy(), Store: store, Bases: bases})
	request := SyncProposalRequest{ID: "sync-1", Repository: "yaniv256/product.dev", Text: "Release", CommitPacketJSON: decodedSyncShapePacket(), PacketHeadSHA: strings.Repeat("a", 40)}
	_, err := service.Propose(context.Background(), Identity{TenantID: "tenant-a", AgentID: "tomas"}, request)
	var policyErr SyncProposalPolicyError
	if !errors.As(err, &policyErr) || !errors.Is(err, ErrSyncProposalDenied) || policyErr.Code != policy.BranchGrantRequired {
		t.Fatalf("error=%v", err)
	}
	if bases.calls != 0 || store.calls != 0 {
		t.Fatalf("denied request reached base/store: %d/%d", bases.calls, store.calls)
	}
}

func TestSyncProposalServiceRejectsInvalidPacketWithoutPersistence(t *testing.T) {
	store := &syncProposalStoreStub{}
	service := NewSyncProposalService(SyncProposalConfig{Policy: syncProposalPolicy(), Store: store, Bases: &syncProposalBasesStub{result: workerrpc.BaseRead{Empty: true}}})
	_, err := service.Propose(context.Background(), Identity{TenantID: "tenant-a", AgentID: "zara"}, SyncProposalRequest{
		ID: "sync-1", Repository: "yaniv256/product.dev", Text: "Release", CommitPacketJSON: `{}`, PacketHeadSHA: strings.Repeat("a", 40),
	})
	if !errors.Is(err, ErrSyncProposalRebase) || store.calls != 0 {
		t.Fatalf("error=%v calls=%d", err, store.calls)
	}
}

func TestSyncProposalServiceUsesCurrentRemoteEnrollmentAndCredentialScope(t *testing.T) {
	snapshot := syncProposalPolicy()
	snapshot.Agents["work-agent"] = policy.Agent{Kind: policy.AgentKindRemote, FirstName: "Work Agent"}
	source := &syncPolicySourceStub{snapshot: snapshot}
	store := &syncProposalStoreStub{}
	bases := &syncProposalBasesStub{result: workerrpc.BaseRead{CommitSHA: strings.Repeat("e", 40), TreeSHA: strings.Repeat("f", 40)}}
	service := NewSyncProposalService(SyncProposalConfig{Policies: source, Store: store, Bases: bases})
	request := SyncProposalRequest{ID: "sync-work", Repository: "yaniv256/product.dev", Text: "Reviewed public change", CommitPacketJSON: decodedSyncShapePacket(), PacketHeadSHA: strings.Repeat("a", 40)}
	if _, err := service.Propose(context.Background(), Identity{TenantID: "tenant-a", AgentID: "work-agent", CredentialID: "family-1"}, request); err != nil {
		t.Fatalf("current remote enrollment was not accepted: %v", err)
	}
	if source.calls != 1 || store.calls != 1 {
		t.Fatalf("calls source=%d store=%d", source.calls, store.calls)
	}
	if _, err := service.Propose(context.Background(), Identity{TenantID: "tenant-a", AgentID: "work-agent"}, SyncProposalRequest{ID: "sync-no-token", Repository: request.Repository, Text: request.Text, CommitPacketJSON: request.CommitPacketJSON, PacketHeadSHA: request.PacketHeadSHA}); !errors.Is(err, ErrSyncProposalDenied) {
		t.Fatalf("remote identity without OAuth credential scope was accepted: %v", err)
	}
}

func syncProposalPolicy() policy.Snapshot {
	return policy.Snapshot{
		QueueCurator: "zara",
		Agents:       map[string]policy.Agent{"zara": {FirstName: "Zara"}, "tomas": {FirstName: "Tomas"}},
		Repositories: map[string]policy.Repository{
			"yaniv256/product.dev": {Visibility: "private", Owners: []string{"zara"}, Writers: []string{"zara"}, SyncsTo: "yaniv256/product"},
			"yaniv256/product":     {Visibility: "public", Owners: []string{"zara"}, Writers: []string{"zara"}},
		},
	}
}

func decodedSyncShapePacket() string {
	decoded := strings.ReplaceAll(syncShapePacketJSON, `\"`, `"`)
	if !json.Valid([]byte(decoded)) {
		panic(decoded)
	}
	return decoded
}
