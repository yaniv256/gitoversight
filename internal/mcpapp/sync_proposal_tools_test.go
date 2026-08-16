package mcpapp

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
)

type syncProposalsStub struct {
	mu       sync.Mutex
	calls    int
	identity brokerapp.Identity
	request  brokerapp.SyncProposalRequest
	result   brokerapp.SyncProposalResult
	err      error
}

func (stub *syncProposalsStub) Propose(_ context.Context, identity brokerapp.Identity, request brokerapp.SyncProposalRequest) (brokerapp.SyncProposalResult, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls++
	stub.identity, stub.request = identity, request
	return stub.result, stub.err
}

func TestSyncProposalToolChecksScopeAndReturnsOnlyReviewBinding(t *testing.T) {
	packet := `{"private":"packet bytes must not echo"}`
	head := strings.Repeat("a", 40)
	proposalHash := strings.Repeat("b", 64)
	proposals := &syncProposalsStub{result: brokerapp.SyncProposalResult{
		ID: "sync-1", State: "proposed", ProposalHash: proposalHash,
		PublicRepository: "example/product", PacketHeadSHA: strings.Repeat("c", 40), Files: []string{"README.md"},
	}}
	handler := newTestHandler(t, func(config *Config) {
		config.SyncProposals = proposals
		config.Scope = scopeStub{denied: map[string]bool{"example/denied.dev": true}}
	})
	session := initializeSession(t, handler, "token-a", "client-a")
	markInitialized(t, handler, "token-a", session)

	denied := callTool(t, handler, "token-a", session, 2, "sync.propose", map[string]any{
		"id": "sync-1", "repository": "example/denied.dev", "text": "Exact public text",
		"commit_packet_json": packet, "packet_head_sha": head,
	})
	if !strings.Contains(denied.Body.String(), `"code":"repository_denied"`) || proposals.calls != 0 {
		t.Fatalf("denied=%s calls=%d", denied.Body.String(), proposals.calls)
	}

	created := callTool(t, handler, "token-a", session, 3, "sync.propose", map[string]any{
		"id": "sync-1", "repository": "example/product.dev", "text": "Exact public text",
		"commit_packet_json": packet, "packet_head_sha": head,
	})
	if strings.Contains(created.Body.String(), `"isError":true`) || proposals.calls != 1 {
		t.Fatalf("created=%s calls=%d", created.Body.String(), proposals.calls)
	}
	if proposals.identity.AgentID == "" || proposals.request.Text != "Exact public text" || proposals.request.CommitPacketJSON != packet || proposals.request.PacketHeadSHA != head {
		t.Fatalf("identity=%+v request=%+v", proposals.identity, proposals.request)
	}
	for _, expected := range []string{"sync-1", "proposed", proposalHash, "example/product", "README.md"} {
		if !strings.Contains(created.Body.String(), expected) {
			t.Fatalf("response missing %q: %s", expected, created.Body.String())
		}
	}
	for _, forbidden := range []string{"packet bytes must not echo", "Exact public text", "commit_packet_json", `"approval"`, `"published"`, `"pull_request"`} {
		if strings.Contains(created.Body.String(), forbidden) {
			t.Fatalf("response leaked or implied execution %q: %s", forbidden, created.Body.String())
		}
	}
}

func TestSyncProposalToolRejectsInvalidAndReportsGovernedErrors(t *testing.T) {
	proposals := &syncProposalsStub{err: brokerapp.ErrSyncProposalExists}
	handler := newTestHandler(t, func(config *Config) { config.SyncProposals = proposals })
	session := initializeSession(t, handler, "token-a", "client-a")
	markInitialized(t, handler, "token-a", session)

	invalid := callTool(t, handler, "token-a", session, 2, "sync.propose", map[string]any{
		"id": "sync/invalid", "repository": "example/product.dev", "text": "Public", "commit_packet_json": `{}`, "packet_head_sha": strings.Repeat("a", 40),
	})
	if !strings.Contains(invalid.Body.String(), `"code":"invalid_arguments"`) || proposals.calls != 0 {
		t.Fatalf("invalid=%s calls=%d", invalid.Body.String(), proposals.calls)
	}
	exists := callTool(t, handler, "token-a", session, 3, "sync.propose", map[string]any{
		"id": "sync-1", "repository": "example/product.dev", "text": "Public", "commit_packet_json": `{}`, "packet_head_sha": strings.Repeat("a", 40),
	})
	if !strings.Contains(exists.Body.String(), `"code":"sync_proposal_exists"`) || proposals.calls != 1 {
		t.Fatalf("exists=%s calls=%d", exists.Body.String(), proposals.calls)
	}
}
