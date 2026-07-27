package auditanchor

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/checkpoint"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type localSigner struct{ signer *checkpoint.Signer }

type bootstrapGate struct{}

func (bootstrapGate) Verify() error                        { return nil }
func (bootstrapGate) Commit(context.Context, string) error { return nil }

func (signer localSigner) Extend(extension checkpoint.Extension) (checkpoint.State, error) {
	return signer.signer.Extend(extension)
}
func (signer localSigner) State() (checkpoint.State, error)    { return signer.signer.State(), nil }
func (signer localSigner) Verify(state checkpoint.State) error { return signer.signer.Verify(state) }

func TestAnchorBindsPolicyAndEveryCommittedAuthorityTail(t *testing.T) {
	ctx := context.Background()
	db, broker := anchorTestBroker(t)
	signer, err := checkpoint.Open(filepath.Join(t.TempDir(), "checkpoint.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := New(db, "tenant-a", localSigner{signer}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	broker.SetWriteGate(anchor)
	if err := anchor.Verify(); err != nil {
		t.Fatal(err)
	}
	initial := signer.State()
	if initial.Tail == "" || initial.PolicyGeneration != 1 {
		t.Fatalf("initial checkpoint = %+v", initial)
	}
	if _, err := broker.Submit(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, server.DurableOperationRequest{
		ID: "anchor-operation", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feat/anchor", ManifestHash: "manifest", Payload: map[string]any{"sha": "abc123"},
	}); err != nil {
		t.Fatal(err)
	}
	events, err := db.AuthorityAuditTrail(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	state := signer.State()
	if len(events) != 2 || state.Tail != events[len(events)-1].Hash || state.Tail == initial.Tail {
		t.Fatalf("events = %d, checkpoint = %+v", len(events), state)
	}
}

func TestAnchorRejectsSignedTailAbsentFromDurableHistory(t *testing.T) {
	db, _ := anchorTestBroker(t)
	signer, err := checkpoint.Open(filepath.Join(t.TempDir(), "checkpoint.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Extend(checkpoint.Extension{NewTail: "unrelated-tail", PolicyGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	anchor, err := New(db, "tenant-a", localSigner{signer}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := anchor.Verify(); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("verify error = %v", err)
	}
}

func anchorTestBroker(t *testing.T) (*sqlite.DB, *server.DurableBroker) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(bootstrapGate{})
	if err := broker.InstallPolicy(context.Background(), "tenant-a", policy.Snapshot{
		Generation:   1,
		Agents:       map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}},
	}); err != nil {
		t.Fatal(err)
	}
	return db, broker
}
