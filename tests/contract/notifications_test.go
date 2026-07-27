package contract_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/notifications"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type contractWriteGate struct{}

func (contractWriteGate) Verify() error                        { return nil }
func (contractWriteGate) Commit(context.Context, string) error { return nil }

func TestNotificationAbsenceCannotChangeAuthorityOutcome(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error { return tx.EnsureTenant(ctx, "tenant-a", now) }); err != nil {
		t.Fatal(err)
	}
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(contractWriteGate{})
	if err := broker.InstallPolicy(ctx, "tenant-a", policy.Snapshot{
		Generation:   1,
		Agents:       map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}},
	}); err != nil {
		t.Fatal(err)
	}
	identity := server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}
	result, err := broker.Submit(ctx, identity, server.DurableOperationRequest{
		ID: "operation-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature",
		HeadSHA: "abc123", ManifestHash: "manifest-1", Payload: map[string]any{"sha": "abc123"},
	})
	if err != nil || result.State != server.DurableAuthorized {
		t.Fatalf("submit=%+v err=%v", result, err)
	}

	dispatcher := notifications.NewDispatcher(db, nil, notifications.Config{Now: func() time.Time { return now }})
	if worked, err := dispatcher.RunOnce(ctx, "notify-1"); err != nil || !worked {
		t.Fatalf("dispatch worked=%v err=%v", worked, err)
	}
	status, err := broker.Status(ctx, identity, "operation-1")
	if err != nil || status.State != server.DurableAuthorized {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}
