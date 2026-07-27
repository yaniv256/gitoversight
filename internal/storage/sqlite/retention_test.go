package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func seedPacket(t *testing.T, db *sqlite.DB, id, state string, updatedAt time.Time) {
	t.Helper()
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.PutOperation(context.Background(), storage.Operation{
			TenantID: "default", ID: id, AgentID: "zara", Repository: "yaniv256/agent-kanban.dev",
			Kind: "branch.push", PacketHash: "hash-" + id, State: state, PolicyGeneration: 4,
			CreatedAt: updatedAt, ExpiresAt: updatedAt.Add(time.Hour), UpdatedAt: updatedAt,
			PayloadJSON: []byte(`{"sha":"abc","object_package":{"blob":"big"}}`),
		})
	}); err != nil {
		t.Fatalf("seed packet %s: %v", id, err)
	}
}

func TestPruneTerminalPacketPayloads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "retention.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	seededAt := time.Unix(1_700_000_000, 0).UTC()
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.EnsureTenant(ctx, "default", seededAt); err != nil {
			return err
		}
		return tx.EnsureAgent(ctx, "default", "zara", seededAt)
	}); err != nil {
		t.Fatalf("seed tenant/agent: %v", err)
	}

	old := time.Unix(1_800_000_000, 0).UTC()
	recent := old.Add(48 * time.Hour)
	cutoff := old.Add(24 * time.Hour)
	seedPacket(t, db, "op-verified-old", "verified", old)
	seedPacket(t, db, "op-denied-old", "denied", old)
	seedPacket(t, db, "op-absent-old", "absent", old)
	seedPacket(t, db, "op-verified-recent", "verified", recent)
	seedPacket(t, db, "op-authorized-old", "authorized", old)
	seedPacket(t, db, "op-indeterminate-old", "indeterminate", old)

	pruned, err := db.PruneTerminalPacketPayloads(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 3 {
		t.Fatalf("pruned = %d, want 3", pruned)
	}

	wantPayload := map[string]bool{
		"op-verified-old":      false, // terminal + old -> pruned
		"op-denied-old":        false,
		"op-absent-old":        false,
		"op-verified-recent":   true, // terminal but inside retention window
		"op-authorized-old":    true, // live state: Execute still needs the payload
		"op-indeterminate-old": true, // reconciliation may still need the payload
	}
	for id, want := range wantPayload {
		operation, err := db.Operation(ctx, "default", id)
		if err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		if got := len(operation.PayloadJSON) > 0; got != want {
			t.Errorf("%s payload present = %v, want %v", id, got, want)
		}
		if operation.PacketHash != "hash-"+id {
			t.Errorf("%s packet hash mutated: %q", id, operation.PacketHash)
		}
	}

	// A second pass finds nothing left to prune.
	again, err := db.PruneTerminalPacketPayloads(ctx, cutoff)
	if err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if again != 0 {
		t.Fatalf("second prune = %d, want 0", again)
	}
}
