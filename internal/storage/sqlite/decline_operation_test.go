package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

// These tests exercise DeclineOperation DIRECTLY, below the broker.
//
// They exist because the broker-level decline tests passed a mutation that
// deleted this statement's `AND state = 'awaiting_approval'` guard entirely:
// those tests were measuring the broker's Go-level state check and never
// reached the SQL underneath. A defense only one caller happens to duplicate is
// not a defense — the next caller inherits nothing. Coverage measured inside a
// boundary cannot see a defect at it.
func openDeclineTestDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "decline.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		if err := tx.EnsureTenant(context.Background(), "default", time.Unix(1_700_000_000, 0).UTC()); err != nil {
			return err
		}
		return tx.EnsureAgent(context.Background(), "default", "zara", time.Unix(1_700_000_000, 0).UTC())
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return db
}

func seedOperationInState(t *testing.T, db *sqlite.DB, id, state string) {
	t.Helper()
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.PutOperation(context.Background(), storage.Operation{
			TenantID: "default", ID: id, AgentID: "zara", Repository: "yaniv256/public",
			Kind: "pull_request.reply", PacketHash: "hash-" + id, State: state,
			PolicyGeneration: 1, CreatedAt: time.Unix(1_800_000_000, 0), ExpiresAt: time.Unix(1_800_020_000, 0),
		})
	}); err != nil {
		t.Fatalf("seed operation %s: %v", id, err)
	}
}

func operationState(t *testing.T, db *sqlite.DB, id string) string {
	t.Helper()
	operation, err := db.Operation(context.Background(), "default", id)
	if err != nil {
		t.Fatalf("read operation %s: %v", id, err)
	}
	return operation.State
}

func declineAt(db *sqlite.DB, id string) error {
	return db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.DeclineOperation(context.Background(), "default", id, "yaniv", "not ready", time.Unix(1_800_001_000, 0))
	})
}

func TestDeclineOperationMovesPendingToDenied(t *testing.T) {
	t.Parallel()
	db := openDeclineTestDB(t)
	seedOperationInState(t, db, "op-pending", "awaiting_approval")
	if err := declineAt(db, "op-pending"); err != nil {
		t.Fatalf("decline: %v", err)
	}
	if got := operationState(t, db, "op-pending"); got != "denied" {
		t.Fatalf("state = %q, want denied", got)
	}
	operation, err := db.Operation(context.Background(), "default", "op-pending")
	if err != nil {
		t.Fatal(err)
	}
	// The receipt must be able to answer "who said no, and why" — an
	// unattributed refusal is indistinguishable from an expiry.
	if operation.ActorSubject != "yaniv" || operation.DecisionCode != "declined_by_human" || operation.Reason != "not ready" {
		t.Fatalf("decline not attributed: subject=%q code=%q reason=%q",
			operation.ActorSubject, operation.DecisionCode, operation.Reason)
	}
}

// The guard the broker-level tests could not see. Each of these states is
// non-pending for a different reason, and none may be declined: authorized may
// already have executed, and the terminal three are decided.
func TestDeclineOperationRefusesEveryNonPendingState(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"authorized", "denied", "revoked", "expired", "verified"} {
		db := openDeclineTestDB(t)
		seedOperationInState(t, db, "op-"+state, state)
		if err := declineAt(db, "op-"+state); err == nil {
			t.Fatalf("declined an operation in state %q", state)
		}
		if got := operationState(t, db, "op-"+state); got != state {
			t.Fatalf("state %q was mutated to %q by a refused decline", state, got)
		}
	}
}

func TestDeclineOperationIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := openDeclineTestDB(t)
	seedOperationInState(t, db, "op-tenant", "awaiting_approval")
	err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.DeclineOperation(context.Background(), "other-tenant", "op-tenant", "mallory", "x", time.Unix(1_800_001_000, 0))
	})
	if err == nil {
		t.Fatal("a foreign tenant declined this operation")
	}
	if got := operationState(t, db, "op-tenant"); got != "awaiting_approval" {
		t.Fatalf("cross-tenant decline mutated state to %q", got)
	}
}
