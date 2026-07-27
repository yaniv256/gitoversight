package approval_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/approval"
)

func TestApprovalStateSurvivesRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "approvals.json")
	store, err := approval.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(packet()); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	if err := store.Reserve("approval-1", "request-1", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != nil {
		t.Fatal(err)
	}
	reopened, err := approval.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Reserve("approval-1", "request-2", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != approval.ErrReserved {
		t.Fatalf("restart reserve = %v", err)
	}
}

func packet() approval.Packet {
	return approval.Packet{
		ID: "approval-1", ManifestHash: "manifest-hash", Repository: "yaniv256/public",
		Operations: []string{"pull_request.create"}, Approver: "yaniv", Nonce: "0123456789abcdef",
		PolicyGeneration: 1,
		ExpiresAt:        time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
	}
}

func TestApprovalReservationConsumesOnlyAfterVerifiedExecution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	store := approval.NewStore()
	if err := store.Put(packet()); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve("approval-1", "request-1", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := store.Reserve("approval-1", "request-2", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != approval.ErrReserved {
		t.Fatalf("second reserve = %v, want ErrReserved", err)
	}
	if err := store.Commit("approval-1", "request-1"); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := store.Reserve("approval-1", "request-3", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != approval.ErrConsumed {
		t.Fatalf("reserve after commit = %v, want ErrConsumed", err)
	}
}

func TestApprovalReservationCanBeReleasedAfterProvenAbsence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	store := approval.NewStore()
	if err := store.Put(packet()); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve("approval-1", "request-1", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Release("approval-1", "request-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve("approval-1", "request-2", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
}

func TestApprovalExactBinding(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name, hash, repo, operation string
	}{
		{"changed manifest", "changed", "yaniv256/public", "pull_request.create"},
		{"changed destination", "manifest-hash", "other/public", "pull_request.create"},
		{"changed operation", "manifest-hash", "yaniv256/public", "issue.comment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := approval.NewStore()
			if err := store.Put(packet()); err != nil {
				t.Fatal(err)
			}
			if err := store.Reserve("approval-1", "request-1", tt.hash, tt.repo, tt.operation, 1, []string{"yaniv"}, now); err != approval.ErrBindingMismatch {
				t.Fatalf("consume = %v", err)
			}
		})
	}
}

func TestApprovalExpiryAndRevocation(t *testing.T) {
	t.Parallel()
	store := approval.NewStore()
	if err := store.Put(packet()); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve("approval-1", "request-1", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)); err != approval.ErrExpired {
		t.Fatalf("expired consume = %v", err)
	}
	store = approval.NewStore()
	if err := store.Put(packet()); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke("approval-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve("approval-1", "request-1", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)); err != approval.ErrRevoked {
		t.Fatalf("revoked consume = %v", err)
	}
}

func TestDuplicateNonceRejected(t *testing.T) {
	t.Parallel()
	store := approval.NewStore()
	one := packet()
	two := packet()
	two.ID = "approval-2"
	if err := store.Put(one); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(two); err != approval.ErrDuplicateNonce {
		t.Fatalf("put = %v", err)
	}
}

func TestExactApprovalRegistrationIsIdempotent(t *testing.T) {
	t.Parallel()
	store := approval.NewStore()
	value := packet()
	if err := store.Put(value); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(value); err != nil {
		t.Fatalf("exact retry = %v", err)
	}
	changed := value
	changed.ManifestHash = "changed"
	if err := store.Put(changed); err == nil {
		t.Fatal("changed packet reused an existing approval id")
	}
}

func TestUnlistedApproverAndOldPolicyGenerationRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		generation uint64
		approvers  []string
	}{{1, []string{"other"}}, {2, []string{"yaniv"}}} {
		store := approval.NewStore()
		if err := store.Put(packet()); err != nil {
			t.Fatal(err)
		}
		if err := store.Reserve("approval-1", "request-1", "manifest-hash", "yaniv256/public", "pull_request.create", tc.generation, tc.approvers, now); err != approval.ErrBindingMismatch {
			t.Fatalf("consume = %v", err)
		}
	}
}

func TestFailedPersistenceDoesNotPublishApprovalStateInMemory(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)

	t.Run("reserve", func(t *testing.T) {
		store, breakPersistence, restorePersistence := persistentStore(t)
		breakPersistence()
		if err := store.Reserve("approval-1", "request-1", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err == nil {
			t.Fatal("reserve unexpectedly succeeded while persistence was unavailable")
		}
		restorePersistence()
		if err := store.Reserve("approval-1", "request-2", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != nil {
			t.Fatalf("failed reserve leaked into memory: %v", err)
		}
	})

	t.Run("commit", func(t *testing.T) {
		store, breakPersistence, restorePersistence := persistentStore(t)
		if err := store.Reserve("approval-1", "request-1", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != nil {
			t.Fatal(err)
		}
		breakPersistence()
		if err := store.Commit("approval-1", "request-1"); err == nil {
			t.Fatal("commit unexpectedly succeeded while persistence was unavailable")
		}
		restorePersistence()
		if err := store.Commit("approval-1", "request-1"); err != nil {
			t.Fatalf("failed commit leaked into memory: %v", err)
		}
	})

	t.Run("release", func(t *testing.T) {
		store, breakPersistence, restorePersistence := persistentStore(t)
		if err := store.Reserve("approval-1", "request-1", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != nil {
			t.Fatal(err)
		}
		breakPersistence()
		if err := store.Release("approval-1", "request-1"); err == nil {
			t.Fatal("release unexpectedly succeeded while persistence was unavailable")
		}
		restorePersistence()
		if err := store.Reserve("approval-1", "request-2", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != approval.ErrReserved {
			t.Fatalf("failed release leaked into memory: %v", err)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		store, breakPersistence, restorePersistence := persistentStore(t)
		breakPersistence()
		if err := store.Revoke("approval-1"); err == nil {
			t.Fatal("revoke unexpectedly succeeded while persistence was unavailable")
		}
		restorePersistence()
		if err := store.Reserve("approval-1", "request-1", "manifest-hash", "yaniv256/public", "pull_request.create", 1, []string{"yaniv"}, now); err != nil {
			t.Fatalf("failed revoke leaked into memory: %v", err)
		}
	})
}

func persistentStore(t *testing.T) (*approval.Store, func(), func()) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "state")
	path := filepath.Join(directory, "approvals.json")
	store, err := approval.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(packet()); err != nil {
		t.Fatal(err)
	}
	broken := false
	breakPersistence := func() {
		t.Helper()
		if err := os.RemoveAll(directory); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(directory, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		broken = true
	}
	restorePersistence := func() {
		t.Helper()
		if !broken {
			return
		}
		if err := os.Remove(directory); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		broken = false
	}
	t.Cleanup(restorePersistence)
	return store, breakPersistence, restorePersistence
}
