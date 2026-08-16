package sqlite_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func TestStagedAssetCleanupClaimsOnlyGraceAgedTerminalPinsAndRecoversCrash(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "cleanup.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Unix(2_000_000_000, 0).UTC()
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.EnsureTenant(ctx, "tenant-a", now); err != nil {
			return err
		}
		if err := tx.EnsureAgent(ctx, "tenant-a", "zara", now); err != nil {
			return err
		}
		for _, item := range []struct{ id, state string }{{"terminal", "verified"}, {"live", "indeterminate"}} {
			if err := tx.PutOperation(ctx, storage.Operation{
				TenantID: "tenant-a", ID: "op-" + item.id, AgentID: "zara",
				Repository: "yaniv256/private", Kind: "release.asset.upload",
				PacketHash: "packet-" + item.id, State: item.state, PolicyGeneration: 1,
				CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-48 * time.Hour),
				ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				return err
			}
			stage := storage.StagedAsset{
				TenantID: "tenant-a", ID: "stage-" + item.id, AgentID: "zara",
				CredentialID: "cred", Repository: "yaniv256/private", Name: item.id + ".zip",
				ContentType: "application/zip", ExpectedSHA256: strings.Repeat("0", 64),
				ExpectedSize: 8, ReservedSize: 8, State: storage.StagedAssetCreated,
				CapabilityHash: "cap-" + item.id, CapabilityExpiresAt: now.Add(time.Hour),
				CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-48 * time.Hour),
				ExpiresAt: now.Add(time.Hour),
			}
			if err := tx.PutStagedAsset(ctx, stage); err != nil {
				return err
			}
			if err := tx.BeginStagedAssetUpload(ctx, stage.TenantID, stage.ID, "temp-"+item.id, now.Add(-47*time.Hour)); err != nil {
				return err
			}
			if err := tx.MarkStagedAssetReady(ctx, stage.TenantID, stage.ID, "object-"+item.id, now.Add(-46*time.Hour)); err != nil {
				return err
			}
			stage.State = storage.StagedAssetReady
			if err := tx.PinStagedAsset(ctx, stage, "op-"+item.id, now.Add(-45*time.Hour)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	type claimResult struct {
		claim storage.StagedAssetCleanup
		found bool
		err   error
	}
	results := make(chan claimResult, 2)
	for range 2 {
		go func() {
			claim, found, err := db.ClaimStagedAssetCleanup(ctx, now, now.Add(-24*time.Hour), now.Add(-time.Hour))
			results <- claimResult{claim: claim, found: found, err: err}
		}()
	}
	var claim storage.StagedAssetCleanup
	winners := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.found {
			winners++
			claim = result.claim
		}
	}
	if winners != 1 || claim.StageID != "stage-terminal" {
		t.Fatalf("cleanup claim winners = %d, claim = %#v", winners, claim)
	}
	// Simulate a crash after claim. A later sweep reclaims the same work.
	reclaimed, found, err := db.ClaimStagedAssetCleanup(ctx, now.Add(2*time.Hour), now.Add(-22*time.Hour), now.Add(time.Hour))
	if err != nil || !found || reclaimed.StageID != claim.StageID || reclaimed.Attempts != 1 {
		t.Fatalf("reclaim = %#v, found = %v, err = %v", reclaimed, found, err)
	}
	if err := db.CompleteStagedAssetCleanup(ctx, reclaimed); err != nil {
		t.Fatal(err)
	}
	if _, found, err := db.ClaimStagedAssetCleanup(ctx, now.Add(3*time.Hour), now, now.Add(2*time.Hour)); err != nil || found {
		t.Fatalf("live indeterminate stage became collectable: found=%v err=%v", found, err)
	}
	op, err := db.Operation(ctx, "tenant-a", "op-terminal")
	if err != nil || op.State != "verified" {
		t.Fatalf("terminal operation changed: %#v err=%v", op, err)
	}
}
