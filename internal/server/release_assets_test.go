package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type stagedAssetWriteGate struct {
	verifyErr error
	commitErr error
}

func (gate stagedAssetWriteGate) Verify() error { return gate.verifyErr }
func (gate stagedAssetWriteGate) Commit(context.Context, string) error {
	return gate.commitErr
}

func TestStagedAssetAuthorityFailsClosedBeforeMutationWhenCheckpointUnavailable(t *testing.T) {
	ctx := context.Background()
	db := openDurableDB(t)
	seedStagedAssetCredential(t, db)
	broker := NewDurableBroker(db)
	broker.SetWriteGate(stagedAssetWriteGate{verifyErr: errors.New("checkpoint unavailable")})
	stage := testStagedAsset()
	if err := broker.CreateStagedAsset(ctx, stage); err == nil {
		t.Fatal("create succeeded without checkpoint verification")
	}
	if _, err := db.StagedAssetForOwner(ctx, stage.TenantID, stage.ID, stage.AgentID, stage.CredentialID, stage.Repository); !errors.Is(err, storage.ErrStagedAssetNotFound) {
		t.Fatalf("stage lookup error = %v", err)
	}
}

func TestStagedAssetAuthorityReportsCommitFailureAfterMetadataOnlyTransition(t *testing.T) {
	ctx := context.Background()
	db := openDurableDB(t)
	seedStagedAssetCredential(t, db)
	broker := NewDurableBroker(db)
	broker.SetWriteGate(stagedAssetWriteGate{commitErr: errors.New("checkpoint commit failed")})
	stage := testStagedAsset()
	if err := broker.CreateStagedAsset(ctx, stage); err == nil || !strings.Contains(err.Error(), "checkpoint commit failed") {
		t.Fatalf("create error = %v", err)
	}
	got, err := db.StagedAssetForOwner(ctx, stage.TenantID, stage.ID, stage.AgentID, stage.CredentialID, stage.Repository)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != storage.StagedAssetCreated {
		t.Fatalf("state = %s", got.State)
	}
	events, err := db.AuthorityAuditEvents(ctx, stage.TenantID, stage.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "staged_asset_created" ||
		strings.Contains(string(events[0].PayloadJSON), stage.CapabilityHash) {
		t.Fatalf("audit events = %+v", events)
	}
}

func TestStagedAssetUploadCheckpointFailureConsumesNeitherNonceNorStage(t *testing.T) {
	ctx := context.Background()
	db := openDurableDB(t)
	seedStagedAssetCredential(t, db)
	broker := NewDurableBroker(db)
	broker.SetWriteGate(stagedAssetWriteGate{})
	stage := testStagedAsset()
	if err := broker.CreateStagedAsset(ctx, stage); err != nil {
		t.Fatal(err)
	}
	broker.SetWriteGate(stagedAssetWriteGate{verifyErr: errors.New("checkpoint unavailable")})
	nonceExpiry := stage.CreatedAt.Add(time.Hour)
	if err := broker.BeginStagedAssetUpload(ctx, stage, "attempt-1", "nonce-1", nonceExpiry, stage.CreatedAt.Add(time.Second)); err == nil {
		t.Fatal("upload began without checkpoint verification")
	}
	got, err := db.StagedAssetForOwner(ctx, stage.TenantID, stage.ID, stage.AgentID, stage.CredentialID, stage.Repository)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != storage.StagedAssetCreated || got.CapabilityUsedAt != nil {
		t.Fatalf("stage after failed checkpoint = %+v", got)
	}
	broker.SetWriteGate(stagedAssetWriteGate{})
	if err := broker.BeginStagedAssetUpload(ctx, stage, "attempt-2", "nonce-1", nonceExpiry, stage.CreatedAt.Add(2*time.Second)); err != nil {
		t.Fatalf("same nonce was consumed by rejected request: %v", err)
	}
}

func seedStagedAssetCredential(t *testing.T, db *sqlite.DB) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.PutAgentCredential(context.Background(), storage.AgentCredential{
			TenantID: "tenant-a", AgentID: "zara", ID: "zara-1",
			PublicKey: make([]byte, 32), CreatedAt: now, ApprovedAt: now, ApprovedBy: "yaniv",
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func testStagedAsset() releaseasset.Stage {
	now := time.Unix(1_780_000_000, 0).UTC()
	return releaseasset.Stage{
		TenantID: "tenant-a", ID: "stage-authority", AgentID: "zara", CredentialID: "zara-1",
		Repository: "yaniv256/private", Name: "bridge.zip", ContentType: "application/zip",
		ExpectedSHA256: strings.Repeat("a", 64), ExpectedSize: 1024, ReservedSize: 1024,
		State: releaseasset.StateCreated, CapabilityHash: strings.Repeat("b", 64),
		CapabilityExpiresAt: now.Add(10 * time.Minute), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}
