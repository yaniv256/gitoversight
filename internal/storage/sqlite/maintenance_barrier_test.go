package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

func TestMaintenanceBarrierBlocksNewAuthorityAndTracksActiveMaintenance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedCredential(t, db, "tenant-a", "zara-1")
	now := time.Unix(1_720_000_000, 0).UTC()
	stage := storage.StagedAsset{
		TenantID: "tenant-a", ID: "stage-before-barrier", AgentID: "zara", CredentialID: "zara-1",
		Repository: "yaniv256/private", Name: "bridge.zip", ContentType: "application/zip",
		ExpectedSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpectedSize:   1, ReservedSize: 1, State: storage.StagedAssetCreated,
		CapabilityHash:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CapabilityExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := db.WithTx(ctx, func(tx *Tx) error { return tx.PutStagedAsset(ctx, stage) }); err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.PutOperation(ctx, storage.Operation{
			TenantID: "tenant-a", ID: "operation-before-barrier", AgentID: "zara",
			Repository: "yaniv256/private", Kind: "branch.push", PacketHash: "packet-before",
			State: "authorized", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.BeginMaintenanceActivity(ctx, "release_asset_maintenance", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `
		UPDATE maintenance_barrier
		   SET generation = generation + 1, state = 'draining', updated_at = ?
		 WHERE singleton = 1 AND state = 'open'`, unix(now)); err != nil {
		t.Fatal(err)
	}

	var active int
	if err := db.sql.QueryRowContext(ctx, `
		SELECT active_count FROM maintenance_activity
		 WHERE kind = 'release_asset_maintenance'`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active maintenance = %d, want 1", active)
	}
	result, err := db.sql.ExecContext(ctx, `
		UPDATE maintenance_barrier SET state = 'quiescent'
		 WHERE singleton = 1 AND state = 'draining'
		   AND NOT EXISTS (SELECT 1 FROM maintenance_activity WHERE active_count <> 0)`)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 0 {
		t.Fatalf("quiescent while active: changed=%d err=%v", changed, err)
	}

	blockedStage := stage
	blockedStage.ID = "stage-during-barrier"
	if err := db.WithTx(ctx, func(tx *Tx) error { return tx.PutStagedAsset(ctx, blockedStage) }); err == nil {
		t.Fatal("staged asset issuance succeeded while barrier was draining")
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.BeginStagedAssetUpload(ctx, stage.TenantID, stage.ID, "temp", now.Add(time.Second))
	}); err == nil {
		t.Fatal("staged upload began while barrier was draining")
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.PutOperation(ctx, storage.Operation{
			TenantID: "tenant-a", ID: "operation-during-barrier", AgentID: "zara",
			Repository: "yaniv256/private", Kind: "branch.push", PacketHash: "packet",
			State: "authorized", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
	}); err == nil {
		t.Fatal("operation submission succeeded while barrier was draining")
	}
	if _, err := db.sql.ExecContext(ctx, `
		UPDATE operation_packets SET state = 'executing'
		 WHERE tenant_id = 'tenant-a' AND id = 'operation-before-barrier'`); err == nil {
		t.Fatal("operation execution began while barrier was draining")
	}
	if err := db.BeginMaintenanceActivity(ctx, "release_asset_maintenance", now); err == nil {
		t.Fatal("maintenance activity began while barrier was draining")
	}

	if err := db.EndMaintenanceActivity(ctx, "release_asset_maintenance", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	result, err = db.sql.ExecContext(ctx, `
		UPDATE maintenance_barrier SET state = 'quiescent'
		 WHERE singleton = 1 AND state = 'draining'
		   AND NOT EXISTS (SELECT 1 FROM maintenance_activity WHERE active_count <> 0)`)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		t.Fatalf("quiescent after drain: changed=%d err=%v", changed, err)
	}
}
