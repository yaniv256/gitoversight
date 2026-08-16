package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

func TestStagedAssetMetadataLifecycleIsOwnerScopedAndTransactional(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedCredential(t, db, "tenant-a", "zara-1")
	now := time.Unix(1_720_000_000, 0).UTC()
	asset := storage.StagedAsset{
		TenantID: "tenant-a", ID: "stage-a", AgentID: "zara", CredentialID: "zara-1",
		Repository: "yaniv256/private", Name: "bridge.zip", ContentType: "application/zip",
		ExpectedSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpectedSize:   15 << 20, ReservedSize: 15 << 20, State: storage.StagedAssetCreated,
		CapabilityHash:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CapabilityExpiresAt: now.Add(10 * time.Minute), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := db.WithTx(ctx, func(tx *Tx) error { return tx.PutStagedAsset(ctx, asset) }); err != nil {
		t.Fatal(err)
	}

	got, err := db.StagedAssetForOwner(ctx, "tenant-a", "stage-a", "zara", "zara-1", "yaniv256/private")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != storage.StagedAssetCreated || got.ExpectedSize != asset.ExpectedSize {
		t.Fatalf("stage = %+v", got)
	}
	if _, err := db.StagedAssetForOwner(ctx, "tenant-a", "stage-a", "other", "zara-1", "yaniv256/private"); !errors.Is(err, storage.ErrStagedAssetNotFound) {
		t.Fatalf("foreign lookup error = %v, want opaque not found", err)
	}

	if err := db.WithTx(ctx, func(tx *Tx) error {
		if err := tx.BeginStagedAssetUpload(ctx, "tenant-a", "stage-a", "temp-a", now.Add(time.Second)); err != nil {
			return err
		}
		return errors.New("checkpoint unavailable")
	}); err == nil {
		t.Fatal("expected rollback sentinel")
	}
	got, err = db.StagedAssetForOwner(ctx, "tenant-a", "stage-a", "zara", "zara-1", "yaniv256/private")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != storage.StagedAssetCreated || got.TempID != "" {
		t.Fatalf("rolled-back stage = %+v", got)
	}

	if err := db.WithTx(ctx, func(tx *Tx) error {
		if err := tx.BeginStagedAssetUpload(ctx, "tenant-a", "stage-a", "temp-a", now.Add(time.Second)); err != nil {
			return err
		}
		return tx.MarkStagedAssetReady(ctx, "tenant-a", "stage-a", "object-a", now.Add(2*time.Second))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.PutOperation(ctx, storage.Operation{
			TenantID: "tenant-a", ID: "operation-a", AgentID: "zara", Repository: "yaniv256/private",
			Kind: "release.asset.upload", PacketHash: "packet-a", State: "authorized",
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.PinStagedAsset(ctx, asset, "operation-a", now.Add(3*time.Second))
	}); err != nil {
		t.Fatal(err)
	}
	got, err = db.StagedAssetForOwner(ctx, "tenant-a", "stage-a", "zara", "zara-1", "yaniv256/private")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != storage.StagedAssetPinned || got.OperationID != "operation-a" || got.ReservedSize != 0 {
		t.Fatalf("pinned stage = %+v", got)
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.AbandonStagedAsset(ctx, "tenant-a", "stage-a", now.Add(4*time.Second))
	}); !errors.Is(err, storage.ErrStagedAssetState) {
		t.Fatalf("abandon pinned error = %v, want ErrStagedAssetState", err)
	}
}

func TestPinStagedAssetChecksExactReadyOwnerRepositoryMetadataAndExpiry(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedCredential(t, db, "tenant-a", "zara-1")
	now := time.Unix(1_720_000_000, 0).UTC()
	asset := storage.StagedAsset{
		TenantID: "tenant-a", ID: "stage-exact", AgentID: "zara", CredentialID: "zara-1",
		Repository: "yaniv256/private", Name: "bridge.zip", ContentType: "application/zip",
		ExpectedSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpectedSize:   42, ReservedSize: 42, State: storage.StagedAssetCreated,
		CapabilityHash: "exact-capability", CapabilityExpiresAt: now.Add(time.Minute),
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		if err := tx.PutStagedAsset(ctx, asset); err != nil {
			return err
		}
		if err := tx.BeginStagedAssetUpload(ctx, asset.TenantID, asset.ID, "tmp", now.Add(time.Second)); err != nil {
			return err
		}
		return tx.MarkStagedAssetReady(ctx, asset.TenantID, asset.ID, "object", now.Add(2*time.Second))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.PutOperation(ctx, storage.Operation{
			TenantID: asset.TenantID, ID: "operation-exact", AgentID: asset.AgentID,
			Repository: asset.Repository, Kind: "release.asset.upload", PacketHash: "packet-exact",
			State: "authorized", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
	}); err != nil {
		t.Fatal(err)
	}

	tampered := asset
	tampered.ExpectedSize++
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.PinStagedAsset(ctx, tampered, "operation-exact", now.Add(3*time.Second))
	}); !errors.Is(err, storage.ErrStagedAssetState) {
		t.Fatalf("tampered pin error = %v", err)
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.PinStagedAsset(ctx, asset, "operation-exact", now.Add(3*time.Second))
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOneOperationMayPinMultipleReleaseAssets(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	seedTenant(t, db, "tenant-a")
	seedCredential(t, db, "tenant-a", "zara-1")
	assets := []storage.StagedAsset{
		{TenantID: "tenant-a", ID: "stage-a", AgentID: "zara", CredentialID: "zara-1", Repository: "yaniv256/private", Name: "linux.tar.gz", ContentType: "application/gzip", ExpectedSHA256: strings.Repeat("a", 64), ExpectedSize: 42, ReservedSize: 42, State: storage.StagedAssetCreated, CapabilityHash: "cap-a", CapabilityExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(24 * time.Hour)},
		{TenantID: "tenant-a", ID: "stage-b", AgentID: "zara", CredentialID: "zara-1", Repository: "yaniv256/private", Name: "mac.tar.gz", ContentType: "application/gzip", ExpectedSHA256: strings.Repeat("b", 64), ExpectedSize: 84, ReservedSize: 84, State: storage.StagedAssetCreated, CapabilityHash: "cap-b", CapabilityExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(24 * time.Hour)},
	}
	err := db.WithTx(ctx, func(tx *Tx) error {
		if err := tx.PutOperation(ctx, storage.Operation{TenantID: "tenant-a", ID: "bundle-op", AgentID: "zara", Repository: "yaniv256/private", Kind: "release.assets.upload", PacketHash: "packet", State: "authorized", PolicyGeneration: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), UpdatedAt: now}); err != nil {
			return err
		}
		for _, asset := range assets {
			if err := tx.PutStagedAsset(ctx, asset); err != nil {
				return err
			}
			if err := tx.BeginStagedAssetUpload(ctx, asset.TenantID, asset.ID, "temp-"+asset.ID, now.Add(time.Second)); err != nil {
				return err
			}
			if err := tx.MarkStagedAssetReady(ctx, asset.TenantID, asset.ID, "object-"+asset.ID, now.Add(2*time.Second)); err != nil {
				return err
			}
			if err := tx.PinStagedAsset(ctx, asset, "bundle-op", now.Add(3*time.Second)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("pin bundle: %v", err)
	}
	for _, asset := range assets {
		stored, err := db.StagedAssetForOwner(ctx, asset.TenantID, asset.ID, asset.AgentID, asset.CredentialID, asset.Repository)
		if err != nil || stored.OperationID != "bundle-op" || stored.State != storage.StagedAssetPinned {
			t.Fatalf("stage %s = %#v, %v", asset.ID, stored, err)
		}
	}
}

func TestStagedAssetMigrationContainsMetadataOnly(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	for _, table := range []string{"staged_assets"} {
		if !hasTable(t, db, table) {
			t.Fatalf("missing table %q", table)
		}
	}
	rows, err := db.sql.Query(`PRAGMA table_info(staged_assets)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if typ == "BLOB" {
			t.Fatalf("staged_assets contains binary column %q", name)
		}
	}
}

func TestStagedAssetAcceptsZeroByteRelease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedCredential(t, db, "tenant-a", "zara-1")
	now := time.Unix(1_720_000_000, 0).UTC()
	asset := storage.StagedAsset{
		TenantID: "tenant-a", ID: "stage-empty", AgentID: "zara", CredentialID: "zara-1",
		Repository: "yaniv256/private", Name: "empty.bin", ContentType: "application/octet-stream",
		ExpectedSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		State:          storage.StagedAssetCreated, CapabilityHash: "empty-capability",
		CapabilityExpiresAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := db.WithTx(ctx, func(tx *Tx) error { return tx.PutStagedAsset(ctx, asset) }); err != nil {
		t.Fatal(err)
	}
}
