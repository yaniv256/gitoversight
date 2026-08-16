package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

type ReleaseAssetMaintenanceStore interface {
	ClaimStagedAssetCleanup(context.Context, time.Time, time.Time, time.Time) (storage.StagedAssetCleanup, bool, error)
	CompleteStagedAssetCleanup(context.Context, storage.StagedAssetCleanup) error
	FailStagedAssetCleanup(context.Context, storage.StagedAssetCleanup, string, time.Time) error
	PruneExpiredEmptyStages(context.Context, time.Time) (int64, error)
	StaleUploadingStages(context.Context, time.Time) ([]storage.StagedAsset, error)
	RecoverStagedAssetReady(context.Context, string, string, string, time.Time) error
	ExpireStaleUploadingStage(context.Context, string, string, time.Time) error
	StagedAssetObjectKeys(context.Context) (map[string]struct{}, error)
	MaintenanceOpen(context.Context) (bool, uint64, error)
	BeginMaintenanceActivity(context.Context, string, time.Time) error
	EndMaintenanceActivity(context.Context, string, time.Time) error
}

type ReleaseAssetMaintenanceFiles interface {
	releaseasset.BlobReader
	ObjectKey(string, string) string
	Remove(string, string, string) error
	CleanupTemps(time.Time) (int, error)
	CleanupOrphanObjects(map[string]struct{}, time.Time) (int, error)
}

type ReleaseAssetMaintenanceConfig struct {
	TerminalGrace time.Duration
	ClaimTimeout  time.Duration
	UploadTimeout time.Duration
	OrphanGrace   time.Duration
	MaxDeletes    int
}

type ReleaseAssetMaintenance struct {
	store  ReleaseAssetMaintenanceStore
	files  ReleaseAssetMaintenanceFiles
	config ReleaseAssetMaintenanceConfig
}

func NewReleaseAssetMaintenance(store ReleaseAssetMaintenanceStore, files ReleaseAssetMaintenanceFiles, config ReleaseAssetMaintenanceConfig) (*ReleaseAssetMaintenance, error) {
	if store == nil || files == nil || config.TerminalGrace <= 0 || config.ClaimTimeout <= 0 ||
		config.UploadTimeout <= 0 || config.OrphanGrace <= 0 || config.MaxDeletes <= 0 {
		return nil, errors.New("release asset maintenance configuration is incomplete")
	}
	return &ReleaseAssetMaintenance{store: store, files: files, config: config}, nil
}

// RunOnce performs bounded repair before deletion. It deliberately has no
// backup-barrier logic: U6b must supply a persisted barrier before backup can
// run concurrently with this maintenance worker.
func (m *ReleaseAssetMaintenance) RunOnce(ctx context.Context, now time.Time) error {
	now = now.UTC()
	if err := m.store.BeginMaintenanceActivity(ctx, "release_asset_maintenance", now); err != nil {
		return nil
	}
	defer func() {
		_ = m.store.EndMaintenanceActivity(context.Background(), "release_asset_maintenance", time.Now().UTC())
	}()
	uploadCutoff := now.Add(-m.config.UploadTimeout)
	staleUploads, err := m.store.StaleUploadingStages(ctx, uploadCutoff)
	if err != nil {
		return err
	}
	for _, stage := range staleUploads {
		source, openErr := m.files.Open(ctx, stage.TenantID, stage.ID, stage.ExpectedSize, stage.ExpectedSHA256)
		switch {
		case openErr == nil:
			_ = source.Close()
			if err := m.store.RecoverStagedAssetReady(ctx, stage.TenantID, stage.ID, m.files.ObjectKey(stage.TenantID, stage.ID), now); err != nil {
				return err
			}
		case errors.Is(openErr, releaseasset.ErrObjectNotFound):
			if err := m.store.ExpireStaleUploadingStage(ctx, stage.TenantID, stage.ID, now); err != nil {
				return err
			}
		default:
			// Corrupt or unsafe published bytes are evidence, not an orphan.
			return fmt.Errorf("staged asset repair requires intervention: %w", openErr)
		}
	}
	if _, err := m.store.PruneExpiredEmptyStages(ctx, now); err != nil {
		return err
	}
	if _, err := m.files.CleanupTemps(uploadCutoff); err != nil {
		return err
	}
	for count := 0; count < m.config.MaxDeletes; count++ {
		claim, found, err := m.store.ClaimStagedAssetCleanup(
			ctx, now, now.Add(-m.config.TerminalGrace), now.Add(-m.config.ClaimTimeout))
		if err != nil {
			return err
		}
		if !found {
			break
		}
		open, _, err := m.store.MaintenanceOpen(ctx)
		if err != nil {
			return err
		}
		if !open {
			if failErr := m.store.FailStagedAssetCleanup(ctx, claim, "maintenance barrier active", now); failErr != nil {
				return failErr
			}
			return nil
		}
		if err := m.files.Remove(claim.TenantID, claim.StageID, claim.ObjectKey); err != nil {
			if failErr := m.store.FailStagedAssetCleanup(ctx, claim, err.Error(), now); failErr != nil {
				return errors.Join(err, failErr)
			}
			continue
		}
		if err := m.store.CompleteStagedAssetCleanup(ctx, claim); err != nil {
			// The object is already absent; the persisted claim is intentionally
			// left for stale-claim recovery and idempotent unlink on the next run.
			return err
		}
	}
	live, err := m.store.StagedAssetObjectKeys(ctx)
	if err != nil {
		return err
	}
	_, err = m.files.CleanupOrphanObjects(live, now.Add(-m.config.OrphanGrace))
	return err
}
