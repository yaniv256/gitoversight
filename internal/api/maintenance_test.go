package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

type maintenanceStore struct {
	claimCalls    int
	completeCalls int
	failCalls     int
}

func (*maintenanceStore) BeginMaintenanceActivity(context.Context, string, time.Time) error {
	return nil
}
func (*maintenanceStore) EndMaintenanceActivity(context.Context, string, time.Time) error { return nil }

func (s *maintenanceStore) ClaimStagedAssetCleanup(context.Context, time.Time, time.Time, time.Time) (storage.StagedAssetCleanup, bool, error) {
	s.claimCalls++
	if s.claimCalls == 1 {
		return storage.StagedAssetCleanup{TenantID: "tenant-a", StageID: "stage-a", ObjectKey: "key-a"}, true, nil
	}
	return storage.StagedAssetCleanup{}, false, nil
}
func (s *maintenanceStore) CompleteStagedAssetCleanup(context.Context, storage.StagedAssetCleanup) error {
	s.completeCalls++
	return nil
}
func (s *maintenanceStore) FailStagedAssetCleanup(context.Context, storage.StagedAssetCleanup, string, time.Time) error {
	s.failCalls++
	return nil
}
func (*maintenanceStore) PruneExpiredEmptyStages(context.Context, time.Time) (int64, error) {
	return 0, nil
}
func (*maintenanceStore) StaleUploadingStages(context.Context, time.Time) ([]storage.StagedAsset, error) {
	return nil, nil
}
func (*maintenanceStore) RecoverStagedAssetReady(context.Context, string, string, string, time.Time) error {
	return nil
}
func (*maintenanceStore) ExpireStaleUploadingStage(context.Context, string, string, time.Time) error {
	return nil
}
func (*maintenanceStore) StagedAssetObjectKeys(context.Context) (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}
func (*maintenanceStore) MaintenanceOpen(context.Context) (bool, uint64, error) {
	return true, 0, nil
}

type maintenanceFiles struct{ removeErr error }

func (*maintenanceFiles) Open(context.Context, string, string, int64, string) (releaseasset.ReadSeekCloser, error) {
	return nil, releaseasset.ErrObjectNotFound
}
func (*maintenanceFiles) ObjectKey(string, string) string { return "key-a" }
func (f *maintenanceFiles) Remove(string, string, string) error {
	return f.removeErr
}
func (*maintenanceFiles) CleanupTemps(time.Time) (int, error) { return 0, nil }
func (*maintenanceFiles) CleanupOrphanObjects(map[string]struct{}, time.Time) (int, error) {
	return 0, nil
}

func TestReleaseAssetMaintenanceFailedUnlinkIsRetriedWithoutCompletingClaim(t *testing.T) {
	store := &maintenanceStore{}
	files := &maintenanceFiles{removeErr: errors.New("disk refused unlink")}
	maintenance, err := NewReleaseAssetMaintenance(store, files, ReleaseAssetMaintenanceConfig{
		TerminalGrace: time.Hour, ClaimTimeout: time.Minute, UploadTimeout: time.Minute,
		OrphanGrace: time.Hour, MaxDeletes: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := maintenance.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if store.failCalls != 1 || store.completeCalls != 0 || store.claimCalls != 2 {
		t.Fatalf("claims=%d failures=%d completions=%d", store.claimCalls, store.failCalls, store.completeCalls)
	}
}
