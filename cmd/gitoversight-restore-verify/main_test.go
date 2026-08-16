package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	storagesqlite "github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func TestVerifyAssetsRequiresExactQuiescentBarrier(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "restore.db")
	db, err := storagesqlite.Open(ctx, storagesqlite.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root := mkdir(t, filepath.Join(t.TempDir(), "assets"))
	quarantine := mkdir(t, filepath.Join(t.TempDir(), "quarantine"))
	manifest := writeManifest(t, 1)

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.ExecContext(ctx, `UPDATE maintenance_barrier SET generation=1, state='draining' WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err := verifyAssets(ctx, db, root, manifest, quarantine); err == nil {
		t.Fatal("draining barrier was accepted as a quiescent snapshot")
	}
	if _, err := raw.ExecContext(ctx, `UPDATE maintenance_barrier SET state='quiescent' WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err := verifyAssets(ctx, db, root, manifest, quarantine); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAssetsRejectsSymlinkComponentsAndQuarantine(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "restore.db")
	db, err := storagesqlite.Open(ctx, storagesqlite.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.ExecContext(ctx, `UPDATE maintenance_barrier SET generation=1, state='quiescent' WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	manifest := writeManifest(t, 1)
	outside := mkdir(t, filepath.Join(t.TempDir(), "outside"))
	if err := os.WriteFile(filepath.Join(outside, "object"), []byte("escape"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := mkdir(t, filepath.Join(t.TempDir(), "assets"))
	if err := os.Symlink(outside, filepath.Join(root, "aa")); err != nil {
		t.Fatal(err)
	}
	quarantine := mkdir(t, filepath.Join(t.TempDir(), "quarantine"))
	if err := verifyAssets(ctx, db, root, manifest, quarantine); err == nil {
		t.Fatal("symlinked asset shard was accepted")
	}

	cleanRoot := mkdir(t, filepath.Join(t.TempDir(), "clean-assets"))
	quarantineLink := filepath.Join(t.TempDir(), "quarantine-link")
	if err := os.Symlink(outside, quarantineLink); err != nil {
		t.Fatal(err)
	}
	if err := verifyAssets(ctx, db, cleanRoot, manifest, quarantineLink); err == nil {
		t.Fatal("archive-controlled quarantine symlink was accepted")
	}
}

func writeManifest(t *testing.T, generation uint64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "release-assets.manifest.json")
	payload, err := json.Marshal(assetManifest{
		Version: 1, SchemaVersion: storagesqlite.CurrentSchemaVersion,
		BarrierGeneration: generation, Objects: []assetManifestObject{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mkdir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
