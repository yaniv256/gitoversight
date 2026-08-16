package releaseasset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFileStorePublishesAndReopensVerifiedStageObject(t *testing.T) {
	t.Parallel()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("native bridge bytes")
	digest := sha256Hex(payload)

	object, err := store.Publish(context.Background(), "tenant-a", "stage-a", int64(len(payload)), digest, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if object.Size != int64(len(payload)) || object.SHA256 != digest {
		t.Fatalf("object = %+v", object)
	}

	reader, err := store.Open(context.Background(), "tenant-a", "stage-a", int64(len(payload)), digest)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestFileStoreRejectsLengthDigestAndSecondPublication(t *testing.T) {
	t.Parallel()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	digest := sha256Hex(payload)
	tests := []struct {
		name string
		size int64
		hash string
		body []byte
	}{
		{name: "short", size: int64(len(payload) + 1), hash: digest, body: payload},
		{name: "long", size: int64(len(payload) - 1), hash: digest, body: payload},
		{name: "digest", size: int64(len(payload)), hash: sha256Hex([]byte("different")), body: payload},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := store.Publish(context.Background(), "tenant-a", "stage-"+test.name, test.size, test.hash, bytes.NewReader(test.body)); err == nil {
				t.Fatal("invalid object was published")
			}
			if _, err := store.Open(context.Background(), "tenant-a", "stage-"+test.name, test.size, test.hash); !errors.Is(err, ErrObjectNotFound) {
				t.Fatalf("Open error = %v, want ErrObjectNotFound", err)
			}
		})
	}

	if _, err := store.Publish(context.Background(), "tenant-a", "stage-once", int64(len(payload)), digest, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(context.Background(), "tenant-a", "stage-once", int64(len(payload)), digest, bytes.NewReader(payload)); !errors.Is(err, ErrObjectExists) {
		t.Fatalf("second Publish error = %v, want ErrObjectExists", err)
	}
}

func TestFileStoreRejectsSymlinkAndNonRegularObjects(t *testing.T) {
	t.Parallel()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	digest := sha256Hex(payload)
	path := store.objectPath("tenant-a", "stage-a")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(context.Background(), "tenant-a", "stage-a", int64(len(payload)), digest); !errors.Is(err, ErrUnsafeObject) {
		t.Fatalf("symlink Open error = %v, want ErrUnsafeObject", err)
	}
}

func TestFileStoreDoesNotDeduplicateSeparateStages(t *testing.T) {
	t.Parallel()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("same bytes")
	digest := sha256Hex(payload)
	first, err := store.Publish(context.Background(), "tenant-a", "stage-a", int64(len(payload)), digest, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Publish(context.Background(), "tenant-a", "stage-b", int64(len(payload)), digest, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if first.Key == second.Key {
		t.Fatalf("separate logical stages shared object key %q", first.Key)
	}
}

func TestFileStorePublishesEmptyAssetAndFinalObjectIsReadOnly(t *testing.T) {
	t.Parallel()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Hex(nil)
	if _, err := store.Publish(context.Background(), "tenant-a", "stage-empty", 0, digest, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.objectPath("tenant-a", "stage-empty"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o220 != 0 {
		t.Fatalf("published object mode = %o, want no write bits", info.Mode().Perm())
	}
	reader, err := store.Open(context.Background(), "tenant-a", "stage-empty", 0, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
}

func TestFileStoreUsesGroupTraversableDirectoriesAndReadOnlyWorkerSurface(t *testing.T) {
	root := filepath.Join(t.TempDir(), "managed")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if rootInfo.Mode().Perm() != 0o750 || rootInfo.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("root mode = %v (%o), want setgid 0750", rootInfo.Mode(), rootInfo.Mode().Perm())
	}
	payload := []byte("group-readable")
	digest := sha256Hex(payload)
	if _, err := store.Publish(context.Background(), "tenant-a", "stage-a", int64(len(payload)), digest, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	objectPath := store.objectPath("tenant-a", "stage-a")
	for directory := filepath.Dir(objectPath); directory != root; directory = filepath.Dir(directory) {
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o050 != 0o050 || info.Mode().Perm()&0o002 != 0 {
			t.Fatalf("shard mode = %o, want group read/traverse and no other write", info.Mode().Perm())
		}
	}
	info, err := os.Stat(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o440 {
		t.Fatalf("object mode = %o, want 0440", info.Mode().Perm())
	}
	reader, err := NewFileReader(root)
	if err != nil {
		t.Fatal(err)
	}
	var workerSurface BlobReader = reader
	opened, err := workerSurface.Open(context.Background(), "tenant-a", "stage-a", int64(len(payload)), digest)
	if err != nil {
		t.Fatal(err)
	}
	opened.Close()
}

func TestFileStoreRepairsShardModesUnderRestrictiveServiceUmask(t *testing.T) {
	if os.Getenv("GITOVERSIGHT_UMASK_HELPER") == "1" {
		syscall.Umask(0o077)
		root := os.Getenv("GITOVERSIGHT_UMASK_ROOT")
		store, err := NewFileStore(root)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte("service-umask")
		if _, err := store.Publish(context.Background(), "tenant-a", "stage-a", int64(len(payload)), sha256Hex(payload), bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
		for directory := filepath.Dir(store.objectPath("tenant-a", "stage-a")); directory != root; directory = filepath.Dir(directory) {
			info, err := os.Lstat(directory)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o750 || info.Mode()&os.ModeSetgid == 0 {
				t.Fatalf("shard mode = %v (%o), want setgid 0750", info.Mode(), info.Mode().Perm())
			}
		}
		return
	}

	root := filepath.Join(t.TempDir(), "managed")
	command := exec.Command(os.Args[0], "-test.run=^TestFileStoreRepairsShardModesUnderRestrictiveServiceUmask$")
	command.Env = append(os.Environ(), "GITOVERSIGHT_UMASK_HELPER=1", "GITOVERSIGHT_UMASK_ROOT="+root)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("restrictive-umask subprocess failed: %v\n%s", err, output)
	}
}

func TestFileStoreRemoveIsBindingCheckedAndIdempotent(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("cleanup")
	digest := sha256Hex(payload)
	object, err := store.Publish(context.Background(), "tenant-a", "stage-a", int64(len(payload)), digest, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("tenant-a", "stage-a", strings.Repeat("0", 64)); !errors.Is(err, ErrUnsafeObject) {
		t.Fatalf("wrong-key remove = %v", err)
	}
	if _, err := store.Open(context.Background(), "tenant-a", "stage-a", int64(len(payload)), digest); err != nil {
		t.Fatalf("wrong-key remove changed object: %v", err)
	}
	if err := store.Remove("tenant-a", "stage-a", object.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("tenant-a", "stage-a", object.Key); err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
}

func TestReleaseAssetReadinessChecksRoleCapabilitiesWithoutLeavingArtifacts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "assets")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriterReadiness(0); err != nil {
		t.Fatalf("writer readiness: %v", err)
	}
	reader, err := NewFileReader(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.ReaderReadiness(); err != nil {
		t.Fatalf("reader readiness: %v", err)
	}
	if store.RootID() == "" || store.RootID() != reader.RootID() {
		t.Fatalf("root ids differ: writer=%q reader=%q", store.RootID(), reader.RootID())
	}
	if err := store.WriterReadiness(^uint64(0)); err == nil {
		t.Fatal("impossible free-space floor was accepted")
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("readiness left probe files: entries=%v err=%v", entries, err)
	}
	if err := os.Rename(root, root+".offline"); err != nil {
		t.Fatal(err)
	}
	if err := store.WriterReadiness(0); err == nil {
		t.Fatal("writer accepted a missing configured root")
	}
	if err := reader.ReaderReadiness(); err == nil {
		t.Fatal("reader accepted a missing configured root")
	}
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
