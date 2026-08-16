package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/checkpoint"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func main() {
	database := flag.String("database", "", "restored SQLite database")
	statePath := flag.String("checkpoint-state", "", "restored signed checkpoint")
	keyPath := flag.String("checkpoint-key", "", "checkpoint HMAC key")
	tenant := flag.String("tenant", "", "expected tenant")
	assetRoot := flag.String("asset-root", "", "restored staged asset root")
	assetManifest := flag.String("asset-manifest", "", "restored staged asset manifest")
	quarantine := flag.String("quarantine", "", "directory for unreferenced restored objects")
	flag.Parse()
	if *database == "" || *statePath == "" || *keyPath == "" || *tenant == "" ||
		*assetRoot == "" || *assetManifest == "" || *quarantine == "" {
		fatal("database, checkpoint-state, checkpoint-key, tenant, asset-root, asset-manifest, and quarantine are required")
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		fatal("read checkpoint key: %v", err)
	}
	signer, err := checkpoint.Open(*statePath, key)
	zero(key)
	if err != nil {
		fatal("verify checkpoint signature: %v", err)
	}
	state := signer.State()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: *database})
	if err != nil {
		fatal("open restored database: %v", err)
	}
	defer db.Close()
	if err := db.VerifyAuthorityAuditChain(ctx, *tenant); err != nil {
		fatal("verify restored audit chain: %v", err)
	}
	policy, err := db.LatestPolicyGeneration(ctx, *tenant)
	if err != nil {
		fatal("read restored policy generation: %v", err)
	}
	events, err := db.AuthorityAuditTrail(ctx, *tenant)
	if err != nil {
		fatal("read restored audit trail: %v", err)
	}
	tail := "GENESIS"
	if len(events) != 0 {
		tail = events[len(events)-1].Hash
	}
	if state.Tail != tail || state.PolicyGeneration != policy.Generation {
		fatal("signed checkpoint does not bind restored authority state")
	}
	if state.Sequence == 0 || state.Signature == "" {
		fatal("restored checkpoint is unsigned")
	}
	if err := verifyAssets(ctx, db, *assetRoot, *assetManifest, *quarantine); err != nil {
		fatal("verify staged assets: %v", err)
	}
	fmt.Println("restored authority chain, signed checkpoint, and staged assets verified")
}

type assetManifest struct {
	Version           int                   `json:"version"`
	SchemaVersion     int                   `json:"schema_version"`
	BarrierGeneration uint64                `json:"barrier_generation"`
	Objects           []assetManifestObject `json:"objects"`
}

type assetManifestObject struct {
	Key    string `json:"key"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func verifyAssets(ctx context.Context, db *sqlite.DB, root, manifestPath, quarantine string) error {
	if err := requireSecureDirectory(root, false); err != nil {
		return fmt.Errorf("asset root: %w", err)
	}
	if err := requireSecureDirectory(quarantine, true); err != nil {
		return fmt.Errorf("quarantine: %w", err)
	}
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest assetManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return err
	}
	if manifest.Version != 1 || manifest.SchemaVersion != sqlite.CurrentSchemaVersion || manifest.BarrierGeneration == 0 {
		return fmt.Errorf("asset manifest protocol is incompatible")
	}
	state, generation, err := db.MaintenanceBarrier(ctx)
	if err != nil {
		return err
	}
	if state != "quiescent" || generation != manifest.BarrierGeneration {
		return fmt.Errorf("asset manifest does not bind quiescent database generation")
	}
	required, err := db.StagedAssetBackupObjects(ctx)
	if err != nil {
		return err
	}
	manifestByKey := make(map[string]assetManifestObject, len(manifest.Objects))
	for _, object := range manifest.Objects {
		if len(object.Key) != 64 || len(object.SHA256) != 64 || object.Size < 0 {
			return fmt.Errorf("asset manifest object is invalid")
		}
		if _, err := hex.DecodeString(object.Key); err != nil {
			return fmt.Errorf("asset manifest key is invalid")
		}
		if _, err := hex.DecodeString(object.SHA256); err != nil {
			return fmt.Errorf("asset manifest digest is invalid")
		}
		if _, exists := manifestByKey[object.Key]; exists {
			return fmt.Errorf("asset manifest contains duplicate key")
		}
		manifestByKey[object.Key] = object
	}
	if len(required) != len(manifestByKey) {
		return fmt.Errorf("asset manifest object set differs from database")
	}
	expectedPaths := map[string]struct{}{}
	for _, object := range required {
		if len(object.Key) != 64 || len(object.SHA256) != 64 || object.Size < 0 {
			return fmt.Errorf("database staged asset metadata is invalid")
		}
		if _, err := hex.DecodeString(object.Key); err != nil {
			return fmt.Errorf("database staged asset key is invalid")
		}
		if _, err := hex.DecodeString(object.SHA256); err != nil {
			return fmt.Errorf("database staged asset digest is invalid")
		}
		item, exists := manifestByKey[object.Key]
		if !exists || item.Size != object.Size || item.SHA256 != object.SHA256 {
			return fmt.Errorf("asset manifest binding differs from database")
		}
		path := filepath.Join(root, object.Key[:2], object.Key[2:4], object.Key)
		expectedPaths[filepath.Clean(path)] = struct{}{}
		if err := rejectSymlinkComponents(root, filepath.Join(object.Key[:2], object.Key[2:4], object.Key)); err != nil {
			return fmt.Errorf("required staged asset %s has unsafe path: %w", object.Key, err)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != object.Size {
			return fmt.Errorf("required staged asset %s is missing or unsafe", object.Key)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		count, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || count != object.Size ||
			hex.EncodeToString(hash.Sum(nil)) != object.SHA256 {
			return fmt.Errorf("required staged asset %s is corrupt", object.Key)
		}
	}
	var extras []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("asset tree contains unsafe non-regular entry %s", path)
		}
		clean := filepath.Clean(path)
		if _, expected := expectedPaths[clean]; expected {
			return nil
		}
		relative, err := filepath.Rel(root, clean)
		if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
			return fmt.Errorf("asset extra escaped root")
		}
		target := filepath.Join(quarantine, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := rejectSymlinkComponents(root, relative); err != nil {
			return err
		}
		if err := rejectSymlinkComponents(quarantine, filepath.Dir(relative)); err != nil {
			return err
		}
		if err := os.Rename(clean, target); err != nil {
			return err
		}
		extras = append(extras, relative)
		return nil
	})
	if err != nil {
		return err
	}
	if len(extras) > 0 {
		sort.Strings(extras)
		if err := os.MkdirAll(quarantine, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(quarantine, "EXTRAS.txt"), []byte(strings.Join(extras, "\n")+"\n"), 0o600); err != nil {
			return err
		}
	}
	return verifyExactAssetSet(root, expectedPaths)
}

func requireSecureDirectory(path string, mustBeEmpty bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("must be a real directory")
	}
	if mustBeEmpty {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("must be empty")
		}
	}
	return nil
}

func rejectSymlinkComponents(root, relative string) error {
	clean := filepath.Clean(relative)
	if clean == "." {
		return nil
	}
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes root")
	}
	current := root
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink component %s", component)
		}
	}
	return nil
}

func verifyExactAssetSet(root string, expected map[string]struct{}) error {
	seen := make(map[string]struct{}, len(expected))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("asset tree contains unsafe non-regular entry %s", path)
		}
		clean := filepath.Clean(path)
		if _, ok := expected[clean]; !ok {
			return fmt.Errorf("asset tree still contains unreferenced object")
		}
		seen[clean] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("asset tree lost a required object during quarantine")
	}
	return nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func fatal(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
