package releaseasset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrObjectNotFound = errors.New("staged asset object not found")
	ErrObjectExists   = errors.New("staged asset object already exists")
	ErrUnsafeObject   = errors.New("staged asset object is unsafe")
	ErrIntegrity      = errors.New("staged asset object integrity mismatch")
)

type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

// ObjectKey returns the non-secret, content-addressed filesystem key for a
// tenant/stage binding. Maintenance uses it to reconcile a crash after file
// publication but before the ready metadata checkpoint.
func (s *FileStore) ObjectKey(tenantID, stageID string) string {
	return s.objectKey(tenantID, stageID)
}

// Remove deletes exactly the derived immutable object and fsyncs its parent.
// Absence is success: a crash after unlink but before SQLite completion must be
// safely retryable.
func (s *FileStore) Remove(tenantID, stageID, expectedKey string) error {
	if tenantID == "" || stageID == "" || expectedKey == "" || s.objectKey(tenantID, stageID) != expectedKey {
		return ErrUnsafeObject
	}
	path := s.objectPath(tenantID, stageID)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// CleanupTemps removes only stale upload temporaries. Final object names are
// never matched by this sweep.
func (s *FileStore) CleanupTemps(cutoff time.Time) (int, error) {
	removed := 0
	err := filepath.WalkDir(s.root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".upload-") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.ModTime().After(cutoff) {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		removed++
		return nil
	})
	return removed, err
}

// CleanupOrphanObjects removes final objects that have no metadata row and are
// older than the repair grace. Keys are validated by shape before deletion.
func (s *FileStore) CleanupOrphanObjects(live map[string]struct{}, cutoff time.Time) (int, error) {
	removed := 0
	err := filepath.WalkDir(s.root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".upload-") {
			return nil
		}
		key := entry.Name()
		if len(key) != 64 {
			return nil
		}
		if _, err := hex.DecodeString(key); err != nil {
			return nil
		}
		if _, exists := live[key]; exists {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.ModTime().After(cutoff) {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		removed++
		return nil
	})
	return removed, err
}

// BlobReader is the worker-facing surface. It deliberately exposes no
// capability, metadata mutation, pin, abandon, or deletion operation.
type BlobReader interface {
	Open(context.Context, string, string, int64, string) (ReadSeekCloser, error)
}

type BlobObject struct {
	Key    string
	Size   int64
	SHA256 string
}

// FileStore keeps one immutable object per logical stage. Object paths are
// derived from tenant and stage IDs rather than accepting caller paths.
type FileStore struct {
	root string
}

func NewFileStore(root string) (*FileStore, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "" || root == "." {
		return nil, errors.New("release asset root is required")
	}
	var err error
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve release asset root: %w", err)
	}
	if err := os.MkdirAll(root, 0o750|os.ModeSetgid); err != nil {
		return nil, fmt.Errorf("create release asset root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafeObject
	}
	wantMode := os.FileMode(0o750) | os.ModeSetgid
	if info.Mode().Perm() != 0o750 || info.Mode()&os.ModeSetgid == 0 {
		if err := os.Chmod(root, wantMode); err != nil {
			return nil, fmt.Errorf("secure release asset root: %w", err)
		}
	}
	return &FileStore{root: root}, nil
}

// NewFileReader opens an existing object root without creating or changing it.
// It is the worker-side constructor: the privileged worker has read-only access
// to staged objects and must never gain a filesystem mutation surface.
func NewFileReader(root string) (*FileStore, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "" || root == "." {
		return nil, errors.New("release asset root is required")
	}
	var err error
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve release asset root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafeObject
	}
	return &FileStore{root: root}, nil
}

// RootID binds API and worker configuration without exposing an object path or
// inspecting any staged bytes.
func (s *FileStore) RootID() string {
	if s == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(s.root))
	return hex.EncodeToString(sum[:])
}

// WriterReadiness performs only constant-time metadata, capacity, inode, and
// create/remove probes. It never walks or hashes staged objects.
func (s *FileStore) WriterReadiness(minimumFreeBytes uint64) error {
	if s == nil {
		return errors.New("release asset writer is unavailable")
	}
	info, err := os.Lstat(s.root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeObject
	}
	var status unix.Statfs_t
	if err := unix.Statfs(s.root, &status); err != nil {
		return fmt.Errorf("release asset capacity: %w", err)
	}
	freeBytes := uint64(status.Bavail)
	blockSize := uint64(status.Bsize)
	if blockSize != 0 && freeBytes > ^uint64(0)/blockSize {
		freeBytes = ^uint64(0)
	} else {
		freeBytes *= blockSize
	}
	if freeBytes < minimumFreeBytes {
		return errors.New("release asset free-space floor is not met")
	}
	if status.Ffree == 0 {
		return errors.New("release asset inode floor is not met")
	}
	probe, err := os.CreateTemp(s.root, ".readiness-*")
	if err != nil {
		return fmt.Errorf("release asset root is not writable: %w", err)
	}
	name := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return fmt.Errorf("close release asset readiness probe: %w", closeErr)
	}
	if removeErr != nil {
		return fmt.Errorf("remove release asset readiness probe: %w", removeErr)
	}
	return nil
}

// ReaderReadiness proves that the worker can read and traverse the configured
// root. It does not enumerate more than one directory entry or open any asset.
func (s *FileStore) ReaderReadiness() error {
	if s == nil {
		return errors.New("release asset reader is unavailable")
	}
	info, err := os.Lstat(s.root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeObject
	}
	if err := unix.Access(s.root, unix.R_OK|unix.X_OK); err != nil {
		return fmt.Errorf("release asset root is not readable: %w", err)
	}
	root, err := os.Open(s.root)
	if err != nil {
		return fmt.Errorf("open release asset root: %w", err)
	}
	defer root.Close()
	if _, err := root.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read release asset root: %w", err)
	}
	return nil
}

func (s *FileStore) Publish(ctx context.Context, tenantID, stageID string, expectedSize int64, expectedSHA256 string, source io.Reader) (BlobObject, error) {
	if tenantID == "" || stageID == "" || expectedSize < 0 || !sha256Pattern.MatchString(expectedSHA256) || source == nil {
		return BlobObject{}, ErrIntegrity
	}
	path := s.objectPath(tenantID, stageID)
	dir := filepath.Dir(path)
	if err := s.ensureShardDirectories(dir); err != nil {
		return BlobObject{}, err
	}
	temp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return BlobObject{}, err
	}
	tempPath := temp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temp.Close()
		}
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(0o640); err != nil {
		return BlobObject{}, err
	}
	hash := sha256.New()
	written, err := io.CopyN(io.MultiWriter(temp, hash), &contextReader{ctx: ctx, reader: source}, expectedSize)
	if err != nil || written != expectedSize {
		return BlobObject{}, ErrIntegrity
	}
	var extra [1]byte
	if count, readErr := (&contextReader{ctx: ctx, reader: source}).Read(extra[:]); count != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return BlobObject{}, ErrIntegrity
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expectedSHA256 {
		return BlobObject{}, ErrIntegrity
	}
	if err := temp.Sync(); err != nil {
		return BlobObject{}, err
	}
	if err := temp.Chmod(0o440); err != nil {
		return BlobObject{}, err
	}
	if err := temp.Close(); err != nil {
		return BlobObject{}, err
	}
	closed = true
	// A hard link is an atomic no-clobber publication on the same filesystem.
	// Unlike Rename, it cannot replace an existing immutable stage object.
	if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return BlobObject{}, ErrObjectExists
		}
		return BlobObject{}, err
	}
	if err := os.Remove(tempPath); err != nil {
		return BlobObject{}, err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return BlobObject{}, err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return BlobObject{}, err
	}
	return BlobObject{Key: s.objectKey(tenantID, stageID), Size: written, SHA256: actual}, nil
}

func (s *FileStore) ensureShardDirectories(dir string) error {
	relative, err := filepath.Rel(s.root, dir)
	if err != nil || relative == "." || relative == "" || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return ErrUnsafeObject
	}
	// The managed root is setgid, so Linux propagates the group and setgid bit
	// to new child directories. Requesting S_ISGID in mkdir itself is rejected
	// by the production unit's RestrictSUIDSGID=yes sandbox.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	current := s.root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return ErrUnsafeObject
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafeObject
		}
		wantMode := os.FileMode(0o750) | os.ModeSetgid
		if info.Mode().Perm() != 0o750 || info.Mode()&os.ModeSetgid == 0 {
			if err := os.Chmod(current, wantMode); err != nil {
				return fmt.Errorf("secure release asset shard: %w", err)
			}
		}
	}
	return nil
}

func (s *FileStore) Open(ctx context.Context, tenantID, stageID string, expectedSize int64, expectedSHA256 string) (ReadSeekCloser, error) {
	if tenantID == "" || stageID == "" || expectedSize < 0 || !sha256Pattern.MatchString(expectedSHA256) {
		return nil, ErrObjectNotFound
	}
	path := s.objectPath(tenantID, stageID)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, ErrObjectNotFound
		}
		if errors.Is(err, unix.ELOOP) {
			return nil, ErrUnsafeObject
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != expectedSize {
		_ = file.Close()
		return nil, ErrUnsafeObject
	}
	hash := sha256.New()
	written, err := io.Copy(hash, &contextReader{ctx: ctx, reader: file})
	if err != nil || written != expectedSize || hex.EncodeToString(hash.Sum(nil)) != expectedSHA256 {
		_ = file.Close()
		return nil, ErrIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (s *FileStore) objectKey(tenantID, stageID string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + stageID))
	return hex.EncodeToString(sum[:])
}

func (s *FileStore) objectPath(tenantID, stageID string) string {
	key := s.objectKey(tenantID, stageID)
	return filepath.Join(s.root, key[:2], key[2:4], key)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(payload []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(payload)
	}
}

var _ BlobReader = (*FileStore)(nil)
