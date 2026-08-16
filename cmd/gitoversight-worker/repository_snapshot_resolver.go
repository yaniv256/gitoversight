package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/githubauth"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

const (
	workerSnapshotMaxFiles      = 100_000
	workerSnapshotMaxFileBytes  = 1 << 20
	workerSnapshotMaxTotalBytes = 8 << 20
)

type snapshotGitReader interface {
	ReadBranchHead(repository, branch, subject string) (string, error)
	ReadCommitTree(repository, commitSHA, subject string) (string, error)
	ReadTree(repository, treeSHA, subject string) ([]githubapp.TreeEntry, error)
	ReadBlob(repository, blobSHA, subject string) ([]byte, error)
}

func (resolver *repositorySnapshotResolver) ReadRepositoryArchive(request workerrpc.RepositoryArchiveRequest) (workerrpc.RepositoryArchiveRead, error) {
	metadata, err := resolver.ReadRepositorySnapshot(request.RepositorySnapshotRequest)
	if err != nil {
		return workerrpc.RepositoryArchiveRead{}, err
	}
	subject, err := resolver.privateSubject(request.Repository)
	if err != nil {
		return workerrpc.RepositoryArchiveRead{}, err
	}
	var buffer bytes.Buffer
	gzipWriter, _ := gzip.NewWriterLevel(&buffer, gzip.BestSpeed)
	tarWriter := tar.NewWriter(gzipWriter)
	total := 0
	for _, entry := range metadata.Entries {
		if entry.Mode == "120000" {
			return workerrpc.RepositoryArchiveRead{}, errors.New("repository archive does not support symlinks")
		}
		content, err := resolver.reader.ReadBlob(request.Repository, entry.BlobSHA, subject)
		if err != nil {
			return workerrpc.RepositoryArchiveRead{}, err
		}
		if int64(len(content)) != entry.Size || len(content) > request.MaxFileBytes {
			return workerrpc.RepositoryArchiveRead{}, errors.New("repository archive blob violates tree size binding")
		}
		total += len(content)
		if total > request.MaxTotalBytes {
			return workerrpc.RepositoryArchiveRead{}, errors.New("repository archive exceeds total-byte bound")
		}
		mode := int64(0o644)
		if entry.Mode == "100755" {
			mode = 0o755
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.Path, Mode: mode, Size: int64(len(content)), ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err != nil {
			return workerrpc.RepositoryArchiveRead{}, err
		}
		if _, err := tarWriter.Write(content); err != nil {
			return workerrpc.RepositoryArchiveRead{}, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return workerrpc.RepositoryArchiveRead{}, err
	}
	if err := gzipWriter.Close(); err != nil {
		return workerrpc.RepositoryArchiveRead{}, err
	}
	if buffer.Len() > request.MaxTotalBytes {
		return workerrpc.RepositoryArchiveRead{}, errors.New("compressed repository archive exceeds byte bound")
	}
	digest := sha256.Sum256(buffer.Bytes())
	return workerrpc.RepositoryArchiveRead{Repository: metadata.Repository, Ref: metadata.Ref, CommitSHA: metadata.CommitSHA, TreeSHA: metadata.TreeSHA, ContentType: "application/gzip", SHA256: hex.EncodeToString(digest[:]), Content: buffer.Bytes()}, nil
}

type repositorySnapshotResolver struct {
	reader        snapshotGitReader
	installations map[string]int64
	visibility    func(string) (string, error)
}

func (resolver *repositorySnapshotResolver) ReadRepositoryBase(request workerrpc.RepositoryBaseRequest) (workerrpc.RepositoryBaseRead, error) {
	if request.TenantID == "" || request.AgentID == "" || !validSnapshotRepository(request.Repository) || !validSnapshotRef(request.Ref) {
		return workerrpc.RepositoryBaseRead{}, errors.New("repository base request is invalid")
	}
	subject, err := resolver.privateSubject(request.Repository)
	if err != nil {
		return workerrpc.RepositoryBaseRead{}, err
	}
	commitSHA, err := resolver.reader.ReadBranchHead(request.Repository, strings.TrimPrefix(request.Ref, "refs/heads/"), subject)
	if err != nil {
		return workerrpc.RepositoryBaseRead{}, err
	}
	treeSHA, err := resolver.reader.ReadCommitTree(request.Repository, commitSHA, subject)
	if err != nil {
		return workerrpc.RepositoryBaseRead{}, err
	}
	if !validSnapshotOID(commitSHA) || !validSnapshotOID(treeSHA) {
		return workerrpc.RepositoryBaseRead{}, errors.New("repository base identity is invalid")
	}
	return workerrpc.RepositoryBaseRead{Repository: request.Repository, Ref: request.Ref, CommitSHA: commitSHA, TreeSHA: treeSHA}, nil
}

func newRepositorySnapshotResolver(reader snapshotGitReader, installations map[string]int64, visibility func(string) (string, error)) (*repositorySnapshotResolver, error) {
	if reader == nil || len(installations) == 0 || visibility == nil {
		return nil, errors.New("repository snapshot resolver configuration is incomplete")
	}
	return &repositorySnapshotResolver{reader: reader, installations: installations, visibility: visibility}, nil
}

func (resolver *repositorySnapshotResolver) ReadRepositorySnapshot(request workerrpc.RepositorySnapshotRequest) (workerrpc.RepositorySnapshotRead, error) {
	if !validSnapshotRepository(request.Repository) || !validSnapshotRef(request.Ref) || !validSnapshotOID(request.ExactCommitSHA) ||
		request.TenantID == "" || request.AgentID == "" || request.MaxFiles <= 0 || request.MaxFiles > workerSnapshotMaxFiles ||
		request.MaxFileBytes <= 0 || request.MaxFileBytes > workerSnapshotMaxFileBytes || request.MaxTotalBytes <= 0 || request.MaxTotalBytes > workerSnapshotMaxTotalBytes {
		return workerrpc.RepositorySnapshotRead{}, errors.New("repository snapshot request exceeds worker bounds")
	}
	subject, err := resolver.privateSubject(request.Repository)
	if err != nil {
		return workerrpc.RepositorySnapshotRead{}, err
	}
	branch := strings.TrimPrefix(request.Ref, "refs/heads/")
	commitSHA, err := resolver.reader.ReadBranchHead(request.Repository, branch, subject)
	if err != nil {
		return workerrpc.RepositorySnapshotRead{}, err
	}
	if commitSHA != request.ExactCommitSHA {
		return workerrpc.RepositorySnapshotRead{}, errors.New("repository snapshot base moved")
	}
	treeSHA, err := resolver.reader.ReadCommitTree(request.Repository, commitSHA, subject)
	if err != nil {
		return workerrpc.RepositorySnapshotRead{}, err
	}
	if !validSnapshotOID(treeSHA) {
		return workerrpc.RepositorySnapshotRead{}, errors.New("repository snapshot tree is invalid")
	}
	tree, err := resolver.reader.ReadTree(request.Repository, treeSHA, subject)
	if err != nil {
		return workerrpc.RepositorySnapshotRead{}, err
	}
	if len(tree) > request.MaxFiles {
		return workerrpc.RepositorySnapshotRead{}, errors.New("repository snapshot exceeds file-count bound")
	}
	entries := make([]workerrpc.RepositorySnapshotEntry, 0, len(tree))
	total := 0
	seen := make(map[string]struct{}, len(tree))
	for _, entry := range tree {
		if entry.Type != "blob" || !validSnapshotMode(entry.Mode) || !validSnapshotPath(entry.Path) || !validSnapshotOID(entry.SHA) || entry.Size < 0 || entry.Size > int64(request.MaxFileBytes) {
			return workerrpc.RepositorySnapshotRead{}, errors.New("repository snapshot tree contains unsupported entry")
		}
		if _, duplicate := seen[entry.Path]; duplicate {
			return workerrpc.RepositorySnapshotRead{}, errors.New("repository snapshot tree contains duplicate path")
		}
		seen[entry.Path] = struct{}{}
		total += int(entry.Size)
		if total > request.MaxTotalBytes {
			return workerrpc.RepositorySnapshotRead{}, errors.New("repository snapshot exceeds total-byte bound")
		}
		entries = append(entries, workerrpc.RepositorySnapshotEntry{Path: entry.Path, Mode: entry.Mode, BlobSHA: entry.SHA, Size: entry.Size})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return workerrpc.RepositorySnapshotRead{Repository: request.Repository, Ref: request.Ref, CommitSHA: commitSHA, TreeSHA: treeSHA, Entries: entries}, nil
}

func (resolver *repositorySnapshotResolver) privateSubject(repository string) (string, error) {
	visibility, err := resolver.visibility(repository)
	if err != nil || visibility != "private" {
		return "", errors.New("repository read requires registered private visibility")
	}
	installationID, ok := githubauth.ResolveInstallation(resolver.installations, repository)
	if !ok || installationID <= 0 {
		return "", errors.New("repository read installation unavailable")
	}
	return strconv.FormatInt(installationID, 10), nil
}

func validSnapshotRepository(value string) bool {
	parts := strings.Split(value, "/")
	return len(value) <= 256 && len(parts) == 2 && parts[0] != "" && parts[1] != "" && !strings.Contains(value, "..") && !strings.ContainsAny(value, "*?[]\\\x00")
}

func validSnapshotRef(value string) bool {
	branch := strings.TrimPrefix(value, "refs/heads/")
	return branch != value && branch != "" && len(value) <= 1024 && !strings.Contains(value, "..") && !strings.ContainsAny(value, " ~^:?*[\\\x00")
}

func validSnapshotOID(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func validSnapshotMode(value string) bool {
	return value == "100644" || value == "100755" || value == "120000"
}

func validSnapshotPath(value string) bool {
	return value != "" && len(value) <= 4096 && utf8.ValidString(value) && value == path.Clean(value) && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && !strings.Contains(value, "\\")
}
