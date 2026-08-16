package workerread

import (
	"context"
	"errors"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/snapshotdownload"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type MetadataReader interface {
	Inspect(context.Context, brokerapp.Identity, string) (brokerapp.RepositoryReadMetadata, error)
	Search(context.Context, brokerapp.Identity, []string, string, int) ([]brokerapp.RepositorySearchHit, error)
}

type ArchiveClient interface {
	ReadRepositoryBase(workerrpc.RepositoryBaseRequest) (workerrpc.RepositoryBaseRead, error)
	ReadRepositoryArchive(workerrpc.RepositoryArchiveRequest) (workerrpc.RepositoryArchiveRead, error)
}

type RepositoryBackend struct {
	metadata                              MetadataReader
	worker                                ArchiveClient
	downloads                             *snapshotdownload.Store
	ref                                   string
	maxFiles, maxFileBytes, maxTotalBytes int
}

var _ brokerapp.RepositoryReadBackend = (*RepositoryBackend)(nil)

func NewRepositoryBackend(metadata MetadataReader, worker ArchiveClient, downloads *snapshotdownload.Store, ref string, maxFiles, maxFileBytes, maxTotalBytes int) (*RepositoryBackend, error) {
	if metadata == nil || worker == nil || downloads == nil || ref == "" || maxFiles <= 0 || maxFileBytes <= 0 || maxTotalBytes <= 0 {
		return nil, errors.New("repository backend configuration is incomplete")
	}
	return &RepositoryBackend{metadata: metadata, worker: worker, downloads: downloads, ref: ref, maxFiles: maxFiles, maxFileBytes: maxFileBytes, maxTotalBytes: maxTotalBytes}, nil
}

func (backend *RepositoryBackend) Inspect(ctx context.Context, identity brokerapp.Identity, repository string) (brokerapp.RepositoryReadMetadata, error) {
	return backend.metadata.Inspect(ctx, identity, repository)
}
func (backend *RepositoryBackend) Search(ctx context.Context, identity brokerapp.Identity, repositories []string, query string, limit int) ([]brokerapp.RepositorySearchHit, error) {
	return backend.metadata.Search(ctx, identity, repositories, query, limit)
}

func (backend *RepositoryBackend) CurrentBase(_ context.Context, identity brokerapp.Identity, repository, ref string) (brokerapp.RepositoryBase, error) {
	if ref != backend.ref {
		return brokerapp.RepositoryBase{}, errors.New("repository ref is unsupported")
	}
	base, err := backend.worker.ReadRepositoryBase(workerrpc.RepositoryBaseRequest{TenantID: identity.TenantID, AgentID: identity.AgentID, Repository: repository, Ref: ref})
	if err != nil {
		return brokerapp.RepositoryBase{}, err
	}
	return brokerapp.RepositoryBase{Repository: base.Repository, Ref: base.Ref, CommitSHA: base.CommitSHA, TreeSHA: base.TreeSHA}, nil
}

func (backend *RepositoryBackend) IssueSnapshot(_ context.Context, identity brokerapp.Identity, repository string, base brokerapp.RepositoryBase, maxBytes int64) (brokerapp.SnapshotDownload, error) {
	limit := backend.maxTotalBytes
	if maxBytes < int64(limit) {
		limit = int(maxBytes)
	}
	archive, err := backend.worker.ReadRepositoryArchive(workerrpc.RepositoryArchiveRequest{RepositorySnapshotRequest: workerrpc.RepositorySnapshotRequest{TenantID: identity.TenantID, AgentID: identity.AgentID, Repository: repository, Ref: base.Ref, ExactCommitSHA: base.CommitSHA, MaxFiles: backend.maxFiles, MaxFileBytes: backend.maxFileBytes, MaxTotalBytes: limit}})
	if err != nil {
		return brokerapp.SnapshotDownload{}, err
	}
	if archive.Repository != repository || archive.Ref != base.Ref || archive.CommitSHA != base.CommitSHA || archive.TreeSHA != base.TreeSHA || archive.SHA256 == "" {
		return brokerapp.SnapshotDownload{}, ErrSnapshotBinding
	}
	metadata, err := backend.downloads.Put(archive.Content, archive.ContentType, archive.SHA256, maxBytes)
	if err != nil {
		return brokerapp.SnapshotDownload{}, err
	}
	return brokerapp.SnapshotDownload{Repository: repository, Base: base, DownloadURL: metadata.URL, SHA256: metadata.SHA256, ExpiresAt: metadata.ExpiresAt, MaxBytes: metadata.Size, OneTime: true}, nil
}
