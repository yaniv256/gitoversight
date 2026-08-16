// Package workerread adapts credential-isolated worker reads to broker
// application contracts. It contains no GitHub credential or network client.
package workerread

import (
	"context"
	"errors"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

var ErrSnapshotBinding = errors.New("worker repository snapshot binding is invalid")

type Client interface {
	ReadRepositoryBase(workerrpc.RepositoryBaseRequest) (workerrpc.RepositoryBaseRead, error)
	ReadRepositorySnapshot(workerrpc.RepositorySnapshotRequest) (workerrpc.RepositorySnapshotRead, error)
}

type ChangeDraftRepository struct {
	client Client
	ref    string
	limits changedraft.Limits
}

var _ brokerapp.ChangeDraftRepository = (*ChangeDraftRepository)(nil)

func NewChangeDraftRepository(client Client, ref string, limits changedraft.Limits) (*ChangeDraftRepository, error) {
	if client == nil || ref == "" || limits.MaxFileBytes <= 0 || limits.MaxTotalBytes <= 0 || limits.MaxResultFiles <= 0 {
		return nil, errors.New("worker change-draft repository configuration is incomplete")
	}
	return &ChangeDraftRepository{client: client, ref: ref, limits: limits}, nil
}

func (repository *ChangeDraftRepository) CurrentBase(_ context.Context, identity brokerapp.Identity, name string) (changedraft.BaseRef, error) {
	result, err := repository.client.ReadRepositoryBase(workerrpc.RepositoryBaseRequest{TenantID: identity.TenantID, AgentID: identity.AgentID, Repository: name, Ref: repository.ref})
	if err != nil {
		return changedraft.BaseRef{}, err
	}
	if result.Repository != name || result.Ref != repository.ref || !validObjectID(result.CommitSHA) || !validObjectID(result.TreeSHA) {
		return changedraft.BaseRef{}, ErrSnapshotBinding
	}
	return changedraft.BaseRef{Commit: changedraft.ObjectID(result.CommitSHA), Tree: changedraft.ObjectID(result.TreeSHA)}, nil
}

func (repository *ChangeDraftRepository) Snapshot(_ context.Context, identity brokerapp.Identity, name string, commit changedraft.ObjectID) (changedraft.Snapshot, error) {
	result, err := repository.client.ReadRepositorySnapshot(workerrpc.RepositorySnapshotRequest{
		TenantID: identity.TenantID, AgentID: identity.AgentID, Repository: name, Ref: repository.ref,
		ExactCommitSHA: string(commit), MaxFiles: repository.limits.MaxResultFiles,
		MaxFileBytes: repository.limits.MaxFileBytes, MaxTotalBytes: repository.limits.MaxTotalBytes,
	})
	if err != nil {
		return changedraft.Snapshot{}, err
	}
	if result.Repository != name || result.Ref != repository.ref || result.CommitSHA != string(commit) || !validObjectID(result.TreeSHA) || len(result.Entries) > repository.limits.MaxResultFiles {
		return changedraft.Snapshot{}, ErrSnapshotBinding
	}
	entries := make([]changedraft.Entry, 0, len(result.Entries))
	var total int64
	for _, entry := range result.Entries {
		mode := changedraft.Mode(entry.Mode)
		if mode != changedraft.ModeFile && mode != changedraft.ModeExecutable && mode != changedraft.ModeSymlink || entry.Path == "" || !validObjectID(entry.BlobSHA) || entry.Size < 0 || entry.Size > int64(repository.limits.MaxFileBytes) {
			return changedraft.Snapshot{}, ErrSnapshotBinding
		}
		total += entry.Size
		if total > int64(repository.limits.MaxTotalBytes) {
			return changedraft.Snapshot{}, ErrSnapshotBinding
		}
		entries = append(entries, changedraft.Entry{Path: entry.Path, Mode: mode, Object: changedraft.ObjectID(entry.BlobSHA)})
	}
	return changedraft.Snapshot{Repository: name, Commit: commit, Tree: changedraft.ObjectID(result.TreeSHA), Entries: entries}, nil
}

func validObjectID(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
