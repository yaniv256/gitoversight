package workerread_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
	"github.com/yaniv256/gitoversight.dev/internal/workerread"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type clientStub struct {
	base     workerrpc.RepositoryBaseRead
	snapshot workerrpc.RepositorySnapshotRead
}

func (stub clientStub) ReadRepositoryBase(workerrpc.RepositoryBaseRequest) (workerrpc.RepositoryBaseRead, error) {
	return stub.base, nil
}
func (stub clientStub) ReadRepositorySnapshot(workerrpc.RepositorySnapshotRequest) (workerrpc.RepositorySnapshotRead, error) {
	return stub.snapshot, nil
}

func TestChangeDraftRepositoryMapsVerifiedWorkerSnapshot(t *testing.T) {
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	blob := strings.Repeat("c", 40)
	client := clientStub{base: workerrpc.RepositoryBaseRead{Repository: "org/private", Ref: "refs/heads/main", CommitSHA: commit, TreeSHA: tree}, snapshot: workerrpc.RepositorySnapshotRead{Repository: "org/private", Ref: "refs/heads/main", CommitSHA: commit, TreeSHA: tree, Entries: []workerrpc.RepositorySnapshotEntry{{Path: "README.md", Mode: "100644", BlobSHA: blob, Size: 6}}}}
	repository, err := workerread.NewChangeDraftRepository(client, "refs/heads/main", changedraft.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	identity := brokerapp.Identity{TenantID: "tenant", AgentID: "work"}
	base, err := repository.CurrentBase(context.Background(), identity, "org/private")
	if err != nil || string(base.Commit) != commit || string(base.Tree) != tree {
		t.Fatalf("base = %#v, err=%v", base, err)
	}
	snapshot, err := repository.Snapshot(context.Background(), identity, "org/private", changedraft.ObjectID(commit))
	if err != nil || len(snapshot.Entries) != 1 || string(snapshot.Entries[0].Object) != blob {
		t.Fatalf("snapshot = %#v, err=%v", snapshot, err)
	}
}

func TestChangeDraftRepositoryRejectsUnsupportedMetadata(t *testing.T) {
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	client := clientStub{snapshot: workerrpc.RepositorySnapshotRead{Repository: "org/private", Ref: "refs/heads/main", CommitSHA: commit, TreeSHA: tree, Entries: []workerrpc.RepositorySnapshotEntry{{Path: "README.md", Mode: "160000", BlobSHA: strings.Repeat("c", 40), Size: 10}}}}
	repository, _ := workerread.NewChangeDraftRepository(client, "refs/heads/main", changedraft.DefaultLimits())
	_, err := repository.Snapshot(context.Background(), brokerapp.Identity{TenantID: "tenant", AgentID: "work"}, "org/private", changedraft.ObjectID(commit))
	if !errors.Is(err, workerread.ErrSnapshotBinding) {
		t.Fatalf("err = %v", err)
	}
}
