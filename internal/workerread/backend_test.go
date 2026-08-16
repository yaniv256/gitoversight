package workerread_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/snapshotdownload"
	"github.com/yaniv256/gitoversight.dev/internal/workerread"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type metadataStub struct{}

func (metadataStub) Inspect(_ context.Context, _ brokerapp.Identity, repository string) (brokerapp.RepositoryReadMetadata, error) {
	return brokerapp.RepositoryReadMetadata{Repository: repository, Visibility: "private"}, nil
}
func (metadataStub) Search(context.Context, brokerapp.Identity, []string, string, int) ([]brokerapp.RepositorySearchHit, error) {
	return nil, nil
}

type archiveClientStub struct {
	base    workerrpc.RepositoryBaseRead
	archive workerrpc.RepositoryArchiveRead
	request workerrpc.RepositoryArchiveRequest
}

func (stub *archiveClientStub) ReadRepositoryBase(workerrpc.RepositoryBaseRequest) (workerrpc.RepositoryBaseRead, error) {
	return stub.base, nil
}
func (stub *archiveClientStub) ReadRepositoryArchive(request workerrpc.RepositoryArchiveRequest) (workerrpc.RepositoryArchiveRead, error) {
	stub.request = request
	return stub.archive, nil
}

func TestRepositoryBackendReturnsOnlyOneTimeDownloadMetadata(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store, _ := snapshotdownload.New("https://gitoversight.test", time.Minute, func() time.Time { return now })
	content := []byte("bounded-archive")
	digest := sha256.Sum256(content)
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	client := &archiveClientStub{base: workerrpc.RepositoryBaseRead{Repository: "org/private", Ref: "refs/heads/main", CommitSHA: commit, TreeSHA: tree}, archive: workerrpc.RepositoryArchiveRead{Repository: "org/private", Ref: "refs/heads/main", CommitSHA: commit, TreeSHA: tree, ContentType: "application/gzip", SHA256: hex.EncodeToString(digest[:]), Content: content}}
	backend, err := workerread.NewRepositoryBackend(metadataStub{}, client, store, "refs/heads/main", 100, 1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	identity := brokerapp.Identity{TenantID: "tenant", AgentID: "work"}
	base, err := backend.CurrentBase(context.Background(), identity, "org/private", "refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	download, err := backend.IssueSnapshot(context.Background(), identity, "org/private", base, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !download.OneTime || download.DownloadURL == "" || download.SHA256 != hex.EncodeToString(digest[:]) || download.MaxBytes != int64(len(content)) {
		t.Fatalf("download = %#v", download)
	}
	if client.request.ExactCommitSHA != commit || client.request.MaxTotalBytes != 4096 {
		t.Fatalf("worker request = %#v", client.request)
	}
}
