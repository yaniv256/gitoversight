package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

func TestRepositoryArchiveReadsBlobsOnlyForExplicitCheckout(t *testing.T) {
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	content := []byte("hello\n")
	sha := string(changedraft.GitObjectID("blob", content))
	reader := &snapshotReaderStub{commit: commit, tree: tree, entries: []githubapp.TreeEntry{{Path: "README.md", Mode: "100644", Type: "blob", SHA: sha, Size: int64(len(content))}}, blobs: map[string][]byte{sha: content}}
	resolver, _ := newRepositorySnapshotResolver(reader, map[string]int64{"org/private": 42}, func(string) (string, error) { return "private", nil })
	request := workerrpc.RepositorySnapshotRequest{TenantID: "tenant", AgentID: "work", Repository: "org/private", Ref: "refs/heads/main", ExactCommitSHA: commit, MaxFiles: 10, MaxFileBytes: 1024, MaxTotalBytes: 2048}
	archive, err := resolver.ReadRepositoryArchive(workerrpc.RepositoryArchiveRequest{RepositorySnapshotRequest: request})
	if err != nil {
		t.Fatal(err)
	}
	if reader.blobReads != 1 || archive.ContentType != "application/gzip" || archive.CommitSHA != commit || archive.TreeSHA != tree {
		t.Fatalf("archive/blob reads = %#v / %d", archive, reader.blobReads)
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive.Content))
	if err != nil {
		t.Fatal(err)
	}
	header, err := tar.NewReader(gzipReader).Next()
	if err != nil {
		t.Fatal(err)
	}
	if header.Name != "README.md" || header.Mode != 0o644 {
		t.Fatalf("header = %#v", header)
	}
}

type snapshotReaderStub struct {
	commit, tree string
	entries      []githubapp.TreeEntry
	blobs        map[string][]byte
	subjects     []string
	blobReads    int
}

func (stub *snapshotReaderStub) ReadBranchHead(_, _, subject string) (string, error) {
	stub.subjects = append(stub.subjects, subject)
	return stub.commit, nil
}
func (stub *snapshotReaderStub) ReadCommitTree(_, _, subject string) (string, error) {
	stub.subjects = append(stub.subjects, subject)
	return stub.tree, nil
}
func (stub *snapshotReaderStub) ReadTree(_, _, subject string) ([]githubapp.TreeEntry, error) {
	stub.subjects = append(stub.subjects, subject)
	return stub.entries, nil
}
func (stub *snapshotReaderStub) ReadBlob(_, sha, subject string) ([]byte, error) {
	stub.blobReads++
	stub.subjects = append(stub.subjects, subject)
	value, ok := stub.blobs[sha]
	if !ok {
		return nil, errors.New("missing")
	}
	return value, nil
}

func TestRepositorySnapshotResolverReadsExactPrivateBaseWithinBounds(t *testing.T) {
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	content := []byte("hello\n")
	sha := string(changedraft.GitObjectID("blob", content))
	reader := &snapshotReaderStub{commit: commit, tree: tree, entries: []githubapp.TreeEntry{{Path: "README.md", Mode: "100644", Type: "blob", SHA: sha, Size: int64(len(content))}}, blobs: map[string][]byte{sha: content}}
	resolver, _ := newRepositorySnapshotResolver(reader, map[string]int64{"org/private": 42}, func(string) (string, error) { return "private", nil })
	result, err := resolver.ReadRepositorySnapshot(workerrpc.RepositorySnapshotRequest{TenantID: "tenant", AgentID: "work", Repository: "org/private", Ref: "refs/heads/main", ExactCommitSHA: commit, MaxFiles: 10, MaxFileBytes: 1024, MaxTotalBytes: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if result.CommitSHA != commit || result.TreeSHA != tree || len(result.Entries) != 1 || result.Entries[0].Size != int64(len(content)) {
		t.Fatalf("result = %#v", result)
	}
	if reader.blobReads != 0 {
		t.Fatalf("ReadBlob called %d times; draft snapshots must remain metadata-only", reader.blobReads)
	}
	for _, subject := range reader.subjects {
		if subject != "42" {
			t.Fatalf("subject = %q", subject)
		}
	}
}

func TestRepositorySnapshotResolverFailsClosedForPublicStaleAndUnsupportedTree(t *testing.T) {
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	request := workerrpc.RepositorySnapshotRequest{TenantID: "tenant", AgentID: "work", Repository: "org/private", Ref: "refs/heads/main", ExactCommitSHA: commit, MaxFiles: 10, MaxFileBytes: 1024, MaxTotalBytes: 2048}
	reader := &snapshotReaderStub{commit: commit, tree: tree, blobs: map[string][]byte{}}
	public, _ := newRepositorySnapshotResolver(reader, map[string]int64{"org/private": 42}, func(string) (string, error) { return "public", nil })
	if _, err := public.ReadRepositorySnapshot(request); err == nil {
		t.Fatal("public repository accepted")
	}
	private, _ := newRepositorySnapshotResolver(reader, map[string]int64{"org/private": 42}, func(string) (string, error) { return "private", nil })
	stale := request
	stale.ExactCommitSHA = strings.Repeat("c", 40)
	if _, err := private.ReadRepositorySnapshot(stale); err == nil {
		t.Fatal("stale base accepted")
	}
	reader.entries = []githubapp.TreeEntry{{Path: "vendor/lib", Mode: "160000", Type: "commit", SHA: strings.Repeat("d", 40)}}
	if _, err := private.ReadRepositorySnapshot(request); err == nil {
		t.Fatal("gitlink accepted")
	}
}
