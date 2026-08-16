package brokerapp

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type readScopeStub struct {
	allowed []string
	err     error
	checks  []string
}

func (stub *readScopeStub) ReadableRepositories(context.Context, Identity) ([]string, error) {
	return append([]string(nil), stub.allowed...), stub.err
}

func (stub *readScopeStub) AuthorizeRepositoryRead(_ context.Context, identity Identity, repository string) error {
	stub.checks = append(stub.checks, identity.TenantID+"/"+identity.AgentID+":"+repository)
	if stub.err != nil {
		return stub.err
	}
	for _, allowed := range stub.allowed {
		if allowed == repository {
			return nil
		}
	}
	return ErrRepositoryReadDenied
}

type repositoryReadBackendStub struct {
	metadata  map[string]RepositoryReadMetadata
	search    []RepositorySearchHit
	base      RepositoryBase
	snapshot  SnapshotDownload
	seenRepos []string
}

func (stub *repositoryReadBackendStub) Inspect(_ context.Context, _ Identity, repository string) (RepositoryReadMetadata, error) {
	stub.seenRepos = append(stub.seenRepos, repository)
	value, ok := stub.metadata[repository]
	if !ok {
		return RepositoryReadMetadata{}, errors.New("missing")
	}
	return value, nil
}

func (stub *repositoryReadBackendStub) Search(_ context.Context, _ Identity, repositories []string, query string, limit int) ([]RepositorySearchHit, error) {
	stub.seenRepos = append(stub.seenRepos, repositories...)
	return append([]RepositorySearchHit(nil), stub.search...), nil
}

func (stub *repositoryReadBackendStub) CurrentBase(_ context.Context, _ Identity, repository, ref string) (RepositoryBase, error) {
	stub.seenRepos = append(stub.seenRepos, repository)
	return stub.base, nil
}

func (stub *repositoryReadBackendStub) IssueSnapshot(_ context.Context, _ Identity, repository string, base RepositoryBase, maxBytes int64) (SnapshotDownload, error) {
	stub.seenRepos = append(stub.seenRepos, repository)
	return stub.snapshot, nil
}

func TestRepositoryReadServiceInspectChecksScopeAndLabelsContent(t *testing.T) {
	scope := &readScopeStub{allowed: []string{"org/private"}}
	backend := &repositoryReadBackendStub{metadata: map[string]RepositoryReadMetadata{"org/private": {
		Repository: "org/private", Visibility: "private", DefaultBranch: "main", Description: "repository supplied",
	}}}
	service := NewRepositoryReadService(scope, backend, RepositoryReadConfig{})

	result, err := service.Inspect(context.Background(), Identity{TenantID: "tenant", AgentID: "work"}, "org/private")
	if err != nil {
		t.Fatal(err)
	}
	if result.ContentTrust != UntrustedRepositoryContent || result.Description != "repository supplied" {
		t.Fatalf("inspect result = %#v", result)
	}
	if !reflect.DeepEqual(scope.checks, []string{"tenant/work:org/private"}) {
		t.Fatalf("scope checks = %#v", scope.checks)
	}
}

func TestRepositoryReadServiceFailsClosedOnIdentityScopeAndBackendBinding(t *testing.T) {
	service := NewRepositoryReadService(&readScopeStub{allowed: []string{"org/private"}}, &repositoryReadBackendStub{
		metadata: map[string]RepositoryReadMetadata{"org/private": {Repository: "org/other"}},
	}, RepositoryReadConfig{})
	if _, err := service.Inspect(context.Background(), Identity{TenantID: "", AgentID: "work"}, "org/private"); !errors.Is(err, ErrRepositoryReadInvalid) {
		t.Fatalf("missing tenant error = %v", err)
	}
	if _, err := service.Inspect(context.Background(), Identity{TenantID: "tenant", AgentID: "work"}, "org/denied"); !errors.Is(err, ErrRepositoryReadDenied) {
		t.Fatalf("scope error = %v", err)
	}
	if _, err := service.Inspect(context.Background(), Identity{TenantID: "tenant", AgentID: "work"}, "org/private"); !errors.Is(err, ErrRepositoryReadBinding) {
		t.Fatalf("binding error = %v", err)
	}
}

func TestRepositoryReadServiceSearchIsBoundedScopedAndLabelsHits(t *testing.T) {
	scope := &readScopeStub{allowed: []string{"org/a", "org/b"}}
	backend := &repositoryReadBackendStub{search: []RepositorySearchHit{
		{Repository: "org/a", Path: "README.md", Snippet: "untrusted a", Score: .9},
		{Repository: "org/b", Path: "docs/use.md", Snippet: "untrusted b", Score: .8},
	}}
	service := NewRepositoryReadService(scope, backend, RepositoryReadConfig{MaxSearchResults: 2, MaxQueryBytes: 32})

	result, err := service.Search(context.Background(), Identity{TenantID: "tenant", AgentID: "work"}, RepositorySearchRequest{Query: "setup", Limit: 50, Repositories: []string{"org/a", "org/b"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Limit != 2 || len(result.Hits) != 2 || result.Hits[0].ContentTrust != UntrustedRepositoryContent {
		t.Fatalf("search result = %#v", result)
	}
	if !reflect.DeepEqual(backend.seenRepos, []string{"org/a", "org/b"}) {
		t.Fatalf("backend repository scope = %#v", backend.seenRepos)
	}
	if len(scope.checks) != 4 {
		t.Fatalf("returned hits were not re-authorized: %#v", scope.checks)
	}
}

func TestRepositoryReadServiceSearchRejectsInvalidAndOutOfScopeBackendHits(t *testing.T) {
	service := NewRepositoryReadService(&readScopeStub{allowed: []string{"org/a"}}, &repositoryReadBackendStub{
		search: []RepositorySearchHit{{Repository: "org/secret", Path: "README.md", Snippet: "leak"}},
	}, RepositoryReadConfig{MaxQueryBytes: 4})
	identity := Identity{TenantID: "tenant", AgentID: "work"}
	if _, err := service.Search(context.Background(), identity, RepositorySearchRequest{Query: "", Limit: 1}); !errors.Is(err, ErrRepositoryReadInvalid) {
		t.Fatalf("empty query error = %v", err)
	}
	if _, err := service.Search(context.Background(), identity, RepositorySearchRequest{Query: "12345", Limit: 1}); !errors.Is(err, ErrRepositoryReadLimit) {
		t.Fatalf("query limit error = %v", err)
	}
	if _, err := service.Search(context.Background(), identity, RepositorySearchRequest{Query: "find", Limit: 1, Repositories: []string{"org/a"}}); !errors.Is(err, ErrRepositoryReadBinding) {
		t.Fatalf("out-of-scope hit error = %v", err)
	}
}

func TestRepositoryReadServiceIssuesExactBaseOneTimeBoundedSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	base := RepositoryBase{Repository: "org/private", Ref: "refs/heads/main", CommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TreeSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	backend := &repositoryReadBackendStub{base: base, snapshot: SnapshotDownload{
		Repository: base.Repository, Base: base, DownloadURL: "https://gitoversight.test/snapshots/opaque", SHA256: strings.Repeat("c", 64), ExpiresAt: now.Add(time.Minute), MaxBytes: 1024, OneTime: true,
	}}
	service := NewRepositoryReadService(&readScopeStub{allowed: []string{"org/private"}}, backend, RepositoryReadConfig{MaxSnapshotBytes: 1024, MaxSnapshotTTL: 2 * time.Minute, Now: func() time.Time { return now }})

	result, err := service.Snapshot(context.Background(), Identity{TenantID: "tenant", AgentID: "work"}, SnapshotRequest{
		Repository: "org/private", Ref: "refs/heads/main", ExactCommitSHA: base.CommitSHA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Base != base || !result.OneTime || result.MaxBytes != 1024 || result.ContentTrust != UntrustedRepositoryContent {
		t.Fatalf("snapshot = %#v", result)
	}
}

func TestRepositoryReadServiceSnapshotRejectsStaleOrUnboundedMetadata(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	base := RepositoryBase{Repository: "org/private", Ref: "refs/heads/main", CommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TreeSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	identity := Identity{TenantID: "tenant", AgentID: "work"}
	request := SnapshotRequest{Repository: base.Repository, Ref: base.Ref, ExactCommitSHA: base.CommitSHA}

	backend := &repositoryReadBackendStub{base: base, snapshot: SnapshotDownload{Repository: base.Repository, Base: base, DownloadURL: "https://example.test/s", SHA256: strings.Repeat("c", 64), ExpiresAt: now.Add(time.Minute), MaxBytes: 2048, OneTime: true}}
	service := NewRepositoryReadService(&readScopeStub{allowed: []string{base.Repository}}, backend, RepositoryReadConfig{MaxSnapshotBytes: 1024, MaxSnapshotTTL: time.Minute, Now: func() time.Time { return now }})
	if _, err := service.Snapshot(context.Background(), identity, SnapshotRequest{Repository: base.Repository, Ref: base.Ref, ExactCommitSHA: "cccccccccccccccccccccccccccccccccccccccc"}); !errors.Is(err, ErrRepositoryReadStaleBase) {
		t.Fatalf("stale base error = %v", err)
	}
	if _, err := service.Snapshot(context.Background(), identity, request); !errors.Is(err, ErrRepositoryReadBinding) {
		t.Fatalf("oversized metadata error = %v", err)
	}
}
