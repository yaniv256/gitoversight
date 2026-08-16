package brokerapp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
)

func TestChangeDraftServiceCreatesDeterministicBrokerBuiltPreview(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	repository := &draftRepositoryFake{snapshot: draftBaseFixture()}
	store := newDraftStoreFake()
	ids := []string{"draft-1", "draft-2"}
	service := NewChangeDraftService(repository, store, ChangeDraftConfig{
		TTL: 15 * time.Minute, Now: func() time.Time { return now },
		NewID: func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil },
	})
	identity := Identity{TenantID: "tenant-a", AgentID: "work-agent"}
	changes := []changedraft.Change{
		{Operation: changedraft.Add, Path: "docs/new.md", Mode: changedraft.ModeFile, Content: []byte("new\n")},
		{Operation: changedraft.Replace, Path: "README.md", Content: []byte("replacement\n")},
	}
	one, err := service.Create(context.Background(), identity, CreateChangeDraftRequest{
		Repository: repository.snapshot.Repository, BaseCommit: repository.snapshot.Commit, Changes: changes,
	})
	if err != nil {
		t.Fatal(err)
	}
	two, err := service.Create(context.Background(), identity, CreateChangeDraftRequest{
		Repository: repository.snapshot.Repository, BaseCommit: repository.snapshot.Commit,
		Changes: []changedraft.Change{changes[1], changes[0]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if one.Preview.Hash != two.Preview.Hash || one.Preview.ResultTree != two.Preview.ResultTree {
		t.Fatalf("preview changed with operation order: %#v %#v", one, two)
	}
	if one.ExpiresAt != now.Add(15*time.Minute) || one.ID != "draft-1" {
		t.Fatalf("receipt=%#v", one)
	}
	stored, ok := store.get(identity, one.ID)
	if !ok || len(stored.Changes) != 2 {
		t.Fatalf("stored=%#v ok=%v", stored, ok)
	}
	if repository.snapshotCalls != 2 || repository.currentCalls != 2 {
		t.Fatalf("repository reads: snapshot=%d current=%d", repository.snapshotCalls, repository.currentCalls)
	}
}

func TestChangeDraftServiceRejectsStaleBaseBeforeSnapshotOrStorage(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	repository := &draftRepositoryFake{snapshot: draftBaseFixture()}
	repository.current.Commit = changedraft.ObjectID(strings.Repeat("f", 40))
	store := newDraftStoreFake()
	service := NewChangeDraftService(repository, store, ChangeDraftConfig{Now: func() time.Time { return now }})
	_, err := service.Create(context.Background(), Identity{TenantID: "tenant-a", AgentID: "work-agent"}, CreateChangeDraftRequest{
		Repository: repository.snapshot.Repository, BaseCommit: repository.snapshot.Commit,
		Changes: []changedraft.Change{{Operation: changedraft.Replace, Path: "README.md", Content: []byte("x")}},
	})
	if !errors.Is(err, ErrChangeDraftStaleBase) {
		t.Fatalf("error=%v", err)
	}
	if repository.snapshotCalls != 0 || store.puts != 0 {
		t.Fatalf("stale request performed work: snapshots=%d puts=%d", repository.snapshotCalls, store.puts)
	}
}

func TestChangeDraftServiceResolveRequiresEveryBindingAndRebuildsContent(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	repository := &draftRepositoryFake{snapshot: draftBaseFixture()}
	store := newDraftStoreFake()
	service := NewChangeDraftService(repository, store, ChangeDraftConfig{
		Now: func() time.Time { return now }, NewID: func() (string, error) { return "draft-1", nil },
	})
	identity := Identity{TenantID: "tenant-a", AgentID: "work-agent"}
	receipt, err := service.Create(context.Background(), identity, CreateChangeDraftRequest{
		Repository: repository.snapshot.Repository, BaseCommit: repository.snapshot.Commit,
		Changes: []changedraft.Change{{Operation: changedraft.Replace, Path: "README.md", Content: []byte("safe")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := ChangeDraftBinding{ID: receipt.ID, Repository: receipt.Preview.Repository, BaseCommit: receipt.Preview.BaseCommit, PreviewHash: receipt.Preview.Hash}
	resolved, err := service.Resolve(context.Background(), identity, binding)
	if err != nil || resolved.Preview.Hash != receipt.Preview.Hash {
		t.Fatalf("resolve=%#v error=%v", resolved, err)
	}

	badBindings := []ChangeDraftBinding{
		{ID: binding.ID, Repository: "other/repo", BaseCommit: binding.BaseCommit, PreviewHash: binding.PreviewHash},
		{ID: binding.ID, Repository: binding.Repository, BaseCommit: changedraft.ObjectID(strings.Repeat("f", 40)), PreviewHash: binding.PreviewHash},
		{ID: binding.ID, Repository: binding.Repository, BaseCommit: binding.BaseCommit, PreviewHash: strings.Repeat("0", 64)},
	}
	for _, bad := range badBindings {
		if _, err := service.Resolve(context.Background(), identity, bad); !errors.Is(err, ErrChangeDraftBinding) {
			t.Fatalf("binding %#v error=%v", bad, err)
		}
	}
	if _, err := service.Resolve(context.Background(), Identity{TenantID: "tenant-a", AgentID: "other-agent"}, binding); !errors.Is(err, ErrChangeDraftNotFound) {
		t.Fatalf("cross-agent error=%v", err)
	}
	repository.current = changedraft.BaseRef{
		Commit: changedraft.ObjectID(strings.Repeat("f", 40)),
		Tree:   repository.snapshot.Tree,
	}
	if _, err := service.Resolve(context.Background(), identity, binding); !errors.Is(err, ErrChangeDraftStaleBase) {
		t.Fatalf("stale resolve error=%v", err)
	}
	repository.current = changedraft.BaseRef{Commit: repository.snapshot.Commit, Tree: repository.snapshot.Tree}

	store.mu.Lock()
	tampered := store.drafts[draftStoreKey(identity, binding.ID)]
	tampered.Changes[0].Content = []byte("malicious replacement")
	store.drafts[draftStoreKey(identity, binding.ID)] = tampered
	store.mu.Unlock()
	if _, err := service.Resolve(context.Background(), identity, binding); !errors.Is(err, ErrChangeDraftTampered) {
		t.Fatalf("tampered content error=%v", err)
	}
}

func TestChangeDraftServiceRejectsExpiredDraft(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	repository := &draftRepositoryFake{snapshot: draftBaseFixture()}
	store := newDraftStoreFake()
	service := NewChangeDraftService(repository, store, ChangeDraftConfig{Now: func() time.Time { return now }})
	identity := Identity{TenantID: "tenant-a", AgentID: "work-agent"}
	preview, err := changedraft.BuildPreview(repository.snapshot, nil, changedraft.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	store.drafts[draftStoreKey(identity, "expired")] = changedraft.StoredDraft{
		ID: "expired", TenantID: identity.TenantID, AgentID: identity.AgentID, Preview: preview,
		CreatedAt: now.Add(-time.Hour), ExpiresAt: now,
	}
	_, err = service.Resolve(context.Background(), identity, ChangeDraftBinding{
		ID: "expired", Repository: preview.Repository, BaseCommit: preview.BaseCommit, PreviewHash: preview.Hash,
	})
	if !errors.Is(err, ErrChangeDraftExpired) {
		t.Fatalf("error=%v", err)
	}
}

type draftRepositoryFake struct {
	mu            sync.Mutex
	snapshot      changedraft.Snapshot
	current       changedraft.BaseRef
	currentErr    error
	snapshotErr   error
	currentCalls  int
	snapshotCalls int
}

func (f *draftRepositoryFake) CurrentBase(_ context.Context, _ Identity, repository string) (changedraft.BaseRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.currentCalls++
	if f.current == (changedraft.BaseRef{}) {
		return changedraft.BaseRef{Commit: f.snapshot.Commit, Tree: f.snapshot.Tree}, f.currentErr
	}
	return f.current, f.currentErr
}

func (f *draftRepositoryFake) Snapshot(_ context.Context, _ Identity, repository string, base changedraft.ObjectID) (changedraft.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshotCalls++
	return f.snapshot, f.snapshotErr
}

func draftBaseFixture() changedraft.Snapshot {
	return changedraft.Snapshot{
		Repository: "yaniv256/example",
		Commit:     changedraft.ObjectID(strings.Repeat("a", 40)),
		Tree:       changedraft.ObjectID(strings.Repeat("b", 40)),
		Entries: []changedraft.Entry{{
			Path: "README.md", Mode: changedraft.ModeFile, Object: changedraft.ObjectID(strings.Repeat("c", 40)),
		}},
	}
}

type draftStoreFake struct {
	mu     sync.Mutex
	drafts map[string]changedraft.StoredDraft
	puts   int
}

func newDraftStoreFake() *draftStoreFake {
	return &draftStoreFake{drafts: map[string]changedraft.StoredDraft{}}
}

func (s *draftStoreFake) PutChangeDraft(_ context.Context, draft changedraft.StoredDraft) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts++
	s.drafts[draftStoreKey(Identity{TenantID: draft.TenantID, AgentID: draft.AgentID}, draft.ID)] = draft
	return nil
}

func (s *draftStoreFake) ChangeDraft(_ context.Context, tenantID, agentID, id string) (changedraft.StoredDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft, ok := s.drafts[draftStoreKey(Identity{TenantID: tenantID, AgentID: agentID}, id)]
	if !ok {
		return changedraft.StoredDraft{}, ErrChangeDraftNotFound
	}
	return draft, nil
}

func draftStoreKey(identity Identity, id string) string {
	return identity.TenantID + "\x00" + identity.AgentID + "\x00" + id
}

func (s *draftStoreFake) get(identity Identity, id string) (changedraft.StoredDraft, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft, ok := s.drafts[draftStoreKey(identity, id)]
	return draft, ok
}
