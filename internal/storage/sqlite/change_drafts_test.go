package sqlite

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
)

func TestChangeDraftStoreScopesIdentityAndExpiresDrafts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedAgent(t, db, "tenant-a", "zara")
	seedAgent(t, db, "tenant-a", "elena")
	now := time.Unix(1_780_000_000, 0).UTC()
	draft := storedDraftFixture(now)
	if err := db.PutChangeDraft(ctx, draft); err != nil {
		t.Fatal(err)
	}

	got, err := db.ChangeDraft(ctx, "tenant-a", "zara", draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Preview.Hash != draft.Preview.Hash || string(got.Changes[0].Content) != "hello\n" {
		t.Fatalf("round trip = %#v", got)
	}
	for _, scope := range [][2]string{{"tenant-a", "elena"}, {"tenant-b", "zara"}} {
		if _, err := db.ChangeDraft(ctx, scope[0], scope[1], draft.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("scope %v error = %v, want not found", scope, err)
		}
	}
	if expired, err := db.ChangeDraft(ctx, "tenant-a", "zara", draft.ID); err != nil || expired.ExpiresAt != draft.ExpiresAt {
		t.Fatalf("expired record must remain classifiable until purge: %#v, %v", expired, err)
	}
	removed, err := db.DeleteExpiredChangeDrafts(ctx, draft.ExpiresAt)
	if err != nil || removed != 1 {
		t.Fatalf("removed=%d error=%v", removed, err)
	}
	if _, err := db.ChangeDraft(ctx, "tenant-a", "zara", draft.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purged private draft content remains readable: %v", err)
	}
}

func TestChangeDraftStoreRejectsInvalidPreview(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedAgent(t, db, "tenant-a", "zara")
	now := time.Unix(1_780_000_000, 0).UTC()
	draft := storedDraftFixture(now)
	draft.Preview.Repository = "other/repo"
	if err := db.PutChangeDraft(ctx, draft); err == nil {
		t.Fatal("stored draft whose preview binding disagrees was accepted")
	}
}

func TestChangeDraftPublicationBindingSurvivesDraftExpiryAndIsUnique(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedAgent(t, db, "tenant-a", "zara")
	now := time.Unix(1_780_000_000, 0).UTC()
	binding := changedraft.PublicationBinding{TenantID: "tenant-a", AgentID: "zara", OperationID: "push-1", RequestHash: "request-hash", HeadSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: now}
	if err := db.PutChangeDraftPublication(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := db.PutChangeDraftPublication(ctx, binding); err == nil {
		t.Fatal("duplicate publication binding accepted")
	}
	if _, err := db.DeleteExpiredChangeDrafts(ctx, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := db.ChangeDraftPublication(ctx, "tenant-a", "zara", "push-1")
	if err != nil || got.RequestHash != binding.RequestHash || got.HeadSHA != binding.HeadSHA {
		t.Fatalf("binding=%+v err=%v", got, err)
	}
	if _, err := db.ChangeDraftPublication(ctx, "tenant-a", "elena", "push-1"); !errors.Is(err, changedraft.ErrStoredPublicationNotFound) {
		t.Fatalf("cross-agent lookup error=%v", err)
	}
}

func TestChangeDraftStorePersistsConcurrentDrafts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedAgent(t, db, "tenant-a", "zara")
	now := time.Unix(1_780_000_000, 0).UTC()
	const count = 12
	start := make(chan struct{})
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for index := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			draft := storedDraftFixture(now)
			draft.ID = fmt.Sprintf("draft-%d", index)
			errs <- db.PutChangeDraft(ctx, draft)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for index := range count {
		if _, err := db.ChangeDraft(ctx, "tenant-a", "zara", fmt.Sprintf("draft-%d", index)); err != nil {
			t.Fatalf("draft %d: %v", index, err)
		}
	}
}

func storedDraftFixture(now time.Time) changedraft.StoredDraft {
	base := changedraft.Snapshot{
		Repository: "yaniv256/example",
		Commit:     changedraft.ObjectID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Tree:       changedraft.ObjectID("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
	}
	changes := []changedraft.Change{{Operation: changedraft.Add, Path: "README.md", Mode: changedraft.ModeFile, Content: []byte("hello\n")}}
	preview, err := changedraft.BuildPreview(base, changes, changedraft.DefaultLimits())
	if err != nil {
		panic(err)
	}
	return changedraft.StoredDraft{
		ID: "draft-1", TenantID: "tenant-a", AgentID: "zara", Preview: preview, Changes: changes,
		CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}
}
