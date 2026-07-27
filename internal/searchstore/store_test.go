package searchstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "search", "search.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func seedRepo(t *testing.T, store *Store, repo Repo) {
	t.Helper()
	if err := store.UpsertRepo(context.Background(), repo); err != nil {
		t.Fatal(err)
	}
}

func TestOpenMigratesFreshAndIsIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "search", "search.db")

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	version := schemaVersion(t, store)
	if version != CurrentSchemaVersion {
		t.Fatalf("user_version = %d, want %d", version, CurrentSchemaVersion)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-open: migration must be a no-op gated by user_version, not re-applied.
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if version := schemaVersion(t, store); version != CurrentSchemaVersion {
		t.Fatalf("user_version after reopen = %d, want %d", version, CurrentSchemaVersion)
	}
}

func TestOpenCreatesGroupReadableDirectory(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "search")
	store, err := Open(context.Background(), filepath.Join(dir, "search.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A second OS user in a shared group reads this DB cross-process via WAL:
	// the directory must be group-traversable (0o750), not owner-only (0o700).
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("db directory mode = %o, want 750", got)
	}
}

func TestOpenReadOnlyMissingFileReturnsErrNotExist(t *testing.T) {
	t.Parallel()

	_, err := OpenReadOnly(context.Background(), filepath.Join(t.TempDir(), "absent.db"))
	if !errors.Is(err, ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestOpenReadOnlyReadsExistingStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "search.db")
	writer, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	seedRepo(t, writer, Repo{FullName: "yaniv256/actions.json", Description: "voice agent"})

	reader, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	repo, ok, err := reader.GetRepo(ctx, "yaniv256/actions.json")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || repo.Description != "voice agent" {
		t.Fatalf("read-only GetRepo = %+v ok=%v", repo, ok)
	}
}

func TestUpsertRepoRoundTripsIncludingReadme(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	want := Repo{
		FullName:      "yaniv256/gitoversight.dev",
		Description:   "governance broker",
		HTMLURL:       "https://github.com/yaniv256/gitoversight.dev",
		DefaultBranch: "main",
		PushedAt:      "2026-07-20T10:00:00Z",
		ReadmeSHA:     "abc123",
		ReadmeText:    "GitOversight brokers agent-mediated GitHub writes.",
	}
	seedRepo(t, store, want)

	got, ok, err := store.GetRepo(ctx, want.FullName)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("repo not found after upsert")
	}
	if got != want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}

	// Upsert again with changed fields: must update, not error or duplicate.
	want.Description = "governance broker v2"
	want.ReadmeText = "Updated README body."
	seedRepo(t, store, want)
	got, ok, err = store.GetRepo(ctx, want.FullName)
	if err != nil || !ok {
		t.Fatalf("second get: ok=%v err=%v", ok, err)
	}
	if got != want {
		t.Fatalf("after second upsert = %+v, want %+v", got, want)
	}

	all, err := store.ListRepos(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("ListRepos returned %d repos, want 1", len(all))
	}
}

func TestFTSSearchMatchesSeededRepoOnly(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	seedRepo(t, store, Repo{
		FullName:    "yaniv256/agent-kanban",
		Description: "kanban board discipline for memory-less agents",
		ReadmeText:  "Reconcile state against the Trello kanban board.",
	})
	seedRepo(t, store, Repo{
		FullName:    "yaniv256/hyperframes",
		Description: "render video from HTML",
		ReadmeText:  "Video rendering pipeline.",
	})

	hits, err := store.FTSSearch(ctx, []string{"kanban"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("FTSSearch(kanban) returned %d hits, want 1: %+v", len(hits), hits)
	}
	if hits[0].FullName != "yaniv256/agent-kanban" {
		t.Fatalf("hit = %q, want yaniv256/agent-kanban", hits[0].FullName)
	}

	// Upsert must refresh the FTS row, not leave a stale duplicate.
	seedRepo(t, store, Repo{
		FullName:    "yaniv256/agent-kanban",
		Description: "board discipline for memory-less agents",
		ReadmeText:  "Reconcile state against the Trello kanban board.",
	})
	hits, err = store.FTSSearch(ctx, []string{"kanban"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("after refresh FTSSearch returned %d hits, want 1", len(hits))
	}
}

func TestFTSSearchHostileTokenDoesNotSyntaxError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	seedRepo(t, store, Repo{FullName: "yaniv256/agent-kanban", Description: "kanban"})

	hostile := []string{`" OR NEAR( col: *`, "kanban"}
	hits, err := store.FTSSearch(ctx, hostile, 10)
	if err != nil {
		t.Fatalf("hostile token caused error: %v", err)
	}
	if len(hits) != 1 || hits[0].FullName != "yaniv256/agent-kanban" {
		t.Fatalf("hits = %+v, want the kanban repo", hits)
	}

	// Tokens that are empty after sanitization must not build a broken MATCH.
	hits, err = store.FTSSearch(ctx, []string{`"`, "  "}, 10)
	if err != nil {
		t.Fatalf("all-empty tokens caused error: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("all-empty tokens returned %d hits, want 0", len(hits))
	}
}

func TestTombstoneLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	seedRepo(t, store, Repo{FullName: "yaniv256/keep", Description: "kanban keeper"})
	seedRepo(t, store, Repo{FullName: "yaniv256/gone", Description: "kanban goner"})

	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	marked, err := store.TombstoneMissing(ctx, []string{"yaniv256/keep"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if marked != 1 {
		t.Fatalf("TombstoneMissing marked %d repos, want 1", marked)
	}

	// Tombstoned repo excluded from ListRepos(false) and FTSSearch.
	live, err := store.ListRepos(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0].FullName != "yaniv256/keep" {
		t.Fatalf("live repos = %+v, want only yaniv256/keep", live)
	}
	all, err := store.ListRepos(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("all repos = %d, want 2", len(all))
	}
	hits, err := store.FTSSearch(ctx, []string{"kanban"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].FullName != "yaniv256/keep" {
		t.Fatalf("FTSSearch hits = %+v, want only yaniv256/keep", hits)
	}

	// A purge with a cutoff before the tombstone keeps the row.
	purged, err := store.PurgeTombstonedBefore(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if purged != 0 {
		t.Fatalf("early purge removed %d repos, want 0", purged)
	}

	purged, err = store.PurgeTombstonedBefore(ctx, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if purged != 1 {
		t.Fatalf("purge removed %d repos, want 1", purged)
	}
	_, ok, err := store.GetRepo(ctx, "yaniv256/gone")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("purged repo still present")
	}

	// Re-upserting a tombstoned repo revives it.
	seedRepo(t, store, Repo{FullName: "yaniv256/keep"})
	marked, err = store.TombstoneMissing(ctx, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if marked != 1 {
		t.Fatalf("tombstone-all marked %d, want 1", marked)
	}
	seedRepo(t, store, Repo{FullName: "yaniv256/keep"})
	live, err = store.ListRepos(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 {
		t.Fatalf("revived repos = %+v, want 1", live)
	}
}

func TestReplaceAndListPulls(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	pulls := []Pull{
		{Number: 7, Title: "Fix reason threading", Author: "zara", HTMLURL: "https://example.test/7", HeadRef: "fix/reason"},
		{Number: 9, Title: "Add search store", Author: "zara", HTMLURL: "https://example.test/9", HeadRef: "feat/search"},
	}
	if err := store.ReplacePulls(ctx, "yaniv256/gitoversight.dev", pulls); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplacePulls(ctx, "yaniv256/actions.json", []Pull{{Number: 1, Title: "Sync"}}); err != nil {
		t.Fatal(err)
	}

	got, err := store.ListPulls(ctx, "yaniv256/gitoversight.dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Number != 7 || got[1].Title != "Add search store" {
		t.Fatalf("ListPulls = %+v", got)
	}
	if got[0].FullName != "yaniv256/gitoversight.dev" {
		t.Fatalf("pull full_name = %q", got[0].FullName)
	}

	// Replace fully overwrites the previous set for that repo only.
	if err := store.ReplacePulls(ctx, "yaniv256/gitoversight.dev", []Pull{{Number: 11, Title: "Only one"}}); err != nil {
		t.Fatal(err)
	}
	got, err = store.ListPulls(ctx, "yaniv256/gitoversight.dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Number != 11 {
		t.Fatalf("after replace ListPulls = %+v", got)
	}

	everything, err := store.ListAllPulls(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(everything) != 2 {
		t.Fatalf("ListAllPulls = %d pulls, want 2", len(everything))
	}
}

func TestVectorsRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	vectors := map[string][]byte{
		"yaniv256/a": {1, 2, 3},
		"yaniv256/b": {4, 5, 6},
	}
	if err := store.ReplaceVectors(ctx, vectors); err != nil {
		t.Fatal(err)
	}
	// Replace is total: the old corpus disappears.
	if err := store.ReplaceVectors(ctx, map[string][]byte{"yaniv256/c": {7}}); err != nil {
		t.Fatal(err)
	}
	seen := map[string][]byte{}
	if err := store.IterateVectors(ctx, func(fullName string, vector []byte) error {
		seen[fullName] = vector
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || len(seen["yaniv256/c"]) != 1 || seen["yaniv256/c"][0] != 7 {
		t.Fatalf("IterateVectors saw %+v", seen)
	}

	if err := store.ReplaceTokenVectors(ctx, map[string]TokenVector{
		"kanban": {Vector: []byte{9, 9}, IDF: 3.5},
	}); err != nil {
		t.Fatal(err)
	}
	tv, ok, err := store.GetTokenVector(ctx, "kanban")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || tv.IDF != 3.5 || len(tv.Vector) != 2 {
		t.Fatalf("GetTokenVector = %+v ok=%v", tv, ok)
	}
	_, ok, err = store.GetTokenVector(ctx, "absent")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("absent token reported present")
	}
}

func TestMetaRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	if err := store.SetMeta(ctx, "last_sync", "2026-07-23T12:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetMeta(ctx, "last_sync", "2026-07-23T13:00:00Z"); err != nil {
		t.Fatal(err)
	}
	value, ok, err := store.GetMeta(ctx, "last_sync")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || value != "2026-07-23T13:00:00Z" {
		t.Fatalf("GetMeta = %q ok=%v", value, ok)
	}
	_, ok, err = store.GetMeta(ctx, "missing")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("missing meta key reported present")
	}
}

func TestConcurrentReadDuringOpenWriteTx(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "search.db")
	writer, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	seedRepo(t, writer, Repo{FullName: "yaniv256/pre-existing", Description: "committed before the write tx"})

	// Hold an open write transaction with uncommitted changes.
	tx, err := writer.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO repos (full_name) VALUES ('yaniv256/uncommitted')`); err != nil {
		t.Fatal(err)
	}

	// A reader on a separate connection must still see the committed snapshot
	// (WAL), neither blocking on the writer nor observing the dirty row.
	reader, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	repo, ok, err := reader.GetRepo(readCtx, "yaniv256/pre-existing")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || repo.Description != "committed before the write tx" {
		t.Fatalf("concurrent read = %+v ok=%v", repo, ok)
	}
	_, ok, err = reader.GetRepo(readCtx, "yaniv256/uncommitted")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("reader observed an uncommitted row")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func schemaVersion(t *testing.T, store *Store) int {
	t.Helper()
	var version int
	if err := store.sql.QueryRowContext(context.Background(), `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}
