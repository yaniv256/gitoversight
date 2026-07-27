package searchsync_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/searchembed"
	"github.com/yaniv256/gitoversight.dev/internal/searchstore"
	"github.com/yaniv256/gitoversight.dev/internal/searchsync"
)

type fakeReadme struct {
	text string
	key  string
}

type fakeReader struct {
	mu        sync.Mutex
	repos     []githubapp.RepoInfo
	readmes   map[string]fakeReadme
	listErr   error
	listCalls int
	fetches   map[string]int
}

func newFakeReader() *fakeReader {
	return &fakeReader{readmes: map[string]fakeReadme{}, fetches: map[string]int{}}
}

func (f *fakeReader) ListInstallationRepositories(_ []int64) ([]githubapp.RepoInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]githubapp.RepoInfo, len(f.repos))
	copy(out, f.repos)
	return out, nil
}

func (f *fakeReader) FetchReadme(repository string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches[repository]++
	readme := f.readmes[repository]
	return readme.text, readme.key, nil
}

func (f *fakeReader) ListCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls
}

func (f *fakeReader) FetchCalls() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int, len(f.fetches))
	for repo, count := range f.fetches {
		out[repo] = count
	}
	return out
}

func (f *fakeReader) totalFetches() int {
	total := 0
	for _, count := range f.FetchCalls() {
		total += count
	}
	return total
}

func (f *fakeReader) setRepos(repos ...githubapp.RepoInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.repos = repos
}

func (f *fakeReader) setReadme(repository, text, key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readmes[repository] = fakeReadme{text: text, key: key}
}

func (f *fakeReader) setListErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listErr = err
}

type fakePulls struct {
	mu    sync.Mutex
	pulls map[string][]searchstore.Pull
	calls map[string]int
	fail  map[string]error
}

func newFakePulls() *fakePulls {
	return &fakePulls{pulls: map[string][]searchstore.Pull{}, calls: map[string]int{}, fail: map[string]error{}}
}

func (f *fakePulls) list(repository string) ([]searchstore.Pull, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[repository]++
	if err := f.fail[repository]; err != nil {
		return nil, err
	}
	return f.pulls[repository], nil
}

func (f *fakePulls) setFail(repository string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[repository] = err
}

func (f *fakePulls) callsFor(repository string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[repository]
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type harness struct {
	syncer      *searchsync.Syncer
	store       *searchstore.Store
	reader      *fakeReader
	pulls       *fakePulls
	clock       *fakeClock
	corpusCalls *int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	store, err := searchstore.Open(context.Background(), filepath.Join(t.TempDir(), "search.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	reader := newFakeReader()
	pulls := newFakePulls()
	clock := &fakeClock{t: time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)}
	corpusCalls := 0
	syncer, err := searchsync.New(searchsync.Options{
		Store:  store,
		Reader: reader,
		Pulls:  pulls.list,
		BuildCorpus: func(docs []searchembed.Document) *searchembed.Corpus {
			corpusCalls++
			return searchembed.BuildCorpus(docs)
		},
		Now:                 clock.Now,
		Logf:                t.Logf,
		Interval:            time.Hour,
		Cooldown:            10 * time.Minute,
		TombstoneRetention:  7 * 24 * time.Hour,
		InstallationIDs:     []int64{101},
		ConfiguredRepoCount: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{syncer: syncer, store: store, reader: reader, pulls: pulls, clock: clock, corpusCalls: &corpusCalls}
}

func repoInfo(fullName, description string, pushedAt time.Time) githubapp.RepoInfo {
	return githubapp.RepoInfo{
		FullName:      fullName,
		Description:   description,
		HTMLURL:       "https://github.com/" + fullName,
		DefaultBranch: "main",
		PushedAt:      pushedAt,
	}
}

func TestFirstSyncPopulatesDataset(t *testing.T) {
	h := newHarness(t)
	pushed := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	h.reader.setRepos(
		repoInfo("owner/alpha", "alpha service", pushed),
		repoInfo("owner/beta", "beta library", pushed),
	)
	h.reader.setReadme("owner/alpha", "alpha readme text", "key-alpha-1")
	h.reader.setReadme("owner/beta", "beta readme text", "key-beta-1")
	h.pulls.pulls["owner/alpha"] = []searchstore.Pull{{Number: 4, Title: "fix", Author: "zara", HTMLURL: "https://github.com/owner/alpha/pull/4", HeadRef: "fix"}}

	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	repos, err := h.store.ListRepos(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 {
		t.Fatalf("live repos = %d, want 2", len(repos))
	}
	alpha, ok, err := h.store.GetRepo(context.Background(), "owner/alpha")
	if err != nil || !ok {
		t.Fatalf("alpha row: ok=%v err=%v", ok, err)
	}
	if alpha.ReadmeText != "alpha readme text" || alpha.ReadmeSHA != "key-alpha-1" || alpha.Description != "alpha service" {
		t.Fatalf("alpha row = %#v", alpha)
	}
	if alpha.PushedAt != pushed.Format(time.RFC3339) {
		t.Fatalf("alpha pushed_at = %q", alpha.PushedAt)
	}
	pulls, err := h.store.ListPulls(context.Background(), "owner/alpha")
	if err != nil || len(pulls) != 1 || pulls[0].Number != 4 {
		t.Fatalf("alpha pulls = %#v err=%v", pulls, err)
	}
	if *h.corpusCalls != 1 {
		t.Fatalf("corpus builds = %d, want 1", *h.corpusCalls)
	}
	vectors := 0
	if err := h.store.IterateVectors(context.Background(), func(string, []byte) error {
		vectors++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if vectors != 2 {
		t.Fatalf("stored vectors = %d, want 2", vectors)
	}
	lastSync, ok, err := h.store.GetMeta(context.Background(), "last_sync")
	if err != nil || !ok || lastSync != h.clock.Now().UTC().Format(time.RFC3339) {
		t.Fatalf("last_sync = %q ok=%v err=%v", lastSync, ok, err)
	}
}

func TestUnchangedSecondSyncFetchesNothing(t *testing.T) {
	h := newHarness(t)
	pushed := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	h.reader.setRepos(repoInfo("owner/alpha", "alpha", pushed))
	h.reader.setReadme("owner/alpha", "readme", "key-1")
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fetchesAfterFirst := h.reader.totalFetches()
	pullCallsAfterFirst := h.pulls.callsFor("owner/alpha")

	h.clock.Advance(time.Hour)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.reader.totalFetches(); got != fetchesAfterFirst {
		t.Fatalf("second sync fetched READMEs: %d -> %d", fetchesAfterFirst, got)
	}
	if got := h.pulls.callsFor("owner/alpha"); got != pullCallsAfterFirst {
		t.Fatalf("second sync refreshed pulls: %d -> %d", pullCallsAfterFirst, got)
	}
	if *h.corpusCalls != 1 {
		t.Fatalf("corpus builds = %d, want 1 (no content change)", *h.corpusCalls)
	}
}

func TestChangedRepoRefetchesOnlyThatRepo(t *testing.T) {
	h := newHarness(t)
	pushed := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	h.reader.setRepos(
		repoInfo("owner/alpha", "alpha", pushed),
		repoInfo("owner/beta", "beta", pushed),
	)
	h.reader.setReadme("owner/alpha", "alpha readme", "key-alpha-1")
	h.reader.setReadme("owner/beta", "beta readme", "key-beta-1")
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Alpha gets a new push with a new README; beta is untouched.
	h.reader.setRepos(
		repoInfo("owner/alpha", "alpha", pushed.Add(time.Hour)),
		repoInfo("owner/beta", "beta", pushed),
	)
	h.reader.setReadme("owner/alpha", "alpha readme v2", "key-alpha-2")
	h.clock.Advance(time.Hour)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := h.reader.FetchCalls()
	if calls["owner/alpha"] != 2 {
		t.Fatalf("alpha fetches = %d, want 2", calls["owner/alpha"])
	}
	if calls["owner/beta"] != 1 {
		t.Fatalf("beta fetches = %d, want 1 (unchanged repo was refetched)", calls["owner/beta"])
	}
	alpha, _, err := h.store.GetRepo(context.Background(), "owner/alpha")
	if err != nil {
		t.Fatal(err)
	}
	if alpha.ReadmeText != "alpha readme v2" || alpha.ReadmeSHA != "key-alpha-2" {
		t.Fatalf("alpha readme not refreshed: %#v", alpha)
	}
	if *h.corpusCalls != 2 {
		t.Fatalf("corpus builds = %d, want 2", *h.corpusCalls)
	}
}

func TestMissingRepoTombstonedThenPurgedAfterRetention(t *testing.T) {
	h := newHarness(t)
	pushed := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	h.reader.setRepos(
		repoInfo("owner/alpha", "alpha", pushed),
		repoInfo("owner/gone", "doomed", pushed),
	)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	h.reader.setRepos(repoInfo("owner/alpha", "alpha", pushed))
	h.clock.Advance(time.Hour)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	gone, ok, err := h.store.GetRepo(context.Background(), "owner/gone")
	if err != nil || !ok {
		t.Fatalf("tombstoned repo missing entirely: ok=%v err=%v", ok, err)
	}
	if gone.TombstonedAt == "" {
		t.Fatal("missing repo was not tombstoned")
	}
	live, err := h.store.ListRepos(context.Background(), false)
	if err != nil || len(live) != 1 {
		t.Fatalf("live repos = %d err=%v, want 1", len(live), err)
	}

	// Within retention the row survives; after retention it is purged.
	h.clock.Advance(8 * 24 * time.Hour)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := h.store.GetRepo(context.Background(), "owner/gone"); err != nil || ok {
		t.Fatalf("repo not purged after retention: ok=%v err=%v", ok, err)
	}
}

func TestPushedAtUnchangedSkipsPullRefresh(t *testing.T) {
	h := newHarness(t)
	pushed := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	h.reader.setRepos(
		repoInfo("owner/alpha", "alpha", pushed),
		repoInfo("owner/beta", "beta", pushed),
	)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.pulls.callsFor("owner/alpha") != 1 || h.pulls.callsFor("owner/beta") != 1 {
		t.Fatalf("first sync pull calls = alpha:%d beta:%d, want 1 each", h.pulls.callsFor("owner/alpha"), h.pulls.callsFor("owner/beta"))
	}

	h.reader.setRepos(
		repoInfo("owner/alpha", "alpha", pushed.Add(time.Minute)),
		repoInfo("owner/beta", "beta", pushed),
	)
	h.clock.Advance(time.Hour)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.pulls.callsFor("owner/alpha"); got != 2 {
		t.Fatalf("pushed repo pull calls = %d, want 2", got)
	}
	if got := h.pulls.callsFor("owner/beta"); got != 1 {
		t.Fatalf("unpushed repo pull calls = %d, want 1", got)
	}
}

// TestPullFailureStillAdvancesPushedAt pins the retry-forever fix: a
// persistently failing pull lister (e.g. a repo missing from the
// installations map) must not hold back the stored pushed_at, because a
// held-back pushed_at makes every later pass re-detect change and re-fetch
// the README over HTTP forever. Chips just stay stale until the next push.
func TestPullFailureStillAdvancesPushedAt(t *testing.T) {
	h := newHarness(t)
	pushed := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	h.reader.setRepos(repoInfo("owner/alpha", "alpha", pushed))
	h.reader.setReadme("owner/alpha", "readme", "key-1")
	h.pulls.setFail("owner/alpha", errors.New("repo not in installations map"))

	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	alpha, ok, err := h.store.GetRepo(context.Background(), "owner/alpha")
	if err != nil || !ok {
		t.Fatalf("alpha row: ok=%v err=%v", ok, err)
	}
	if alpha.PushedAt != pushed.Format(time.RFC3339) {
		t.Fatalf("pushed_at held back on pull failure: %q", alpha.PushedAt)
	}
	// The README fetched before the pull failure is kept (store-churn is
	// gated by the sha compare, not by the pull outcome).
	if alpha.ReadmeText != "readme" || alpha.ReadmeSHA != "key-1" {
		t.Fatalf("readme not stored on pull failure: %#v", alpha)
	}
	fetchesAfterFirst := h.reader.totalFetches()
	pullCallsAfterFirst := h.pulls.callsFor("owner/alpha")

	// Next pass, nothing pushed: no README refetch, no pull retry storm.
	h.clock.Advance(time.Hour)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.reader.totalFetches(); got != fetchesAfterFirst {
		t.Fatalf("pull failure caused README refetch on unchanged pass: %d -> %d", fetchesAfterFirst, got)
	}
	if got := h.pulls.callsFor("owner/alpha"); got != pullCallsAfterFirst {
		t.Fatalf("pull failure caused pull refetch on unchanged pass: %d -> %d", pullCallsAfterFirst, got)
	}

	// A real new push retries the pulls (and they now succeed).
	h.pulls.setFail("owner/alpha", nil)
	h.pulls.pulls["owner/alpha"] = []searchstore.Pull{{Number: 9, Title: "late", Author: "zara", HTMLURL: "https://github.com/owner/alpha/pull/9", HeadRef: "late"}}
	h.reader.setRepos(repoInfo("owner/alpha", "alpha", pushed.Add(time.Hour)))
	h.clock.Advance(time.Hour)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	pulls, err := h.store.ListPulls(context.Background(), "owner/alpha")
	if err != nil || len(pulls) != 1 || pulls[0].Number != 9 {
		t.Fatalf("pulls not refreshed on next push: %#v err=%v", pulls, err)
	}
}

func TestEnumerationFailureLeavesDatasetIntact(t *testing.T) {
	h := newHarness(t)
	pushed := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	h.reader.setRepos(repoInfo("owner/alpha", "alpha", pushed))
	h.reader.setReadme("owner/alpha", "readme", "key-1")
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstSync, _, err := h.store.GetMeta(context.Background(), "last_sync")
	if err != nil {
		t.Fatal(err)
	}

	h.reader.setListErr(errors.New("github is down"))
	h.clock.Advance(time.Hour)
	if err := h.syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("enumeration failure did not surface an error")
	}
	repos, err := h.store.ListRepos(context.Background(), false)
	if err != nil || len(repos) != 1 || repos[0].ReadmeText != "readme" {
		t.Fatalf("dataset damaged after failed pass: %#v err=%v", repos, err)
	}
	lastSync, _, err := h.store.GetMeta(context.Background(), "last_sync")
	if err != nil || lastSync != firstSync {
		t.Fatalf("last_sync moved on a failed pass: %q -> %q err=%v", firstSync, lastSync, err)
	}
}

func TestVectorsRebuiltOnlyWhenContentChanged(t *testing.T) {
	h := newHarness(t)
	pushed := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	h.reader.setRepos(repoInfo("owner/alpha", "alpha", pushed))
	h.reader.setReadme("owner/alpha", "readme", "key-1")
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if *h.corpusCalls != 1 {
		t.Fatalf("corpus builds = %d, want 1", *h.corpusCalls)
	}

	// A push whose README change-key is unchanged (and identical metadata):
	// PRs refresh, but the corpus does not rebuild.
	h.reader.setRepos(repoInfo("owner/alpha", "alpha", pushed.Add(time.Minute)))
	h.clock.Advance(time.Hour)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if *h.corpusCalls != 1 {
		t.Fatalf("corpus rebuilt without content change: builds = %d", *h.corpusCalls)
	}

	// A README change rebuilds.
	h.reader.setRepos(repoInfo("owner/alpha", "alpha", pushed.Add(2*time.Minute)))
	h.reader.setReadme("owner/alpha", "readme v2", "key-2")
	h.clock.Advance(time.Hour)
	if err := h.syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if *h.corpusCalls != 2 {
		t.Fatalf("corpus builds = %d, want 2", *h.corpusCalls)
	}
}

func TestSequentialTriggersInsideCooldownCoalesceIntoOnePass(t *testing.T) {
	store, err := searchstore.Open(context.Background(), filepath.Join(t.TempDir(), "search.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reader := newFakeReader()
	reader.setRepos(repoInfo("owner/alpha", "alpha", time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)))
	pulls := newFakePulls()
	syncer, err := searchsync.New(searchsync.Options{
		Store:               store,
		Reader:              reader,
		Pulls:               pulls.list,
		Logf:                t.Logf,
		Interval:            time.Hour,
		Cooldown:            150 * time.Millisecond,
		InstallationIDs:     []int64{101},
		ConfiguredRepoCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		syncer.Run(ctx)
		close(done)
	}()

	// Wait for the startup pass.
	waitFor(t, 2*time.Second, func() bool { return reader.ListCalls() == 1 })

	// Three sequential triggers inside the cooldown window.
	syncer.Trigger()
	syncer.Trigger()
	syncer.Trigger()

	// Exactly one extra pass runs once the cooldown elapses.
	waitFor(t, 2*time.Second, func() bool { return reader.ListCalls() == 2 })
	time.Sleep(400 * time.Millisecond)
	if got := reader.ListCalls(); got != 2 {
		t.Fatalf("passes = %d, want exactly 2 (three triggers must coalesce)", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on context cancel")
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached before timeout")
}
