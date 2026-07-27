package ui_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/api"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"os"

	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/searchembed"
	"github.com/yaniv256/gitoversight.dev/internal/searchstore"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/ui"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

func uiDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "ui.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.EnsureTenant(context.Background(), "default", time.Unix(1_700_000_000, 0).UTC())
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return db
}

func uiGet(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(&http.Cookie{Name: "gitoversight_csrf", Value: "csrf-token-123"})
	return request.WithContext(api.WithHumanApprover(request.Context(), api.HumanApprover{TenantID: "default", ID: "yaniv"}))
}

func TestNowRendersEmptyState(t *testing.T) {
	t.Parallel()
	handler, err := ui.NewHandler(ui.Config{Store: uiDB(t)})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/now"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "Nothing needs you.") {
		t.Fatalf("empty state missing: %s", body[:200])
	}
	if !strings.Contains(body, `content="csrf-token-123"`) {
		t.Fatal("csrf token not injected")
	}
	csp := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "http") {
		t.Fatalf("csp = %q", csp)
	}
}

func TestNowRendersTopItemWithDepth(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	req := sqlite.SyncRequest{TenantID: "default", ID: "sync-ui",
		PrivateRepository: "yaniv256/mirror.dev", PublicRepository: "yaniv256/mirror",
		ProposalText: "Release", FileManifest: []string{"SKILL.md"},
		CommitPacketJSON: `{"sha":"abc"}`, PacketHeadSHA: "abc", CreatedBy: "zara"}
	if err := db.CreateSyncProposal(context.Background(), req, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := db.ReplaceQueueOrder(context.Background(), "default",
		[]sqlite.QueueItem{{ItemID: "q1", Kind: "sync", Ref: "sync-ui"}}, time.Unix(1_800_000_001, 0)); err != nil {
		t.Fatalf("queue: %v", err)
	}
	handler, _ := ui.NewHandler(ui.Config{Store: db})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/now"))
	body := response.Body.String()
	if !strings.Contains(body, "sync-ui") || !strings.Contains(body, "1 of 1") {
		t.Fatalf("top item not rendered: %s", body[:300])
	}
}

func TestUIWithoutApproverRedirects(t *testing.T) {
	t.Parallel()
	handler, _ := ui.NewHandler(ui.Config{Store: uiDB(t)})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ui/now", nil))
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/login/github" {
		t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestQueueRefEscaped(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	req := sqlite.SyncRequest{TenantID: "default", ID: "<script>alert(1)</script>",
		PrivateRepository: "yaniv256/mirror.dev", PublicRepository: "yaniv256/mirror",
		ProposalText: "x", FileManifest: []string{"SKILL.md"},
		CommitPacketJSON: `{"sha":"abc"}`, PacketHeadSHA: "abc", CreatedBy: "zara"}
	if err := db.CreateSyncProposal(context.Background(), req, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := db.ReplaceQueueOrder(context.Background(), "default",
		[]sqlite.QueueItem{{ItemID: "q1", Kind: "sync", Ref: "<script>alert(1)</script>"}}, time.Unix(1_800_000_001, 0)); err != nil {
		t.Fatalf("queue: %v", err)
	}
	handler, _ := ui.NewHandler(ui.Config{Store: db})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/now"))
	if strings.Contains(response.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("untrusted ref rendered unescaped")
	}
}

type fakeLister struct {
	byRepo map[string][]githubapp.PullRequestSummary
	fail   map[string]bool
}

func (f *fakeLister) List(request worker.Request) ([]githubapp.PullRequestSummary, error) {
	if f.fail[request.Repository] {
		return nil, errors.New("boom")
	}
	return f.byRepo[request.Repository], nil
}

func everythingPolicy() policy.Snapshot {
	return policy.Snapshot{Generation: 1,
		Agents: map[string]policy.Agent{"zara": {UID: 1002, FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{
			"yaniv256/alpha": {Visibility: "private", Owners: []string{"zara"}},
			"yaniv256/beta":  {Visibility: "public", Owners: []string{"zara"}},
		}}
}

// countingLister fails the "zero live calls" invariant loudly: the everything
// view must render purely from the search dataset.
type countingLister struct{ calls int32 }

func (c *countingLister) List(worker.Request) ([]githubapp.PullRequestSummary, error) {
	atomic.AddInt32(&c.calls, 1)
	return nil, nil
}

const uiTestLastSync = "2026-07-23T00:00:00Z"

// seedUISearchStore builds a real on-disk searchstore at path: repo rows, FTS,
// a trained corpus, cached pulls, and the last_sync stamp.
func seedUISearchStore(t *testing.T, path string, repos []searchstore.Repo, pullsByRepo map[string][]searchstore.Pull) {
	t.Helper()
	ctx := context.Background()
	store, err := searchstore.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	docs := make([]searchembed.Document, 0, len(repos))
	for _, repo := range repos {
		if err := store.UpsertRepo(ctx, repo); err != nil {
			t.Fatal(err)
		}
		docs = append(docs, searchembed.NewDocument(repo.FullName, repo.FullName, repo.Description, repo.ReadmeText))
	}
	corpus := searchembed.BuildCorpus(docs)
	if err := store.ReplaceVectors(ctx, corpus.Docs); err != nil {
		t.Fatal(err)
	}
	tokens := make(map[string]searchstore.TokenVector, len(corpus.Tokens))
	for token, entry := range corpus.Tokens {
		tokens[token] = searchstore.TokenVector{Vector: entry.Vector, IDF: entry.IDF}
	}
	if err := store.ReplaceTokenVectors(ctx, tokens); err != nil {
		t.Fatal(err)
	}
	for fullName, pulls := range pullsByRepo {
		if err := store.ReplacePulls(ctx, fullName, pulls); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetMeta(ctx, "last_sync", uiTestLastSync); err != nil {
		t.Fatal(err)
	}
}

func uiSearchRepos() []searchstore.Repo {
	return []searchstore.Repo{
		{
			FullName:    "yaniv256/agent-kanban",
			Description: "kanban board tooling for memory-less agents",
			HTMLURL:     "https://github.com/yaniv256/agent-kanban",
			ReadmeText:  "Trello kanban workflows keep multi-session agent work on one board.",
		},
		{
			FullName:    "yaniv256/hyperframes",
			Description: "html video rendering engine",
			HTMLURL:     "https://github.com/yaniv256/hyperframes",
			ReadmeText:  "HyperFrames renders video from html timelines.",
		},
		{
			FullName:    "yaniv256/hostile",
			Description: `<script>alert(1)</script> description`,
			HTMLURL:     "https://github.com/yaniv256/hostile",
			ReadmeText:  `hostile readme " onmouseover=alert(2) <script>alert(1)</script> payload`,
		},
	}
}

func searchUIHandler(t *testing.T, dbPath string) *ui.Handler {
	t.Helper()
	handler, err := ui.NewHandler(ui.Config{Store: uiDB(t), Policy: everythingPolicy(), Pulls: &fakeLister{}, SearchDBPath: dbPath})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	return handler
}

func TestSearchPageWithoutApproverRedirects(t *testing.T) {
	t.Parallel()
	handler := searchUIHandler(t, filepath.Join(t.TempDir(), "search.db"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ui/search", nil))
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/login/github" {
		t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestSearchPageEmptyQueryRendersEmptyState(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "search.db")
	seedUISearchStore(t, path, uiSearchRepos(), nil)
	response := httptest.NewRecorder()
	searchUIHandler(t, path).ServeHTTP(response, uiGet("/ui/search"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "Search your repositories.") {
		t.Fatalf("empty state missing: %s", response.Body.String())
	}
}

func TestSearchPageRendersSeededResults(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "search.db")
	seedUISearchStore(t, path, uiSearchRepos(), nil)
	response := httptest.NewRecorder()
	searchUIHandler(t, path).ServeHTTP(response, uiGet("/ui/search?q=kanban"))
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if !strings.Contains(body, "yaniv256/agent-kanban") {
		t.Fatalf("expected repo row missing: %s", body)
	}
	if !strings.Contains(body, `href="https://github.com/yaniv256/agent-kanban"`) {
		t.Fatal("result link does not point at github.com")
	}
	if !strings.Contains(body, "kanban board tooling") {
		t.Fatal("description missing")
	}
}

func TestSearchPageEscapesHostileDatasetContent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "search.db")
	seedUISearchStore(t, path, uiSearchRepos(), nil)
	response := httptest.NewRecorder()
	searchUIHandler(t, path).ServeHTTP(response, uiGet("/ui/search?q=hostile"))
	body := response.Body.String()
	if !strings.Contains(body, "yaniv256/hostile") {
		t.Fatalf("hostile repo did not surface for its own name: %s", body)
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("raw script tag leaked into HTML")
	}
	if strings.Contains(body, `" onmouseover=`) {
		t.Fatal("raw attribute-breaking quote leaked into HTML")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("escaped entity form missing — hostile text not rendered at all?")
	}
}

func TestSearchPageIndexNotBuilt(t *testing.T) {
	t.Parallel()
	handler := searchUIHandler(t, filepath.Join(t.TempDir(), "missing.db"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/search?q=kanban"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "still building") {
		t.Fatalf("index-building notice missing: %s", response.Body.String())
	}
}

// notConfiguredHandler builds a handler whose search dataset feature is off
// (empty SearchDBPath) — the state every pre-search deployment runs in.
func notConfiguredHandler(t *testing.T) *ui.Handler {
	t.Helper()
	handler, err := ui.NewHandler(ui.Config{Store: uiDB(t), Policy: everythingPolicy(), Pulls: &fakeLister{}})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	return handler
}

func TestSearchPageNotConfiguredIsNotIndexBuilding(t *testing.T) {
	t.Parallel()
	response := httptest.NewRecorder()
	notConfiguredHandler(t).ServeHTTP(response, uiGet("/ui/search?q=kanban"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "not configured") {
		t.Fatalf("not-configured notice missing: %s", body)
	}
	if strings.Contains(body, "still building") {
		t.Fatal("unconfigured search rendered the index-building state")
	}
}

func TestEverythingNotConfiguredHidesRefreshButton(t *testing.T) {
	t.Parallel()
	response := httptest.NewRecorder()
	notConfiguredHandler(t).ServeHTTP(response, uiGet("/ui/everything"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "not configured") {
		t.Fatalf("not-configured notice missing: %s", body)
	}
	if strings.Contains(body, "not built yet") {
		t.Fatal("unconfigured everything rendered the index-building state")
	}
	// The refresh route is not registered when the feature is off: rendering
	// the button would 404 on tap.
	if strings.Contains(body, "/v1/human/search/refresh") {
		t.Fatal("refresh button rendered without a search dataset configured")
	}
	// Registered repos still render their neutral rows.
	if !strings.Contains(body, "yaniv256/alpha") || !strings.Contains(body, "yaniv256/beta") {
		t.Fatal("policy repos missing from unconfigured everything view")
	}
}

// brokenSearchDB returns a SearchDBPath whose open fails with a real error
// (the path is a directory), NOT the not-built sentinel.
func brokenSearchDB(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func TestEverythingDatasetOpenErrorRendersErrorNotConfiguredNotBuilding(t *testing.T) {
	t.Parallel()
	logged := int32(0)
	handler, err := ui.NewHandler(ui.Config{Store: uiDB(t), Policy: everythingPolicy(), Pulls: &fakeLister{},
		SearchDBPath: brokenSearchDB(t),
		Logf:         func(string, ...any) { atomic.AddInt32(&logged, 1) }})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/everything"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if strings.Contains(body, "not built yet") {
		t.Fatal("real open error rendered as the benign index-building state")
	}
	if !strings.Contains(body, "unavailable") {
		t.Fatalf("error notice missing: %s", body)
	}
	if atomic.LoadInt32(&logged) == 0 {
		t.Fatal("dataset open error was not logged")
	}
	// Repos still render as neutral not-synced rows.
	if !strings.Contains(body, "yaniv256/alpha") {
		t.Fatal("policy repos missing from degraded everything view")
	}
}

func TestSearchPageOpenErrorRendersErrorNotice(t *testing.T) {
	t.Parallel()
	handler, err := ui.NewHandler(ui.Config{Store: uiDB(t), Policy: everythingPolicy(), Pulls: &fakeLister{},
		SearchDBPath: brokenSearchDB(t), Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/search?q=kanban"))
	body := response.Body.String()
	if strings.Contains(body, "still building") {
		t.Fatal("real open error rendered as the benign index-building state")
	}
	if !strings.Contains(body, "unavailable") {
		t.Fatalf("error notice missing: %s", body)
	}
}

func TestSearchTabInNav(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "search.db")
	seedUISearchStore(t, path, uiSearchRepos(), nil)
	response := httptest.NewRecorder()
	searchUIHandler(t, path).ServeHTTP(response, uiGet("/ui/search"))
	if !strings.Contains(response.Body.String(), `href="/ui/search"`) {
		t.Fatal("search nav tab missing")
	}
}

func TestEverythingRendersFromDatasetWithoutLiveCalls(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	// a sync in state proposed whose branch matches a cached PR head
	req := sqlite.SyncRequest{TenantID: "default", ID: "s9",
		PrivateRepository: "yaniv256/alpha.dev", PublicRepository: "yaniv256/beta",
		ProposalText: "x", FileManifest: []string{"SKILL.md"},
		CommitPacketJSON: `{"sha":"abc"}`, PacketHeadSHA: "abc", CreatedBy: "zara"}
	if err := db.CreateSyncProposal(context.Background(), req, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	path := filepath.Join(t.TempDir(), "search.db")
	seedUISearchStore(t, path,
		[]searchstore.Repo{{FullName: "yaniv256/beta", Description: "beta", HTMLURL: "https://github.com/yaniv256/beta"}},
		map[string][]searchstore.Pull{"yaniv256/beta": {
			{Number: 5, Title: "Sync the rules", Author: "yaniv256", HTMLURL: "https://github.com/yaniv256/beta/pull/5", HeadRef: "sync/s9"},
			{Number: 6, Title: "Plain change", Author: "yaniv256", HTMLURL: "https://github.com/yaniv256/beta/pull/6", HeadRef: "feature/x"},
		}})
	lister := &countingLister{}
	handler, err := ui.NewHandler(ui.Config{Store: db, Policy: everythingPolicy(), Pulls: lister, SearchDBPath: path})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/everything"))
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if got := atomic.LoadInt32(&lister.calls); got != 0 {
		t.Fatalf("everything view made %d live pull_request.list calls, want 0", got)
	}
	if !strings.Contains(body, "Your review") {
		t.Fatalf("sync-linked PR chip missing: %s", body)
	}
	if !strings.Contains(body, ">Open<") {
		t.Fatal("plain PR chip missing")
	}
	if !strings.Contains(body, "https://github.com/yaniv256/beta/pull/5") {
		t.Fatal("GitHub link missing")
	}
	// alpha is registered in policy but absent from the dataset
	if !strings.Contains(body, "yaniv256/alpha") || !strings.Contains(body, "not synced yet") {
		t.Fatal("policy repo absent from dataset did not render its not-synced row")
	}
	if !strings.Contains(body, "synced "+uiTestLastSync) {
		t.Fatal("freshness stamp missing")
	}
	if !strings.Contains(body, "/v1/human/search/refresh") {
		t.Fatal("refresh action missing")
	}
}

func TestEverythingWithoutDatasetRendersNotSyncedRows(t *testing.T) {
	t.Parallel()
	handler := searchUIHandler(t, filepath.Join(t.TempDir(), "missing.db"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/everything"))
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	for _, needle := range []string{"yaniv256/alpha", "yaniv256/beta", "not synced yet", "not built yet"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("degraded everything view missing %q: %s", needle, body)
		}
	}
}

func TestEverythingEscapesHostileDatasetContent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "search.db")
	seedUISearchStore(t, path,
		[]searchstore.Repo{{FullName: "yaniv256/beta", Description: "beta", HTMLURL: "https://github.com/yaniv256/beta"}},
		map[string][]searchstore.Pull{"yaniv256/beta": {
			{Number: 7, Title: `<script>alert(1)</script>`, Author: `" onmouseover=alert(2)`, HTMLURL: "https://github.com/yaniv256/beta/pull/7", HeadRef: "feature/y"},
		}})
	response := httptest.NewRecorder()
	searchUIHandler(t, path).ServeHTTP(response, uiGet("/ui/everything"))
	body := response.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("raw script tag leaked into HTML")
	}
	if strings.Contains(body, `" onmouseover=`) {
		t.Fatal("raw attribute-breaking quote leaked into HTML")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("escaped entity form missing — hostile title not rendered at all?")
	}
}

func TestNowStillRendersAfterEverythingAdded(t *testing.T) {
	t.Parallel()
	handler, _ := ui.NewHandler(ui.Config{Store: uiDB(t), Policy: everythingPolicy(), Pulls: &fakeLister{}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/now"))
	if !strings.Contains(response.Body.String(), "Nothing needs you.") {
		t.Fatal("now view broken by template-set split")
	}
}

func seedSyncState(t *testing.T, db *sqlite.DB, id, state string) sqlite.SyncRequest {
	t.Helper()
	req := sqlite.SyncRequest{TenantID: "default", ID: id,
		PrivateRepository: "yaniv256/mirror.dev", PublicRepository: "yaniv256/mirror",
		ProposalText: "Release <b>now</b>\n\nDetails.", FileManifest: []string{"SKILL.md", "docs/<img>.md"},
		CommitPacketJSON: `{"sha":"abc"}`, PacketHeadSHA: "abc", CreatedBy: "zara"}
	if err := db.CreateSyncProposal(context.Background(), req, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	now := time.Unix(1_800_000_100, 0)
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	switch state {
	case "authorized":
		if err := db.AuthorizeSync(context.Background(), "default", id, hash, now); err != nil {
			t.Fatalf("authorize: %v", err)
		}
	case "public_pr_created":
		if err := db.AuthorizeSync(context.Background(), "default", id, hash, now); err != nil {
			t.Fatalf("authorize: %v", err)
		}
		if err := db.RecordSyncPublicPR(context.Background(), "default", id, 55, now.Add(time.Minute)); err != nil {
			t.Fatalf("record pr: %v", err)
		}
	case "abandoned":
		if err := db.AuthorizeSync(context.Background(), "default", id, hash, now); err != nil {
			t.Fatalf("authorize: %v", err)
		}
		if err := db.RecordSyncPublicPR(context.Background(), "default", id, 55, now.Add(time.Minute)); err != nil {
			t.Fatalf("record pr: %v", err)
		}
		if err := db.AbandonSync(context.Background(), "default", id, 55, now.Add(2*time.Minute)); err != nil {
			t.Fatalf("abandon: %v", err)
		}
	}
	out, _ := db.GetSyncRequest(context.Background(), "default", id)
	return out
}

func syncViewHandler(t *testing.T, db *sqlite.DB) *ui.Handler {
	t.Helper()
	handler, err := ui.NewHandler(ui.Config{Store: db, Policy: everythingPolicy(), Pulls: &fakeLister{}})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	return handler
}

func TestSyncViewProposedShowsAuthorizeWithHash(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	sync := seedSyncState(t, db, "sv1", "proposed")
	response := httptest.NewRecorder()
	syncViewHandler(t, db).ServeHTTP(response, uiGet("/ui/sync/sv1"))
	body := response.Body.String()
	if !strings.Contains(body, "Authorize publication") || !strings.Contains(body, sync.ProposalHash) {
		t.Fatalf("authorize button/hash missing")
	}
	if !strings.Contains(body, "Request changes") {
		t.Fatal("request-changes missing")
	}
	// escaping: proposal text + manifest paths render inert
	if strings.Contains(body, "<b>now</b>") || strings.Contains(body, "<img>") {
		t.Fatal("agent-supplied text rendered unescaped")
	}
}

func TestSyncViewPublicPRShowsMergeLinkAndDone(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	seedSyncState(t, db, "sv2", "public_pr_created")
	response := httptest.NewRecorder()
	syncViewHandler(t, db).ServeHTTP(response, uiGet("/ui/sync/sv2"))
	body := response.Body.String()
	if !strings.Contains(body, "https://github.com/yaniv256/mirror/pull/55") {
		t.Fatal("GitHub merge link missing")
	}
	if !strings.Contains(body, "/v1/human/sync/sv2/done") {
		t.Fatal("done action missing")
	}
	if strings.Contains(body, "Authorize publication") {
		t.Fatal("authorize rendered outside proposed state")
	}
}

func TestSyncViewAuthorizedShowsPending(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	seedSyncState(t, db, "sv3", "authorized")
	response := httptest.NewRecorder()
	syncViewHandler(t, db).ServeHTTP(response, uiGet("/ui/sync/sv3"))
	if !strings.Contains(response.Body.String(), "Publishing") {
		t.Fatal("pending state missing")
	}
}

// The twin of TestStaticAssetsServed. That test passes an ALREADY AUTHENTICATED
// request (uiGet attaches an approver), so it enters below the session gate and
// cannot see whether the assets sit in front of it or behind it. They sat
// behind it: a logged-out browser got a 302 to login instead of CSS/JS.
//
// Found by the post-deploy smoke on its first run, not by the suite — the same
// shape as every other defect in this incident, where the test enters below the
// layer the bug lives at.
func TestStaticAssetsServedWithoutASession(t *testing.T) {
	t.Parallel()
	handler := syncViewHandler(t, uiDB(t))
	for path, marker := range map[string]string{
		"/ui/static/styles.css": ".rail",
		"/ui/static/app.js":     "X-CSRF-Token",
	} {
		response := httptest.NewRecorder()
		// No approver in context — exactly what a logged-out browser sends.
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s: status=%d, want 200 without a session (assets carry no tenant data)", path, response.Code)
		}
		if !strings.Contains(response.Body.String(), marker) {
			t.Fatalf("%s: body did not contain %q", path, marker)
		}
	}
}

func TestStaticAssetsServed(t *testing.T) {
	t.Parallel()
	handler := syncViewHandler(t, uiDB(t))
	for path, marker := range map[string]string{
		"/ui/static/styles.css": ".rail",
		"/ui/static/app.js":     "X-CSRF-Token",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, uiGet(path))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), marker) {
			t.Fatalf("%s: status=%d", path, response.Code)
		}
	}
}

func TestNowRendersDeferralButtons(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	req := sqlite.SyncRequest{TenantID: "default", ID: "nd1",
		PrivateRepository: "yaniv256/mirror.dev", PublicRepository: "yaniv256/mirror",
		ProposalText: "x", FileManifest: []string{"SKILL.md"},
		CommitPacketJSON: `{"sha":"abc"}`, PacketHeadSHA: "abc", CreatedBy: "zara"}
	if err := db.CreateSyncProposal(context.Background(), req, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := db.ReplaceQueueOrder(context.Background(), "default",
		[]sqlite.QueueItem{{ItemID: "q-nd1", Kind: "sync", Ref: "nd1"}}, time.Unix(1_800_000_001, 0)); err != nil {
		t.Fatalf("queue: %v", err)
	}
	response := httptest.NewRecorder()
	syncViewHandler(t, db).ServeHTTP(response, uiGet("/ui/now"))
	body := response.Body.String()
	for _, mode := range []string{`"mode":"skip"`, `"mode":"later"`, `"mode":"shelve"`} {
		if !strings.Contains(body, mode) {
			t.Fatalf("deferral %s missing", mode)
		}
	}
	if !strings.Contains(body, "/v1/human/queue/q-nd1/defer") {
		t.Fatal("defer url missing")
	}
}

func TestApprovalViewRendersApproveWithBinding(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	expires := time.Unix(1_800_010_000, 0).UTC()
	record := storage.Operation{
		TenantID: "default", ID: "req-appr-1", AgentID: "zara",
		Repository: "yaniv256/agent-kanban.dev", Kind: "repository.create",
		PacketHash: "packethash1234567890", State: "awaiting_approval",
		PolicyGeneration: 1, CreatedAt: time.Unix(1_800_000_000, 0), ExpiresAt: time.Unix(1_800_020_000, 0),
		HeadSHA: "headsha1", ManifestHash: "manifesthash1",
		ApprovalID: "appr-1", ApprovalNonce: "nonce-1", ApprovalExpiresAt: expires, Approver: "yaniv",
	}
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		if err := tx.EnsureAgent(context.Background(), "default", "zara", time.Unix(1_700_000_000, 0).UTC()); err != nil {
			return err
		}
		return tx.PutOperation(context.Background(), record)
	}); err != nil {
		t.Fatalf("seed operation: %v", err)
	}
	response := httptest.NewRecorder()
	syncViewHandler(t, db).ServeHTTP(response, uiGet("/ui/approval/req-appr-1"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, needle := range []string{"/v1/reviews/req-appr-1/approve", "appr-1", "nonce-1", "packethash1234567890", "repository.create"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("approval binding %q missing from render", needle)
		}
	}
}

func TestApprovalViewNonAwaitingShowsState(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	record := storage.Operation{
		TenantID: "default", ID: "req-appr-2", AgentID: "zara",
		Repository: "yaniv256/x", Kind: "branch.push", PacketHash: "h", State: "verified",
		PolicyGeneration: 1, CreatedAt: time.Unix(1_800_000_000, 0), ExpiresAt: time.Unix(1_800_020_000, 0),
	}
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		if err := tx.EnsureAgent(context.Background(), "default", "zara", time.Unix(1_700_000_000, 0).UTC()); err != nil {
			return err
		}
		return tx.PutOperation(context.Background(), record)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	response := httptest.NewRecorder()
	syncViewHandler(t, db).ServeHTTP(response, uiGet("/ui/approval/req-appr-2"))
	body := response.Body.String()
	if strings.Contains(body, "data-action=\"approve\"") {
		t.Fatal("approve button rendered for non-awaiting operation")
	}
	if !strings.Contains(body, "verified") {
		t.Fatal("state note missing")
	}
}

// seedOperation stores one awaiting-approval operation packet and returns the
// rendered approval page for it. The approval page is the surface where a human
// authorizes an agent's action on a PUBLIC repository, so what it renders is the
// whole of the oversight this product offers for that action.
func seedOperation(t *testing.T, record storage.Operation) string {
	t.Helper()
	db := uiDB(t)
	if record.PolicyGeneration == 0 {
		record.PolicyGeneration = 1
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Unix(1_800_000_000, 0)
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = time.Unix(1_800_020_000, 0)
	}
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		if err := tx.EnsureAgent(context.Background(), "default", record.AgentID, time.Unix(1_700_000_000, 0).UTC()); err != nil {
			return err
		}
		return tx.PutOperation(context.Background(), record)
	}); err != nil {
		t.Fatalf("seed operation: %v", err)
	}
	response := httptest.NewRecorder()
	syncViewHandler(t, db).ServeHTTP(response, uiGet("/ui/approval/"+record.ID))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	return response.Body.String()
}

// A comment published to a public repository is the exact text in Body. Showing
// the approver a packet hash instead asks them to authorize something they
// cannot read — the packet already carried the body all along.
func TestApprovalViewRendersCommentBody(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"pull_request.reply", "issue.comment"} {
		body := seedOperation(t, storage.Operation{
			TenantID: "default", ID: "req-body-" + strings.ReplaceAll(kind, ".", "-"), AgentID: "zara",
			Repository: "yaniv256/agent-kanban", Kind: kind, PacketHash: "packethashaaaaaaaaaa",
			State: "awaiting_approval", HeadSHA: "headsha1", ManifestHash: "m1",
			ApprovalID: "appr-b", ApprovalNonce: "nonce-b", Approver: "yaniv",
			Body:        "Thanks for the review — I rebased onto main and dropped the vendored binary.",
			PayloadJSON: []byte(`{"number":42}`),
		})
		if !strings.Contains(body, "I rebased onto main and dropped the vendored binary") {
			t.Fatalf("%s: comment body not rendered — the approver cannot see what is being published", kind)
		}
	}
}

// The published text is agent-authored and lands in HTML. html/template escapes
// by default; this pins that nobody "improves" it with a template.HTML cast to
// render markdown.
func TestApprovalViewEscapesPublishedText(t *testing.T) {
	t.Parallel()
	body := seedOperation(t, storage.Operation{
		TenantID: "default", ID: "req-escape", AgentID: "zara",
		Repository: "yaniv256/agent-kanban", Kind: "issue.comment", PacketHash: "packethashbbbbbbbbbb",
		State: "awaiting_approval", HeadSHA: "h", ManifestHash: "m",
		ApprovalID: "appr-e", ApprovalNonce: "nonce-e", Approver: "yaniv",
		Body:        `<script>alert("x")</script>`,
		PayloadJSON: []byte(`{"number":7}`),
	})
	if strings.Contains(body, "<script>alert") {
		t.Fatal("published text rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("published text missing entirely — escaping check is vacuous")
	}
}

// Every comment packet carries an HTML reconciliation marker so the worker can
// find its own comment on GitHub afterward. It is plumbing, and showing it to
// the reviewer as part of "the comment to be posted" is the publish-what-you-see
// promise leaking in the wrong direction. Found by driving the deployed page,
// not by any unit test — the fixtures here were hand-written without markers,
// so nothing exercised the shape a real packet actually has.
func TestApprovalViewHidesTheReconciliationMarker(t *testing.T) {
	t.Parallel()
	body := seedOperation(t, storage.Operation{
		TenantID: "default", ID: "journey-marker", AgentID: "zara",
		Repository: "yaniv256/agent-kanban", Kind: "issue.comment", PacketHash: "packethashgggggggggg",
		State: "awaiting_approval", HeadSHA: "h", ManifestHash: "m",
		ApprovalID: "appr-m", ApprovalNonce: "nonce-m", Approver: "yaniv",
		Body: "Rebased onto main and dropped the vendored binary.\n\n" +
			"<!-- gitoversight-request:journey-marker -->",
		PayloadJSON: []byte(`{"number":9}`),
	})
	if strings.Contains(body, "gitoversight-request:") {
		t.Fatal("reconciliation marker shown to the reviewer as part of the comment")
	}
	if !strings.Contains(body, "Rebased onto main and dropped the vendored binary.") {
		t.Fatal("stripping the marker removed the comment itself")
	}
}

// A pull_request.update replaces the title and body of a live public PR. The
// approver needs to see the proposed values, not a hash of them.
func TestApprovalViewRendersUpdateFields(t *testing.T) {
	t.Parallel()
	body := seedOperation(t, storage.Operation{
		TenantID: "default", ID: "req-update", AgentID: "zara",
		Repository: "yaniv256/agent-kanban", Kind: "pull_request.update", PacketHash: "packethashcccccccccc",
		State: "awaiting_approval", HeadSHA: "headsha9", ManifestHash: "m",
		ApprovalID: "appr-u", ApprovalNonce: "nonce-u", Approver: "yaniv",
		Title: "Narrow the retry window", Body: "Reworded the second paragraph per review.",
		PayloadJSON: []byte(`{"number":11}`),
	})
	for _, needle := range []string{"Narrow the retry window", "Reworded the second paragraph per review."} {
		if !strings.Contains(body, needle) {
			t.Fatalf("update field %q not rendered", needle)
		}
	}
}

// The effect statement answers "what happens on GitHub if I tap this?" — the
// repository, the target number, and a link to look at it first.
func TestApprovalViewStatesTheEffect(t *testing.T) {
	t.Parallel()
	body := seedOperation(t, storage.Operation{
		TenantID: "default", ID: "req-effect", AgentID: "zara",
		Repository: "yaniv256/agent-kanban", Kind: "pull_request.reply", PacketHash: "packethashdddddddddd",
		State: "awaiting_approval", HeadSHA: "h", ManifestHash: "m",
		ApprovalID: "appr-x", ApprovalNonce: "nonce-x", Approver: "yaniv",
		Body: "ack", PayloadJSON: []byte(`{"number":42}`),
	})
	if !strings.Contains(body, "https://github.com/yaniv256/agent-kanban/pull/42") {
		t.Fatal("no link to the public target the approver is about to write to")
	}
}

// An operation whose payload carries no number must not render a broken link,
// and an unknown kind must still render rather than erroring — U9 adds display
// only, so no packet shape may become unrenderable.
func TestApprovalViewToleratesMissingPayloadAndUnknownKind(t *testing.T) {
	t.Parallel()
	body := seedOperation(t, storage.Operation{
		TenantID: "default", ID: "req-bare", AgentID: "zara",
		Repository: "yaniv256/x", Kind: "release.publish", PacketHash: "packethasheeeeeeeeee",
		State: "awaiting_approval", HeadSHA: "h", ManifestHash: "m",
		ApprovalID: "appr-n", ApprovalNonce: "nonce-n", Approver: "yaniv",
	})
	if !strings.Contains(body, "release.publish") {
		t.Fatal("unknown kind failed to render its generic card")
	}
	if strings.Contains(body, "/pull/</a>") || strings.Contains(body, "/pull/\"") {
		t.Fatal("rendered a broken link for a payload with no number")
	}
}

// The approve POST body is the binding the broker cross-checks field by field.
// U9 is a display change; if it perturbs this JSON, approval breaks at the
// broker with a hash mismatch rather than in this package.
func TestApprovalBindingUnchangedByRendering(t *testing.T) {
	t.Parallel()
	body := seedOperation(t, storage.Operation{
		TenantID: "default", ID: "req-binding", AgentID: "zara",
		Repository: "yaniv256/agent-kanban", Kind: "pull_request.reply", PacketHash: "packethashffffffffff",
		State: "awaiting_approval", HeadSHA: "headshaZ", ManifestHash: "manifestZ",
		ApprovalID: "appr-z", ApprovalNonce: "nonce-z", Approver: "yaniv",
		ApprovalExpiresAt: time.Unix(1_800_010_000, 0).UTC(),
		Body:              "hello", PayloadJSON: []byte(`{"number":3}`),
	})
	for _, needle := range []string{
		`&#34;approval_id&#34;:&#34;appr-z&#34;`,
		`&#34;packet_hash&#34;:&#34;packethashffffffffff&#34;`,
		`&#34;manifest_hash&#34;:&#34;manifestZ&#34;`,
		`&#34;head_sha&#34;:&#34;headshaZ&#34;`,
		`&#34;nonce&#34;:&#34;nonce-z&#34;`,
	} {
		if !strings.Contains(body, needle) {
			t.Fatalf("approve binding field missing or altered: %s", needle)
		}
	}
}

func TestPromoteViewRendersStagedPolicy(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	// seed active generation 4 via the broker's install path
	base := everythingPolicy()
	base.Generation = 4
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(uiTestWriteGate{})
	if err := broker.InstallPolicy(context.Background(), "default", base); err != nil {
		t.Fatalf("install policy: %v", err)
	}
	proposed := everythingPolicy()
	proposed.Generation = 5
	proposed.QueueCurator = "zara"
	raw, _ := json.Marshal(proposed)
	staged := filepath.Join(t.TempDir(), "policy.json.proposed")
	if err := os.WriteFile(staged, raw, 0o600); err != nil {
		t.Fatalf("stage: %v", err)
	}
	handler, err := ui.NewHandler(ui.Config{Store: db, Policy: everythingPolicy(), Pulls: &fakeLister{}, ProposedPolicyPath: staged})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/promote-policy"))
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	for _, needle := range []string{"Promote policy", `"expected_generation":4`, `"generation":5`, "curator: zara", "/v1/policy"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("promote body missing %q", needle)
		}
	}
}

func TestPromoteViewEmptyWhenNothingStaged(t *testing.T) {
	t.Parallel()
	handler, _ := ui.NewHandler(ui.Config{Store: uiDB(t), Policy: everythingPolicy(), Pulls: &fakeLister{}, ProposedPolicyPath: "/nonexistent/nope"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/promote-policy"))
	if !strings.Contains(response.Body.String(), "No policy update staged.") {
		t.Fatal("empty state missing")
	}
}

type uiTestWriteGate struct{}

func (uiTestWriteGate) Verify() error                        { return nil }
func (uiTestWriteGate) Commit(context.Context, string) error { return nil }

// The template's final {{else}} renders "This sync is complete." An unhandled
// abandoned state falls into it, so the page would assert the OPPOSITE of the
// truth — a confident-wrong message, which ends a reviewer's investigation
// before it starts. Worse than an error, and the exact class this plan corrects.
func TestSyncViewRendersAbandonedHonestly(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	seedSyncState(t, db, "sv-abandoned", "abandoned")
	response := httptest.NewRecorder()
	syncViewHandler(t, db).ServeHTTP(response, uiGet("/ui/sync/sv-abandoned"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if strings.Contains(body, "This sync is complete") {
		t.Fatal("an abandoned sync renders as complete — the page asserts the opposite of the truth")
	}
	if !strings.Contains(body, "Closed without merging") {
		t.Fatal("the abandoned page does not say what happened")
	}
	// R3: no control that cannot succeed.
	if strings.Contains(body, `data-action="done"`) || strings.Contains(body, `data-action="authorize"`) {
		t.Fatal("an abandoned sync still offers a control that can never succeed")
	}
	// Trap 2: an unknown state yields order[state]==0, rendering every rail
	// stage un-started — a blank, apparently-fresh progress rail.
	if strings.Contains(body, `class=" "`) && !strings.Contains(body, "done") {
		t.Fatal("the progress rail renders as never-started for a finished sync")
	}
}

// A revised pre-PR must show its provenance; a FIRST proposal must not. The
// false-positive half matters as much as the true-positive one — a banner
// reading "Revision 0" on every proposal would train the reviewer to ignore it.
func TestSyncViewShowsRevisionProvenanceOnlyWhenRevised(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	req := seedSyncState(t, db, "sv-prov", "proposed")
	handler := syncViewHandler(t, db)

	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, uiGet("/ui/sync/sv-prov"))
	if strings.Contains(firstResponse.Body.String(), "Revision") {
		t.Fatal("a first proposal rendered a revision banner")
	}

	now := time.Unix(1_800_000_200, 0)
	if err := db.RequestSyncChanges(context.Background(), "default", "sv-prov", now); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendSyncEvent(context.Background(), "default", "sv-prov", "sync_change_note",
		map[string]any{"note": "drop the <b>vendored</b> binary", "by": "yaniv"}, now); err != nil {
		t.Fatal(err)
	}
	if err := db.ReviseSyncProposal(context.Background(), "default", "sv-prov", "Revised proposal",
		req.FileManifest, `{"sha":"def"}`, "def", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	revised := httptest.NewRecorder()
	handler.ServeHTTP(revised, uiGet("/ui/sync/sv-prov"))
	body := revised.Body.String()
	if !strings.Contains(body, "Revision 1") {
		t.Fatal("a revised proposal does not say it is a revision")
	}
	if !strings.Contains(body, "drop the") {
		t.Fatal("the reviewer's own change request is not shown")
	}
	// The note is human free text landing in HTML.
	if strings.Contains(body, "<b>vendored</b>") {
		t.Fatal("the change note rendered unescaped")
	}
}

// A closed pre-PR must render honestly and offer no control that cannot
// succeed. Without its branch it falls into the template's final {{else}} and
// says "This sync is complete" — the third state in this plan that would have
// hit that trap.
func TestSyncViewRendersClosedHonestly(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	seedSyncState(t, db, "sv-closed", "proposed")
	if err := db.CloseSync(context.Background(), "default", "sv-closed", "yaniv", "not wanted", time.Unix(1_800_000_500, 0)); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	syncViewHandler(t, db).ServeHTTP(response, uiGet("/ui/sync/sv-closed"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if strings.Contains(body, "This sync is complete") {
		t.Fatal("a closed pre-PR renders as complete — the opposite of the truth")
	}
	if !strings.Contains(body, "Closed without publishing") {
		t.Fatal("the closed page does not say what happened")
	}
	if strings.Contains(body, `data-action="authorize"`) || strings.Contains(body, `data-action="close"`) {
		t.Fatal("a closed pre-PR still offers a control that cannot succeed")
	}
	// The thread stays: a closed pre-PR is still discussable, so losing the
	// compose box would discard "here is why we closed this".
	if !strings.Contains(body, `data-action="comment"`) {
		t.Fatal("a closed pre-PR lost its discussion thread")
	}
}

// Static assets must revalidate. Without an ETag, a browser that had ever loaded
// a page kept the OLD stylesheet after a deploy — max-age alone means a plain
// reload does not refetch, so a shipped CSS fix never reached returning users.
// Observed live 2026-07-26: same URL, cached copy missing a rule the freshly
// fetched bytes contained.
func TestStaticAssetsRevalidateWithETag(t *testing.T) {
	handler, err := ui.NewHandler(ui.Config{Store: uiDB(t)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, path := range []string{"/ui/static/styles.css", "/ui/static/app.js"} {
		first := httptest.NewRecorder()
		handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, path, nil))
		if first.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, first.Code)
		}
		etag := first.Header().Get("ETag")
		if etag == "" {
			t.Fatalf("%s: no ETag, so a cached copy never revalidates after a deploy", path)
		}
		if first.Body.Len() == 0 {
			t.Fatalf("%s: empty body", path)
		}

		// A matching If-None-Match must short-circuit: that is what makes the
		// revalidation cheap enough to be worth doing on every load.
		second := httptest.NewRecorder()
		conditional := httptest.NewRequest(http.MethodGet, path, nil)
		conditional.Header.Set("If-None-Match", etag)
		handler.ServeHTTP(second, conditional)
		if second.Code != http.StatusNotModified {
			t.Fatalf("%s: matching If-None-Match returned %d, want 304", path, second.Code)
		}

		// A STALE validator must serve fresh bytes. This is the direction that
		// actually matters — it is the deploy case, and a handler that always
		// 304s would pass the check above while shipping nothing.
		third := httptest.NewRecorder()
		stale := httptest.NewRequest(http.MethodGet, path, nil)
		stale.Header.Set("If-None-Match", `"stale-etag-from-a-previous-deploy"`)
		handler.ServeHTTP(third, stale)
		if third.Code != http.StatusOK || third.Body.Len() == 0 {
			t.Fatalf("%s: stale validator returned %d with %d bytes, want 200 with content",
				path, third.Code, third.Body.Len())
		}
	}
}

// The Now page must offer a promotion only when one could actually happen.
//
// Observed live 2026-07-26: Now said "A policy update is staged for your
// review" and the page behind Review & promote said "No policy update staged".
// Now tested only that the staged FILE EXISTS; promote additionally required
// generation == active+1. A leftover generation-6 file against active
// generation 6 satisfied the first and failed the second, so the queue
// advertised work that was already done.
//
// The stale case is the direction that matters: a test that only checked the
// promotable case would have passed against the shipped bug, because os.Stat
// and the real predicate agree whenever the staged file IS promotable.
func TestNowOffersPromotionOnlyWhenItCanActuallyHappen(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name             string
		stagedGeneration uint64
		wantOffer        bool
	}{
		{"promotable: staged is the next generation", 5, true},
		{"stale: staged generation already promoted", 4, false},
		{"stale: staged generation far behind", 2, false},
	} {
		db := uiDB(t)
		base := everythingPolicy()
		base.Generation = 4
		broker := server.NewDurableBroker(db)
		broker.SetWriteGate(uiTestWriteGate{})
		if err := broker.InstallPolicy(context.Background(), "default", base); err != nil {
			t.Fatalf("%s: install policy: %v", testCase.name, err)
		}
		proposed := everythingPolicy()
		proposed.Generation = testCase.stagedGeneration
		raw, _ := json.Marshal(proposed)
		staged := filepath.Join(t.TempDir(), "policy.json.proposed")
		if err := os.WriteFile(staged, raw, 0o600); err != nil {
			t.Fatalf("%s: stage: %v", testCase.name, err)
		}
		handler, err := ui.NewHandler(ui.Config{Store: db, Policy: everythingPolicy(),
			Pulls: &fakeLister{}, ProposedPolicyPath: staged})
		if err != nil {
			t.Fatalf("%s: new handler: %v", testCase.name, err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, uiGet("/ui/now"))
		offered := strings.Contains(response.Body.String(), "staged for your review")
		if offered != testCase.wantOffer {
			t.Fatalf("%s: Now offered promotion = %v, want %v — the file exists in every case, so an os.Stat check cannot tell these apart",
				testCase.name, offered, testCase.wantOffer)
		}
	}
}
