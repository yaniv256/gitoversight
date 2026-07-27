package api_test

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/api"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/searchembed"
	"github.com/yaniv256/gitoversight.dev/internal/searchstore"
)

const searchTestLastSync = "2026-07-23T00:00:00Z"

func searchTestRepos() []searchstore.Repo {
	return []searchstore.Repo{
		{
			FullName:    "yaniv256/hyperframes",
			Description: "html video rendering engine",
			HTMLURL:     "https://github.com/yaniv256/hyperframes",
			ReadmeText:  "HyperFrames renders video from html timelines with deterministic seeking and gsap animation.",
		},
		{
			FullName:    "yaniv256/actions-json",
			Description: "browser automation action maps",
			HTMLURL:     "https://github.com/yaniv256/actions-json",
			ReadmeText:  "actions json exposes website operating maps for voice agents driving a browser bridge.",
		},
		{
			FullName:    "yaniv256/secret-vault",
			Description: "credential vault storage",
			HTMLURL:     "https://github.com/yaniv256/secret-vault",
			ReadmeText:  "vault keeps secrets sealed with audited credential access.",
		},
		{
			FullName:    "yaniv256/ghost-repo",
			Description: "unregistered ghost repository",
			HTMLURL:     "https://github.com/yaniv256/ghost-repo",
			ReadmeText:  "ghost repo exists in the search dataset only and is absent from policy.",
		},
	}
}

// seedSearchStore builds a real on-disk searchstore at path: repo rows, FTS,
// and a corpus trained with searchembed.BuildCorpus.
func seedSearchStore(t *testing.T, path string, repos []searchstore.Repo) {
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
	if err := store.SetMeta(ctx, "last_sync", searchTestLastSync); err != nil {
		t.Fatal(err)
	}
}

// searchSnapshot registers three of the four seeded repos: reads fall back to
// allowed, except secret-vault which denies repository.read explicitly, and
// ghost-repo which is not registered at all.
func searchSnapshot() policy.Snapshot {
	denied := policy.PermissionSet{}
	return policy.Snapshot{
		Generation:          1,
		FallbackPermissions: policy.PermissionSet{Read: true},
		Agents:              map[string]policy.Agent{"tomas": {UID: 1005, FirstName: "Tomas"}},
		Repositories: map[string]policy.Repository{
			"yaniv256/hyperframes":  {Visibility: "private", Owners: []string{"zara"}},
			"yaniv256/actions-json": {Visibility: "private", Owners: []string{"zara"}},
			"yaniv256/secret-vault": {Visibility: "private", Owners: []string{"zara"}, Permissions: &denied},
		},
	}
}

func newSearchHandler(t *testing.T, dbPath string) *api.SearchHandler {
	t.Helper()
	handler, err := api.NewSearchHandler(api.SearchHandlerConfig{Policy: searchSnapshot(), DBPath: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func seededSearchHandler(t *testing.T) *api.SearchHandler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "search.db")
	seedSearchStore(t, path, searchTestRepos())
	return newSearchHandler(t, path)
}

func searchRequest(target string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	return request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(),
		agentauth.Identity{TenantID: "tenant-a", AgentID: "tomas", CredentialID: "tomas-1"}))
}

type searchTestRow struct {
	FullName    string  `json:"full_name"`
	Description string  `json:"description"`
	Snippet     string  `json:"snippet"`
	Score       float64 `json:"score"`
	HTMLURL     string  `json:"html_url"`
	LastSynced  string  `json:"last_synced"`
}

func decodeSearchResults(t *testing.T, response *httptest.ResponseRecorder) []searchTestRow {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Results []searchTestRow `json:"results"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Results
}

func TestSearchHandlerRequiresAgentIdentity(t *testing.T) {
	t.Parallel()
	handler := seededSearchHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/search?q=hyperframes", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
}

func TestSearchHandlerRanksExactNameQueryFirst(t *testing.T) {
	t.Parallel()
	handler := seededSearchHandler(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q="+url.QueryEscape("yaniv256/hyperframes")))
	results := decodeSearchResults(t, response)
	if len(results) == 0 {
		t.Fatal("no results")
	}
	first := results[0]
	if first.FullName != "yaniv256/hyperframes" {
		t.Fatalf("first result = %q, want yaniv256/hyperframes (all: %#v)", first.FullName, results)
	}
	if first.Description != "html video rendering engine" {
		t.Fatalf("description = %q", first.Description)
	}
	if first.HTMLURL != "https://github.com/yaniv256/hyperframes" {
		t.Fatalf("html_url = %q", first.HTMLURL)
	}
	if first.LastSynced != searchTestLastSync {
		t.Fatalf("last_synced = %q, want %q", first.LastSynced, searchTestLastSync)
	}
	if !strings.HasPrefix(first.Snippet, "HyperFrames renders video") {
		t.Fatalf("snippet = %q", first.Snippet)
	}
	if len([]rune(first.Snippet)) > 200 {
		t.Fatalf("snippet is %d runes, want <= 200", len([]rune(first.Snippet)))
	}
	for i := 1; i < len(results); i++ {
		if results[i].Score > first.Score {
			t.Fatalf("result %d outscores the first: %#v", i, results)
		}
	}
}

func TestSearchHandlerAcceptsKeywordOnlyQuery(t *testing.T) {
	t.Parallel()
	handler := seededSearchHandler(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?keyword=hyperframes&keyword=video"))
	results := decodeSearchResults(t, response)
	if len(results) == 0 || results[0].FullName != "yaniv256/hyperframes" {
		t.Fatalf("results = %#v", results)
	}
}

func TestSearchHandlerRejectsEmptyQuery(t *testing.T) {
	t.Parallel()
	handler := seededSearchHandler(t)
	for _, target := range []string{"/v1/search", "/v1/search?q=", "/v1/search?q=%20&keyword="} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, searchRequest(target))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s code = %d: %s", target, response.Code, response.Body.String())
		}
	}
}

func TestSearchHandlerRejectsOversizedQuery(t *testing.T) {
	t.Parallel()
	handler := seededSearchHandler(t)
	long := strings.Repeat("a", 513)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q="+long))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
	// 512 bytes exactly is still accepted.
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q="+strings.Repeat("a", 512)))
	if response.Code != http.StatusOK {
		t.Fatalf("512-byte q code = %d: %s", response.Code, response.Body.String())
	}
}

func TestSearchHandlerLimitBehaviour(t *testing.T) {
	t.Parallel()
	handler := seededSearchHandler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q=yaniv&limit=1"))
	if results := decodeSearchResults(t, response); len(results) != 1 {
		t.Fatalf("limit=1 returned %d results", len(results))
	}

	// Above the cap the limit clamps to 50 rather than erroring.
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q=yaniv&limit=999"))
	if results := decodeSearchResults(t, response); len(results) > 50 {
		t.Fatalf("limit=999 returned %d results", len(results))
	}

	for _, bad := range []string{"0", "-3", "abc"} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, searchRequest("/v1/search?q=yaniv&limit="+bad))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("limit=%s code = %d: %s", bad, response.Code, response.Body.String())
		}
	}
}

func TestSearchHandlerNeverReturnsPolicyDeniedRepo(t *testing.T) {
	t.Parallel()
	handler := seededSearchHandler(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q="+url.QueryEscape("credential vault secrets")))
	for _, row := range decodeSearchResults(t, response) {
		if row.FullName == "yaniv256/secret-vault" {
			t.Fatalf("policy-denied repo leaked: %#v", row)
		}
	}
}

func TestSearchHandlerNeverReturnsUnregisteredRepo(t *testing.T) {
	t.Parallel()
	handler := seededSearchHandler(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q="+url.QueryEscape("ghost repository dataset")))
	for _, row := range decodeSearchResults(t, response) {
		if row.FullName == "yaniv256/ghost-repo" {
			t.Fatalf("unregistered repo leaked: %#v", row)
		}
	}
}

// TestSearchHandlerDeniedReposCannotCrowdOutAllowedResults pins the
// filter-before-truncate fix: with a bounded over-fetch (the old limit*3
// window) five higher-scoring policy-denied repos crowd the one allowed match
// out of the candidate window entirely. The handler must walk the full
// ranking and collect until `limit` allowed rows.
func TestSearchHandlerDeniedReposCannotCrowdOutAllowedResults(t *testing.T) {
	t.Parallel()
	denied := policy.PermissionSet{}
	repositories := map[string]policy.Repository{
		"yaniv256/quiet-notes": {Visibility: "private", Owners: []string{"zara"}},
	}
	repos := []searchstore.Repo{{
		FullName:    "yaniv256/quiet-notes",
		Description: "personal note taking",
		HTMLURL:     "https://github.com/yaniv256/quiet-notes",
		ReadmeText:  "quiet notes keeps plain text notes organized.",
	}}
	for _, name := range []string{"alpha", "bravo", "charlie", "delta", "echo"} {
		full := "yaniv256/telemetry-" + name
		repositories[full] = policy.Repository{Visibility: "private", Owners: []string{"zara"}, Permissions: &denied}
		repos = append(repos, searchstore.Repo{
			FullName:    full,
			Description: "telemetry pipeline " + name,
			HTMLURL:     "https://github.com/" + full,
			ReadmeText:  "telemetry collector streaming telemetry metrics for " + name,
		})
	}
	snapshot := policy.Snapshot{
		Generation:          1,
		FallbackPermissions: policy.PermissionSet{Read: true},
		Agents:              map[string]policy.Agent{"tomas": {UID: 1005, FirstName: "Tomas"}},
		Repositories:        repositories,
	}
	path := filepath.Join(t.TempDir(), "search.db")
	seedSearchStore(t, path, repos)
	handler, err := api.NewSearchHandler(api.SearchHandlerConfig{Policy: snapshot, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q=telemetry&limit=1"))
	results := decodeSearchResults(t, response)
	if len(results) != 1 || results[0].FullName != "yaniv256/quiet-notes" {
		t.Fatalf("allowed repo crowded out by denied higher-scoring repos: %#v", results)
	}
}

// Scores are rounded to 2 decimal places before leaving the API: exact
// cosine values are a differential probing channel over content the caller
// cannot read.
func TestSearchHandlerRoundsScoresToTwoDecimals(t *testing.T) {
	t.Parallel()
	handler := seededSearchHandler(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q=yaniv"))
	results := decodeSearchResults(t, response)
	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, row := range results {
		if math.Abs(row.Score*100-math.Round(row.Score*100)) > 1e-9 {
			t.Fatalf("score %v of %s is not rounded to 2 decimals", row.Score, row.FullName)
		}
	}
}

func TestSearchHandlerSurvivesHostileFTSQuery(t *testing.T) {
	t.Parallel()
	handler := seededSearchHandler(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q="+url.QueryEscape(`" OR NEAR( col: *`)))
	if response.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
	decodeSearchResults(t, response)
}

func TestSearchHandlerReportsIndexNotBuilt(t *testing.T) {
	t.Parallel()
	handler := newSearchHandler(t, filepath.Join(t.TempDir(), "missing.db"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q=hyperframes"))
	if response.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Status != "index_not_built" {
		t.Fatalf("status = %q, body = %s", payload.Status, response.Body.String())
	}
}

func TestSearchHandlerLazilyOpensStoreCreatedAfterConstruction(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "search.db")
	handler := newSearchHandler(t, path)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q=hyperframes"))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "index_not_built") {
		t.Fatalf("pre-build code = %d: %s", response.Code, response.Body.String())
	}

	seedSearchStore(t, path, searchTestRepos())

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, searchRequest("/v1/search?q=hyperframes"))
	results := decodeSearchResults(t, response)
	if len(results) == 0 || results[0].FullName != "yaniv256/hyperframes" {
		t.Fatalf("post-build results = %#v", results)
	}
}
