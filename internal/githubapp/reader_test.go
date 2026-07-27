package githubapp_test

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
)

// newReaderForServer wires a Reader against a fake GitHub whose token provider
// hands out "tok-<installation id>" so handlers can tell installations apart by
// the Authorization header.
func newReaderForServer(t *testing.T, server *httptest.Server, config githubapp.ReaderConfig) *githubapp.Reader {
	t.Helper()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	client, err := githubapp.New(server.URL, httpClient, func(mode githubapp.TokenMode, subject string) (string, error) {
		if mode != githubapp.InstallationWide {
			t.Fatalf("token mode = %q", mode)
		}
		return "tok-" + subject, nil
	}, func(string) (string, error) { return "private", nil })
	if err != nil {
		t.Fatal(err)
	}
	reader, err := githubapp.NewReader(client, config)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func repositoriesPage(totalCount int, names ...string) string {
	repositories := make([]map[string]any, 0, len(names))
	for _, name := range names {
		repositories = append(repositories, map[string]any{
			"full_name":      name,
			"description":    "about " + name,
			"html_url":       "https://github.test/" + name,
			"default_branch": "main",
			"pushed_at":      "2026-07-01T12:00:00Z",
			"private":        true,
		})
	}
	page, _ := json.Marshal(map[string]any{"total_count": totalCount, "repositories": repositories})
	return string(page)
}

func TestListInstallationRepositoriesStitchesPaginatedPages(t *testing.T) {
	t.Parallel()
	pageOne := make([]string, 0, 100)
	for i := range 100 {
		pageOne = append(pageOne, fmt.Sprintf("owner/repo-%03d", i))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/installation/repositories" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok-7" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("per_page") != "100" {
			t.Fatalf("per_page = %q", r.URL.Query().Get("per_page"))
		}
		switch r.URL.Query().Get("page") {
		case "1":
			io.WriteString(w, repositoriesPage(103, pageOne...))
		case "2":
			io.WriteString(w, repositoriesPage(103, "owner/repo-100", "owner/repo-101", "owner/repo-102"))
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()
	reader := newReaderForServer(t, server, githubapp.ReaderConfig{Sleep: func(time.Duration) {}})
	repositories, err := reader.ListInstallationRepositories([]int64{7})
	if err != nil {
		t.Fatal(err)
	}
	if len(repositories) != 103 {
		t.Fatalf("repositories = %d", len(repositories))
	}
	first, last := repositories[0], repositories[102]
	if first.FullName != "owner/repo-000" || last.FullName != "owner/repo-102" {
		t.Fatalf("first = %q, last = %q", first.FullName, last.FullName)
	}
	if first.Description != "about owner/repo-000" || first.HTMLURL != "https://github.test/owner/repo-000" || first.DefaultBranch != "main" || !first.Private {
		t.Fatalf("first = %#v", first)
	}
	if !first.PushedAt.Equal(time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("pushed at = %v", first.PushedAt)
	}
}

func TestListInstallationRepositoriesDeduplicatesAcrossInstallations(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer tok-1":
			io.WriteString(w, repositoriesPage(2, "owner/shared", "owner/only-first"))
		case "Bearer tok-2":
			io.WriteString(w, repositoriesPage(2, "owner/shared", "owner/only-second"))
		default:
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
	}))
	defer server.Close()
	reader := newReaderForServer(t, server, githubapp.ReaderConfig{Sleep: func(time.Duration) {}})
	repositories, err := reader.ListInstallationRepositories([]int64{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(repositories))
	for _, repository := range repositories {
		names = append(names, repository.FullName)
	}
	if len(names) != 3 || names[0] != "owner/shared" || names[1] != "owner/only-first" || names[2] != "owner/only-second" {
		t.Fatalf("names = %#v", names)
	}
}

func TestListInstallationRepositoriesSurfacesStatusOnFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	reader := newReaderForServer(t, server, githubapp.ReaderConfig{Sleep: func(time.Duration) {}})
	_, err := reader.ListInstallationRepositories([]int64{7})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v", err)
	}
}

func TestFetchReadmeMissingYieldsEmptyWithoutError(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/installation/repositories":
			io.WriteString(w, repositoriesPage(1, "owner/bare"))
		case "/repos/owner/bare/readme":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	reader := newReaderForServer(t, server, githubapp.ReaderConfig{Sleep: func(time.Duration) {}})
	if _, err := reader.ListInstallationRepositories([]int64{7}); err != nil {
		t.Fatal(err)
	}
	text, sha, err := reader.FetchReadme("owner/bare")
	if err != nil || text != "" || sha != "" {
		t.Fatalf("readme = (%q, %q, %v)", text, sha, err)
	}
}

func TestFetchReadmeTruncatesOversizedTextAndReportsChangeKey(t *testing.T) {
	t.Parallel()
	oversized := strings.Repeat("a", 300*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/installation/repositories":
			io.WriteString(w, repositoriesPage(1, "owner/big"))
		case "/repos/owner/big/readme":
			if accept := r.Header.Get("Accept"); accept != "application/vnd.github.raw+json" {
				t.Fatalf("accept = %q", accept)
			}
			w.Header().Set("ETag", `W/"readme-sha-abc"`)
			io.WriteString(w, oversized)
		default:
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	reader := newReaderForServer(t, server, githubapp.ReaderConfig{Sleep: func(time.Duration) {}})
	if _, err := reader.ListInstallationRepositories([]int64{7}); err != nil {
		t.Fatal(err)
	}
	text, sha, err := reader.FetchReadme("owner/big")
	if err != nil {
		t.Fatal(err)
	}
	if len(text) != 256*1024 || !strings.HasPrefix(text, "aaaa") {
		t.Fatalf("text length = %d", len(text))
	}
	if sha != "readme-sha-abc" {
		t.Fatalf("sha = %q", sha)
	}
}

func TestFetchReadmeRejectsRepositoryThatWasNeverEnumerated(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("network reached")
	}))
	defer server.Close()
	reader := newReaderForServer(t, server, githubapp.ReaderConfig{Sleep: func(time.Duration) {}})
	if _, _, err := reader.FetchReadme("owner/unknown"); err == nil {
		t.Fatal("unenumerated repository accepted")
	}
}

func TestPacerSleepsUntilResetWhenRateLimitRemainingIsLow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	reset := now.Add(30 * time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "5")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		io.WriteString(w, repositoriesPage(1, "owner/slow"))
	}))
	defer server.Close()
	var sleeps []time.Duration
	reader := newReaderForServer(t, server, githubapp.ReaderConfig{
		Sleep: func(d time.Duration) { sleeps = append(sleeps, d) },
		Now:   func() time.Time { return now },
	})
	if _, err := reader.ListInstallationRepositories([]int64{7}); err != nil {
		t.Fatal(err)
	}
	if len(sleeps) != 1 || sleeps[0] != 30*time.Second {
		t.Fatalf("sleeps = %v — expected one 30s rate-limit sleep", sleeps)
	}
}

func TestPacerEnforcesMinimumInterCallDelay(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer tok-1":
			io.WriteString(w, repositoriesPage(1, "owner/first"))
		case "Bearer tok-2":
			io.WriteString(w, repositoriesPage(1, "owner/second"))
		default:
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
	}))
	defer server.Close()
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	var sleeps []time.Duration
	reader := newReaderForServer(t, server, githubapp.ReaderConfig{
		MinDelay: 100 * time.Millisecond,
		Sleep:    func(d time.Duration) { sleeps = append(sleeps, d) },
		Now:      func() time.Time { return now },
	})
	if _, err := reader.ListInstallationRepositories([]int64{1, 2}); err != nil {
		t.Fatal(err)
	}
	// The clock is frozen, so the second call arrives 0ns after the first and
	// the pacer must insert the full minimum delay before it.
	if len(sleeps) != 1 || sleeps[0] != 100*time.Millisecond {
		t.Fatalf("sleeps = %v — expected one 100ms inter-call delay", sleeps)
	}
}

// --- Public-repository read path (pre-PR base resolution) ---

// gitBlobSHA computes git's own blob hash so tests assert on real object
// identity rather than a placeholder string.
func gitBlobSHA(content []byte) string {
	hash := sha1.New()
	fmt.Fprintf(hash, "blob %d\x00", len(content))
	hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

func TestReadBranchHeadReturnsCommitSHA(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/git/ref/heads/main" {
			t.Errorf("path = %q", r.URL.Path)
		}
		io.WriteString(w, `{"ref":"refs/heads/main","object":{"sha":"aa11bb22cc33dd44ee55ff6600112233445566aa","type":"commit"}}`)
	}))
	defer server.Close()

	head, err := newReaderForServer(t, server, githubapp.ReaderConfig{}).ReadBranchHead("owner/repo", "main", "42")
	if err != nil {
		t.Fatal(err)
	}
	if head != "aa11bb22cc33dd44ee55ff6600112233445566aa" {
		t.Fatalf("head = %q", head)
	}
}

func TestReadBranchHeadDistinguishesMissingBranch(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := newReaderForServer(t, server, githubapp.ReaderConfig{}).ReadBranchHead("owner/repo", "nope", "42")
	if !errors.Is(err, githubapp.ErrGitHubNotFound) {
		t.Fatalf("err = %v, want ErrGitHubNotFound", err)
	}
}

func TestReadTreeReturnsEveryLeafAndSkipsDirectories(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("recursive") != "1" {
			t.Errorf("recursive = %q, want 1", r.URL.Query().Get("recursive"))
		}
		io.WriteString(w, `{"sha":"t1","truncated":false,"tree":[
			{"path":"README.md","mode":"100644","type":"blob","sha":"b1","size":12},
			{"path":"internal","mode":"040000","type":"tree","sha":"t2"},
			{"path":"internal/app.go","mode":"100644","type":"blob","sha":"b2","size":40},
			{"path":"vendor/lib","mode":"160000","type":"commit","sha":"c9"}
		]}`)
	}))
	defer server.Close()

	entries, err := newReaderForServer(t, server, githubapp.ReaderConfig{}).ReadTree("owner/repo", "t1", "42")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3 (directory node must be skipped)", len(entries))
	}
	if entries[2].Type != "commit" || entries[2].Mode != "160000" {
		t.Fatalf("submodule entry = %+v, want type commit mode 160000", entries[2])
	}
}

func TestReadTreeRejectsTruncatedListing(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"sha":"t1","truncated":true,"tree":[{"path":"a","mode":"100644","type":"blob","sha":"b1"}]}`)
	}))
	defer server.Close()

	_, err := newReaderForServer(t, server, githubapp.ReaderConfig{}).ReadTree("owner/repo", "t1", "42")
	if err == nil {
		t.Fatal("truncated tree must be an error, not a partial result")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("err = %v, want it to name truncation", err)
	}
}

func TestReadBlobReturnsContentAndVerifiesHash(t *testing.T) {
	t.Parallel()
	content := []byte("package main\n\nfunc main() {}\n")
	sha := gitBlobSHA(content)
	// GitHub wraps base64 at 60 columns; embed a newline to prove the decoder
	// tolerates the real wire format.
	encoded := base64.StdEncoding.EncodeToString(content)
	wrapped := encoded[:8] + "\n" + encoded[8:]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := json.Marshal(map[string]any{"sha": sha, "content": wrapped, "encoding": "base64"})
		w.Write(payload)
	}))
	defer server.Close()

	got, err := newReaderForServer(t, server, githubapp.ReaderConfig{}).ReadBlob("owner/repo", sha, "42")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("content = %q, want %q", got, content)
	}
}

func TestReadBlobRejectsMismatchedHash(t *testing.T) {
	t.Parallel()
	content := []byte("tampered")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := json.Marshal(map[string]any{
			"sha":      "ffffffffffffffffffffffffffffffffffffffff",
			"content":  base64.StdEncoding.EncodeToString(content),
			"encoding": "base64",
		})
		w.Write(payload)
	}))
	defer server.Close()

	_, err := newReaderForServer(t, server, githubapp.ReaderConfig{}).ReadBlob("owner/repo", gitBlobSHA(content), "42")
	if err == nil {
		t.Fatal("a blob whose returned hash differs from the requested one must be rejected")
	}
}

// TestReadBlobRejectsOversizedResponse is the FAILING-direction test for the
// callRaw bound. Before the fix the body was silently cut at 1 MiB, so a large
// base file would decode short (or fail to decode) with no error naming the
// cause — a wrong diff rather than a refusal.
func TestReadBlobRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"sha":"b1","encoding":"base64","content":"`)
		chunk := strings.Repeat("A", 64*1024)
		for written := 0; written < 17<<20; written += len(chunk) {
			io.WriteString(w, chunk)
		}
		io.WriteString(w, `"}`)
	}))
	defer server.Close()

	_, err := newReaderForServer(t, server, githubapp.ReaderConfig{}).ReadBlob("owner/repo", "b1", "42")
	if err == nil {
		t.Fatal("an oversized blob response must error, never truncate silently")
	}
	if !strings.Contains(err.Error(), "exceeds bound") {
		t.Fatalf("err = %v, want it to name the bound", err)
	}
}
