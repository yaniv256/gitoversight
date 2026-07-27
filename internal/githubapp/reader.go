package githubapp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	repositoriesPerPage = 100
	// maxRepositoryPages bounds pagination so a misbehaving endpoint cannot
	// spin the sync job forever (100 pages x 100 repos = 10k repositories).
	maxRepositoryPages = 100
	// readmeTextCap bounds the README text handed to the sync ledger.
	readmeTextCap = 256 * 1024
	// maxTreeResponseBytes bounds a recursive tree listing. A tree is metadata
	// only (path, mode, sha per entry), so this is generous for MaxTreeEntries.
	maxTreeResponseBytes = 8 << 20
	// maxBlobResponseBytes bounds one blob read. It matches
	// commitpacket.MaxBlobBytes (10 MiB) plus base64 expansion and JSON framing,
	// so any blob a packet may legally carry can also be read back as a diff base.
	maxBlobResponseBytes = 16 << 20
)

// RepoInfo is one repository row the repo-search sync job ingests.
type RepoInfo struct {
	FullName      string
	Description   string
	HTMLURL       string
	DefaultBranch string
	PushedAt      time.Time
	Private       bool
}

// ReaderConfig tunes the Reader's pacing. Zero values select the defaults;
// Sleep and Now exist so tests can observe pacing without waiting.
type ReaderConfig struct {
	// MinDelay is the minimum spacing between consecutive GitHub calls
	// (default 100ms).
	MinDelay time.Duration
	// LowRemaining is the X-RateLimit-Remaining threshold below which the
	// reader sleeps until the advertised reset (default 100).
	LowRemaining int
	// MaxRateSleep bounds the rate-limit sleep (default 5m).
	MaxRateSleep time.Duration
	Sleep        func(time.Duration)
	Now          func() time.Time
}

// Reader provides the read-only GitHub views the repo-search sync job needs:
// installation-wide repository enumeration and README fetches, paced to stay
// well inside the API rate limit. All requests authenticate with the
// InstallationWide token mode; the subject is the decimal installation ID.
type Reader struct {
	client       *Client
	minDelay     time.Duration
	lowRemaining int
	maxRateSleep time.Duration
	sleep        func(time.Duration)
	now          func() time.Time

	mu       sync.Mutex
	lastCall time.Time
	// installations remembers which installation enumerated each repository so
	// FetchReadme can present the credential that is known to see the repo.
	installations map[string]int64
}

func NewReader(client *Client, config ReaderConfig) (*Reader, error) {
	if client == nil {
		return nil, errors.New("reader requires a github client")
	}
	reader := &Reader{
		client:        client,
		minDelay:      config.MinDelay,
		lowRemaining:  config.LowRemaining,
		maxRateSleep:  config.MaxRateSleep,
		sleep:         config.Sleep,
		now:           config.Now,
		installations: make(map[string]int64),
	}
	if reader.minDelay <= 0 {
		reader.minDelay = 100 * time.Millisecond
	}
	if reader.lowRemaining <= 0 {
		reader.lowRemaining = 100
	}
	if reader.maxRateSleep <= 0 {
		reader.maxRateSleep = 5 * time.Minute
	}
	if reader.sleep == nil {
		reader.sleep = time.Sleep
	}
	if reader.now == nil {
		reader.now = time.Now
	}
	return reader, nil
}

// ListInstallationRepositories enumerates every repository visible to the
// given installations via GET /installation/repositories, following page
// pagination and deduplicating by full name across installations (first
// listing wins). Order is the enumeration order.
func (r *Reader) ListInstallationRepositories(installationIDs []int64) ([]RepoInfo, error) {
	seen := make(map[string]bool)
	repositories := make([]RepoInfo, 0)
	for _, installationID := range installationIDs {
		if installationID <= 0 {
			return nil, errors.New("installation id is invalid")
		}
		subject := strconv.FormatInt(installationID, 10)
		for page := 1; ; page++ {
			if page > maxRepositoryPages {
				return nil, errors.New("installation repository listing exceeded the page bound")
			}
			path := fmt.Sprintf("/installation/repositories?per_page=%d&page=%d", repositoriesPerPage, page)
			body, _, err := r.paced(http.MethodGet, path, subject, "", 0)
			if err != nil {
				return nil, err
			}
			var parsed struct {
				Repositories []struct {
					FullName      string    `json:"full_name"`
					Description   string    `json:"description"`
					HTMLURL       string    `json:"html_url"`
					DefaultBranch string    `json:"default_branch"`
					PushedAt      time.Time `json:"pushed_at"`
					Private       bool      `json:"private"`
				} `json:"repositories"`
			}
			if err := json.Unmarshal(body, &parsed); err != nil {
				return nil, errors.New("installation repositories response decode failed")
			}
			for _, repository := range parsed.Repositories {
				r.remember(repository.FullName, installationID)
				if repository.FullName == "" || seen[repository.FullName] {
					continue
				}
				seen[repository.FullName] = true
				repositories = append(repositories, RepoInfo{
					FullName:      repository.FullName,
					Description:   repository.Description,
					HTMLURL:       repository.HTMLURL,
					DefaultBranch: repository.DefaultBranch,
					PushedAt:      repository.PushedAt,
					Private:       repository.Private,
				})
			}
			if len(parsed.Repositories) < repositoriesPerPage {
				break
			}
		}
	}
	return repositories, nil
}

// FetchReadme returns the repository's README text (truncated to 256 KiB) and
// a change-detection key for the sync ledger — the response ETag when GitHub
// sends one, otherwise a SHA-256 of the full body. A repository without a
// README yields ("", "", nil). The repository must have been enumerated by
// ListInstallationRepositories first; that is what tells the reader which
// installation's credential can see it.
func (r *Reader) FetchReadme(repository string) (string, string, error) {
	installationID, known := r.installationFor(repository)
	if !known {
		return "", "", fmt.Errorf("repository %s was not enumerated by an installation listing", repository)
	}
	subject := strconv.FormatInt(installationID, 10)
	body, headers, err := r.paced(http.MethodGet, "/repos/"+repository+"/readme", subject, "application/vnd.github.raw+json", 0)
	if errors.Is(err, ErrGitHubNotFound) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	changeKey := readmeChangeKey(headers, body)
	if len(body) > readmeTextCap {
		body = body[:readmeTextCap]
	}
	return string(body), changeKey, nil
}

// TreeEntry is one path in a repository tree read back from GitHub. Mode and
// Type carry git's own vocabulary ("100644"/"blob", "160000"/"commit") so a
// caller can distinguish a file from a submodule pointer without a second read.
type TreeEntry struct {
	Path string
	Mode string
	Type string
	SHA  string
	Size int64
}

// ReadBranchHead returns the commit SHA a branch currently points at. This is
// the BASE of a pre-PR: the state of the public repository the proposed change
// is measured against. A missing branch yields ErrGitHubNotFound and a
// repository with no commits yields ErrGitHubRepositoryEmpty — distinct answers,
// because "the branch is misnamed" and "the repo is empty" need opposite fixes.
func (r *Reader) ReadBranchHead(repository, branch, subject string) (string, error) {
	if repository == "" || branch == "" {
		return "", errors.New("branch head read requires a repository and branch")
	}
	path := "/repos/" + repository + "/git/ref/heads/" + url.PathEscape(branch)
	body, _, err := r.paced(http.MethodGet, path, subject, "", 0)
	if err != nil {
		return "", err
	}
	var parsed struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", errors.New("git ref response decode failed")
	}
	if parsed.Object.SHA == "" {
		return "", errors.New("git ref response carried no commit hash")
	}
	return parsed.Object.SHA, nil
}

// ReadCommitTree returns the tree SHA a commit points at, so a caller can read
// the base tree without assuming the commit SHA and tree SHA are interchangeable.
func (r *Reader) ReadCommitTree(repository, commitSHA, subject string) (string, error) {
	if repository == "" || commitSHA == "" {
		return "", errors.New("commit tree read requires a repository and commit")
	}
	path := "/repos/" + repository + "/git/commits/" + url.PathEscape(commitSHA)
	body, _, err := r.paced(http.MethodGet, path, subject, "", 0)
	if err != nil {
		return "", err
	}
	var parsed struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", errors.New("git commit response decode failed")
	}
	if parsed.Tree.SHA == "" {
		return "", errors.New("git commit response carried no tree hash")
	}
	return parsed.Tree.SHA, nil
}

// ReadTree returns every entry in a tree, recursively. A tree GitHub reports as
// truncated is an ERROR, never a partial result: a pre-PR's file set is derived
// by comparing this listing against the proposed shape, and a silently short
// base would present added files as unchanged and omit deletions entirely.
func (r *Reader) ReadTree(repository, treeSHA, subject string) ([]TreeEntry, error) {
	if repository == "" || treeSHA == "" {
		return nil, errors.New("tree read requires a repository and tree")
	}
	path := "/repos/" + repository + "/git/trees/" + url.PathEscape(treeSHA) + "?recursive=1"
	body, _, err := r.paced(http.MethodGet, path, subject, "", maxTreeResponseBytes)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Tree []struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
			Size int64  `json:"size"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, errors.New("git tree response decode failed")
	}
	if parsed.Truncated {
		return nil, errors.New("git tree listing was truncated by github")
	}
	entries := make([]TreeEntry, 0, len(parsed.Tree))
	for _, entry := range parsed.Tree {
		// "tree" rows are directory nodes; a recursive listing carries them
		// alongside the leaves, and they name no content to diff.
		if entry.Type == "tree" {
			continue
		}
		entries = append(entries, TreeEntry{Path: entry.Path, Mode: entry.Mode, Type: entry.Type, SHA: entry.SHA, Size: entry.Size})
	}
	return entries, nil
}

// ReadBlob returns one blob's bytes, verifying that the content GitHub returned
// hashes to the SHA that was asked for. This mirrors the publish path's
// discipline (operations.go rejects a blob whose returned hash differs): a diff
// base that is not the requested object would produce a confident wrong diff.
func (r *Reader) ReadBlob(repository, blobSHA, subject string) ([]byte, error) {
	if repository == "" || blobSHA == "" {
		return nil, errors.New("blob read requires a repository and blob")
	}
	path := "/repos/" + repository + "/git/blobs/" + url.PathEscape(blobSHA)
	body, _, err := r.paced(http.MethodGet, path, subject, "", maxBlobResponseBytes)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		SHA      string `json:"sha"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, errors.New("git blob response decode failed")
	}
	if parsed.SHA != blobSHA {
		return nil, errors.New("github returned an unexpected blob hash")
	}
	if parsed.Encoding != "base64" {
		return nil, errors.New("git blob response used an unsupported encoding")
	}
	// GitHub wraps base64 blob content at 60 columns; the strict decoder rejects
	// the embedded newlines, so they are removed before decoding.
	content, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(parsed.Content, "\n", ""))
	if err != nil {
		return nil, errors.New("git blob content is not valid base64")
	}
	return content, nil
}

func readmeChangeKey(headers http.Header, body []byte) string {
	etag := strings.TrimPrefix(headers.Get("ETag"), "W/")
	if etag = strings.Trim(etag, `"`); etag != "" {
		return etag
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// paced wraps callRaw with the reader's two pacing rules: a minimum inter-call
// delay, and — when GitHub advertises a nearly exhausted rate budget — a
// bounded sleep until the advertised reset. maxResponse bounds the body; zero
// selects callRaw's default. An oversized body is an error, never a truncation.
func (r *Reader) paced(method, path, subject, accept string, maxResponse int64) ([]byte, http.Header, error) {
	r.mu.Lock()
	if !r.lastCall.IsZero() {
		if wait := r.minDelay - r.now().Sub(r.lastCall); wait > 0 {
			r.sleep(wait)
		}
	}
	r.lastCall = r.now()
	r.mu.Unlock()
	body, headers, err := r.client.callRaw(method, path, InstallationWide, subject, accept, nil, maxResponse)
	if err != nil {
		return nil, nil, err
	}
	r.observeRateLimit(headers)
	return body, headers, nil
}

func (r *Reader) observeRateLimit(headers http.Header) {
	remaining, err := strconv.Atoi(headers.Get("X-RateLimit-Remaining"))
	if err != nil || remaining >= r.lowRemaining {
		return
	}
	reset, err := strconv.ParseInt(headers.Get("X-RateLimit-Reset"), 10, 64)
	if err != nil {
		return
	}
	wait := time.Unix(reset, 0).Sub(r.now())
	if wait <= 0 {
		return
	}
	if wait > r.maxRateSleep {
		wait = r.maxRateSleep
	}
	r.sleep(wait)
}

func (r *Reader) remember(repository string, installationID int64) {
	if repository == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.installations[repository]; !exists {
		r.installations[repository] = installationID
	}
}

func (r *Reader) installationFor(repository string) (int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	installationID, known := r.installations[repository]
	return installationID, known
}
