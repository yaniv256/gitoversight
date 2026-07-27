package githubapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type TokenMode string

const (
	AppInstallation TokenMode = "app_installation"
	HumanUser       TokenMode = "human_user"
	// InstallationWide is the read-only credential the repo-search sync job
	// uses: an installation token spanning every repository the installation
	// can see. The subject is the decimal installation ID and the provider is
	// expected to route it to InstallationMinter.InstallationToken.
	InstallationWide TokenMode = "installation_wide"
)

// defaultRawResponseCap is callRaw's bound when a caller does not set one. It
// preserves the historical 1 MiB limit for callers sized around it (README
// text); callers reading git objects pass their own larger bound.
const defaultRawResponseCap = 1 << 20

var ErrHumanTokenRequired = errors.New("public mutation requires approving human user token")
var ErrGitHubNotFound = errors.New("github resource not found")

// ErrGitHubRepositoryEmpty marks GitHub's 409 "Git Repository is empty"
// answer to git-data reads on a repo with no commits (it is not a 404).
var ErrGitHubRepositoryEmpty = errors.New("github repository is empty")

type TokenProvider func(mode TokenMode, subject string) (string, error)
type VisibilityResolver func(repository string) (string, error)

type Client struct {
	baseURL    string
	http       *http.Client
	tokens     TokenProvider
	visibility VisibilityResolver
	// sleepFn is injectable so retry backoff is testable without a test that
	// actually waits minutes. A test that sleeps for real gets deleted or
	// skipped, and then the retry it covers is untested.
	sleepFn func(time.Duration)
}

// sleep waits, using the injected function when a test supplied one.
func (c *Client) sleep(d time.Duration) {
	if c.sleepFn != nil {
		c.sleepFn(d)
		return
	}
	time.Sleep(d)
}

// SetSleepForTest replaces the backoff sleep. Test-only.
func (c *Client) SetSleepForTest(fn func(time.Duration)) { c.sleepFn = fn }

// pow3 returns 3^n for small n — the retry backoff multiplier.
func pow3(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 3
	}
	return result
}

type CreatePullRequest struct {
	Repository string
	Head       string
	Base       string
	Title      string
	Body       string
	Mode       TokenMode
	Subject    string
}

type PullRequest struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	Head    struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

func New(baseURL string, httpClient *http.Client, tokens TokenProvider, visibility VisibilityResolver) (*Client, error) {
	if httpClient == nil || httpClient.Timeout <= 0 {
		return nil, errors.New("github http client requires a positive timeout")
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient, tokens: tokens, visibility: visibility}, nil
}

func (c *Client) CreatePullRequest(input CreatePullRequest) (PullRequest, error) {
	visibility, err := c.visibility(input.Repository)
	if err != nil || (visibility != "public" && visibility != "private") {
		return PullRequest{}, errors.New("repository visibility unavailable")
	}
	if visibility == "public" && input.Mode != HumanUser {
		return PullRequest{}, ErrHumanTokenRequired
	}
	input.Subject = scopedSubject(input.Mode, input.Subject, input.Repository, "pull_request.create")
	payload, err := json.Marshal(map[string]string{"head": input.Head, "base": input.Base, "title": input.Title, "body": input.Body})
	if err != nil {
		return PullRequest{}, err
	}
	var result PullRequest
	if err := c.call(http.MethodPost, "/repos/"+input.Repository+"/pulls", input.Mode, input.Subject, bytes.NewReader(payload), &result); err != nil {
		return PullRequest{}, err
	}
	return result, nil
}

// PullRequestSummary is one open pull request as returned by pull_request.list.
// It is a READ result — no mutation, no grant, no reconciliation.
type PullRequestSummary struct {
	Number         int    `json:"number"`
	Title          string `json:"title"`
	State          string `json:"state"`
	Draft          bool   `json:"draft"`
	HTMLURL        string `json:"html_url"`
	MergeableState string `json:"mergeable_state,omitempty"`
	HeadRef        string `json:"head_ref"`
	HeadSHA        string `json:"head_sha"`
	BaseRef        string `json:"base_ref"`
	Author         string `json:"author"`
}

// ListPullRequests returns the OPEN pull requests on a repository. It is a pure
// read authorized as repository.read; the worker holds the credential. Callers
// (owner-agents) use it to discover PRs they can then read/review/merge.
func (c *Client) ListPullRequests(repository string, mode TokenMode, subject string) ([]PullRequestSummary, error) {
	subject = scopedSubject(mode, subject, repository, "pull_request.list")
	query := url.Values{"state": []string{"open"}, "per_page": []string{"100"}, "sort": []string{"updated"}, "direction": []string{"desc"}}
	var raw []struct {
		Number         int    `json:"number"`
		Title          string `json:"title"`
		State          string `json:"state"`
		Draft          bool   `json:"draft"`
		HTMLURL        string `json:"html_url"`
		MergeableState string `json:"mergeable_state"`
		Head           struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
		User struct {
			Login string `json:"login"`
		} `json:"user"`
	}
	if err := c.call(http.MethodGet, "/repos/"+repository+"/pulls?"+query.Encode(), mode, subject, nil, &raw); err != nil {
		return nil, err
	}
	summaries := make([]PullRequestSummary, 0, len(raw))
	for _, r := range raw {
		summaries = append(summaries, PullRequestSummary{
			Number: r.Number, Title: r.Title, State: r.State, Draft: r.Draft,
			HTMLURL: r.HTMLURL, MergeableState: r.MergeableState,
			HeadRef: r.Head.Ref, HeadSHA: r.Head.SHA, BaseRef: r.Base.Ref, Author: r.User.Login,
		})
	}
	return summaries, nil
}

// PullRequestState resolves one pull request's lifecycle.
//
// `state` arrives in the same response as `merged` and used to be unmarshalled
// away — which is the whole root cause of the closed-PR family of bugs. Reading
// it costs nothing extra; the field was already on the wire.
func (c *Client) PullRequestState(repository string, number int64, mode TokenMode, subject string) (PullState, error) {
	subject = scopedSubject(mode, subject, repository, "pull_request.list")
	var raw struct {
		State          string `json:"state"`
		Merged         bool   `json:"merged"`
		MergeCommitSHA string `json:"merge_commit_sha"`
		HTMLURL        string `json:"html_url"`
	}
	if err := c.call(http.MethodGet, fmt.Sprintf("/repos/%s/pulls/%d", repository, number), mode, subject, nil, &raw); err != nil {
		// A failed read is indeterminate, never a verdict. The error is
		// returned too so callers can distinguish "GitHub is down" from
		// "GitHub answered but ambiguously" — both block, for different reasons.
		return PullState{Outcome: PullOutcomeIndeterminate}, err
	}
	state := classifyPull(raw.State, raw.Merged, raw.MergeCommitSHA)
	state.HTMLURL = raw.HTMLURL
	return state, nil
}

func (c *Client) VerifyPullRequest(repository, head, sha string, mode TokenMode, subject string) (PullRequest, bool, error) {
	subject = scopedSubject(mode, subject, repository, "pull_request.create")
	query := url.Values{"head": []string{head}, "state": []string{"all"}}
	var results []PullRequest
	if err := c.call(http.MethodGet, "/repos/"+repository+"/pulls?"+query.Encode(), mode, subject, nil, &results); err != nil {
		return PullRequest{}, false, err
	}
	for _, result := range results {
		if result.Head.SHA == sha {
			return result, true, nil
		}
	}
	return PullRequest{}, false, nil
}

func scopedSubject(mode TokenMode, subject, repository, operation string) string {
	if mode == AppInstallation {
		return repository + "\x00" + operation
	}
	return subject
}

// sanitizeGitHubError extracts a compact, human-readable reason from a GitHub
// 4xx error body. GitHub returns {"message":...,"errors":[{resource,field,code,
// message}]}; the errors[] entries carry the actual validation failure (e.g.
// field "head" code "invalid", or "No commits between main and X"). We return a
// bounded single line so the agent sees WHY without leaking a large body.
func sanitizeGitHubError(body []byte) string {
	var parsed struct {
		Message string `json:"message"`
		Errors  []struct {
			Resource string `json:"resource"`
			Field    string `json:"field"`
			Code     string `json:"code"`
			Message  string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	parts := make([]string, 0, len(parsed.Errors)+1)
	if parsed.Message != "" {
		parts = append(parts, parsed.Message)
	}
	for _, e := range parsed.Errors {
		switch {
		case e.Message != "":
			parts = append(parts, e.Message)
		case e.Field != "" && e.Code != "":
			parts = append(parts, e.Resource+" field "+e.Field+" "+e.Code)
		case e.Code != "":
			parts = append(parts, e.Resource+" "+e.Code)
		}
	}
	detail := strings.Join(parts, "; ")
	if len(detail) > 300 {
		detail = detail[:300]
	}
	return strings.TrimSpace(strings.ReplaceAll(detail, "\n", " "))
}

func (c *Client) callAbsolute(method, rawURL string, mode TokenMode, subject, contentType string, body io.Reader, maxResponse int64) ([]byte, error) {
	token, err := c.tokens(mode, subject)
	if err != nil {
		return nil, fmt.Errorf("token provider failed")
	}
	request, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if method == http.MethodGet {
		request.Header.Set("Accept", "application/octet-stream")
	} else {
		request.Header.Set("Accept", "application/vnd.github+json")
	}
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "gitoversight-broker")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("github request outcome indeterminate")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode == http.StatusNotFound {
			return nil, ErrGitHubNotFound
		}
		return nil, fmt.Errorf("github returned status %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, maxResponse+1)
	result, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("github response read failed")
	}
	if int64(len(result)) > maxResponse {
		return nil, errors.New("github response exceeds bound")
	}
	return result, nil
}

func (c *Client) call(method, path string, mode TokenMode, subject string, body io.Reader, result any) error {
	response, err := c.do(method, path, mode, subject, "application/vnd.github+json", body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if result == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(result); err != nil {
		return fmt.Errorf("github response decode failed")
	}
	return nil
}

// callRaw is the Accept-overriding variant of call for endpoints whose useful
// representation is not the JSON media type (e.g. raw README text). It returns
// the response body capped at 1 MiB plus the response headers so callers can
// read rate-limit state; errors keep call's exact shape.
func (c *Client) callRaw(method, path string, mode TokenMode, subject, accept string, body io.Reader, maxResponse int64) ([]byte, http.Header, error) {
	if accept == "" {
		accept = "application/vnd.github+json"
	}
	if maxResponse <= 0 {
		maxResponse = defaultRawResponseCap
	}
	response, err := c.do(method, path, mode, subject, accept, body)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	// Read one byte past the bound so an oversized body is an ERROR rather than
	// a silent truncation. A short read is indistinguishable from a small
	// response, so a caller that diffs truncated content would produce a wrong
	// answer with no failure anywhere (matches callAbsolute's discipline).
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return nil, nil, fmt.Errorf("github response read failed")
	}
	if int64(len(payload)) > maxResponse {
		return nil, nil, errors.New("github response exceeds bound")
	}
	return payload, response.Header, nil
}

// do issues one authenticated GitHub request and maps non-2xx statuses to the
// package's error shape. On success the caller owns closing the response body.
func (c *Client) do(method, path string, mode TokenMode, subject, accept string, body io.Reader) (*http.Response, error) {
	token, err := c.tokens(mode, subject)
	if err != nil {
		// Token providers return constant diagnostic strings (never token
		// material); carry them so a failed operation names WHICH credential
		// problem occurred instead of an opaque "token provider failed".
		return nil, fmt.Errorf("token provider failed: %v", err)
	}
	request, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", accept)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "gitoversight-broker")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("github request outcome indeterminate")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		// GitHub 4xx bodies carry the actual validation reason (e.g. a 422's
		// errors[]: "No commits between main and X", "A pull request already
		// exists", "field head invalid"). Surface a bounded, sanitized snippet so
		// the agent learns WHY the op was refused instead of a bare status code.
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		if response.StatusCode == http.StatusNotFound {
			return nil, ErrGitHubNotFound
		}
		detail := sanitizeGitHubError(body)
		// GitHub's git-data calls on a repo with no commits answer 409 with this
		// exact message rather than 404 — callers that treat "ref absent" as a
		// creatable state (branch.push bootstrapping an unborn branch) need to
		// distinguish it from real conflicts, so it gets a sentinel.
		//
		// Every error names the failing call (method + path): a multi-call
		// operation like branch.push otherwise produces failures that cannot be
		// localized from the receipt (brand-yaniv, 2026-07-24).
		site := method + " " + path
		if response.StatusCode == http.StatusConflict && strings.Contains(detail, "Git Repository is empty") {
			return nil, fmt.Errorf("github returned status %d for %s: %s: %w", response.StatusCode, site, detail, ErrGitHubRepositoryEmpty)
		}
		if detail != "" {
			return nil, fmt.Errorf("github returned status %d for %s: %s", response.StatusCode, site, detail)
		}
		return nil, fmt.Errorf("github returned status %d for %s", response.StatusCode, site)
	}
	return response, nil
}
