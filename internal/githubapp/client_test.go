package githubapp_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
)

func TestCreatePrivatePullRequestUsesExactEndpointAndMachineToken(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/repos/yaniv256/private/pulls" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer installation-token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["head"] != "agent/zara/change" || body["base"] != "main" || body["title"] != "Private review" {
			t.Fatalf("body = %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"number":17,"html_url":"https://github.test/pull/17"}`)
	}))
	defer server.Close()

	httpClient := server.Client()
	httpClient.Timeout = time.Second
	var tokenSubject string
	client, err := githubapp.New(server.URL, httpClient, func(_ githubapp.TokenMode, subject string) (string, error) {
		tokenSubject = subject
		return "installation-token", nil
	}, func(string) (string, error) { return "private", nil })
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CreatePullRequest(githubapp.CreatePullRequest{Repository: "yaniv256/private", Head: "agent/zara/change", Base: "main", Title: "Private review", Body: "Review.\n\n— Zara", Mode: githubapp.AppInstallation})
	if err != nil || result.Number != 17 {
		t.Fatalf("result = %#v, %v", result, err)
	}
	if tokenSubject != "yaniv256/private\x00pull_request.create" {
		t.Fatalf("token subject = %q", tokenSubject)
	}
}

func TestPublicMutationRequiresHumanTokenMode(t *testing.T) {
	t.Parallel()
	client, err := githubapp.New("https://api.github.test", &http.Client{Timeout: time.Second}, func(githubapp.TokenMode, string) (string, error) { return "token", nil }, func(string) (string, error) { return "public", nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreatePullRequest(githubapp.CreatePullRequest{Repository: "yaniv256/public", Head: "export", Base: "main", Title: "Public", Mode: githubapp.AppInstallation})
	if err != githubapp.ErrHumanTokenRequired {
		t.Fatalf("error = %v", err)
	}
}

func TestErrorsNeverContainToken(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream failed", http.StatusInternalServerError)
	}))
	defer server.Close()
	secret := "github_pat_super_secret"
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	client, err := githubapp.New(server.URL, httpClient, func(githubapp.TokenMode, string) (string, error) { return secret, nil }, func(string) (string, error) { return "private", nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreatePullRequest(githubapp.CreatePullRequest{Repository: "yaniv256/private", Head: "feature", Base: "main", Title: "Review", Mode: githubapp.AppInstallation})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error = %v", err)
	}
}

func TestGitHubValidationReasonSurfacesInError(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"head","code":"invalid","message":"No commits between main and feature"}]}`)
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	client, err := githubapp.New(server.URL, httpClient, func(githubapp.TokenMode, string) (string, error) { return "installation-token", nil }, func(string) (string, error) { return "private", nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreatePullRequest(githubapp.CreatePullRequest{Repository: "yaniv256/private", Head: "feature", Base: "main", Title: "Review", Mode: githubapp.AppInstallation})
	if err == nil {
		t.Fatal("expected a 422 error")
	}
	// The reason (not just the status code) must reach the caller.
	if !strings.Contains(err.Error(), "No commits between main and feature") {
		t.Fatalf("error did not surface the GitHub validation reason: %v", err)
	}
	if !strings.Contains(err.Error(), "422") {
		t.Fatalf("error lost the status code: %v", err)
	}
}

func TestClientRejectsHTTPClientWithoutTimeout(t *testing.T) {
	t.Parallel()
	client, err := githubapp.New("https://api.github.test", &http.Client{}, func(githubapp.TokenMode, string) (string, error) { return "token", nil }, func(string) (string, error) { return "private", nil })
	if err == nil || client != nil {
		t.Fatalf("client = %#v, err = %v", client, err)
	}
}

func TestVerifyPullRequestReadsIndependentState(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/repos/yaniv256/private/pulls" || r.URL.Query().Get("head") != "yaniv256:feature" {
			t.Fatalf("request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		io.WriteString(w, `[{"number":9,"html_url":"https://github.test/pull/9","head":{"sha":"abc123"}}]`)
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	client, err := githubapp.New(server.URL, httpClient, func(githubapp.TokenMode, string) (string, error) { return "token", nil }, func(string) (string, error) { return "private", nil })
	if err != nil {
		t.Fatal(err)
	}
	result, found, err := client.VerifyPullRequest("yaniv256/private", "yaniv256:feature", "abc123", githubapp.AppInstallation, "")
	if err != nil || !found || result.Number != 9 {
		t.Fatalf("verify = %#v, %v, %v", result, found, err)
	}
}

func TestAppSuspensionFailsClosedAndRecoveryRequiresFreshGitHubSuccess(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/repos/yaniv256/private/pulls" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if calls.Add(1) == 1 {
			http.Error(response, "installation suspended", http.StatusForbidden)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		io.WriteString(response, `{"number":18,"html_url":"https://github.test/pull/18"}`)
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	client, err := githubapp.New(server.URL, httpClient, func(githubapp.TokenMode, string) (string, error) { return "installation-token", nil }, func(string) (string, error) { return "private", nil })
	if err != nil {
		t.Fatal(err)
	}
	request := githubapp.CreatePullRequest{Repository: "yaniv256/private", Head: "agent/zara/recovery", Base: "main", Title: "Recovery", Mode: githubapp.AppInstallation}
	if result, err := client.CreatePullRequest(request); err == nil || result.Number != 0 {
		t.Fatalf("suspended result = %#v, err = %v", result, err)
	}
	result, err := client.CreatePullRequest(request)
	if err != nil || result.Number != 18 || calls.Load() != 2 {
		t.Fatalf("recovered result = %#v, calls = %d, err = %v", result, calls.Load(), err)
	}
}
