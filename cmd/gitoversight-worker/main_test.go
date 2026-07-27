package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/oauthflow"
	"github.com/yaniv256/gitoversight.dev/internal/searchstore"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type oauthCoordinatorStub struct {
	begin oauthflow.BeginRequest
}

func (stub *oauthCoordinatorStub) Begin(request oauthflow.BeginRequest) (string, error) {
	stub.begin = request
	return "https://github.test/login/oauth/authorize", nil
}

func (stub *oauthCoordinatorStub) Complete(string, string) (oauthflow.Completion, error) {
	return oauthflow.Completion{}, nil
}

func TestHumanLoginUsesOnlyAllowlistedHumanInstallation(t *testing.T) {
	coordinator := &oauthCoordinatorStub{}
	service := &repositoryOAuthBeginner{
		coordinator: coordinator, installations: map[string]int64{"example/repo": 41},
		humanInstallations: map[string]int64{"Yaniv256": 42},
	}
	request := workerrpc.OAuthBeginRequest{
		Purpose: "human_login", Session: "pending-session", Subject: "yaniv",
		GitHubLogin: "Yaniv256", ExpiresAt: time.Now().Add(time.Minute),
	}
	if _, err := service.BeginOAuth(request); err != nil {
		t.Fatal(err)
	}
	if coordinator.begin.Installation != 42 || coordinator.begin.Subject != "yaniv" || coordinator.begin.GitHubLogin != "Yaniv256" {
		t.Fatalf("begin = %#v", coordinator.begin)
	}
	request.GitHubLogin = "attacker"
	if _, err := service.BeginOAuth(request); err == nil {
		t.Fatal("unknown human installation was accepted")
	}
}

func TestPublicActorUsesOwnerWideInstallationFallback(t *testing.T) {
	coordinator := &oauthCoordinatorStub{}
	service := &repositoryOAuthBeginner{
		coordinator:        coordinator,
		installations:      map[string]int64{"babel3-com/*": 147756859},
		humanInstallations: map[string]int64{"Yaniv256": 42},
	}
	request := workerrpc.OAuthBeginRequest{
		Purpose: "public_actor", Session: "pending-session", Subject: "yaniv",
		Repository: "babel3-com/new-repository", GitHubLogin: "Yaniv256", ExpiresAt: time.Now().Add(time.Minute),
	}
	if _, err := service.BeginOAuth(request); err != nil {
		t.Fatal(err)
	}
	if coordinator.begin.Installation != 147756859 {
		t.Fatalf("installation = %d", coordinator.begin.Installation)
	}
}

func TestPublicActorExactInstallationDisablesOwnerFallback(t *testing.T) {
	coordinator := &oauthCoordinatorStub{}
	service := &repositoryOAuthBeginner{
		coordinator: coordinator,
		installations: map[string]int64{
			"babel3-com/*":           147756859,
			"babel3-com/disabled":    0,
			"babel3-com/explicit-ok": 17,
		},
		humanInstallations: map[string]int64{"Yaniv256": 42},
	}
	for _, repository := range []string{"babel3-com/disabled", "babel3-com/one/two", "babel3-com/../escape"} {
		request := workerrpc.OAuthBeginRequest{Purpose: "public_actor", Repository: repository, ExpiresAt: time.Now().Add(time.Minute)}
		if _, err := service.BeginOAuth(request); err == nil {
			t.Fatalf("repository %q was accepted", repository)
		}
	}
	request := workerrpc.OAuthBeginRequest{Purpose: "public_actor", Repository: "babel3-com/explicit-ok", ExpiresAt: time.Now().Add(time.Minute)}
	if _, err := service.BeginOAuth(request); err != nil {
		t.Fatal(err)
	}
	if coordinator.begin.Installation != 17 {
		t.Fatalf("installation = %d", coordinator.begin.Installation)
	}
}

func TestInstallationIDsDeduplicatesAndSkipsDisabled(t *testing.T) {
	ids := installationIDs(map[string]int64{
		"owner/a":  41,
		"owner/*":  41,
		"other/*":  52,
		"disabled": 0,
	})
	if len(ids) != 2 || ids[0] != 41 || ids[1] != 52 {
		t.Fatalf("ids = %v, want [41 52]", ids)
	}
}

func TestStorePullsConvertsSummaries(t *testing.T) {
	pulls := storePulls([]githubapp.PullRequestSummary{
		{Number: 7, Title: "first", Author: "zara", HTMLURL: "https://github.test/owner/repo/pull/7", HeadRef: "feature"},
	})
	if len(pulls) != 1 {
		t.Fatalf("pulls = %#v", pulls)
	}
	want := searchstore.Pull{Number: 7, Title: "first", Author: "zara", HTMLURL: "https://github.test/owner/repo/pull/7", HeadRef: "feature"}
	if pulls[0] != want {
		t.Fatalf("pull = %#v, want %#v", pulls[0], want)
	}
}

// TestOpenSearchStoreFailureDisablesSearchInsteadOfDying pins the worker
// resilience contract: a search store open failure logs loudly and returns
// nil (search sync disabled) — it must never take the governance worker down,
// because the dataset is a rebuildable cache.
func TestOpenSearchStoreFailureDisablesSearchInsteadOfDying(t *testing.T) {
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }

	// A file where a parent directory must be created makes MkdirAll fail
	// with ENOTDIR — a persistent, permission-style failure.
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if store := openSearchStore(context.Background(), filepath.Join(blocker, "sub", "search.db"), logf); store != nil {
		store.Close()
		t.Fatal("openSearchStore returned a store for an unopenable path")
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "SEARCH SYNC DISABLED") {
		t.Fatalf("loud disable log missing: %q", logged)
	}

	// The success path still returns a working store.
	store := openSearchStore(context.Background(), filepath.Join(base, "ok", "search.db"), logf)
	if store == nil {
		t.Fatalf("openSearchStore failed on a valid path: %q", logged)
	}
	store.Close()
}
