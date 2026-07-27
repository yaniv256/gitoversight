package security_test

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/approval"
	"github.com/yaniv256/gitoversight.dev/internal/audit"
	"github.com/yaniv256/gitoversight.dev/internal/daemon"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/identity"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type pullListRunner struct {
	*worker.Worker
}

func (pullListRunner) List(worker.Request) ([]githubapp.PullRequestSummary, error) {
	return nil, nil
}

func (r pullListRunner) PullState(request worker.Request, number int64) (githubapp.PullState, error) {
	return githubapp.PullState{Outcome: githubapp.PullOutcomeOpen}, nil
}

func TestBrokerWorkerReconcilesAmbiguousGitHubCreateWithoutRetry(t *testing.T) {
	var posts atomic.Int32
	var reads atomic.Int32
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer root-owned-installation-token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.Method {
		case http.MethodPost:
			posts.Add(1)
			if r.URL.Path != "/repos/yaniv256/private/pulls" {
				t.Fatalf("path = %s", r.URL.Path)
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Fatal(err)
			}
			connection.Close()
		case http.MethodGet:
			reads.Add(1)
			if r.URL.Query().Get("head") != "agent/zara/change" {
				t.Fatalf("head = %q", r.URL.Query().Get("head"))
			}
			io.WriteString(w, `[{"number":42,"html_url":"https://github.test/private/pull/42","head":{"sha":"abc123"}}]`)
		default:
			t.Fatalf("method = %s", r.Method)
		}
	}))
	defer github.Close()
	httpClient := github.Client()
	httpClient.Timeout = time.Second
	githubClient, err := githubapp.New(github.URL, httpClient, func(mode githubapp.TokenMode, _ string) (string, error) {
		if mode != githubapp.AppInstallation {
			t.Fatalf("mode = %q", mode)
		}
		return "root-owned-installation-token", nil
	}, func(repository string) (string, error) {
		if repository != "yaniv256/private" {
			t.Fatalf("repository = %q", repository)
		}
		return "private", nil
	})
	if err != nil {
		t.Fatal(err)
	}

	journal, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policy.Snapshot{
		Generation:   1,
		Agents:       map[string]policy.Agent{"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}},
	}
	broker := server.New(snapshot, approval.NewStore(), journal, time.Minute)
	workerPath := filepath.Join(t.TempDir(), "worker.sock")
	workerService := workerrpc.NewServer(workerPath, uint32(os.Getuid()), workerrpc.WithRunner(pullListRunner{worker.New(broker, githubapp.NewExecutor(githubClient))}))
	workerListener, err := workerService.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer workerListener.Close()
	go workerService.Serve(workerListener)
	registry, err := identity.NewRegistry(map[string]uint32{"zara": uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	brokerPath := filepath.Join(t.TempDir(), "broker.sock")
	service := daemon.New(brokerPath, registry, broker, daemon.WithRunner(workerrpc.NewClient(workerPath)))
	brokerListener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer brokerListener.Close()
	go service.Serve(brokerListener)

	connection, err := net.Dial("unix", brokerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request := daemon.Request{
		SchemaVersion: 1, Action: "request", RequestID: "request-ambiguous-1",
		Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "agent/zara/change",
		Title: "Private review", Body: "Exact body", Payload: map[string]any{"base": "main", "head_sha": "abc123"},
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response daemon.Response
	if err := json.NewDecoder(bufio.NewReader(connection)).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error != "" || !response.Executed || response.Result.ResourceID != "https://github.test/private/pull/42" || response.Authorization.Capability != "" {
		t.Fatalf("response = %#v", response)
	}
	if posts.Load() != 1 || reads.Load() != 1 {
		t.Fatalf("posts = %d, reads = %d", posts.Load(), reads.Load())
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "root-owned-installation-token") {
		t.Fatal("worker credential escaped into broker response")
	}
	events, err := broker.Receipt("zara", "request-ambiguous-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[len(events)-1].State != worker.OutcomeVerified {
		t.Fatalf("events = %#v", events)
	}
}
