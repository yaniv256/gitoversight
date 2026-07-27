package daemon_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
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

type countingExecutor struct {
	calls int
}

type pullListRunner struct {
	*worker.Worker
}

func (pullListRunner) List(worker.Request) ([]githubapp.PullRequestSummary, error) {
	return nil, nil
}

func (pullListRunner) PullState(worker.Request, int64) (githubapp.PullState, error) {
	return githubapp.PullState{Outcome: githubapp.PullOutcomeOpen}, nil
}

type concurrentExecutor struct {
	calls atomic.Int32
}

func (e *concurrentExecutor) Execute(request worker.Request) (worker.Result, error) {
	e.calls.Add(1)
	return worker.Result{ResourceID: request.RequestID}, nil
}

func (e *concurrentExecutor) Reconcile(request worker.Request) (worker.Reconciliation, error) {
	return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: request.RequestID}, nil
}

type oauthRequester struct {
	request workerrpc.OAuthBeginRequest
	calls   int
}

func (r *oauthRequester) BeginOAuth(request workerrpc.OAuthBeginRequest) (string, error) {
	r.calls++
	r.request = request
	return "https://github.test/login/oauth/authorize?state=opaque", nil
}

func (e *countingExecutor) Execute(worker.Request) (worker.Result, error) {
	e.calls++
	return worker.Result{ResourceID: "private-pr-42"}, nil
}

func (e *countingExecutor) Reconcile(worker.Request) (worker.Reconciliation, error) {
	return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: "private-pr-42"}, nil
}

func TestCredentiallessUnixProtocolBindsKernelCaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.sock")
	j, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := identity.NewRegistry(map[string]uint32{"zara": uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	broker := server.New(policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}}}, approval.NewStore(), j, time.Minute)
	workerPath := filepath.Join(t.TempDir(), "worker.sock")
	executor := &countingExecutor{}
	workerService := workerrpc.NewServer(workerPath, uint32(os.Getuid()), workerrpc.WithRunner(pullListRunner{worker.New(broker, executor)}))
	workerListener, err := workerService.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer workerListener.Close()
	go workerService.Serve(workerListener)
	daemonServer := daemon.New(path, registry, broker, daemon.WithRunner(workerrpc.NewClient(workerPath)))
	listener, err := daemonServer.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go daemonServer.Serve(listener)

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := daemon.Request{SchemaVersion: 1, Action: "request", RequestID: "request-1", CallerClaim: "elena", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "feature", Title: "Private review"}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response daemon.Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Authorization.Caller != "zara" || response.Authorization.Capability != "" || response.Result.ResourceID != "private-pr-42" || !response.Executed {
		t.Fatalf("response = %#v", response)
	}
	if executor.calls != 1 {
		t.Fatalf("execute calls = %d", executor.calls)
	}
}

func TestDeniedRequestNeverReachesPrivilegedWorker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.sock")
	j, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := identity.NewRegistry(map[string]uint32{"zara": uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	broker := server.New(policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/public": {Visibility: "public", Owners: []string{"zara"}, Approvers: []string{"yaniv"}}}}, approval.NewStore(), j, time.Minute)
	executor := &countingExecutor{}
	runner := worker.New(broker, executor)
	service := daemon.New(path, registry, broker, daemon.WithRunner(runner))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := daemon.Request{SchemaVersion: 1, Action: "request", RequestID: "denied-1", Repository: "yaniv256/public", Operation: "pull_request.create", Branch: "feature", Title: "Public review"}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response daemon.Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Authorization.Capability != "" || response.Result.ResourceID != "" || executor.calls != 0 {
		t.Fatalf("response = %#v, execute calls = %d", response, executor.calls)
	}
}

func TestReceiptReadUsesKernelCaller(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "broker.sock")
	j, err := audit.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := identity.NewRegistry(map[string]uint32{"zara": uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	b := server.New(policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}}}, approval.NewStore(), j, time.Minute)
	b.Authorize("zara", server.MutationRequest{RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature"}, "", time.Now())
	service := daemon.New(path, registry, b)
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(daemon.Request{SchemaVersion: 1, Action: "receipt", RequestID: "request-1", CallerClaim: "tomas"}); err != nil {
		t.Fatal(err)
	}
	var response daemon.Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error != "" || len(response.Events) == 0 {
		t.Fatalf("response = %#v", response)
	}
}

func TestSocketPermissionsAreOwnerGroupOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.sock")
	registry, _ := identity.NewRegistry(map[string]uint32{"zara": uint32(os.Getuid())})
	j, _ := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	daemonServer := daemon.New(path, registry, server.New(policy.Snapshot{}, approval.NewStore(), j, time.Minute))
	listener, err := daemonServer.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %o", info.Mode().Perm())
	}
}

func TestSocketPermissionDriftFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.sock")
	registry, _ := identity.NewRegistry(map[string]uint32{"zara": uint32(os.Getuid())})
	j, _ := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	b := server.New(policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}}}, approval.NewStore(), j, time.Minute)
	executor := &countingExecutor{}
	service := daemon.New(path, registry, b, daemon.WithRunner(worker.New(b, executor)))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := json.NewEncoder(connection).Encode(daemon.Request{SchemaVersion: 1, Action: "request", RequestID: "drift-1", Repository: "yaniv256/private", Operation: "pull_request.create"}); err != nil {
		t.Fatal(err)
	}
	var response daemon.Response
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error != "socket_permissions_invalid" || executor.calls != 0 {
		t.Fatalf("response = %#v, calls = %d", response, executor.calls)
	}
}

func TestConcurrentCredentiallessRequestsRemainIsolated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.sock")
	registry, _ := identity.NewRegistry(map[string]uint32{"zara": uint32(os.Getuid())})
	j, _ := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	b := server.New(policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}}}, approval.NewStore(), j, time.Minute)
	executor := &concurrentExecutor{}
	service := daemon.New(path, registry, b, daemon.WithRunner(worker.New(b, executor)))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	const requestCount = 32
	errors := make(chan error, requestCount)
	var group sync.WaitGroup
	for index := range requestCount {
		group.Add(1)
		go func() {
			defer group.Done()
			requestID := fmt.Sprintf("concurrent-%d", index)
			connection, err := net.Dial("unix", path)
			if err != nil {
				errors <- err
				return
			}
			defer connection.Close()
			request := daemon.Request{SchemaVersion: 1, Action: "request", RequestID: requestID, Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "feature-" + requestID}
			if err := json.NewEncoder(connection).Encode(request); err != nil {
				errors <- err
				return
			}
			var response daemon.Response
			if err := json.NewDecoder(connection).Decode(&response); err != nil {
				errors <- err
				return
			}
			if response.Error != "" || !response.Executed || response.Result.ResourceID != requestID {
				errors <- fmt.Errorf("%s response = %#v", requestID, response)
			}
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if got := executor.calls.Load(); got != requestCount {
		t.Fatalf("execute calls = %d, want %d", got, requestCount)
	}
}

func TestUnsupportedSchemaNeverAuthorizesOrExecutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.sock")
	registry, _ := identity.NewRegistry(map[string]uint32{"zara": uint32(os.Getuid())})
	j, _ := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	b := server.New(policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}}}, approval.NewStore(), j, time.Minute)
	executor := &countingExecutor{}
	service := daemon.New(path, registry, b, daemon.WithRunner(worker.New(b, executor)))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := json.NewEncoder(connection).Encode(daemon.Request{SchemaVersion: 2, Action: "request", RequestID: "wrong-schema", Repository: "yaniv256/private", Operation: "pull_request.create"}); err != nil {
		t.Fatal(err)
	}
	var response daemon.Response
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error != "schema_version_unsupported" || executor.calls != 0 {
		t.Fatalf("response = %#v, calls = %d", response, executor.calls)
	}
}

func TestOAuthBeginUsesKernelCallerAndExactPolicyApprover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.sock")
	registry, _ := identity.NewRegistry(map[string]uint32{"zara": uint32(os.Getuid())})
	j, _ := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	b := server.New(policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/public": {Visibility: "public", Owners: []string{"zara"}, Approvers: []string{"yaniv"}}}}, approval.NewStore(), j, time.Minute)
	requester := &oauthRequester{}
	service := daemon.New(path, registry, b, daemon.WithOAuthRequester(requester))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	call := func(request daemon.Request) daemon.Response {
		connection, dialErr := net.Dial("unix", path)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		defer connection.Close()
		if encodeErr := json.NewEncoder(connection).Encode(request); encodeErr != nil {
			t.Fatal(encodeErr)
		}
		var response daemon.Response
		if decodeErr := json.NewDecoder(connection).Decode(&response); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		return response
	}
	expires := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	response := call(daemon.Request{SchemaVersion: 1, Action: "oauth.begin", RequestID: "oauth-1", CallerClaim: "elena", Repository: "yaniv256/public", Approver: "yaniv", ExpiresAt: expires})
	if response.Error != "" || response.AuthorizationURL == "" || requester.calls != 1 || requester.request.Session != "zara:oauth-1" || requester.request.Repository != "yaniv256/public" || requester.request.Subject != "yaniv" || requester.request.GitHubLogin != "yaniv" {
		t.Fatalf("response = %#v, requester = %#v", response, requester)
	}
	denied := call(daemon.Request{SchemaVersion: 1, Action: "oauth.begin", RequestID: "oauth-2", Repository: "yaniv256/public", Approver: "mallory", ExpiresAt: expires})
	if denied.Error == "" || requester.calls != 1 {
		t.Fatalf("denied = %#v, calls = %d", denied, requester.calls)
	}
}
