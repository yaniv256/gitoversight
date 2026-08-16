package workerrpc_test

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/approval"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type runner struct {
	calls int
	fail  error
	last  worker.Request
}

func (runner *runner) Handle(request worker.Request, _ time.Time) (worker.Result, error) {
	runner.calls++
	runner.last = request
	if request.Capability == "" {
		return worker.Result{}, errors.New("missing capability")
	}
	if runner.fail != nil {
		return worker.Result{}, runner.fail
	}
	return worker.Result{ResourceID: "verified-private-pr-42"}, nil
}

func TestWorkerRPCCarriesOnlyReleaseAssetDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	run := &runner{}
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithRunner(run))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	digest := strings.Repeat("a", 64)
	_, err = workerrpc.NewClient(path).Run(worker.Request{
		TenantID: "tenant-a", Capability: "capability", RequestID: "operation-a",
		Repository: "yaniv256/private", Operation: "release.asset.upload",
		Payload: map[string]any{
			"tag_name": "v1", "name": "bridge.zip", "content_type": "application/zip",
			"asset": map[string]any{"stage_id": "stage-a", "sha256": digest, "size": float64(16 << 20)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := run.last.Payload["content_base64"]; present {
		t.Fatal("worker RPC carried release asset bytes")
	}
	asset, ok := run.last.Payload["asset"].(map[string]any)
	if !ok || asset["stage_id"] != "stage-a" || asset["sha256"] != digest {
		t.Fatalf("descriptor = %#v", run.last.Payload)
	}
}

func TestPrivateWorkerRPCReportsSanitizedMutationFailureWithoutExposingItToClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	run := &runner{fail: errors.New("installation token scope is not registered")}
	reported := make(chan workerrpc.Failure, 1)
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithRunner(run), workerrpc.WithFailureReporter(func(failure workerrpc.Failure) {
		reported <- failure
	}))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	_, err = workerrpc.NewClient(path).Run(worker.Request{
		Capability: "must-not-be-reported", RequestID: "request-1", Repository: "ActionsJson/actions.json.dev",
		Operation: "branch.push", Payload: map[string]any{"secret": "must-not-be-reported"},
	})
	if err == nil || err.Error() != "github_mutation_failed" {
		t.Fatalf("client error = %v", err)
	}
	select {
	case failure := <-reported:
		if failure.Action != "run" || failure.RequestID != "request-1" || failure.Repository != "ActionsJson/actions.json.dev" || failure.Operation != "branch.push" || failure.Err == nil || failure.Err.Error() != "installation token scope is not registered" {
			t.Fatalf("failure = %#v", failure)
		}
	case <-time.After(time.Second):
		t.Fatal("mutation failure was not reported")
	}
}

func (runner *runner) Reconcile(request worker.Request, _ time.Time) (worker.Result, error) {
	runner.calls++
	if request.TenantID == "" {
		return worker.Result{}, errors.New("missing tenant")
	}
	return worker.Result{ResourceID: "reconciled-private-pr-42"}, nil
}

func (runner *runner) PullState(request worker.Request, number int64) (githubapp.PullState, error) {
	if request.Repository == "" || number <= 0 {
		return githubapp.PullState{Outcome: githubapp.PullOutcomeIndeterminate}, errors.New("missing repository or number")
	}
	return githubapp.PullState{Outcome: githubapp.PullOutcomeMerged, MergeSHA: "rpc-merge-sha"}, nil
}

func (runner *runner) List(request worker.Request) ([]githubapp.PullRequestSummary, error) {
	runner.calls++
	if request.Repository == "" {
		return nil, errors.New("missing repository")
	}
	return []githubapp.PullRequestSummary{
		{Number: 7, Title: "first", State: "open", HeadRef: "feature", BaseRef: "main", Author: "zara"},
		{Number: 9, Title: "second", State: "open", HeadRef: "fix", BaseRef: "main", Author: "tomas"},
	}, nil
}

type expecter struct {
	packet approval.Packet
	head   string
}

type oauthBeginner struct {
	request  workerrpc.OAuthBeginRequest
	callback workerrpc.OAuthCallbackRequest
	complete workerrpc.OAuthCompletion
	url      string
}

func (b *oauthBeginner) CompleteOAuth(request workerrpc.OAuthCallbackRequest) (workerrpc.OAuthCompletion, error) {
	b.callback = request
	return b.complete, nil
}

func (b *oauthBeginner) BeginOAuth(request workerrpc.OAuthBeginRequest) (string, error) {
	b.request = request
	return b.url, nil
}

func (e *expecter) Expect(packet approval.Packet, head string) error {
	e.packet = packet
	e.head = head
	return nil
}

func TestPrivateWorkerRPCExposesOnlyCapabilityGuardedMutationSurface(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	service := workerrpc.NewServer(path, uint32(os.Getuid()))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	client := workerrpc.NewClient(path)
	if err := client.Ping(); err != nil {
		t.Fatalf("worker ping: %v", err)
	}
}

func TestWorkerPingReportsReleaseAssetProtocolAndReadableRootWithoutPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithReleaseAssetReadiness(func() workerrpc.ReleaseAssetReadiness {
		return workerrpc.ReleaseAssetReadiness{
			ProtocolVersion: 1, RootID: strings.Repeat("a", 64), Readable: true,
		}
	}))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	status, err := workerrpc.NewClient(path).PingStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.ProtocolVersion != 1 || status.RootID != strings.Repeat("a", 64) || !status.Readable {
		t.Fatalf("ping status = %+v", status)
	}
}

func TestPrivateWorkerRPCRunsCapabilityGuardedMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	run := &runner{}
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithRunner(run))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	result, err := workerrpc.NewClient(path).Run(worker.Request{Capability: "single-use", RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create"})
	if err != nil {
		t.Fatal(err)
	}
	if result.ResourceID != "verified-private-pr-42" || run.calls != 1 {
		t.Fatalf("result = %#v, calls = %d", result, run.calls)
	}
}

func TestPrivateWorkerRPCListsOpenPullRequests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	run := &runner{}
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithRunner(run))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	summaries, err := workerrpc.NewClient(path).List(worker.Request{Repository: "yaniv256/private"})
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 2 || summaries[0].Number != 7 || summaries[1].Number != 9 || run.calls != 1 {
		t.Fatalf("summaries = %#v, calls = %d", summaries, run.calls)
	}

	if _, err := workerrpc.NewClient(path).List(worker.Request{}); err == nil {
		t.Fatal("pull list without repository was accepted")
	}
}

func TestPrivateWorkerRPCRejectsUnexpectedUnixCaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	service := workerrpc.NewServer(path, uint32(os.Getuid()+1))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	err = workerrpc.NewClient(path).Ping()
	if err == nil {
		t.Fatal("unexpected Unix caller was accepted")
	}
}

func TestPrivateWorkerSocketIsNotWorldAccessible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	service := workerrpc.NewServer(path, uint32(os.Getuid()))
	listener, err := service.Listen()
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
	if _, ok := listener.(*net.UnixListener); !ok {
		t.Fatalf("listener type = %T", listener)
	}
}

func TestPrivateWorkerSocketPermissionDriftFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	service := workerrpc.NewServer(path, uint32(os.Getuid()))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	err = workerrpc.NewClient(path).Ping()
	if err == nil || !strings.Contains(err.Error(), "socket_permissions_invalid") {
		t.Fatalf("execute error = %v", err)
	}
}

func TestPrivateWorkerRPCRegistersExactApprovalExpectation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	want := approval.Packet{ID: "approval-1", ManifestHash: "manifest", Repository: "yaniv256/public", Operations: []string{"pull_request.create"}, Approver: "yaniv", Nonce: "nonce", ExpiresAt: time.Now().Add(time.Minute), PolicyGeneration: 1}
	registered := &expecter{}
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithApprovalExpecter(registered))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	if err := workerrpc.NewClient(path).ExpectApproval(workerrpc.ApprovalExpectation{Packet: want, Head: "abc123"}); err != nil {
		t.Fatal(err)
	}
	if registered.packet.ID != want.ID || registered.head != "abc123" {
		t.Fatalf("registered = %#v, head = %q", registered.packet, registered.head)
	}
}

func TestPrivateWorkerRPCBeginsBoundedHumanOAuthWithoutReturningCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	beginner := &oauthBeginner{url: "https://github.test/login/oauth/authorize?state=opaque", complete: workerrpc.OAuthCompletion{Purpose: "human_login", Session: "pending", Subject: "yaniv"}}
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithOAuthBeginner(beginner), workerrpc.WithOAuthCompleter(beginner))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	want := workerrpc.OAuthBeginRequest{Repository: "yaniv256/public", Purpose: "public_actor", Session: "zara:request-1", Subject: "yaniv", GitHubLogin: "Yaniv256", ExpiresAt: time.Now().Add(time.Minute)}
	got, err := workerrpc.NewClient(path).BeginOAuth(want)
	if err != nil {
		t.Fatal(err)
	}
	if got != beginner.url || beginner.request.Repository != want.Repository || beginner.request.Session != want.Session || beginner.request.Subject != want.Subject || beginner.request.GitHubLogin != want.GitHubLogin {
		t.Fatalf("url = %q, request = %#v", got, beginner.request)
	}
	completion, err := workerrpc.NewClient(path).CompleteOAuth(workerrpc.OAuthCallbackRequest{State: "opaque", Code: "one-time-code"})
	if err != nil {
		t.Fatal(err)
	}
	if completion != beginner.complete {
		t.Fatalf("completion = %#v", completion)
	}
	if beginner.callback.State != "opaque" || beginner.callback.Code != "one-time-code" {
		t.Fatalf("callback = %#v", beginner.callback)
	}
}

func TestPrivateWorkerRPCTriggersSearchSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	triggered := 0
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithSearchSyncTrigger(func() { triggered++ }))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	if err := workerrpc.NewClient(path).TriggerSearchSync(); err != nil {
		t.Fatal(err)
	}
	if triggered != 1 {
		t.Fatalf("triggered = %d, want 1", triggered)
	}
}

// stubBaseReader answers the two pre-PR reads without touching GitHub.
type stubBaseReader struct {
	base  workerrpc.BaseRead
	blob  []byte
	calls int
}

type stubSnapshotReader struct {
	request workerrpc.RepositorySnapshotRequest
	result  workerrpc.RepositorySnapshotRead
}

func (reader *stubSnapshotReader) ReadRepositoryBase(request workerrpc.RepositoryBaseRequest) (workerrpc.RepositoryBaseRead, error) {
	return workerrpc.RepositoryBaseRead{Repository: request.Repository, Ref: request.Ref, CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40)}, nil
}

func (reader *stubSnapshotReader) ReadRepositorySnapshot(request workerrpc.RepositorySnapshotRequest) (workerrpc.RepositorySnapshotRead, error) {
	reader.request = request
	return reader.result, nil
}

func (reader *stubSnapshotReader) ReadRepositoryArchive(request workerrpc.RepositoryArchiveRequest) (workerrpc.RepositoryArchiveRead, error) {
	return workerrpc.RepositoryArchiveRead{Repository: request.Repository, Ref: request.Ref, CommitSHA: request.ExactCommitSHA, TreeSHA: strings.Repeat("b", 40), ContentType: "application/gzip", SHA256: strings.Repeat("c", 64), Content: []byte("archive")}, nil
}

func TestPrivateWorkerRPCReadsExactBoundedRepositorySnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	reader := &stubSnapshotReader{result: workerrpc.RepositorySnapshotRead{Repository: "org/private", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40)}}
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithRepositorySnapshotReader(reader))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	request := workerrpc.RepositorySnapshotRequest{TenantID: "tenant", AgentID: "work", Repository: "org/private", Ref: "refs/heads/main", ExactCommitSHA: strings.Repeat("a", 40), MaxFiles: 10, MaxFileBytes: 1024, MaxTotalBytes: 4096}
	result, err := workerrpc.NewClient(path).ReadRepositorySnapshot(request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Repository != request.Repository || reader.request != request {
		t.Fatalf("result/request = %#v / %#v", result, reader.request)
	}
}

func TestPrivateWorkerRPCRejectsUnboundedRepositorySnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	reader := &stubSnapshotReader{}
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithRepositorySnapshotReader(reader))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	_, err = workerrpc.NewClient(path).ReadRepositorySnapshot(workerrpc.RepositorySnapshotRequest{TenantID: "tenant", AgentID: "work", Repository: "org/private", Ref: "refs/heads/main", ExactCommitSHA: strings.Repeat("a", 40)})
	if err == nil || !strings.Contains(err.Error(), "repository_snapshot_rejected") {
		t.Fatalf("err = %v", err)
	}
}

func (reader *stubBaseReader) ReadBase(workerrpc.BaseReadRequest) (workerrpc.BaseRead, error) {
	reader.calls++
	return reader.base, nil
}

func (reader *stubBaseReader) ReadBlob(string, string) ([]byte, error) {
	reader.calls++
	return reader.blob, nil
}

// The pre-PR reads carry their arguments in the Base/Blob fields, NOT in
// Request. The dispatcher's generic completeness gate gets to run first, and it
// demands Request.RequestID/Repository/Operation — so an action omitted from
// that gate's exemption list is rejected before its own validation is ever
// reached, however correct that validation is.
//
// This drives the real socket rather than calling the handler directly: the
// defect lives in the dispatch prologue, which a direct handler test cannot see.
// Reverting the exemption reproduces the live failure exactly —
// "worker_request_incomplete" on every propose.
func TestPrivateWorkerRPCReadsBaseWhoseArgumentsBypassTheRequestEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	reader := &stubBaseReader{base: workerrpc.BaseRead{CommitSHA: "c0ffee", TreeSHA: "7ee5"}}
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithBaseReader(reader))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	base, err := workerrpc.NewClient(path).ReadBase(workerrpc.BaseReadRequest{
		Repository: "yaniv256/agent-kanban", Branch: "main",
	})
	if err != nil {
		t.Fatalf("ReadBase: %v", err)
	}
	if base.CommitSHA != "c0ffee" || base.TreeSHA != "7ee5" {
		t.Fatalf("base = %+v, want the stub's commit and tree", base)
	}
	if reader.calls != 1 {
		t.Fatalf("reader.calls = %d, want 1 (the gate swallowed the call)", reader.calls)
	}
}

func TestPrivateWorkerRPCReadsBlobWhoseArgumentsBypassTheRequestEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	reader := &stubBaseReader{blob: []byte("hello world\n")}
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithBaseReader(reader))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	content, err := workerrpc.NewClient(path).ReadBlob("yaniv256/agent-kanban", "deadbeef")
	if err != nil {
		t.Fatalf("ReadBlob: %v", err)
	}
	if string(content) != "hello world\n" {
		t.Fatalf("content = %q, want the stub's bytes", content)
	}
	if reader.calls != 1 {
		t.Fatalf("reader.calls = %d, want 1 (the gate swallowed the call)", reader.calls)
	}
}

// The exemption must not become a hole: an action that skips the generic gate
// still has to enforce its OWN required fields.
func TestPrivateWorkerRPCStillRejectsBaseReadMissingItsOwnArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	reader := &stubBaseReader{}
	service := workerrpc.NewServer(path, uint32(os.Getuid()), workerrpc.WithBaseReader(reader))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	_, err = workerrpc.NewClient(path).ReadBase(workerrpc.BaseReadRequest{Repository: "yaniv256/agent-kanban"})
	if err == nil || !strings.Contains(err.Error(), "base_read_rejected") {
		t.Fatalf("err = %v, want base_read_rejected for a missing branch", err)
	}
	if reader.calls != 0 {
		t.Fatalf("reader.calls = %d, want 0", reader.calls)
	}
}

func TestPrivateWorkerRPCSearchSyncUnavailableWithoutTrigger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.sock")
	service := workerrpc.NewServer(path, uint32(os.Getuid()))
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)

	err = workerrpc.NewClient(path).TriggerSearchSync()
	if err == nil || !strings.Contains(err.Error(), "search_sync_unavailable") {
		t.Fatalf("err = %v, want search_sync_unavailable", err)
	}
}
