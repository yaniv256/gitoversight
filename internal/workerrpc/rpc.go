package workerrpc

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/approval"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/identity"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

const (
	// maxMessageBytes bounds a single worker-RPC message. A branch.push carries
	// its full commit packet (blobs+tree+commit) in the request payload, which
	// the commit-packet contract caps at commitpacket.MaxRequestBodyBytes (42 MiB).
	// The prior 1 MiB limit silently failed to decode any large packet, so the
	// worker never ran the mutation and the execution grant expired unconsumed
	// (Elena's ff-3, Dakota's meetuproom — both large-payload executes). Size this
	// above the packet cap with headroom for JSON/RPC framing.
	maxMessageBytes = 48 << 20
	// requestTimeout bounds ordinary RPCs. Streamed release assets deliberately
	// do not use a whole-call deadline: their approved size can approach
	// GitHub's 2 GiB limit, so any fixed wall-clock cutoff becomes an accidental
	// size limit on slower links.
	requestTimeout = 120 * time.Second
	maxConnections = 64
)

type request struct {
	PullNumber     int64                     `json:"pull_number,omitempty"`
	Action         string                    `json:"action"`
	Request        worker.Request            `json:"request"`
	Expectation    ApprovalExpectation       `json:"expectation,omitempty"`
	OAuth          OAuthBeginRequest         `json:"oauth,omitempty"`
	OAuthCallback  OAuthCallbackRequest      `json:"oauth_callback,omitempty"`
	Base           BaseReadRequest           `json:"base,omitempty"`
	Blob           BlobReadRequest           `json:"blob,omitempty"`
	Snapshot       RepositorySnapshotRequest `json:"snapshot,omitempty"`
	RepositoryBase RepositoryBaseRequest     `json:"repository_base,omitempty"`
	Archive        RepositoryArchiveRequest  `json:"archive,omitempty"`
}

// BlobReadRequest fetches one object's content from a public repository, so a
// pre-PR's OLD side can be shown next to its new side.
type BlobReadRequest struct {
	Repository string `json:"repository"`
	SHA        string `json:"sha"`
}

type response struct {
	PullState        githubapp.PullState            `json:"pull_state,omitempty"`
	Result           worker.Result                  `json:"result,omitempty"`
	Reconciliation   worker.Reconciliation          `json:"reconciliation,omitempty"`
	PullRequests     []githubapp.PullRequestSummary `json:"pull_requests,omitempty"`
	AuthorizationURL string                         `json:"authorization_url,omitempty"`
	OAuthCompletion  OAuthCompletion                `json:"oauth_completion,omitempty"`
	Base             BaseRead                       `json:"base,omitempty"`
	BlobContent      []byte                         `json:"blob_content,omitempty"`
	Snapshot         RepositorySnapshotRead         `json:"snapshot,omitempty"`
	RepositoryBase   RepositoryBaseRead             `json:"repository_base,omitempty"`
	Archive          RepositoryArchiveRead          `json:"archive,omitempty"`
	ReleaseAssets    ReleaseAssetReadiness          `json:"release_assets,omitempty"`
	Error            string                         `json:"error,omitempty"`
}

// ReleaseAssetReadiness is bounded protocol/configuration metadata. It never
// carries a filesystem path, staged descriptor, capability, or asset bytes.
type ReleaseAssetReadiness struct {
	ProtocolVersion int    `json:"protocol_version"`
	RootID          string `json:"root_id"`
	Readable        bool   `json:"readable"`
}

// BaseReadRequest asks the worker for a public repository's current state — the
// BASE half of a pre-PR's cross-repository diff. The API cannot read GitHub
// itself (it holds no credentials by design), so base resolution happens where
// the tokens live.
type BaseReadRequest struct {
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
}

// BaseRead is a public repository's resolved base. Empty CommitSHA means the
// repository has no commits yet, which publishes as a root commit rather than
// an error.
type BaseRead struct {
	CommitSHA string                `json:"commit_sha,omitempty"`
	TreeSHA   string                `json:"tree_sha,omitempty"`
	Entries   []githubapp.TreeEntry `json:"entries,omitempty"`
	Empty     bool                  `json:"empty,omitempty"`
}

// BaseReader is the worker-side capability the API depends on.
type BaseReader interface {
	ReadBase(BaseReadRequest) (BaseRead, error)
	ReadBlob(repository, sha string) ([]byte, error)
}

// RepositorySnapshotRequest is an exact-base, bounded private repository read.
// Tenant and agent are audit bindings supplied by the already-authenticated API
// adapter; the worker independently enforces installation and private visibility.
type RepositorySnapshotRequest struct {
	TenantID       string `json:"tenant_id"`
	AgentID        string `json:"agent_id"`
	Repository     string `json:"repository"`
	Ref            string `json:"ref"`
	ExactCommitSHA string `json:"exact_commit_sha"`
	MaxFiles       int    `json:"max_files"`
	MaxFileBytes   int    `json:"max_file_bytes"`
	MaxTotalBytes  int    `json:"max_total_bytes"`
}

type RepositorySnapshotEntry struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	BlobSHA string `json:"blob_sha"`
	Size    int64  `json:"size"`
}

type RepositorySnapshotRead struct {
	Repository string                    `json:"repository"`
	Ref        string                    `json:"ref"`
	CommitSHA  string                    `json:"commit_sha"`
	TreeSHA    string                    `json:"tree_sha"`
	Entries    []RepositorySnapshotEntry `json:"entries"`
}

type RepositorySnapshotReader interface {
	ReadRepositoryBase(RepositoryBaseRequest) (RepositoryBaseRead, error)
	ReadRepositorySnapshot(RepositorySnapshotRequest) (RepositorySnapshotRead, error)
	ReadRepositoryArchive(RepositoryArchiveRequest) (RepositoryArchiveRead, error)
}

type RepositoryBaseRequest struct {
	TenantID   string `json:"tenant_id"`
	AgentID    string `json:"agent_id"`
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
}

type RepositoryBaseRead struct {
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	CommitSHA  string `json:"commit_sha"`
	TreeSHA    string `json:"tree_sha"`
}

type RepositoryArchiveRequest struct{ RepositorySnapshotRequest }

type RepositoryArchiveRead struct {
	Repository  string `json:"repository"`
	Ref         string `json:"ref"`
	CommitSHA   string `json:"commit_sha"`
	TreeSHA     string `json:"tree_sha"`
	ContentType string `json:"content_type"`
	SHA256      string `json:"sha256"`
	Content     []byte `json:"content"`
}

type Client struct {
	path string
}

type ApprovalExpectation struct {
	Packet approval.Packet `json:"packet"`
	Head   string          `json:"head"`
}

type ApprovalExpecter interface {
	Expect(approval.Packet, string) error
}

type OAuthBeginRequest struct {
	Repository  string    `json:"repository,omitempty"`
	Purpose     string    `json:"purpose"`
	Session     string    `json:"session"`
	Subject     string    `json:"subject"`
	GitHubLogin string    `json:"github_login"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type OAuthBeginner interface {
	BeginOAuth(OAuthBeginRequest) (string, error)
}

type OAuthCallbackRequest struct {
	State string `json:"state"`
	Code  string `json:"code"`
}

type OAuthCompletion struct {
	Purpose string `json:"purpose"`
	Session string `json:"session"`
	Subject string `json:"subject"`
}

type OAuthCompleter interface {
	CompleteOAuth(OAuthCallbackRequest) (OAuthCompletion, error)
}

func NewClient(path string) *Client {
	return &Client{path: path}
}

func (c *Client) Ping() error {
	_, err := c.PingStatus()
	return err
}

func (c *Client) PingStatus() (ReleaseAssetReadiness, error) {
	result, err := c.call(request{Action: "ping"})
	return result.ReleaseAssets, err
}

func (c *Client) Run(value worker.Request) (worker.Result, error) {
	result, err := c.call(request{Action: "run", Request: value})
	return result.Result, err
}

func (c *Client) Reconcile(value worker.Request) (worker.Result, error) {
	result, err := c.call(request{Action: "reconcile", Request: value})
	return result.Result, err
}

func (c *Client) List(value worker.Request) ([]githubapp.PullRequestSummary, error) {
	result, err := c.call(request{Action: "pull_list", Request: value})
	return result.PullRequests, err
}

func (c *Client) PullState(value worker.Request, number int64) (githubapp.PullState, error) {
	result, err := c.call(request{Action: "pull_merged", Request: value, PullNumber: number})
	if err != nil {
		return githubapp.PullState{Outcome: githubapp.PullOutcomeIndeterminate}, err
	}
	return result.PullState, nil
}

func (c *Client) Handle(value worker.Request, _ time.Time) (worker.Result, error) {
	return c.Run(value)
}

func (c *Client) ExpectApproval(value ApprovalExpectation) error {
	_, err := c.call(request{Action: "expect_approval", Expectation: value})
	return err
}

func (c *Client) BeginOAuth(value OAuthBeginRequest) (string, error) {
	result, err := c.call(request{Action: "oauth_begin", OAuth: value})
	return result.AuthorizationURL, err
}

func (c *Client) CompleteOAuth(value OAuthCallbackRequest) (OAuthCompletion, error) {
	result, err := c.call(request{Action: "oauth_complete", OAuthCallback: value})
	return result.OAuthCompletion, err
}

// TriggerSearchSync asks the worker to run an on-demand repo-search sync pass.
// The worker coalesces triggers, so calling this repeatedly is safe and cheap.
func (c *Client) TriggerSearchSync() error {
	_, err := c.call(request{Action: "search.sync"})
	return err
}

// ReadBase resolves a public repository's current HEAD and tree — the base a
// pre-PR is diffed against. It is a read: it mutates nothing and needs no
// approval, but it runs worker-side because that is where GitHub credentials
// live.
func (c *Client) ReadBase(value BaseReadRequest) (BaseRead, error) {
	result, err := c.call(request{Action: "read_base", Base: value})
	return result.Base, err
}

// ReadBlob fetches one object's bytes from a public repository.
func (c *Client) ReadBlob(repository, sha string) ([]byte, error) {
	result, err := c.call(request{Action: "read_blob", Blob: BlobReadRequest{Repository: repository, SHA: sha}})
	return result.BlobContent, err
}

func (c *Client) ReadRepositorySnapshot(value RepositorySnapshotRequest) (RepositorySnapshotRead, error) {
	result, err := c.call(request{Action: "repository_snapshot", Snapshot: value})
	return result.Snapshot, err
}

func (c *Client) ReadRepositoryBase(value RepositoryBaseRequest) (RepositoryBaseRead, error) {
	result, err := c.call(request{Action: "repository_base", RepositoryBase: value})
	return result.RepositoryBase, err
}

func (c *Client) ReadRepositoryArchive(value RepositoryArchiveRequest) (RepositoryArchiveRead, error) {
	result, err := c.call(request{Action: "repository_archive", Archive: value})
	return result.Archive, err
}

func (c *Client) call(value request) (response, error) {
	connection, err := net.DialTimeout("unix", c.path, 3*time.Second)
	if err != nil {
		return response{}, errors.New("privileged worker unavailable")
	}
	defer connection.Close()
	if value.Request.Operation != "release.asset.upload" && value.Request.Operation != "release.assets.upload" {
		_ = connection.SetDeadline(time.Now().Add(requestTimeout))
	}
	requestErr := json.NewEncoder(connection).Encode(value)
	var result response
	decoder := json.NewDecoder(io.LimitReader(connection, maxMessageBytes))
	decoder.DisallowUnknownFields()
	responseErr := decoder.Decode(&result)
	if requestErr != nil {
		if responseErr == nil && result.Error != "" {
			return result, errors.New(result.Error)
		}
		return response{}, errors.New("privileged worker request failed")
	}
	if responseErr != nil {
		return response{}, errors.New("privileged worker response failed")
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}

type Server struct {
	path           string
	brokerUID      uint32
	expecter       ApprovalExpecter
	oauth          OAuthBeginner
	oauthComplete  OAuthCompleter
	runner         Runner
	searchSync     func()
	baseReader     BaseReader
	snapshotReader RepositorySnapshotReader
	failure        func(Failure)
	releaseAssets  func() ReleaseAssetReadiness
}

// Failure is the bounded, secret-free diagnostic surface for privileged
// worker failures. It deliberately omits capability tokens and payloads.
type Failure struct {
	Action     string
	RequestID  string
	Repository string
	Operation  string
	Err        error
}

type Runner interface {
	Handle(worker.Request, time.Time) (worker.Result, error)
	Reconcile(worker.Request, time.Time) (worker.Result, error)
	List(worker.Request) ([]githubapp.PullRequestSummary, error)
	PullState(worker.Request, int64) (githubapp.PullState, error)
}

type Option func(*Server)

func WithApprovalExpecter(expecter ApprovalExpecter) Option {
	return func(server *Server) {
		server.expecter = expecter
	}
}

func WithOAuthBeginner(beginner OAuthBeginner) Option {
	return func(server *Server) {
		server.oauth = beginner
	}
}

func WithOAuthCompleter(completer OAuthCompleter) Option {
	return func(server *Server) {
		server.oauthComplete = completer
	}
}

func WithRunner(runner Runner) Option {
	return func(server *Server) {
		server.runner = runner
	}
}

// WithSearchSyncTrigger wires the repo-search sync trigger. The function must
// be non-blocking (searchsync.Syncer.Trigger already is).
func WithSearchSyncTrigger(trigger func()) Option {
	return func(server *Server) {
		server.searchSync = trigger
	}
}

func WithFailureReporter(reporter func(Failure)) Option {
	return func(server *Server) {
		server.failure = reporter
	}
}

func WithReleaseAssetReadiness(readiness func() ReleaseAssetReadiness) Option {
	return func(server *Server) {
		server.releaseAssets = readiness
	}
}

// actionsCarryingTheirOwnArguments are the actions whose parameters live OUTSIDE
// the shared Request envelope — in Base, Blob, PullNumber, or in no payload at
// all. The generic completeness gate demands Request.RequestID/Repository/
// Operation, so an action listed here would be rejected before its own, more
// precise validation ever ran.
//
// This list was a bare `&&` chain in the dispatch prologue, and adding an action
// without extending it silently disabled that action while leaving its purpose-
// built validation as unreachable code. That is exactly what happened to
// read_base/read_blob: every pre-PR proposal failed with a
// "worker_request_incomplete" that named no field, and the feature shipped and
// was reported as verified having never once executed.
// The failure was invisible from the outside: the error named no field, so it
// read as a malformed request rather than a dispatch table that had never
// learned the action existed.
//
// Adding a new action? If its arguments do not live in Request, it belongs here,
// and it MUST validate its own required fields in its case body — the exemption
// removes a check, so the case has to replace it.
var actionsCarryingTheirOwnArguments = map[string]bool{
	"ping":                true, // no payload
	"expect_approval":     true, // Approval
	"oauth_begin":         true, // OAuth
	"oauth_complete":      true, // OAuth
	"pull_list":           true, // Request.Repository only
	"pull_merged":         true, // Request.Repository + PullNumber
	"search.sync":         true, // no payload
	"read_base":           true, // Base
	"read_blob":           true, // Blob
	"repository_snapshot": true, // Snapshot
	"repository_base":     true, // RepositoryBase
	"repository_archive":  true, // Archive
}

// requiresRequestEnvelope reports whether the generic completeness gate applies.
// Unknown actions default to requiring the envelope: an action nobody declared
// should be rejected, not waved through.
func requiresRequestEnvelope(action string) bool {
	return !actionsCarryingTheirOwnArguments[action]
}

// WithBaseReader wires public-repository base resolution for pre-PR review.
func WithBaseReader(reader BaseReader) Option {
	return func(server *Server) {
		server.baseReader = reader
	}
}

func WithRepositorySnapshotReader(reader RepositorySnapshotReader) Option {
	return func(server *Server) { server.snapshotReader = reader }
}

func NewServer(path string, brokerUID uint32, options ...Option) *Server {
	result := &Server{path: path, brokerUID: brokerUID}
	for _, option := range options {
		option(result)
	}
	return result
}

func (s *Server) Listen() (net.Listener, error) {
	_ = os.Remove(s.path)
	listener, err := net.Listen("unix", s.path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(s.path, 0o660); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func (s *Server) Serve(listener net.Listener) error {
	connections := make(chan struct{}, maxConnections)
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		connections <- struct{}{}
		go func() {
			defer func() { <-connections }()
			s.handle(connection)
		}()
	}
}

func (s *Server) handle(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(requestTimeout))
	if !socketPermissionsValid(s.path) {
		s.respond(connection, response{Error: "socket_permissions_invalid"})
		return
	}
	peer, err := identity.FromUnixConn(connection)
	if err != nil || peer.UID != s.brokerUID {
		s.respond(connection, response{Error: "worker_caller_forbidden"})
		return
	}
	var value request
	decoder := json.NewDecoder(io.LimitReader(connection, maxMessageBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		s.respond(connection, response{Error: "worker_request_invalid"})
		return
	}
	if requiresRequestEnvelope(value.Action) && (value.Request.RequestID == "" || value.Request.Repository == "" || value.Request.Operation == "") {
		s.respond(connection, response{Error: "worker_request_incomplete: request.request_id, request.repository and request.operation are all required for action " + value.Action})
		return
	}
	switch value.Action {
	case "ping":
		status := ReleaseAssetReadiness{}
		if s.releaseAssets != nil {
			status = s.releaseAssets()
		}
		s.respond(connection, response{ReleaseAssets: status})
	case "run":
		if s.runner == nil || value.Request.Capability == "" {
			s.respond(connection, response{Error: "worker_request_incomplete"})
			return
		}
		result, err := s.runner.Handle(value.Request, time.Now().UTC())
		if err != nil {
			s.reportFailure("run", value.Request, err)
			s.respond(connection, response{Result: result, Error: "github_mutation_failed"})
			return
		}
		s.respond(connection, response{Result: result})
	case "reconcile":
		if s.runner == nil || value.Request.TenantID == "" || value.Request.Capability != "" {
			s.respond(connection, response{Error: "worker_request_incomplete"})
			return
		}
		result, err := s.runner.Reconcile(value.Request, time.Now().UTC())
		if err != nil {
			// Carry the underlying cause across the RPC seam: a bare
			// "github_reconciliation_failed" leaves the coordinator (and the human
			// reading the banner) unable to distinguish an expired token from a
			// hash-binding refusal from a GitHub outage.
			s.respond(connection, response{Result: result, Error: "github_reconciliation_failed: " + err.Error()})
			s.reportFailure("reconcile", value.Request, err)
			s.respond(connection, response{Result: result, Error: "github_reconciliation_failed"})
			return
		}
		s.respond(connection, response{Result: result})
	case "pull_list":
		if s.runner == nil || value.Request.Repository == "" {
			s.respond(connection, response{Error: "worker_request_incomplete"})
			return
		}
		summaries, err := s.runner.List(value.Request)
		if err != nil {
			s.respond(connection, response{Error: "github_pull_list_failed"})
			return
		}
		s.respond(connection, response{PullRequests: summaries})
	case "pull_merged":
		if s.runner == nil || value.Request.Repository == "" || value.PullNumber <= 0 {
			s.respond(connection, response{Error: "worker_request_incomplete"})
			return
		}
		state, err := s.runner.PullState(value.Request, value.PullNumber)
		if err != nil {
			s.respond(connection, response{Error: "github_pull_merge_check_failed"})
			return
		}
		s.respond(connection, response{PullState: state})
	case "search.sync":
		if s.searchSync == nil {
			s.respond(connection, response{Error: "search_sync_unavailable"})
			return
		}
		s.searchSync()
		s.respond(connection, response{})
	case "read_base":
		if s.baseReader == nil {
			s.respond(connection, response{Error: "base_read_unavailable"})
			return
		}
		if value.Base.Repository == "" || value.Base.Branch == "" {
			s.respond(connection, response{Error: "base_read_rejected"})
			return
		}
		base, err := s.baseReader.ReadBase(value.Base)
		if err != nil {
			s.reportFailure("read_base", worker.Request{Repository: value.Base.Repository, Operation: "repository.read"}, err)
			s.respond(connection, response{Error: "base_read_failed"})
			return
		}
		s.respond(connection, response{Base: base})
	case "read_blob":
		if s.baseReader == nil {
			s.respond(connection, response{Error: "base_read_unavailable"})
			return
		}
		if value.Blob.Repository == "" || value.Blob.SHA == "" {
			s.respond(connection, response{Error: "base_read_rejected"})
			return
		}
		content, err := s.baseReader.ReadBlob(value.Blob.Repository, value.Blob.SHA)
		if err != nil {
			s.reportFailure("read_blob", worker.Request{Repository: value.Blob.Repository, Operation: "repository.read"}, err)
			s.respond(connection, response{Error: "base_read_failed"})
			return
		}
		s.respond(connection, response{BlobContent: content})
	case "repository_snapshot":
		if s.snapshotReader == nil {
			s.respond(connection, response{Error: "repository_snapshot_unavailable"})
			return
		}
		request := value.Snapshot
		if request.TenantID == "" || request.AgentID == "" || request.Repository == "" || request.Ref == "" || request.ExactCommitSHA == "" || request.MaxFiles <= 0 || request.MaxFileBytes <= 0 || request.MaxTotalBytes <= 0 {
			s.respond(connection, response{Error: "repository_snapshot_rejected"})
			return
		}
		snapshot, err := s.snapshotReader.ReadRepositorySnapshot(request)
		if err != nil {
			s.reportFailure("repository_snapshot", worker.Request{TenantID: request.TenantID, Repository: request.Repository, Operation: "repository.read"}, err)
			s.respond(connection, response{Error: "repository_snapshot_failed"})
			return
		}
		s.respond(connection, response{Snapshot: snapshot})
	case "repository_base":
		if s.snapshotReader == nil {
			s.respond(connection, response{Error: "repository_base_unavailable"})
			return
		}
		request := value.RepositoryBase
		if request.TenantID == "" || request.AgentID == "" || request.Repository == "" || request.Ref == "" {
			s.respond(connection, response{Error: "repository_base_rejected"})
			return
		}
		base, err := s.snapshotReader.ReadRepositoryBase(request)
		if err != nil {
			s.reportFailure("repository_base", worker.Request{TenantID: request.TenantID, Repository: request.Repository, Operation: "repository.read"}, err)
			s.respond(connection, response{Error: "repository_base_failed"})
			return
		}
		s.respond(connection, response{RepositoryBase: base})
	case "repository_archive":
		if s.snapshotReader == nil {
			s.respond(connection, response{Error: "repository_archive_unavailable"})
			return
		}
		request := value.Archive.RepositorySnapshotRequest
		if request.TenantID == "" || request.AgentID == "" || request.Repository == "" || request.Ref == "" || request.ExactCommitSHA == "" || request.MaxFiles <= 0 || request.MaxFileBytes <= 0 || request.MaxTotalBytes <= 0 {
			s.respond(connection, response{Error: "repository_archive_rejected"})
			return
		}
		archive, err := s.snapshotReader.ReadRepositoryArchive(value.Archive)
		if err != nil {
			s.reportFailure("repository_archive", worker.Request{TenantID: request.TenantID, Repository: request.Repository, Operation: "repository.read"}, err)
			s.respond(connection, response{Error: "repository_archive_failed"})
			return
		}
		s.respond(connection, response{Archive: archive})
	case "expect_approval":
		if s.expecter == nil {
			s.respond(connection, response{Error: "approval_expectation_unavailable"})
			return
		}
		if err := s.expecter.Expect(value.Expectation.Packet, value.Expectation.Head); err != nil {
			s.respond(connection, response{Error: "approval_expectation_rejected"})
			return
		}
		s.respond(connection, response{})
	case "oauth_begin":
		validPurpose := value.OAuth.Purpose == "human_login" || (value.OAuth.Purpose == "public_actor" && value.OAuth.Repository != "")
		if s.oauth == nil || !validPurpose || value.OAuth.Session == "" || value.OAuth.Subject == "" || value.OAuth.GitHubLogin == "" || value.OAuth.ExpiresAt.IsZero() {
			s.respond(connection, response{Error: "oauth_begin_rejected"})
			return
		}
		authorizationURL, err := s.oauth.BeginOAuth(value.OAuth)
		if err != nil {
			s.respond(connection, response{Error: "oauth_begin_rejected"})
			return
		}
		s.respond(connection, response{AuthorizationURL: authorizationURL})
	case "oauth_complete":
		if s.oauthComplete == nil || value.OAuthCallback.State == "" || value.OAuthCallback.Code == "" || len(value.OAuthCallback.State) > 512 || len(value.OAuthCallback.Code) > 512 {
			s.respond(connection, response{Error: "oauth_callback_rejected"})
			return
		}
		completion, err := s.oauthComplete.CompleteOAuth(value.OAuthCallback)
		if err != nil {
			s.respond(connection, response{Error: "oauth_callback_rejected"})
			return
		}
		s.respond(connection, response{OAuthCompletion: completion})
	default:
		s.respond(connection, response{Error: "worker_action_invalid"})
	}
}

func (s *Server) reportFailure(action string, request worker.Request, err error) {
	if s.failure == nil || err == nil {
		return
	}
	s.failure(Failure{Action: action, RequestID: request.RequestID, Repository: request.Repository, Operation: request.Operation, Err: err})
}

func socketPermissionsValid(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o660
}

func (s *Server) respond(connection net.Conn, value response) {
	_ = json.NewEncoder(connection).Encode(value)
}
