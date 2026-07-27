package daemon

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/approval"
	"github.com/yaniv256/gitoversight.dev/internal/audit"
	"github.com/yaniv256/gitoversight.dev/internal/gitref"
	"github.com/yaniv256/gitoversight.dev/internal/identity"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

const maxRequestBytes = 1 << 20

type Request struct {
	SchemaVersion int            `json:"schema_version"`
	Action        string         `json:"action,omitempty"`
	Capability    string         `json:"capability,omitempty"`
	RequestID     string         `json:"request_id"`
	CallerClaim   string         `json:"caller,omitempty"`
	Repository    string         `json:"repository"`
	Operation     string         `json:"operation"`
	Branch        string         `json:"branch,omitempty"`
	Title         string         `json:"title,omitempty"`
	Body          string         `json:"body,omitempty"`
	ApprovalID    string         `json:"approval_id,omitempty"`
	ManifestHash  string         `json:"manifest_hash,omitempty"`
	Payload       map[string]any `json:"payload,omitempty"`
	Approver      string         `json:"approver,omitempty"`
	HeadSHA       string         `json:"head_sha,omitempty"`
	ExpiresAt     string         `json:"expires_at,omitempty"`
}

type Response struct {
	Authorization    server.Authorization `json:"authorization"`
	Result           worker.Result        `json:"result,omitempty"`
	Events           []audit.Event        `json:"events,omitempty"`
	Status           *audit.Event         `json:"status,omitempty"`
	Verified         bool                 `json:"verified,omitempty"`
	Executed         bool                 `json:"executed,omitempty"`
	Error            string               `json:"error,omitempty"`
	Approval         *approval.Packet     `json:"approval,omitempty"`
	AuthorizationURL string               `json:"authorization_url,omitempty"`
}

type Runner interface {
	Handle(worker.Request, time.Time) (worker.Result, error)
}

type ApprovalRequester interface {
	ExpectApproval(workerrpc.ApprovalExpectation) error
}

type OAuthRequester interface {
	BeginOAuth(workerrpc.OAuthBeginRequest) (string, error)
}

type Option func(*Server)

func WithRunner(runner Runner) Option {
	return func(server *Server) {
		server.runner = runner
	}
}

func WithApprovalRequester(requester ApprovalRequester) Option {
	return func(server *Server) {
		server.approvalRequester = requester
	}
}

func WithOAuthRequester(requester OAuthRequester) Option {
	return func(server *Server) {
		server.oauthRequester = requester
	}
}

type Server struct {
	path              string
	registry          *identity.Registry
	broker            *server.Broker
	runner            Runner
	approvalRequester ApprovalRequester
	oauthRequester    OAuthRequester
}

func New(path string, registry *identity.Registry, broker *server.Broker, options ...Option) *Server {
	result := &Server{path: path, registry: registry, broker: broker}
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
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.handle(connection)
	}
}

func (s *Server) handle(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if !socketPermissionsValid(s.path) {
		s.respond(connection, Response{Error: "socket_permissions_invalid"})
		return
	}
	peer, err := identity.FromUnixConn(connection)
	if err != nil {
		s.respond(connection, Response{Error: "peer_identity_failed"})
		return
	}
	caller, ok := s.registry.AgentForUID(peer.UID)
	if !ok {
		s.respond(connection, Response{Error: "caller_unregistered"})
		return
	}
	var request Request
	decoder := json.NewDecoder(io.LimitReader(connection, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		s.respond(connection, Response{Error: "request_invalid"})
		return
	}
	if request.SchemaVersion != 1 {
		s.respond(connection, Response{Error: "schema_version_unsupported"})
		return
	}
	originalBranch := request.Branch
	request.Branch = gitref.BranchName(request.Branch)
	if originalBranch != "" && request.Branch == "" {
		s.respond(connection, Response{Error: "branch_ref_invalid"})
		return
	}
	if request.Action == "receipt" {
		events, err := s.broker.Receipt(caller, request.RequestID)
		if err != nil {
			s.respond(connection, Response{Error: err.Error()})
			return
		}
		s.respond(connection, Response{Events: events})
		return
	}
	if request.Action == "status" {
		status, err := s.broker.Status(caller, request.RequestID)
		if err != nil {
			s.respond(connection, Response{Error: err.Error()})
			return
		}
		s.respond(connection, Response{Status: &status})
		return
	}
	if request.Action == "verify" {
		if err := s.broker.VerifyReceipt(caller, request.RequestID); err != nil {
			s.respond(connection, Response{Error: err.Error()})
			return
		}
		s.respond(connection, Response{Verified: true})
		return
	}
	if request.Action == "revoke" {
		if err := s.broker.RevokeCapability(caller, request.Capability, time.Now().UTC()); err != nil {
			s.respond(connection, Response{Error: err.Error()})
			return
		}
		s.respond(connection, Response{})
		return
	}
	if request.Action == "approval.expect" {
		if s.approvalRequester == nil {
			s.respond(connection, Response{Error: "approval_expectation_unavailable"})
			return
		}
		expiresAt, err := time.Parse(time.RFC3339, request.ExpiresAt)
		if err != nil {
			s.respond(connection, Response{Error: "approval_expectation_invalid"})
			return
		}
		mutation := server.MutationRequest{RequestID: request.RequestID, Repository: request.Repository, Operation: request.Operation, Branch: request.Branch, Title: request.Title, Body: request.Body, Payload: request.Payload}
		packet, err := s.broker.PrepareApproval(caller, mutation, request.RequestID, request.ManifestHash, request.ApprovalID, request.Approver, request.HeadSHA, expiresAt, time.Now().UTC())
		if err != nil {
			s.respond(connection, Response{Error: "approval_expectation_rejected"})
			return
		}
		if err := s.approvalRequester.ExpectApproval(workerrpc.ApprovalExpectation{Packet: packet, Head: request.HeadSHA}); err != nil {
			s.respond(connection, Response{Error: "approval_expectation_unavailable"})
			return
		}
		s.respond(connection, Response{Approval: &packet})
		return
	}
	if request.Action == "oauth.begin" {
		if s.oauthRequester == nil {
			s.respond(connection, Response{Error: "oauth_begin_unavailable"})
			return
		}
		expiresAt, err := time.Parse(time.RFC3339, request.ExpiresAt)
		if err != nil || !expiresAt.After(time.Now().UTC()) || expiresAt.After(time.Now().UTC().Add(10*time.Minute)) {
			s.respond(connection, Response{Error: "oauth_begin_invalid"})
			return
		}
		if err := s.broker.BeginOAuth(caller, request.RequestID, request.Repository, request.Approver, time.Now().UTC()); err != nil {
			s.respond(connection, Response{Error: "oauth_begin_rejected"})
			return
		}
		authorizationURL, err := s.oauthRequester.BeginOAuth(workerrpc.OAuthBeginRequest{
			Repository: request.Repository, Purpose: "public_actor", Session: caller + ":" + request.RequestID,
			Subject: request.Approver, GitHubLogin: request.Approver, ExpiresAt: expiresAt,
		})
		if err != nil {
			s.respond(connection, Response{Error: "oauth_begin_unavailable"})
			return
		}
		s.respond(connection, Response{AuthorizationURL: authorizationURL})
		return
	}
	if request.Action != "request" {
		s.respond(connection, Response{Error: "action_invalid"})
		return
	}
	if s.runner == nil {
		s.respond(connection, Response{Error: "execution_unavailable"})
		return
	}
	mutation := server.MutationRequest{RequestID: request.RequestID, CallerClaim: request.CallerClaim, Repository: request.Repository, Operation: request.Operation, Branch: request.Branch, Title: request.Title, Body: request.Body, ApprovalID: request.ApprovalID, Payload: request.Payload}
	authorization := s.broker.Authorize(caller, mutation, request.ManifestHash, time.Now().UTC())
	capability := authorization.Capability
	authorization.Capability = ""
	if capability == "" {
		s.respond(connection, Response{Authorization: authorization})
		return
	}
	result, err := s.runner.Handle(worker.Request{Capability: capability, RequestID: request.RequestID, Repository: request.Repository, Operation: request.Operation, Branch: request.Branch, Title: request.Title, Body: request.Body, ManifestHash: request.ManifestHash, Payload: request.Payload, ActorMode: authorization.ActorMode, ActorSubject: authorization.ActorSubject}, time.Now().UTC())
	if err != nil {
		code := "mutation_failed"
		if result.Indeterminate {
			code = "mutation_outcome_indeterminate"
		}
		s.respond(connection, Response{Authorization: authorization, Result: result, Error: code})
		return
	}
	s.respond(connection, Response{Authorization: authorization, Result: result, Executed: true})
}

func socketPermissionsValid(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o660
}

func (s *Server) respond(connection net.Conn, response Response) {
	_ = json.NewEncoder(connection).Encode(response)
}
