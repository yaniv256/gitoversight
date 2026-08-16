// Package mcpapp implements the bounded Streamable HTTP MCP adapter used by
// remote agent clients. It owns protocol/session concerns and delegates all
// governed operation semantics to brokerapp.
package mcpapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
	"github.com/yaniv256/gitoversight.dev/internal/server"
)

const ProtocolVersion = "2025-06-18"

const minimumResultBytes = 512

var (
	ErrUnauthenticated  = errors.New("mcp bearer authentication failed")
	ErrRepositoryDenied = errors.New("repository is outside the agent scope")
)

type Principal struct {
	Identity     brokerapp.Identity
	ClientID     string
	Repositories []string
	AllPrivate   bool
}

type Repository struct {
	Key        string `json:"key"`
	Visibility string `json:"visibility"`
}

type BearerResolver interface {
	ResolveBearer(context.Context, string) (Principal, error)
}

type RepositoryScope interface {
	ListAuthorized(context.Context, Principal) ([]Repository, error)
	Authorize(context.Context, Principal, string) error
}

type Operations interface {
	Submit(context.Context, brokerapp.Identity, brokerapp.OperationRequest) (brokerapp.SubmitResult, error)
	Status(context.Context, brokerapp.Identity, string) (server.DurableResult, error)
	Reconcile(context.Context, brokerapp.Identity, string) (server.DurableResult, error)
}

type Config struct {
	AllowedOrigins []string
	// AllowMissingOrigin permits trusted server-to-server clients that omit
	// Origin. Every non-empty Origin is still checked against AllowedOrigins.
	AllowMissingOrigin   bool
	Resolver             BearerResolver
	Scope                RepositoryScope
	Operations           Operations
	ChangeDrafts         ChangeDrafts
	ChangeDraftPublisher ChangeDraftPublisher
	RepositoryReads      RepositoryReads
	SyncProposals        SyncProposals
	SessionTTL           time.Duration
	MaxSessions          int
	MaxInFlight          int
	MaxBodyBytes         int64
	MaxResultBytes       int
	ServerName           string
	ServerVersion        string
	Now                  func() time.Time
	Random               io.Reader
}

type Handler struct {
	allowedOrigins       map[string]struct{}
	allowMissingOrigin   bool
	resolver             BearerResolver
	scope                RepositoryScope
	operations           Operations
	changeDrafts         ChangeDrafts
	changeDraftPublisher ChangeDraftPublisher
	repositoryReads      RepositoryReads
	syncProposals        SyncProposals
	sessionTTL           time.Duration
	maxSessions          int
	maxInFlight          int
	maxBodyBytes         int64
	maxResultBytes       int
	serverName           string
	serverVersion        string
	now                  func() time.Time
	random               io.Reader

	mu       sync.Mutex
	sessions map[string]session
}

type session struct {
	Principal   Principal
	Origin      string
	ClientName  string
	ExpiresAt   time.Time
	Initialized bool
	InFlight    map[string]struct{}
}

func NewHandler(config Config) (*Handler, error) {
	if config.Resolver == nil || config.Scope == nil || config.Operations == nil {
		return nil, errors.New("resolver, repository scope, and operations are required")
	}
	if len(config.AllowedOrigins) == 0 {
		return nil, errors.New("at least one allowed origin is required")
	}
	allowedOrigins := make(map[string]struct{}, len(config.AllowedOrigins))
	for _, origin := range config.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			return nil, errors.New("allowed origins must not be empty")
		}
		allowedOrigins[origin] = struct{}{}
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = 15 * time.Minute
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = 1024
	}
	if config.MaxInFlight <= 0 {
		config.MaxInFlight = 32
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 1 << 20
	}
	if config.MaxResultBytes <= 0 {
		config.MaxResultBytes = 1 << 20
	} else if config.MaxResultBytes < minimumResultBytes {
		return nil, fmt.Errorf("max result bytes must be at least %d", minimumResultBytes)
	}
	if config.ServerName == "" {
		config.ServerName = "gitoversight"
	}
	if config.ServerVersion == "" {
		config.ServerVersion = "development"
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	return &Handler{
		allowedOrigins: allowedOrigins, allowMissingOrigin: config.AllowMissingOrigin,
		resolver: config.Resolver, scope: config.Scope, operations: config.Operations,
		changeDrafts: config.ChangeDrafts, changeDraftPublisher: config.ChangeDraftPublisher, repositoryReads: config.RepositoryReads, syncProposals: config.SyncProposals,
		sessionTTL: config.SessionTTL, maxSessions: config.MaxSessions, maxInFlight: config.MaxInFlight,
		maxBodyBytes: config.MaxBodyBytes, maxResultBytes: config.MaxResultBytes,
		serverName: config.ServerName, serverVersion: config.ServerVersion,
		now: config.Now, random: config.Random, sessions: make(map[string]session),
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	origin := request.Header.Get("Origin")
	if origin == "" && !handler.allowMissingOrigin {
		handler.writeTransportError(response, http.StatusForbidden, "origin_required")
		return
	}
	if origin != "" {
		if _, ok := handler.allowedOrigins[origin]; !ok {
			handler.writeTransportError(response, http.StatusForbidden, "origin_not_allowed")
			return
		}
	}
	principal, ok := handler.authenticate(response, request)
	if !ok {
		return
	}

	switch request.Method {
	case http.MethodGet:
		response.Header().Set("Allow", "POST, DELETE")
		handler.writeTransportError(response, http.StatusMethodNotAllowed, "sse_not_supported")
	case http.MethodDelete:
		handler.deleteSession(response, request, principal, origin)
	case http.MethodPost:
		handler.post(response, request, principal, origin)
	default:
		response.Header().Set("Allow", "POST, DELETE")
		handler.writeTransportError(response, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (handler *Handler) authenticate(response http.ResponseWriter, request *http.Request) (Principal, bool) {
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")) == "" {
		response.Header().Set("WWW-Authenticate", `Bearer realm="gitoversight-mcp"`)
		handler.writeTransportError(response, http.StatusUnauthorized, "authentication_required")
		return Principal{}, false
	}
	principal, err := handler.resolver.ResolveBearer(request.Context(), strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
	if err != nil || principal.Identity.TenantID == "" || principal.Identity.AgentID == "" || principal.ClientID == "" {
		response.Header().Set("WWW-Authenticate", `Bearer realm="gitoversight-mcp", error="invalid_token"`)
		handler.writeTransportError(response, http.StatusUnauthorized, "invalid_token")
		return Principal{}, false
	}
	return principal, true
}

func (handler *Handler) post(response http.ResponseWriter, request *http.Request, principal Principal, origin string) {
	if !accepts(request.Header.Get("Accept"), "application/json") || !accepts(request.Header.Get("Accept"), "text/event-stream") {
		handler.writeTransportError(response, http.StatusNotAcceptable, "streamable_http_accept_required")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		handler.writeTransportError(response, http.StatusUnsupportedMediaType, "application_json_required")
		return
	}
	payload, tooLarge, err := readBounded(request.Body, handler.maxBodyBytes)
	if tooLarge {
		handler.writeTransportError(response, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	if err != nil {
		handler.writeTransportError(response, http.StatusBadRequest, "request_read_failed")
		return
	}
	var message rpcRequest
	if err := strictDecode(payload, &message); err != nil {
		handler.writeRPCError(response, nil, -32700, "parse_error", nil)
		return
	}
	if message.JSONRPC != "2.0" || message.Method == "" {
		handler.writeRPCError(response, message.ID, -32600, "invalid_request", nil)
		return
	}

	if message.Method == "initialize" {
		handler.initialize(response, request, principal, origin, message)
		return
	}
	sessionID := request.Header.Get("Mcp-Session-Id")
	current, status, code := handler.session(sessionID, principal, origin)
	if code != "" {
		handler.writeTransportError(response, status, code)
		return
	}
	if request.Header.Get("MCP-Protocol-Version") != ProtocolVersion {
		handler.writeTransportError(response, http.StatusBadRequest, "unsupported_protocol_version")
		return
	}
	if message.Method == "notifications/initialized" {
		if len(message.ID) != 0 {
			handler.writeRPCError(response, message.ID, -32600, "invalid_initialized_notification", nil)
			return
		}
		handler.markInitialized(sessionID)
		response.WriteHeader(http.StatusAccepted)
		return
	}
	if len(message.ID) != 0 {
		if code := handler.beginRequest(sessionID, message.ID); code != "" {
			handler.writeRPCError(response, message.ID, -32600, code, nil)
			return
		}
		defer handler.finishRequest(sessionID, message.ID)
	}
	if !current.Initialized && message.Method != "ping" {
		handler.writeRPCError(response, message.ID, -32002, "session_not_initialized", nil)
		return
	}
	if len(message.ID) == 0 {
		handler.writeTransportError(response, http.StatusBadRequest, "unsupported_notification")
		return
	}

	switch message.Method {
	case "ping":
		handler.writeRPCResult(response, message.ID, map[string]any{})
	case "tools/list":
		handler.listTools(response, message)
	case "tools/call":
		handler.callTool(response, request.Context(), principal, message)
	default:
		handler.writeRPCError(response, message.ID, -32601, "method_not_found", nil)
	}
}

func (handler *Handler) initialize(response http.ResponseWriter, request *http.Request, principal Principal, origin string, message rpcRequest) {
	if request.Header.Get("Mcp-Session-Id") != "" {
		handler.writeTransportError(response, http.StatusBadRequest, "initialize_with_session")
		return
	}
	if len(message.ID) == 0 {
		handler.writeRPCError(response, nil, -32600, "initialize_request_id_required", nil)
		return
	}
	var params struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ClientInfo      struct {
			Name    string `json:"name"`
			Title   string `json:"title,omitempty"`
			Version string `json:"version"`
		} `json:"clientInfo"`
		Meta map[string]any `json:"_meta,omitempty"`
	}
	if err := strictDecode(message.Params, &params); err != nil || params.ProtocolVersion != ProtocolVersion || params.Capabilities == nil || params.ClientInfo.Name == "" || params.ClientInfo.Version == "" {
		handler.writeRPCError(response, message.ID, -32602, "unsupported_protocol_version", map[string]any{"supported": []string{ProtocolVersion}})
		return
	}
	sessionID, err := handler.newSessionID()
	if err != nil {
		handler.writeRPCError(response, message.ID, -32603, "session_creation_failed", nil)
		return
	}
	handler.mu.Lock()
	handler.pruneExpiredLocked(handler.now().UTC())
	if len(handler.sessions) >= handler.maxSessions {
		handler.mu.Unlock()
		handler.writeRPCError(response, message.ID, -32003, "session_capacity_exceeded", nil)
		return
	}
	if _, exists := handler.sessions[sessionID]; exists {
		handler.mu.Unlock()
		handler.writeRPCError(response, message.ID, -32603, "session_creation_failed", nil)
		return
	}
	handler.sessions[sessionID] = session{
		Principal: principal, Origin: origin, ClientName: params.ClientInfo.Name,
		ExpiresAt: handler.now().UTC().Add(handler.sessionTTL),
		InFlight:  make(map[string]struct{}),
	}
	handler.mu.Unlock()
	response.Header().Set("Mcp-Session-Id", sessionID)
	handler.writeRPCResult(response, message.ID, map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]string{"name": handler.serverName, "version": handler.serverVersion},
		"instructions":    "Use repository scope discovery before governed operations; reconcile the same operation ID after indeterminate outcomes.",
	})
}

func (handler *Handler) listTools(response http.ResponseWriter, message rpcRequest) {
	var params struct {
		Cursor string         `json:"cursor,omitempty"`
		Meta   map[string]any `json:"_meta,omitempty"`
	}
	if len(message.Params) != 0 {
		if err := strictDecode(message.Params, &params); err != nil || params.Cursor != "" {
			handler.writeRPCError(response, message.ID, -32602, "invalid_arguments", nil)
			return
		}
	}
	handler.writeRPCResult(response, message.ID, map[string]any{"tools": toolCatalog(handler.changeDrafts != nil, handler.changeDraftPublisher != nil, handler.repositoryReads != nil, handler.syncProposals != nil)})
}

func (handler *Handler) callTool(response http.ResponseWriter, ctx context.Context, principal Principal, message rpcRequest) {
	identity := principal.Identity
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      map[string]any  `json:"_meta,omitempty"`
	}
	if err := strictDecode(message.Params, &params); err != nil || params.Name == "" {
		handler.writeRPCError(response, message.ID, -32602, "invalid_arguments", nil)
		return
	}
	if len(params.Arguments) == 0 {
		params.Arguments = json.RawMessage(`{}`)
	}
	var value any
	var err error
	switch params.Name {
	case "repositories.list":
		var arguments struct{}
		if decodeErr := strictDecode(params.Arguments, &arguments); decodeErr != nil {
			err = errInvalidArguments
		} else {
			var repositories []Repository
			repositories, err = handler.scope.ListAuthorized(ctx, principal)
			if err != nil {
				err = errRepositoryScopeUnavailable
			}
			value = map[string]any{"repositories": repositories}
		}
	case "operation.submit":
		var arguments submitArguments
		if decodeErr := strictDecode(params.Arguments, &arguments); decodeErr != nil {
			err = errInvalidArguments
		} else {
			if arguments.ID == "" || arguments.Repository == "" || arguments.Operation == "" {
				err = errInvalidArguments
			} else {
				err = handler.scope.Authorize(ctx, principal, arguments.Repository)
				if err != nil && !errors.Is(err, ErrRepositoryDenied) {
					err = errRepositoryScopeUnavailable
				}
				if err == nil {
					var submitted brokerapp.SubmitResult
					submitted, err = handler.operations.Submit(ctx, identity, arguments.operationRequest())
					value = map[string]any{"executed": submitted.Executed, "operation": submitted.Result}
				}
			}
		}
	case "operation.status", "operation.reconcile":
		var arguments operationIDArguments
		if decodeErr := strictDecode(params.Arguments, &arguments); decodeErr != nil {
			err = errInvalidArguments
		} else {
			if arguments.OperationID == "" {
				err = errInvalidArguments
			} else {
				value, err = handler.authorizedOperation(ctx, principal, arguments.OperationID)
				if err == nil && params.Name == "operation.reconcile" {
					value, err = handler.operations.Reconcile(ctx, identity, arguments.OperationID)
				}
			}
		}
	case "change_draft.create":
		var arguments createDraftArguments
		if decodeErr := strictDecode(params.Arguments, &arguments); decodeErr != nil || handler.changeDrafts == nil {
			err = errInvalidArguments
		} else {
			var draftRequest brokerapp.CreateChangeDraftRequest
			draftRequest, err = arguments.request()
			if err == nil {
				err = handler.scope.Authorize(ctx, principal, arguments.Repository)
				if err != nil && !errors.Is(err, ErrRepositoryDenied) {
					err = errRepositoryScopeUnavailable
				}
			}
			if err == nil {
				var receipt brokerapp.ChangeDraftReceipt
				receipt, err = handler.changeDrafts.Create(ctx, identity, draftRequest)
				value = receiptEnvelope(receipt)
			}
		}
	case "change_draft.inspect":
		var arguments inspectDraftArguments
		if decodeErr := strictDecode(params.Arguments, &arguments); decodeErr != nil || handler.changeDrafts == nil {
			err = errInvalidArguments
		} else {
			var binding brokerapp.ChangeDraftBinding
			binding, err = arguments.binding()
			if err == nil {
				err = handler.scope.Authorize(ctx, principal, arguments.Repository)
				if err != nil && !errors.Is(err, ErrRepositoryDenied) {
					err = errRepositoryScopeUnavailable
				}
			}
			if err == nil {
				var draft changedraft.StoredDraft
				draft, err = handler.changeDrafts.Resolve(ctx, identity, binding)
				value = storedDraftEnvelope(draft)
			}
		}
	case "change_draft.publish":
		var arguments publishDraftArguments
		if decodeErr := strictDecode(params.Arguments, &arguments); decodeErr != nil || handler.changeDraftPublisher == nil {
			err = errInvalidArguments
		} else {
			var request brokerapp.PublishChangeDraftRequest
			request, err = arguments.request()
			if err == nil {
				err = handler.authorizeRepository(ctx, principal, arguments.Repository)
			}
			if err == nil {
				var published brokerapp.SubmitResult
				published, err = handler.changeDraftPublisher.Publish(ctx, identity, request)
				value = map[string]any{"executed": published.Executed, "operation": published.Result}
			}
		}
	case "repository.inspect":
		var arguments repositoryInspectArguments
		if decodeErr := strictDecode(params.Arguments, &arguments); decodeErr != nil || !validMCPRepository(arguments.Repository) || handler.repositoryReads == nil {
			err = errInvalidArguments
		} else {
			err = handler.authorizeRepository(ctx, principal, arguments.Repository)
			if err == nil {
				var metadata brokerapp.RepositoryReadMetadata
				metadata, err = handler.repositoryReads.Inspect(ctx, identity, arguments.Repository)
				value = metadataEnvelope(metadata)
			}
		}
	case "repository.search":
		var arguments repositorySearchArguments
		if decodeErr := strictDecode(params.Arguments, &arguments); decodeErr != nil || handler.repositoryReads == nil {
			err = errInvalidArguments
		} else {
			var searchRequest brokerapp.RepositorySearchRequest
			var repositories []string
			if err == nil {
				searchRequest, err = arguments.request(nil)
			}
			if err == nil {
				repositories, err = handler.authorizeRepositorySearch(ctx, principal)
				searchRequest.Repositories = repositories
			}
			if err == nil {
				var result brokerapp.RepositorySearchResult
				result, err = handler.repositoryReads.Search(ctx, identity, searchRequest)
				value = searchEnvelope(result)
			}
		}
	case "repository.snapshot":
		var arguments repositorySnapshotArguments
		if decodeErr := strictDecode(params.Arguments, &arguments); decodeErr != nil || !validMCPRepository(arguments.Repository) || arguments.Ref == "" || len(arguments.Ref) > maxMCPRepositoryRefBytes || !validMCPObjectID(arguments.ExactCommitSHA) || handler.repositoryReads == nil {
			err = errInvalidArguments
		} else {
			err = handler.authorizeRepository(ctx, principal, arguments.Repository)
			if err == nil {
				var snapshot brokerapp.SnapshotDownload
				snapshot, err = handler.repositoryReads.Snapshot(ctx, identity, brokerapp.SnapshotRequest{
					Repository: arguments.Repository, Ref: arguments.Ref, ExactCommitSHA: arguments.ExactCommitSHA,
				})
				value = snapshotEnvelope(snapshot)
			}
		}
	case "sync.propose":
		var arguments syncProposalArguments
		if decodeErr := strictDecode(params.Arguments, &arguments); decodeErr != nil || handler.syncProposals == nil {
			err = errInvalidArguments
		} else {
			var proposal brokerapp.SyncProposalRequest
			proposal, err = arguments.request()
			if err == nil {
				err = handler.authorizeRepository(ctx, principal, arguments.Repository)
			}
			if err == nil {
				var result brokerapp.SyncProposalResult
				result, err = handler.syncProposals.Propose(ctx, identity, proposal)
				value = syncEnvelope(result)
			}
		}
	default:
		handler.writeRPCError(response, message.ID, -32602, "unknown_tool", map[string]any{"tool": params.Name})
		return
	}
	if err != nil {
		handler.writeRPCResult(response, message.ID, handler.toolError(toolErrorCode(err)))
		return
	}
	handler.writeRPCResult(response, message.ID, handler.toolResult(value))
}

func (handler *Handler) authorizeRepository(ctx context.Context, principal Principal, repository string) error {
	err := handler.scope.Authorize(ctx, principal, repository)
	if err != nil && !errors.Is(err, ErrRepositoryDenied) {
		return errRepositoryScopeUnavailable
	}
	return err
}

func (handler *Handler) authorizeRepositorySearch(ctx context.Context, principal Principal) ([]string, error) {
	repositories, err := handler.scope.ListAuthorized(ctx, principal)
	if err != nil {
		return nil, errRepositoryScopeUnavailable
	}
	result := make([]string, 0, len(repositories))
	for _, repository := range repositories {
		if err := handler.authorizeRepository(ctx, principal, repository.Key); err != nil {
			return nil, err
		}
		result = append(result, repository.Key)
	}
	return result, nil
}

func (handler *Handler) authorizedOperation(ctx context.Context, principal Principal, operationID string) (server.DurableResult, error) {
	identity := principal.Identity
	result, err := handler.operations.Status(ctx, identity, operationID)
	if err != nil {
		return result, err
	}
	if result.Repository == "" {
		return server.DurableResult{}, errOperationRepositoryUnavailable
	}
	if err := handler.scope.Authorize(ctx, principal, result.Repository); err != nil {
		if errors.Is(err, ErrRepositoryDenied) {
			return server.DurableResult{}, ErrRepositoryDenied
		}
		return server.DurableResult{}, errRepositoryScopeUnavailable
	}
	return result, nil
}

func (handler *Handler) toolResult(value any) map[string]any {
	structured, err := json.Marshal(value)
	if err != nil || len(structured) > handler.maxResultBytes {
		return handler.toolError("result_too_large")
	}
	result := map[string]any{
		"content":           []map[string]string{{"type": "text", "text": string(structured)}},
		"structuredContent": value,
		"isError":           false,
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded)+128 > handler.maxResultBytes {
		return handler.toolError("result_too_large")
	}
	return result
}

func (handler *Handler) toolError(code string) map[string]any {
	value := map[string]any{"ok": false, "error": map[string]string{"code": code}}
	structured, _ := json.Marshal(value)
	return map[string]any{
		"content":           []map[string]string{{"type": "text", "text": string(structured)}},
		"structuredContent": value,
		"isError":           true,
	}
}

func (handler *Handler) deleteSession(response http.ResponseWriter, request *http.Request, principal Principal, origin string) {
	if request.Header.Get("MCP-Protocol-Version") != ProtocolVersion {
		handler.writeTransportError(response, http.StatusBadRequest, "unsupported_protocol_version")
		return
	}
	sessionID := request.Header.Get("Mcp-Session-Id")
	if _, status, code := handler.session(sessionID, principal, origin); code != "" {
		handler.writeTransportError(response, status, code)
		return
	}
	handler.mu.Lock()
	delete(handler.sessions, sessionID)
	handler.mu.Unlock()
	response.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) session(sessionID string, principal Principal, origin string) (session, int, string) {
	if sessionID == "" {
		return session{}, http.StatusBadRequest, "session_required"
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	current, ok := handler.sessions[sessionID]
	now := handler.now().UTC()
	if !ok {
		handler.pruneExpiredLocked(now)
		return session{}, http.StatusNotFound, "session_not_found"
	}
	if !now.Before(current.ExpiresAt) {
		handler.pruneExpiredLocked(now)
		return session{}, http.StatusNotFound, "session_expired"
	}
	handler.pruneExpiredLocked(now)
	if current.Origin != origin || current.Principal.ClientID != principal.ClientID || current.Principal.Identity.TenantID != principal.Identity.TenantID || current.Principal.Identity.AgentID != principal.Identity.AgentID {
		return session{}, http.StatusForbidden, "session_identity_mismatch"
	}
	return current, 0, ""
}

func (handler *Handler) markInitialized(sessionID string) {
	handler.mu.Lock()
	current := handler.sessions[sessionID]
	current.Initialized = true
	handler.sessions[sessionID] = current
	handler.mu.Unlock()
}

func (handler *Handler) beginRequest(sessionID string, id json.RawMessage) string {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	current, ok := handler.sessions[sessionID]
	if !ok {
		return "session_not_found"
	}
	key := string(id)
	if _, exists := current.InFlight[key]; exists {
		return "duplicate_request_id"
	}
	if len(current.InFlight) >= handler.maxInFlight {
		return "request_capacity_exceeded"
	}
	current.InFlight[key] = struct{}{}
	handler.sessions[sessionID] = current
	return ""
}

func (handler *Handler) finishRequest(sessionID string, id json.RawMessage) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	current, ok := handler.sessions[sessionID]
	if !ok {
		return
	}
	delete(current.InFlight, string(id))
	handler.sessions[sessionID] = current
}

func (handler *Handler) pruneExpiredLocked(now time.Time) {
	for id, current := range handler.sessions {
		if !now.Before(current.ExpiresAt) {
			delete(handler.sessions, id)
		}
	}
}

func (handler *Handler) newSessionID() (string, error) {
	buffer := make([]byte, 32)
	if _, err := io.ReadFull(handler.random, buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (handler *Handler) writeRPCResult(response http.ResponseWriter, id json.RawMessage, result any) {
	handler.writeRPC(response, rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func (handler *Handler) writeRPCError(response http.ResponseWriter, id json.RawMessage, code int, message string, data any) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	handler.writeRPC(response, rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message, Data: data}})
}

func (handler *Handler) writeRPC(response http.ResponseWriter, value rpcResponse) {
	payload, err := json.Marshal(value)
	status := http.StatusOK
	if err != nil || len(payload) > handler.maxResultBytes {
		payload = []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"response_too_large"}}`)
		status = http.StatusInternalServerError
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(payload)
}

func (handler *Handler) writeTransportError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(rpcResponse{
		JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32000, Message: code, Data: map[string]string{"code": code}},
	})
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type submitArguments struct {
	ID                string         `json:"id"`
	Repository        string         `json:"repository"`
	Operation         string         `json:"operation"`
	Branch            string         `json:"branch,omitempty"`
	Title             string         `json:"title,omitempty"`
	Body              string         `json:"body,omitempty"`
	HeadSHA           string         `json:"head_sha,omitempty"`
	ManifestHash      string         `json:"manifest_hash,omitempty"`
	ApprovalID        string         `json:"approval_id,omitempty"`
	ApprovalNonce     string         `json:"approval_nonce,omitempty"`
	ApprovalExpiresAt time.Time      `json:"approval_expires_at,omitempty"`
	Approver          string         `json:"approver,omitempty"`
	Payload           map[string]any `json:"payload,omitempty"`
}

func (arguments submitArguments) operationRequest() brokerapp.OperationRequest {
	return brokerapp.OperationRequest{
		ID: arguments.ID, Repository: arguments.Repository, Operation: arguments.Operation, Branch: arguments.Branch,
		Title: arguments.Title, Body: arguments.Body, HeadSHA: arguments.HeadSHA, ManifestHash: arguments.ManifestHash,
		ApprovalID: arguments.ApprovalID, ApprovalNonce: arguments.ApprovalNonce, ApprovalExpiresAt: arguments.ApprovalExpiresAt,
		Approver: arguments.Approver, Payload: arguments.Payload,
	}
}

type operationIDArguments struct {
	OperationID string `json:"operation_id"`
}

var (
	errInvalidArguments               = errors.New("invalid tool arguments")
	errRepositoryScopeUnavailable     = errors.New("repository scope unavailable")
	errOperationRepositoryUnavailable = errors.New("operation repository unavailable")
)

func toolErrorCode(err error) string {
	switch {
	case errors.Is(err, errInvalidArguments):
		return "invalid_arguments"
	case errors.Is(err, ErrRepositoryDenied):
		return "repository_denied"
	case errors.Is(err, errRepositoryScopeUnavailable):
		return "repository_scope_unavailable"
	case errors.Is(err, errOperationRepositoryUnavailable):
		return "operation_repository_unavailable"
	case errors.Is(err, server.ErrDurableForbidden):
		return "operation_forbidden"
	case errors.Is(err, server.ErrDurableNotFound):
		return "operation_not_found"
	case errors.Is(err, brokerapp.ErrReconciliationUnavailable):
		return "reconciliation_unavailable"
	case errors.Is(err, brokerapp.ErrChangeDraftInvalid),
		errors.Is(err, brokerapp.ErrChangeDraftNotFound),
		errors.Is(err, brokerapp.ErrChangeDraftStaleBase),
		errors.Is(err, brokerapp.ErrChangeDraftBinding),
		errors.Is(err, brokerapp.ErrChangeDraftExpired),
		errors.Is(err, brokerapp.ErrChangeDraftTampered),
		errors.Is(err, brokerapp.ErrChangeDraftRepository):
		return changeDraftToolErrorCode(err)
	case errors.Is(err, brokerapp.ErrRepositoryReadInvalid),
		errors.Is(err, brokerapp.ErrRepositoryReadDenied),
		errors.Is(err, brokerapp.ErrRepositoryReadLimit),
		errors.Is(err, brokerapp.ErrRepositoryReadBinding),
		errors.Is(err, brokerapp.ErrRepositoryReadStaleBase),
		errors.Is(err, brokerapp.ErrRepositoryReadBackend):
		return repositoryReadToolErrorCode(err)
	case errors.Is(err, brokerapp.ErrSyncProposalInvalid),
		errors.Is(err, brokerapp.ErrSyncProposalDenied),
		errors.Is(err, brokerapp.ErrSyncProposalRebase),
		errors.Is(err, brokerapp.ErrSyncProposalExists),
		errors.Is(err, brokerapp.ErrSyncProposalRejected),
		errors.Is(err, brokerapp.ErrSyncProposalUnavailable):
		return syncProposalToolErrorCode(err)
	default:
		return "operation_failed"
	}
}

func toolCatalog(includeChangeDrafts, includeChangeDraftPublisher, includeRepositoryReads, includeSyncProposals bool) []map[string]any {
	annotations := func(readOnly, destructive bool) map[string]bool {
		return map[string]bool{"readOnlyHint": readOnly, "destructiveHint": destructive, "idempotentHint": true, "openWorldHint": true}
	}
	stringProperty := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description}
	}
	tools := []map[string]any{
		{
			"name": "repositories.list", "title": "List authorized repositories",
			"description": "List private repositories available to this GitOversight agent identity.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
			"annotations": annotations(true, false),
		},
		{
			"name": "operation.submit", "title": "Submit governed operation",
			"description": "Submit one idempotently identified GitOversight operation. The result may require approval, execution, status, or reconciliation.",
			"inputSchema": map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"id":         stringProperty("Unique request ID; reuse the same ID only to observe/reconcile the same operation."),
					"repository": stringProperty("owner/name repository key"), "operation": stringProperty("Governed operation name"),
					"branch": stringProperty("Branch when applicable"), "title": stringProperty("Reviewed title when applicable"),
					"body": stringProperty("Reviewed body when applicable"), "head_sha": stringProperty("Expected head SHA when applicable"),
					"manifest_hash": stringProperty("Manifest hash when applicable"), "approval_id": stringProperty("Approval ID when applicable"),
					"approval_nonce": stringProperty("Approval nonce when applicable"), "approval_expires_at": stringProperty("RFC3339 approval expiry"),
					"approver": stringProperty("Expected human approver"), "payload": map[string]any{"type": "object"},
				},
				"required": []string{"id", "repository", "operation"},
			},
			"annotations": annotations(false, true),
		},
		{
			"name": "operation.status", "title": "Read operation status",
			"description": "Read the durable state of an operation visible to this agent.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"operation_id": stringProperty("Operation request ID")}, "required": []string{"operation_id"}},
			"annotations": annotations(true, false),
		},
		{
			"name": "operation.reconcile", "title": "Reconcile operation outcome",
			"description": "Reconcile the same operation ID through independent reads after an indeterminate outcome. Never submit a replacement first.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"operation_id": stringProperty("Original operation request ID")}, "required": []string{"operation_id"}},
			"annotations": annotations(false, false),
		},
	}
	if includeChangeDrafts {
		changeProperties := map[string]any{
			"operation":      stringProperty("add, replace, delete, or mode"),
			"path":           stringProperty("Repository-relative path"),
			"mode":           stringProperty("100644 or 100755 when required"),
			"content_base64": stringProperty("Base64 file bytes for add or replace; omit for delete or mode"),
		}
		tools = append(tools,
			map[string]any{
				"name": "change_draft.create", "title": "Create bounded change draft",
				"description": "Build an expiring broker-side preview from bounded path changes against an exact private-repository base commit. This does not write GitHub.",
				"inputSchema": map[string]any{
					"type": "object", "additionalProperties": false,
					"properties": map[string]any{
						"repository":  stringProperty("Authorized owner/name repository key"),
						"base_commit": stringProperty("Exact current base commit SHA"),
						"changes": map[string]any{
							"type": "array", "minItems": 1,
							"items": map[string]any{"type": "object", "additionalProperties": false, "properties": changeProperties, "required": []string{"operation", "path"}},
						},
					},
					"required": []string{"repository", "base_commit", "changes"},
				},
				"annotations": map[string]bool{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true},
			},
			map[string]any{
				"name": "change_draft.inspect", "title": "Inspect bound change draft",
				"description": "Revalidate an expiring draft against its exact repository, base commit, and preview hash, returning a compact summary without file contents.",
				"inputSchema": map[string]any{
					"type": "object", "additionalProperties": false,
					"properties": map[string]any{
						"draft_id":     stringProperty("Draft ID returned by change_draft.create"),
						"repository":   stringProperty("Exact repository bound to the draft"),
						"base_commit":  stringProperty("Exact base commit bound to the draft"),
						"preview_hash": stringProperty("Exact content-addressed preview hash"),
					},
					"required": []string{"draft_id", "repository", "base_commit", "preview_hash"},
				},
				"annotations": annotations(true, false),
			},
		)
	}
	if includeChangeDraftPublisher {
		tools = append(tools, map[string]any{
			"name": "change_draft.publish", "title": "Publish governed change draft",
			"description": "Revalidate an exact broker-side draft and submit it as a governed private branch operation without transferring repository bytes through the tool call.",
			"inputSchema": map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"draft_id": stringProperty("Draft ID returned by change_draft.create"), "repository": stringProperty("Exact repository bound to the draft"),
					"base_commit": stringProperty("Exact base commit bound to the draft"), "preview_hash": stringProperty("Exact reviewed preview hash"),
					"operation_id": stringProperty("Unique governed operation ID"), "branch": stringProperty("Private target branch"), "message": stringProperty("Commit message"),
				},
				"required": []string{"draft_id", "repository", "base_commit", "preview_hash", "operation_id", "branch", "message"},
			},
			"annotations": map[string]bool{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true},
		})
	}
	if includeRepositoryReads {
		tools = appendRepositoryReadTools(tools, annotations)
	}
	if includeSyncProposals {
		tools = appendSyncProposalTool(tools)
	}
	return tools
}

func strictDecode(payload []byte, destination any) error {
	if len(payload) == 0 {
		return io.EOF
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("exactly one JSON value is required")
	}
	return nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, bool, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, false, err
	}
	return payload, int64(len(payload)) > limit, nil
}

func accepts(header, mediaType string) bool {
	for _, part := range strings.Split(header, ",") {
		parsed, _, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err == nil && (parsed == mediaType || parsed == "*/*") {
			return true
		}
	}
	return false
}
