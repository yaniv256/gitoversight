package mcpapp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/server"
)

type resolverStub struct {
	principals map[string]Principal
}

func (stub resolverStub) ResolveBearer(_ context.Context, token string) (Principal, error) {
	principal, ok := stub.principals[token]
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	return principal, nil
}

type scopeStub struct {
	repositories []Repository
	denied       map[string]bool
}

func (stub scopeStub) ListAuthorized(context.Context, Principal) ([]Repository, error) {
	return stub.repositories, nil
}

func (stub scopeStub) Authorize(_ context.Context, _ Principal, repository string) error {
	if stub.denied[repository] {
		return ErrRepositoryDenied
	}
	return nil
}

type operationsStub struct {
	submitIdentity    brokerapp.Identity
	submitRequest     brokerapp.OperationRequest
	submitResult      brokerapp.SubmitResult
	submitErr         error
	statusResult      server.DurableResult
	statusErr         error
	statusIdentity    brokerapp.Identity
	statusID          string
	statusStarted     chan struct{}
	statusRelease     <-chan struct{}
	reconcileResult   server.DurableResult
	reconcileErr      error
	reconcileIdentity brokerapp.Identity
	reconcileID       string
}

func (stub *operationsStub) Submit(_ context.Context, identity brokerapp.Identity, request brokerapp.OperationRequest) (brokerapp.SubmitResult, error) {
	stub.submitIdentity = identity
	stub.submitRequest = request
	return stub.submitResult, stub.submitErr
}

func (stub *operationsStub) Status(_ context.Context, identity brokerapp.Identity, operationID string) (server.DurableResult, error) {
	stub.statusIdentity = identity
	stub.statusID = operationID
	if stub.statusStarted != nil {
		close(stub.statusStarted)
	}
	if stub.statusRelease != nil {
		<-stub.statusRelease
	}
	return stub.statusResult, stub.statusErr
}

func (stub *operationsStub) Reconcile(_ context.Context, identity brokerapp.Identity, operationID string) (server.DurableResult, error) {
	stub.reconcileIdentity = identity
	stub.reconcileID = operationID
	return stub.reconcileResult, stub.reconcileErr
}

type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

func TestStreamableHTTPLifecycleAndSafeToolCatalog(t *testing.T) {
	handler := newTestHandler(t, nil)
	session := initializeSession(t, handler, "token-a", "client-a")
	premature := performRPC(t, handler, "token-a", session, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{},
	})
	if premature.Code != http.StatusOK || !strings.Contains(premature.Body.String(), "session_not_initialized") {
		t.Fatalf("premature=%d body=%s", premature.Code, premature.Body.String())
	}

	initialized := performRPC(t, handler, "token-a", session, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "method": "notifications/initialized",
	})
	if initialized.Code != http.StatusAccepted || initialized.Body.Len() != 0 {
		t.Fatalf("initialized=%d body=%q", initialized.Code, initialized.Body.String())
	}

	listed := performRPC(t, handler, "token-a", session, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": map[string]any{},
	})
	if listed.Code != http.StatusOK {
		t.Fatalf("tools/list=%d body=%s", listed.Code, listed.Body.String())
	}
	var envelope rpcEnvelope
	if err := json.Unmarshal(listed.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Tools []struct {
			Name        string          `json:"name"`
			Annotations map[string]bool `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 10 {
		t.Fatalf("tools=%v", result.Tools)
	}
	want := map[string]map[string]bool{
		"repositories.list":    {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true},
		"operation.submit":     {"readOnlyHint": false, "destructiveHint": true, "idempotentHint": true, "openWorldHint": true},
		"operation.status":     {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true},
		"operation.reconcile":  {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true},
		"change_draft.create":  {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true},
		"change_draft.inspect": {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true},
		"repository.inspect":   {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true},
		"repository.search":    {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true},
		"repository.snapshot":  {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true},
		"sync.propose":         {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true},
	}
	for _, tool := range result.Tools {
		if got := tool.Annotations; !sameBoolMap(got, want[tool.Name]) {
			t.Fatalf("annotations[%s]=%v want=%v", tool.Name, got, want[tool.Name])
		}
	}

	get := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	get.Header.Set("Origin", "https://chatgpt.com")
	get.Header.Set("Authorization", "Bearer token-a")
	get.Header.Set("Accept", "text/event-stream")
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET=%d", getResponse.Code)
	}
}

func TestOriginProtocolAndSessionBindingAreEnforced(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	handler := newTestHandler(t, func(config *Config) {
		config.Now = func() time.Time { return clock }
		config.SessionTTL = time.Minute
	})

	badOrigin := initializeRequest(t, handler, "token-a", "client-a", "https://evil.example")
	if badOrigin.Code != http.StatusForbidden || !strings.Contains(badOrigin.Body.String(), "origin_not_allowed") {
		t.Fatalf("bad origin=%d body=%s", badOrigin.Code, badOrigin.Body.String())
	}

	session := initializeSession(t, handler, "token-a", "client-a")
	wrongVersion := performRPC(t, handler, "token-a", session, "2025-03-26", map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{},
	})
	if wrongVersion.Code != http.StatusBadRequest || !strings.Contains(wrongVersion.Body.String(), "unsupported_protocol_version") {
		t.Fatalf("wrong version=%d body=%s", wrongVersion.Code, wrongVersion.Body.String())
	}

	markInitialized(t, handler, "token-a", session)
	first := performRPC(t, handler, "token-a", session, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "id": 9, "method": "ping", "params": map[string]any{},
	})
	reused := performRPC(t, handler, "token-a", session, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "id": 9, "method": "ping", "params": map[string]any{},
	})
	if first.Code != http.StatusOK || reused.Code != http.StatusOK || strings.Contains(reused.Body.String(), "duplicate_request_id") {
		t.Fatalf("first=%d reused=%d body=%s", first.Code, reused.Code, reused.Body.String())
	}

	crossClient := performRPC(t, handler, "token-b", session, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": map[string]any{},
	})
	if crossClient.Code != http.StatusForbidden || !strings.Contains(crossClient.Body.String(), "session_identity_mismatch") {
		t.Fatalf("cross client=%d body=%s", crossClient.Code, crossClient.Body.String())
	}

	clock = clock.Add(2 * time.Minute)
	expired := performRPC(t, handler, "token-a", session, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": map[string]any{},
	})
	if expired.Code != http.StatusNotFound || !strings.Contains(expired.Body.String(), "session_expired") {
		t.Fatalf("expired=%d body=%s", expired.Code, expired.Body.String())
	}
}

func TestMissingOriginRequiresExplicitServerToServerOptIn(t *testing.T) {
	strict := newTestHandler(t, nil)
	missing := initializeRequest(t, strict, "token-a", "client-a", "")
	if missing.Code != http.StatusForbidden || !strings.Contains(missing.Body.String(), "origin_required") {
		t.Fatalf("strict missing origin=%d body=%s", missing.Code, missing.Body.String())
	}

	serverToServer := newTestHandler(t, func(config *Config) { config.AllowMissingOrigin = true })
	accepted := initializeRequest(t, serverToServer, "token-a", "client-a", "")
	if accepted.Code != http.StatusOK || accepted.Header().Get("Mcp-Session-Id") == "" {
		t.Fatalf("opt-in missing origin=%d body=%s", accepted.Code, accepted.Body.String())
	}
	hostile := initializeRequest(t, serverToServer, "token-a", "client-a", "https://evil.example")
	if hostile.Code != http.StatusForbidden || !strings.Contains(hostile.Body.String(), "origin_not_allowed") {
		t.Fatalf("hostile origin=%d body=%s", hostile.Code, hostile.Body.String())
	}
}

func TestSessionCapacityPrunesExpiredSessions(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	handler := newTestHandler(t, func(config *Config) {
		config.Now = func() time.Time { return clock }
		config.SessionTTL = time.Minute
		config.MaxSessions = 1
	})
	first := initializeSession(t, handler, "token-a", "client-a")
	full := initializeRequest(t, handler, "token-a", "client-a", "https://chatgpt.com")
	if full.Code != http.StatusOK || !strings.Contains(full.Body.String(), "session_capacity_exceeded") || full.Header().Get("Mcp-Session-Id") != "" {
		t.Fatalf("capacity=%d session=%q body=%s", full.Code, full.Header().Get("Mcp-Session-Id"), full.Body.String())
	}

	clock = clock.Add(2 * time.Minute)
	afterExpiry := initializeRequest(t, handler, "token-a", "client-a", "https://chatgpt.com")
	if afterExpiry.Code != http.StatusOK || afterExpiry.Header().Get("Mcp-Session-Id") == "" || afterExpiry.Header().Get("Mcp-Session-Id") == first {
		t.Fatalf("after expiry=%d session=%q body=%s", afterExpiry.Code, afterExpiry.Header().Get("Mcp-Session-Id"), afterExpiry.Body.String())
	}
}

func TestSessionLookupPrunesOtherExpiredSessions(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	handler := newTestHandler(t, func(config *Config) {
		config.Now = func() time.Time { return clock }
		config.SessionTTL = time.Minute
		config.MaxSessions = 2
	})
	_ = initializeSession(t, handler, "token-a", "client-a")
	clock = clock.Add(45 * time.Second)
	live := initializeSession(t, handler, "token-a", "client-a")
	markInitialized(t, handler, "token-a", live)
	clock = clock.Add(30 * time.Second)
	response := performRPC(t, handler, "token-a", live, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "ping", "params": map[string]any{},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("live session=%d body=%s", response.Code, response.Body.String())
	}
	concrete := handler.(*Handler)
	concrete.mu.Lock()
	remaining := len(concrete.sessions)
	concrete.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("remaining sessions=%d, want 1", remaining)
	}
}

func TestConcurrentRequestIDsAreBoundedAndReleased(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	operations := &operationsStub{
		statusResult:  server.DurableResult{ID: "op-1", Repository: "yaniv256/allowed", State: server.DurableExecuting},
		statusStarted: started,
		statusRelease: release,
	}
	handler := newTestHandler(t, func(config *Config) {
		config.Operations = operations
		config.MaxInFlight = 1
	})
	session := initializeSession(t, handler, "token-a", "client-a")
	markInitialized(t, handler, "token-a", session)

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstDone <- callTool(t, handler, "token-a", session, 20, "operation.status", map[string]any{"operation_id": "op-1"})
	}()
	<-started
	duplicate := callTool(t, handler, "token-a", session, 20, "ping", map[string]any{})
	atCapacity := performRPC(t, handler, "token-a", session, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "id": 21, "method": "ping", "params": map[string]any{},
	})
	if !strings.Contains(duplicate.Body.String(), "duplicate_request_id") || !strings.Contains(atCapacity.Body.String(), "request_capacity_exceeded") {
		t.Fatalf("duplicate=%s capacity=%s", duplicate.Body.String(), atCapacity.Body.String())
	}
	close(release)
	if first := <-firstDone; first.Code != http.StatusOK {
		t.Fatalf("first=%d body=%s", first.Code, first.Body.String())
	}
	reused := performRPC(t, handler, "token-a", session, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "id": 20, "method": "ping", "params": map[string]any{},
	})
	if reused.Code != http.StatusOK || strings.Contains(reused.Body.String(), "duplicate_request_id") {
		t.Fatalf("sequential reuse=%d body=%s", reused.Code, reused.Body.String())
	}
}

func TestToolCallsEnforceScopeAndReturnBoundedStructuredResults(t *testing.T) {
	operations := &operationsStub{submitResult: brokerapp.SubmitResult{Result: server.DurableResult{
		ID: "op-1", Repository: "yaniv256/allowed", Operation: "branch.push", State: server.DurableVerified,
	}}, statusResult: server.DurableResult{ID: "op-1", Repository: "yaniv256/allowed", State: server.DurableExecuting}, reconcileResult: server.DurableResult{ID: "op-1", Repository: "yaniv256/allowed", State: server.DurableVerified}}
	handler := newTestHandler(t, func(config *Config) {
		config.Operations = operations
		config.Scope = scopeStub{
			repositories: []Repository{{Key: "yaniv256/allowed", Visibility: "private"}},
			denied:       map[string]bool{"yaniv256/denied": true},
		}
	})
	session := initializeSession(t, handler, "token-a", "client-a")
	markInitialized(t, handler, "token-a", session)

	denied := callTool(t, handler, "token-a", session, 2, "operation.submit", map[string]any{
		"id": "op-denied", "repository": "yaniv256/denied", "operation": "branch.push", "manifest_hash": "manifest",
	})
	if denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), `"code":"repository_denied"`) || !strings.Contains(denied.Body.String(), `"isError":true`) {
		t.Fatalf("denied=%d body=%s", denied.Code, denied.Body.String())
	}
	if operations.submitRequest.ID != "" {
		t.Fatal("denied request reached operation service")
	}

	allowed := callTool(t, handler, "token-a", session, 3, "operation.submit", map[string]any{
		"id": "op-1", "repository": "yaniv256/allowed", "operation": "branch.push", "branch": "feat/a", "manifest_hash": "manifest",
		"payload": map[string]any{"sha": "abc123"},
	})
	if allowed.Code != http.StatusOK || strings.Contains(allowed.Body.String(), `"isError":true`) || !strings.Contains(allowed.Body.String(), `"structuredContent"`) {
		t.Fatalf("allowed=%d body=%s", allowed.Code, allowed.Body.String())
	}
	if operations.submitIdentity.AgentID != "zara" || operations.submitIdentity.CredentialID != "credential-a" || operations.submitRequest.Repository != "yaniv256/allowed" {
		t.Fatalf("identity=%+v request=%+v", operations.submitIdentity, operations.submitRequest)
	}

	repositories := callTool(t, handler, "token-a", session, 4, "repositories.list", map[string]any{})
	if repositories.Code != http.StatusOK || !strings.Contains(repositories.Body.String(), "yaniv256/allowed") {
		t.Fatalf("repositories=%d body=%s", repositories.Code, repositories.Body.String())
	}
	status := callTool(t, handler, "token-a", session, 5, "operation.status", map[string]any{"operation_id": "op-1"})
	reconciled := callTool(t, handler, "token-a", session, 6, "operation.reconcile", map[string]any{"operation_id": "op-1"})
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), "executing") || reconciled.Code != http.StatusOK || !strings.Contains(reconciled.Body.String(), "verified") {
		t.Fatalf("status=%d %s reconcile=%d %s", status.Code, status.Body.String(), reconciled.Code, reconciled.Body.String())
	}
	if operations.statusID != "op-1" || operations.reconcileID != "op-1" || operations.statusIdentity.AgentID != "zara" || operations.reconcileIdentity.AgentID != "zara" {
		t.Fatalf("status identity=%+v id=%q reconcile identity=%+v id=%q", operations.statusIdentity, operations.statusID, operations.reconcileIdentity, operations.reconcileID)
	}
}

func TestBodyAndResultLimitsFailClosed(t *testing.T) {
	handler := newTestHandler(t, func(config *Config) {
		config.MaxBodyBytes = 256
		config.Scope = scopeStub{repositories: []Repository{{Key: strings.Repeat("large", 100), Visibility: "private"}}}
	})

	oversized := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(strings.Repeat("x", 257)))
	setBaseHeaders(oversized, "token-a")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, oversized)
	if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "request_too_large") {
		t.Fatalf("oversized=%d body=%s", response.Code, response.Body.String())
	}

	// Use a separate handler because initialization itself must fit the result bound.
	handler = newTestHandler(t, func(config *Config) {
		config.MaxResultBytes = 700
		config.Scope = scopeStub{repositories: []Repository{{Key: strings.Repeat("large", 200), Visibility: "private"}}}
	})
	session := initializeSession(t, handler, "token-a", "client-a")
	markInitialized(t, handler, "token-a", session)
	large := callTool(t, handler, "token-a", session, 5, "repositories.list", map[string]any{})
	if large.Code != http.StatusOK || !strings.Contains(large.Body.String(), `"code":"result_too_large"`) || !strings.Contains(large.Body.String(), `"isError":true`) {
		t.Fatalf("large=%d body=%s", large.Code, large.Body.String())
	}
}

func TestStatusAndReconcileRecheckCurrentRepositoryScope(t *testing.T) {
	operations := &operationsStub{
		statusResult:    server.DurableResult{ID: "op-1", Repository: "yaniv256/denied", State: server.DurableIndeterminate},
		reconcileResult: server.DurableResult{ID: "op-1", Repository: "yaniv256/denied", State: server.DurableVerified},
	}
	handler := newTestHandler(t, func(config *Config) {
		config.Operations = operations
		config.Scope = scopeStub{denied: map[string]bool{"yaniv256/denied": true}}
	})
	session := initializeSession(t, handler, "token-a", "client-a")
	markInitialized(t, handler, "token-a", session)

	status := callTool(t, handler, "token-a", session, 2, "operation.status", map[string]any{"operation_id": "op-1"})
	reconciled := callTool(t, handler, "token-a", session, 3, "operation.reconcile", map[string]any{"operation_id": "op-1"})
	if !strings.Contains(status.Body.String(), `"code":"repository_denied"`) || !strings.Contains(reconciled.Body.String(), `"code":"repository_denied"`) {
		t.Fatalf("status=%s reconcile=%s", status.Body.String(), reconciled.Body.String())
	}
	if operations.reconcileID != "" {
		t.Fatalf("reconcile reached operation service for denied repository: %q", operations.reconcileID)
	}
}

func newTestHandler(t *testing.T, mutate func(*Config)) http.Handler {
	t.Helper()
	config := Config{
		AllowedOrigins: []string{"https://chatgpt.com"},
		Resolver: resolverStub{principals: map[string]Principal{
			"token-a": {Identity: brokerapp.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "credential-a"}, ClientID: "client-a"},
			"token-b": {Identity: brokerapp.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "credential-b"}, ClientID: "client-b"},
		}},
		Scope:           scopeStub{},
		Operations:      &operationsStub{},
		ChangeDrafts:    &changeDraftsStub{},
		RepositoryReads: &repositoryReadsStub{},
		SyncProposals:   &syncProposalsStub{},
		SessionTTL:      5 * time.Minute,
		MaxBodyBytes:    16 << 10,
		MaxResultBytes:  16 << 10,
		ServerName:      "gitoversight-test",
		ServerVersion:   "test",
	}
	if mutate != nil {
		mutate(&config)
	}
	handler, err := NewHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func initializeSession(t *testing.T, handler http.Handler, token, clientName string) string {
	t.Helper()
	response := initializeRequest(t, handler, token, clientName, "https://chatgpt.com")
	if response.Code != http.StatusOK {
		t.Fatalf("initialize=%d body=%s", response.Code, response.Body.String())
	}
	session := response.Header().Get("Mcp-Session-Id")
	if session == "" {
		t.Fatal("missing Mcp-Session-Id")
	}
	var envelope rpcEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || !strings.Contains(string(envelope.Result), ProtocolVersion) {
		t.Fatalf("initialize body=%s err=%v", response.Body.String(), err)
	}
	return session
}

func initializeRequest(t *testing.T, handler http.Handler, token, clientName, origin string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": clientName, "version": "1.0"},
		},
	}
	payload, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(payload))
	setBaseHeaders(request, token)
	request.Header.Set("Origin", origin)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func markInitialized(t *testing.T, handler http.Handler, token, session string) {
	t.Helper()
	response := performRPC(t, handler, token, session, ProtocolVersion, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if response.Code != http.StatusAccepted {
		t.Fatalf("initialized=%d body=%s", response.Code, response.Body.String())
	}
}

func callTool(t *testing.T, handler http.Handler, token, session string, id int, name string, arguments map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	return performRPC(t, handler, token, session, ProtocolVersion, map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": name, "arguments": arguments},
	})
}

func performRPC(t *testing.T, handler http.Handler, token, session, version string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(payload))
	setBaseHeaders(request, token)
	request.Header.Set("Mcp-Session-Id", session)
	request.Header.Set("MCP-Protocol-Version", version)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func setBaseHeaders(request *http.Request, token string) {
	request.Header.Set("Origin", "https://chatgpt.com")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Content-Type", "application/json")
}

func sameBoolMap(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
