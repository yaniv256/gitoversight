package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type recordingOperationExecutor struct {
	calls int
}

type apiTestWriteGate struct{}

func (apiTestWriteGate) Verify() error                        { return nil }
func (apiTestWriteGate) Commit(context.Context, string) error { return nil }

type retryingOperationExecutor struct{ calls int }

func (executor *retryingOperationExecutor) Execute(_ context.Context, _ server.DurableIdentity, operationID string) (server.DurableResult, error) {
	executor.calls++
	result := server.DurableResult{ID: operationID, TenantID: "tenant-a", AgentID: "zara", State: server.DurableAuthorized}
	if executor.calls == 1 {
		return result, errors.New("worker delivery failed before consumption")
	}
	result.State = server.DurableVerified
	return result, nil
}

func (executor *recordingOperationExecutor) Execute(_ context.Context, _ server.DurableIdentity, operationID string) (server.DurableResult, error) {
	executor.calls++
	return server.DurableResult{ID: operationID, TenantID: "tenant-a", AgentID: "zara", State: server.DurableVerified}, nil
}

func TestOperationAPIUsesAuthenticatedContextAndScopesStatus(t *testing.T) {
	broker := operationTestBroker(t)
	executor := &recordingOperationExecutor{}
	handler := NewAuthorityHandler(broker, AuthorityHandlerConfig{MaxBodyBytes: 4096, Executor: executor})

	request := httptest.NewRequest(http.MethodPost, "/v1/operations", jsonBody(t, map[string]any{
		"id": "operation-1", "repository": "yaniv256/private", "operation": "branch.push",
		"branch": "feat/one", "manifest_hash": "manifest-1", "payload": map[string]any{"sha": "abc123", "caller": "elena"},
	}))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("submit = %d: %s", response.Code, response.Body.String())
	}
	var submitted server.DurableResult
	if err := json.Unmarshal(response.Body.Bytes(), &submitted); err != nil {
		t.Fatal(err)
	}
	if submitted.AgentID != "zara" || submitted.State != server.DurableVerified || executor.calls != 1 {
		t.Fatalf("submitted = %+v", submitted)
	}
	policyRequest := httptest.NewRequest(http.MethodGet, "/v1/policy", nil)
	policyRequest = policyRequest.WithContext(agentauth.WithIdentityForTrustedBoundary(policyRequest.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1"}))
	policyResponse := httptest.NewRecorder()
	handler.ServeHTTP(policyResponse, policyRequest)
	if policyResponse.Code != http.StatusOK {
		t.Fatalf("policy status = %d: %s", policyResponse.Code, policyResponse.Body.String())
	}
	receiptRequest := httptest.NewRequest(http.MethodGet, "/v1/operations/operation-1/receipt", nil)
	receiptRequest = receiptRequest.WithContext(agentauth.WithIdentityForTrustedBoundary(receiptRequest.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1"}))
	receiptResponse := httptest.NewRecorder()
	handler.ServeHTTP(receiptResponse, receiptRequest)
	if receiptResponse.Code != http.StatusOK {
		t.Fatalf("receipt = %d: %s", receiptResponse.Code, receiptResponse.Body.String())
	}

	statusRequest := httptest.NewRequest(http.MethodGet, "/v1/operations/operation-1", nil)
	statusRequest = statusRequest.WithContext(agentauth.WithIdentityForTrustedBoundary(statusRequest.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "elena", CredentialID: "elena-key-1"}))
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-agent status = %d, want 403", statusResponse.Code)
	}
}

func TestPolicyPromotionRequiresHumanContextAndExactPredecessor(t *testing.T) {
	broker := operationTestBroker(t)
	handler := NewAuthorityHandler(broker, AuthorityHandlerConfig{MaxBodyBytes: 16 << 10})
	current, err := broker.PolicyStatus(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	next := policy.Snapshot{
		Generation: 2,
		Agents:     map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{
			"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
		},
	}
	body := map[string]any{"tenant_id": "tenant-a", "expected_generation": current.Generation, "expected_policy_hash": current.PolicyHash, "snapshot": next}
	unauthorized := httptest.NewRequest(http.MethodPost, "/v1/policy", jsonBody(t, body))
	unauthorized.Header.Set("Content-Type", "application/json")
	unauthorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized policy promotion = %d", unauthorizedResponse.Code)
	}

	authorized := httptest.NewRequest(http.MethodPost, "/v1/policy", jsonBody(t, body))
	authorized.Header.Set("Content-Type", "application/json")
	authorized = authorized.WithContext(WithHumanApprover(authorized.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv", SessionID: "session-1"}))
	authorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizedResponse, authorized)
	if authorizedResponse.Code != http.StatusCreated {
		t.Fatalf("policy promotion = %d: %s", authorizedResponse.Code, authorizedResponse.Body.String())
	}
	status, err := broker.PolicyStatus(context.Background(), "tenant-a")
	if err != nil || status.Generation != 2 {
		t.Fatalf("policy status = %+v, err = %v", status, err)
	}
}

func TestPolicyOrchestratorMayAddPrivateOwnerWithoutHumanContext(t *testing.T) {
	broker := operationTestBroker(t)
	handler := NewAuthorityHandler(broker, AuthorityHandlerConfig{
		MaxBodyBytes: 16 << 10, PolicyOrchestrators: []string{"zara"},
	})
	currentStatus, err := broker.PolicyStatus(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	current, err := broker.PolicySnapshot(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	next := clonePolicySnapshot(t, current)
	next.Generation++
	next.Repositories["yaniv256/private"] = policy.Repository{
		Visibility: "private", Owners: []string{"zara", "elena"}, Approvers: []string{"yaniv"},
	}
	body := policyPromotionInput{
		TenantID: "tenant-a", ExpectedGeneration: currentStatus.Generation,
		ExpectedPolicyHash: currentStatus.PolicyHash, Snapshot: next,
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/policy/private-owner-additions", jsonBody(t, body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{
		TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1",
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("private owner promotion = %d: %s", response.Code, response.Body.String())
	}
	active, err := broker.PolicySnapshot(context.Background(), "tenant-a")
	if err != nil || active.Generation != 2 || !containsString(active.Repositories["yaniv256/private"].Owners, "elena") {
		t.Fatalf("active policy = %+v, err = %v", active, err)
	}
}

func TestPolicyOrchestratorMayPromoteAnyValidNextGenerationWithoutHumanContext(t *testing.T) {
	broker := operationTestBroker(t)
	handler := NewAuthorityHandler(broker, AuthorityHandlerConfig{
		MaxBodyBytes: 16 << 10, PolicyOrchestrators: []string{"zara"},
	})
	currentStatus, err := broker.PolicyStatus(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	current, err := broker.PolicySnapshot(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	next := clonePolicySnapshot(t, current)
	next.Generation++
	private := next.Repositories["yaniv256/private"]
	private.SyncsTo = "yaniv256/public"
	next.Repositories["yaniv256/private"] = private
	body := policyPromotionInput{
		TenantID: "tenant-a", ExpectedGeneration: currentStatus.Generation,
		ExpectedPolicyHash: currentStatus.PolicyHash, Snapshot: next,
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/policy/orchestrator", jsonBody(t, body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{
		TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1",
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("orchestrator policy promotion = %d: %s", response.Code, response.Body.String())
	}
	active, err := broker.PolicySnapshot(context.Background(), "tenant-a")
	if err != nil || active.Generation != 2 || active.Repositories["yaniv256/private"].SyncsTo != "yaniv256/public" {
		t.Fatalf("active policy = %+v, err = %v", active, err)
	}
}

func TestPolicyOrchestratorPromotionRejectsInvalidSnapshotAndStalePredecessor(t *testing.T) {
	broker := operationTestBroker(t)
	handler := NewAuthorityHandler(broker, AuthorityHandlerConfig{
		MaxBodyBytes: 16 << 10, PolicyOrchestrators: []string{"zara"},
	})
	currentStatus, err := broker.PolicyStatus(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	current, err := broker.PolicySnapshot(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	next := clonePolicySnapshot(t, current)
	next.Generation++
	private := next.Repositories["yaniv256/private"]
	private.SyncsTo = "*"
	next.Repositories["yaniv256/private"] = private

	for _, test := range []struct {
		name               string
		snapshot           policy.Snapshot
		expectedGeneration uint64
		expectedHash       string
		want               int
	}{
		{"invalid snapshot", next, currentStatus.Generation, currentStatus.PolicyHash, http.StatusBadRequest},
		{"stale predecessor", current, currentStatus.Generation + 1, currentStatus.PolicyHash, http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := policyPromotionInput{TenantID: "tenant-a", ExpectedGeneration: test.expectedGeneration, ExpectedPolicyHash: test.expectedHash, Snapshot: test.snapshot}
			request := httptest.NewRequest(http.MethodPost, "/v1/policy/orchestrator", jsonBody(t, body))
			request.Header.Set("Content-Type", "application/json")
			request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1"}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestPolicyOrchestratorPromotionRejectsBroaderPolicyChanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(policy.Snapshot)
	}{
		{"public owner", func(next policy.Snapshot) {
			repository := next.Repositories["yaniv256/public"]
			repository.Owners = append(repository.Owners, "elena")
			next.Repositories["yaniv256/public"] = repository
		}},
		{"private owner removal", func(next policy.Snapshot) {
			repository := next.Repositories["yaniv256/private"]
			repository.Owners = []string{"elena"}
			next.Repositories["yaniv256/private"] = repository
		}},
		{"writer addition", func(next policy.Snapshot) {
			repository := next.Repositories["yaniv256/private"]
			repository.Writers = []string{"elena"}
			next.Repositories["yaniv256/private"] = repository
		}},
		{"unregistered owner", func(next policy.Snapshot) {
			repository := next.Repositories["yaniv256/private"]
			repository.Owners = append(repository.Owners, "unknown-agent")
			next.Repositories["yaniv256/private"] = repository
		}},
		{"duplicate owner", func(next policy.Snapshot) {
			repository := next.Repositories["yaniv256/private"]
			repository.Owners = append(repository.Owners, repository.Owners[0])
			next.Repositories["yaniv256/private"] = repository
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broker := operationTestBroker(t)
			current, err := broker.PolicySnapshot(context.Background(), "tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			next := clonePolicySnapshot(t, current)
			next.Generation++
			test.mutate(next)
			if err := validatePrivateOwnerAdditions(current, next); err == nil {
				t.Fatal("broader policy change was accepted")
			}
		})
	}
}

func TestPolicyOrchestratorEndpointRejectsOrdinaryAgent(t *testing.T) {
	broker := operationTestBroker(t)
	handler := NewAuthorityHandler(broker, AuthorityHandlerConfig{
		MaxBodyBytes: 16 << 10, PolicyOrchestrators: []string{"zara"},
	})
	for _, path := range []string{"/v1/policy/private-owner-additions", "/v1/policy/orchestrator"} {
		request := httptest.NewRequest(http.MethodPost, path, jsonBody(t, map[string]any{}))
		request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{
			TenantID: "tenant-a", AgentID: "elena", CredentialID: "elena-key-1",
		}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("ordinary agent on %s = %d: %s", path, response.Code, response.Body.String())
		}
	}
}

func TestOperationAPIRequiresHumanContextForExactApproval(t *testing.T) {
	broker := operationTestBroker(t)
	executor := &recordingOperationExecutor{}
	handler := NewAuthorityHandler(broker, AuthorityHandlerConfig{MaxBodyBytes: 4096, Executor: executor})
	approvalExpiresAt := time.Now().UTC().Add(time.Hour)

	submitRequest := httptest.NewRequest(http.MethodPost, "/v1/operations", jsonBody(t, map[string]any{
		"id": "public-1", "repository": "yaniv256/public", "operation": "pull_request.create",
		"branch": "feat/public", "title": "Public change", "body": "Reviewed content",
		"manifest_hash": "manifest-public", "approval_id": "approval-public", "approval_nonce": "approval-nonce-1234",
		"approval_expires_at": approvalExpiresAt.Format(time.RFC3339Nano), "approver": "yaniv", "head_sha": "abc1234",
		"payload": map[string]any{"base": "main", "head_sha": "abc1234"},
	}))
	submitRequest.Header.Set("Content-Type", "application/json")
	submitRequest = submitRequest.WithContext(agentauth.WithIdentityForTrustedBoundary(submitRequest.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1"}))
	submitResponse := httptest.NewRecorder()
	handler.ServeHTTP(submitResponse, submitRequest)
	if submitResponse.Code != http.StatusAccepted {
		t.Fatalf("public submit = %d: %s", submitResponse.Code, submitResponse.Body.String())
	}
	var pending server.DurableResult
	if err := json.Unmarshal(submitResponse.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}

	approvalBody := map[string]any{
		"tenant_id": "tenant-a", "approval_id": "approval-public", "packet_hash": pending.PacketHash,
		"manifest_hash": "manifest-public", "head_sha": "abc1234", "nonce": "approval-nonce-1234",
		"expires_at": approvalExpiresAt.Format(time.RFC3339Nano),
	}
	unauthorized := httptest.NewRequest(http.MethodPost, "/v1/reviews/public-1/approve", jsonBody(t, approvalBody))
	unauthorized.Header.Set("Content-Type", "application/json")
	unauthorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("approval without human = %d, want 401", unauthorizedResponse.Code)
	}

	approved := httptest.NewRequest(http.MethodPost, "/v1/reviews/public-1/approve", jsonBody(t, approvalBody))
	approved.Header.Set("Content-Type", "application/json")
	approved = approved.WithContext(WithHumanApprover(approved.Context(), HumanApprover{TenantID: "tenant-a", ID: "yaniv"}))
	approvedResponse := httptest.NewRecorder()
	handler.ServeHTTP(approvedResponse, approved)
	if approvedResponse.Code != http.StatusOK {
		t.Fatalf("approval = %d: %s", approvedResponse.Code, approvedResponse.Body.String())
	}
	if executor.calls != 1 {
		t.Fatalf("execution calls = %d, want 1", executor.calls)
	}
}

func TestAuthorizedOperationHasAuthenticatedExecutionRetryRoute(t *testing.T) {
	broker := operationTestBroker(t)
	executor := &retryingOperationExecutor{}
	handler := NewAuthorityHandler(broker, AuthorityHandlerConfig{MaxBodyBytes: 4096, Executor: executor})
	identity := agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1"}

	submit := httptest.NewRequest(http.MethodPost, "/v1/operations", jsonBody(t, map[string]any{
		"id": "retry-route", "repository": "yaniv256/private", "operation": "branch.push",
		"branch": "feat/retry-route", "manifest_hash": "manifest", "payload": map[string]any{"sha": "abc123"},
	}))
	submit.Header.Set("Content-Type", "application/json")
	submit = submit.WithContext(agentauth.WithIdentityForTrustedBoundary(submit.Context(), identity))
	submitResponse := httptest.NewRecorder()
	handler.ServeHTTP(submitResponse, submit)
	if submitResponse.Code != http.StatusBadGateway {
		t.Fatalf("initial execution = %d: %s", submitResponse.Code, submitResponse.Body.String())
	}

	retry := httptest.NewRequest(http.MethodPost, "/v1/operations/retry-route/execute", nil)
	retry = retry.WithContext(agentauth.WithIdentityForTrustedBoundary(retry.Context(), identity))
	retryResponse := httptest.NewRecorder()
	handler.ServeHTTP(retryResponse, retry)
	if retryResponse.Code != http.StatusOK || executor.calls != 2 {
		t.Fatalf("retry = %d calls=%d: %s", retryResponse.Code, executor.calls, retryResponse.Body.String())
	}
}

func TestStructurallyInvalidOperationReturnsBadRequest(t *testing.T) {
	handler := NewAuthorityHandler(operationTestBroker(t), AuthorityHandlerConfig{MaxBodyBytes: 4096})
	request := httptest.NewRequest(http.MethodPost, "/v1/operations", jsonBody(t, map[string]any{
		"repository": "yaniv256/private", "operation": "branch.push", "branch": "feat/missing-id",
	}))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{
		TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1",
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid operation = %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthorizedSubmitWithoutExecutorPreservesExecutionUnavailableResponse(t *testing.T) {
	handler := NewAuthorityHandler(operationTestBroker(t), AuthorityHandlerConfig{MaxBodyBytes: 4096})
	request := httptest.NewRequest(http.MethodPost, "/v1/operations", jsonBody(t, map[string]any{
		"id": "no-executor", "repository": "yaniv256/private", "operation": "branch.push",
		"branch": "feat/no-executor", "manifest_hash": "manifest", "payload": map[string]any{"sha": "abc123"},
	}))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{
		TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1",
	}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != "execution_unavailable" {
		t.Fatalf("body=%v err=%v", body, err)
	}
}

type failingOperationExecutor struct{ err error }

func (executor failingOperationExecutor) Execute(context.Context, server.DurableIdentity, string) (server.DurableResult, error) {
	return server.DurableResult{}, executor.err
}

func TestExecuteRoutePreservesAuthorityErrorSemantics(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		status     int
		code, next string
	}{
		{"forbidden", server.ErrDurableForbidden, http.StatusForbidden, "operation_forbidden", "stop"},
		{"missing", server.ErrDurableNotFound, http.StatusNotFound, "operation_not_found", "stop"},
		{"invalid", server.ErrDurableInvalid, http.StatusBadRequest, "invalid_operation", "stop"},
		{"expired", server.ErrCapabilityExpired, http.StatusConflict, "operation_expired", "status"},
		{"state", server.ErrDurableState, http.StatusConflict, "operation_not_executable", "status"},
		{"dependency", context.DeadlineExceeded, http.StatusServiceUnavailable, "execution_unavailable", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := NewAuthorityHandler(operationTestBroker(t), AuthorityHandlerConfig{Executor: failingOperationExecutor{err: test.err}})
			request := httptest.NewRequest(http.MethodPost, "/v1/operations/op-1/execute", nil)
			request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1"}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != test.code || body["next_action"] != test.next {
				t.Fatalf("body=%v err=%v", body, err)
			}
		})
	}
}

func operationTestBroker(t *testing.T) *server.DurableBroker {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.EnsureTenant(context.Background(), "tenant-a", time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(apiTestWriteGate{})
	snapshot := policy.Snapshot{
		Generation: 1,
		Agents:     map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}, "elena": {UID: 1001, FirstName: "Elena"}},
		Repositories: map[string]policy.Repository{
			"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
			"yaniv256/public":  {Visibility: "public", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
		},
	}
	if err := broker.InstallPolicy(context.Background(), "tenant-a", snapshot); err != nil {
		t.Fatal(err)
	}
	return broker
}

func jsonBody(t *testing.T, value any) *bytes.Reader {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(payload)
}

func clonePolicySnapshot(t *testing.T, input policy.Snapshot) policy.Snapshot {
	t.Helper()
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var output policy.Snapshot
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatal(err)
	}
	return output
}

// recordingQueue captures the (kind, ref) a decision clears, so a test can pin
// WHICH entry was completed rather than merely that something was.
type recordingQueue struct{ kinds, refs []string }

func (q *recordingQueue) CompleteQueueItemForRef(_ context.Context, _, kind, ref string, _ time.Time) error {
	q.kinds = append(q.kinds, kind)
	q.refs = append(q.refs, ref)
	return nil
}

// A decided approval must leave the reviewer's queue.
//
// Observed live 2026-07-26: `u4-comment-allowed-1` reached state `verified` —
// approved and executed — while its human_queue row stayed `queued`, so it sat
// on the Now page forever with no control that would clear it. The three
// existing CompleteQueueItemForRef calls all pass kind "sync"; nothing ever
// completed an "approval". A queue that still shows finished work teaches the
// reviewer to distrust the queue, and the queue is the only place pending
// public actions are visible at all.
//
// The kind assertion is the point: passing "sync" here would clear nothing,
// silently, exactly as the shipped code did.
func TestDecidedApprovalLeavesTheHumanQueue(t *testing.T) {
	t.Parallel()
	for _, decision := range []string{"approve", "decline"} {
		queue := &recordingQueue{}
		handler := &AuthorityHandler{queue: queue}
		handler.completeQueueEntry(context.Background(), "default", "op-"+decision)

		if len(queue.refs) != 1 {
			t.Fatalf("%s: cleared %d queue entries, want exactly 1", decision, len(queue.refs))
		}
		if queue.kinds[0] != "approval" {
			t.Fatalf("%s: cleared kind %q, want \"approval\" — kind \"sync\" matches no approval row and clears nothing",
				decision, queue.kinds[0])
		}
		if queue.refs[0] != "op-"+decision {
			t.Fatalf("%s: cleared ref %q, want %q", decision, queue.refs[0], "op-"+decision)
		}
	}
}

// A handler built without a queue must not panic. The field is optional so
// every existing construction site stays valid.
func TestApprovalQueueCompletionIsOptional(t *testing.T) {
	t.Parallel()
	handler := &AuthorityHandler{}
	handler.completeQueueEntry(context.Background(), "default", "op-1")
}
