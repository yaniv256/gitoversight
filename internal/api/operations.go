package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
)

type AuthorityHandlerConfig struct {
	MaxBodyBytes int64
	Executor     OperationExecutor
	// PolicyOrchestrators are transport-authenticated agents allowed to promote
	// any valid, compare-and-swap-bound next policy generation. This is an
	// administrative role, not a request for human review by proxy.
	PolicyOrchestrators []string
	// Queue clears an approval's queue entry once the human has decided it.
	// Optional: nil leaves the queue untouched, which is the pre-existing
	// behaviour and keeps every existing construction site valid.
	Queue QueueCompleter
}

// QueueCompleter drops a human-queue entry whose underlying record is settled.
//
// The sync paths have always called this; the approval paths never did, so an
// approved-and-executed operation sat in the reviewer's Now page forever with
// no control that would clear it. A queue that still shows finished work
// teaches the reviewer to distrust the queue — and the queue is the only place
// pending public actions are visible at all.
type QueueCompleter interface {
	CompleteQueueItemForRef(ctx context.Context, tenantID, kind, ref string, now time.Time) error
}

type OperationExecutor = brokerapp.OperationExecutor

type OperationReconciler = brokerapp.OperationReconciler

type AuthorityHandler struct {
	broker              *server.DurableBroker
	operations          *brokerapp.OperationService
	maxBodyBytes        int64
	executor            OperationExecutor
	queue               QueueCompleter
	policyOrchestrators map[string]struct{}
}

// completeQueueEntry clears the reviewer's queue entry for a decided approval.
// Best-effort by design, exactly like the sync paths: the queue is a view over
// broker records, never their source of truth, so a failure here must not fail
// a decision the human already made.
func (handler *AuthorityHandler) completeQueueEntry(ctx context.Context, tenantID, operationID string) {
	if handler.queue == nil {
		return
	}
	_ = handler.queue.CompleteQueueItemForRef(ctx, tenantID, "approval", operationID, time.Now().UTC())
}

func NewAuthorityHandler(broker *server.DurableBroker, config AuthorityHandlerConfig) *AuthorityHandler {
	limit := config.MaxBodyBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	orchestrators := make(map[string]struct{}, len(config.PolicyOrchestrators))
	for _, agentID := range config.PolicyOrchestrators {
		if agentID != "" {
			orchestrators[agentID] = struct{}{}
		}
	}
	return &AuthorityHandler{
		broker: broker, operations: brokerapp.NewOperationService(broker, config.Executor),
		maxBodyBytes: limit, executor: config.Executor, queue: config.Queue, policyOrchestrators: orchestrators,
	}
}

func (handler *AuthorityHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	path := strings.Trim(request.URL.Path, "/")
	if request.Method == http.MethodPost && path == "v1/operations" {
		handler.submit(response, request)
		return
	}
	if request.Method == http.MethodGet && path == "v1/policy" {
		handler.policyStatus(response, request)
		return
	}
	if request.Method == http.MethodPost && path == "v1/policy" {
		handler.promotePolicy(response, request)
		return
	}
	if request.Method == http.MethodPost && path == "v1/policy/private-owner-additions" {
		handler.promotePrivateOwnerAdditions(response, request)
		return
	}
	if request.Method == http.MethodPost && path == "v1/policy/orchestrator" {
		handler.promotePolicyAsOrchestrator(response, request)
		return
	}
	parts := strings.Split(path, "/")
	if request.Method == http.MethodPost && len(parts) == 4 && parts[0] == "v1" && parts[1] == "operations" && parts[2] != "" && parts[3] == "execute" {
		handler.executeOperation(response, request, parts[2])
		return
	}
	if request.Method == http.MethodPost && len(parts) == 4 && parts[0] == "v1" && parts[1] == "operations" && parts[2] != "" && parts[3] == "reconcile" {
		handler.reconcileOperation(response, request, parts[2])
		return
	}
	if request.Method == http.MethodPost && len(parts) == 4 && parts[0] == "v1" && parts[1] == "operations" && parts[2] != "" && parts[3] == "revoke" {
		handler.revoke(response, request, parts[2])
		return
	}
	if request.Method == http.MethodGet && len(parts) == 4 && parts[0] == "v1" && parts[1] == "operations" && parts[2] != "" && parts[3] == "receipt" {
		handler.receipt(response, request, parts[2])
		return
	}
	if request.Method == http.MethodGet && len(parts) == 3 && parts[0] == "v1" && parts[1] == "operations" && parts[2] != "" {
		handler.status(response, request, parts[2])
		return
	}
	if request.Method == http.MethodPost && len(parts) == 4 && parts[0] == "v1" && parts[1] == "reviews" && parts[2] != "" && parts[3] == "decline" {
		handler.declineOperation(response, request, parts[2])
		return
	}
	if request.Method == http.MethodPost && len(parts) == 4 && parts[0] == "v1" && parts[1] == "reviews" && parts[2] != "" && parts[3] == "approve" {
		handler.approveOperation(response, request, parts[2])
		return
	}
	http.NotFound(response, request)
}

func (handler *AuthorityHandler) reconcileOperation(response http.ResponseWriter, request *http.Request, operationID string) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	result, err := handler.operations.Reconcile(request.Context(), brokerapp.Identity{TenantID: identity.TenantID, AgentID: identity.AgentID}, operationID)
	if errors.Is(err, brokerapp.ErrReconciliationUnavailable) {
		writeError(response, http.StatusServiceUnavailable, "reconciliation_unavailable")
		return
	}
	if errors.Is(err, server.ErrDurableForbidden) {
		writeError(response, http.StatusForbidden, "operation_forbidden")
		return
	}
	if errors.Is(err, server.ErrDurableNotFound) {
		writeError(response, http.StatusNotFound, "operation_not_found")
		return
	}
	if err != nil {
		if result.ID != "" {
			writeJSON(response, http.StatusBadGateway, result)
			return
		}
		writeError(response, http.StatusConflict, "reconciliation_rejected")
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *AuthorityHandler) executeOperation(response http.ResponseWriter, request *http.Request, operationID string) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	handler.execute(response, request, server.DurableIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}, operationID, http.StatusOK)
}

func (handler *AuthorityHandler) policyStatus(response http.ResponseWriter, request *http.Request) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	status, err := handler.broker.PolicyStatus(request.Context(), identity.TenantID)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "policy_unavailable")
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (handler *AuthorityHandler) promotePolicy(response http.ResponseWriter, request *http.Request) {
	approver, ok := HumanApproverFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "human_authentication_required")
		return
	}
	var input struct {
		TenantID           string          `json:"tenant_id"`
		ExpectedGeneration uint64          `json:"expected_generation"`
		ExpectedPolicyHash string          `json:"expected_policy_hash"`
		Snapshot           policy.Snapshot `json:"snapshot"`
	}
	if err := handler.decode(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_policy_promotion")
		return
	}
	if input.TenantID == "" || approver.TenantID != input.TenantID {
		writeError(response, http.StatusForbidden, "policy_tenant_mismatch")
		return
	}
	if err := handler.broker.PromotePolicy(request.Context(), input.TenantID, approver.ID, input.ExpectedGeneration, input.ExpectedPolicyHash, input.Snapshot); err != nil {
		if errors.Is(err, server.ErrDurablePolicy) || errors.Is(err, server.ErrDurableInvalid) {
			writeError(response, http.StatusConflict, "policy_promotion_rejected")
			return
		}
		writeError(response, http.StatusServiceUnavailable, "authority_unavailable")
		return
	}
	status, err := handler.broker.PolicyStatus(request.Context(), input.TenantID)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "policy_unavailable")
		return
	}
	writeJSON(response, http.StatusCreated, status)
}

type policyPromotionInput struct {
	TenantID           string          `json:"tenant_id"`
	ExpectedGeneration uint64          `json:"expected_generation"`
	ExpectedPolicyHash string          `json:"expected_policy_hash"`
	Snapshot           policy.Snapshot `json:"snapshot"`
}

func (handler *AuthorityHandler) promotePolicyAsOrchestrator(response http.ResponseWriter, request *http.Request) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	if _, ok := handler.policyOrchestrators[identity.AgentID]; !ok {
		writeError(response, http.StatusForbidden, "policy_orchestrator_required")
		return
	}
	var input policyPromotionInput
	if err := handler.decode(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_policy_promotion")
		return
	}
	if input.TenantID == "" || identity.TenantID != input.TenantID {
		writeError(response, http.StatusForbidden, "policy_tenant_mismatch")
		return
	}
	if err := input.Snapshot.Validate(); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_policy_snapshot")
		return
	}
	handler.promotePolicyForActor(response, request, input, "agent:"+identity.AgentID)
}

func (handler *AuthorityHandler) promotePolicyForActor(response http.ResponseWriter, request *http.Request, input policyPromotionInput, actor string) {
	if err := handler.broker.PromotePolicy(request.Context(), input.TenantID, actor, input.ExpectedGeneration, input.ExpectedPolicyHash, input.Snapshot); err != nil {
		if errors.Is(err, server.ErrDurablePolicy) || errors.Is(err, server.ErrDurableInvalid) {
			writeError(response, http.StatusConflict, "policy_promotion_rejected")
			return
		}
		writeError(response, http.StatusServiceUnavailable, "authority_unavailable")
		return
	}
	status, err := handler.broker.PolicyStatus(request.Context(), input.TenantID)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "policy_unavailable")
		return
	}
	writeJSON(response, http.StatusCreated, status)
}

func (handler *AuthorityHandler) promotePrivateOwnerAdditions(response http.ResponseWriter, request *http.Request) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	if _, ok := handler.policyOrchestrators[identity.AgentID]; !ok {
		writeError(response, http.StatusForbidden, "policy_orchestrator_required")
		return
	}
	var input policyPromotionInput
	if err := handler.decode(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_policy_promotion")
		return
	}
	if input.TenantID == "" || identity.TenantID != input.TenantID {
		writeError(response, http.StatusForbidden, "policy_tenant_mismatch")
		return
	}
	current, err := handler.broker.PolicySnapshot(request.Context(), input.TenantID)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "policy_unavailable")
		return
	}
	if err := validatePrivateOwnerAdditions(current, input.Snapshot); err != nil {
		writeError(response, http.StatusForbidden, "private_owner_additions_only")
		return
	}
	actor := "agent:" + identity.AgentID
	if err := handler.broker.PromotePolicy(request.Context(), input.TenantID, actor, input.ExpectedGeneration, input.ExpectedPolicyHash, input.Snapshot); err != nil {
		if errors.Is(err, server.ErrDurablePolicy) || errors.Is(err, server.ErrDurableInvalid) {
			writeError(response, http.StatusConflict, "policy_promotion_rejected")
			return
		}
		writeError(response, http.StatusServiceUnavailable, "authority_unavailable")
		return
	}
	status, err := handler.broker.PolicyStatus(request.Context(), input.TenantID)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "policy_unavailable")
		return
	}
	writeJSON(response, http.StatusCreated, status)
}

func validatePrivateOwnerAdditions(current, next policy.Snapshot) error {
	if next.Generation != current.Generation+1 ||
		current.FallbackOwner != next.FallbackOwner ||
		current.FallbackPermissions != next.FallbackPermissions ||
		current.QueueCurator != next.QueueCurator ||
		!reflect.DeepEqual(current.Agents, next.Agents) ||
		!reflect.DeepEqual(current.BranchGrants, next.BranchGrants) ||
		len(current.Repositories) != len(next.Repositories) {
		return errors.New("policy contains changes outside private owner additions")
	}
	changed := false
	for name, before := range current.Repositories {
		after, ok := next.Repositories[name]
		if !ok {
			return errors.New("repository set changed")
		}
		beforeWithoutOwners, afterWithoutOwners := before, after
		beforeWithoutOwners.Owners, afterWithoutOwners.Owners = nil, nil
		if !reflect.DeepEqual(beforeWithoutOwners, afterWithoutOwners) {
			return errors.New("repository policy changed outside owners")
		}
		if reflect.DeepEqual(before.Owners, after.Owners) {
			continue
		}
		if before.Visibility != "private" || before.ProtectedPolicy {
			return errors.New("owner additions require an ordinary private repository")
		}
		for _, owner := range before.Owners {
			if !containsString(after.Owners, owner) {
				return errors.New("owner removal is not allowed")
			}
		}
		seenOwners := make(map[string]struct{}, len(after.Owners))
		added := 0
		for _, owner := range after.Owners {
			if owner == "" {
				return errors.New("owner id is required")
			}
			if _, duplicate := seenOwners[owner]; duplicate {
				return errors.New("duplicate owner is not allowed")
			}
			seenOwners[owner] = struct{}{}
			if !containsString(before.Owners, owner) {
				if _, registered := current.Agents[owner]; !registered {
					return errors.New("new owner must be a registered agent")
				}
				added++
			}
		}
		if added == 0 {
			return errors.New("at least one owner must be added")
		}
		changed = true
	}
	if !changed {
		return errors.New("no private owner addition")
	}
	return next.Validate()
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (handler *AuthorityHandler) revoke(response http.ResponseWriter, request *http.Request, operationID string) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	result, err := handler.broker.Revoke(request.Context(), server.DurableIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}, operationID)
	if errors.Is(err, server.ErrDurableForbidden) {
		writeError(response, http.StatusForbidden, "operation_forbidden")
		return
	}
	if errors.Is(err, server.ErrDurableNotFound) {
		writeError(response, http.StatusNotFound, "operation_not_found")
		return
	}
	if err != nil {
		writeError(response, http.StatusConflict, "revocation_rejected")
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *AuthorityHandler) receipt(response http.ResponseWriter, request *http.Request, operationID string) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	events, err := handler.broker.Receipt(request.Context(), server.DurableIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}, operationID)
	if errors.Is(err, server.ErrDurableForbidden) {
		writeError(response, http.StatusForbidden, "operation_forbidden")
		return
	}
	if errors.Is(err, server.ErrDurableNotFound) {
		writeError(response, http.StatusNotFound, "receipt_not_found")
		return
	}
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "authority_unavailable")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"operation_id": operationID, "events": events})
}

func (handler *AuthorityHandler) submit(response http.ResponseWriter, request *http.Request) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	var input struct {
		ID                string         `json:"id"`
		Repository        string         `json:"repository"`
		Operation         string         `json:"operation"`
		Branch            string         `json:"branch,omitempty"`
		Title             string         `json:"title,omitempty"`
		Body              string         `json:"body,omitempty"`
		HeadSHA           string         `json:"head_sha,omitempty"`
		ManifestHash      string         `json:"manifest_hash"`
		ApprovalID        string         `json:"approval_id,omitempty"`
		ApprovalNonce     string         `json:"approval_nonce,omitempty"`
		ApprovalExpiresAt time.Time      `json:"approval_expires_at,omitempty"`
		Approver          string         `json:"approver,omitempty"`
		Payload           map[string]any `json:"payload,omitempty"`
	}
	if err := handler.decode(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_operation")
		return
	}
	result, err := handler.operations.Submit(request.Context(), brokerapp.Identity{TenantID: identity.TenantID, AgentID: identity.AgentID, CredentialID: identity.CredentialID}, brokerapp.OperationRequest{
		ID: input.ID, Repository: input.Repository, Operation: input.Operation, Branch: input.Branch,
		Title: input.Title, Body: input.Body, HeadSHA: input.HeadSHA, ManifestHash: input.ManifestHash,
		ApprovalID: input.ApprovalID, ApprovalNonce: input.ApprovalNonce,
		ApprovalExpiresAt: input.ApprovalExpiresAt, Approver: input.Approver, Payload: input.Payload,
	})
	if result.Executed {
		if errors.Is(err, brokerapp.ErrExecutionUnavailable) {
			writeError(response, http.StatusServiceUnavailable, "execution_unavailable")
			return
		}
		handler.writeExecutionResult(response, result.Result, err, http.StatusCreated)
		return
	}
	if err != nil {
		if errors.Is(err, server.ErrStreamedAssetRequired) {
			writeActionError(response, http.StatusBadRequest, "streamed_asset_required", "release-asset-stage")
			return
		}
		if errors.Is(err, server.ErrDurableInvalid) {
			writeError(response, http.StatusBadRequest, "invalid_operation")
			return
		}
		writeError(response, http.StatusServiceUnavailable, "authority_unavailable")
		return
	}
	switch result.Result.State {
	case server.DurableAwaitingApproval:
		writeJSON(response, http.StatusAccepted, result.Result)
	default:
		writeJSON(response, http.StatusForbidden, result.Result)
	}
}

func (handler *AuthorityHandler) status(response http.ResponseWriter, request *http.Request, operationID string) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	result, err := handler.operations.Status(request.Context(), brokerapp.Identity{TenantID: identity.TenantID, AgentID: identity.AgentID}, operationID)
	if errors.Is(err, server.ErrDurableForbidden) {
		writeError(response, http.StatusForbidden, "operation_forbidden")
		return
	}
	if errors.Is(err, server.ErrDurableNotFound) {
		writeError(response, http.StatusNotFound, "operation_not_found")
		return
	}
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "authority_unavailable")
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *AuthorityHandler) approveOperation(response http.ResponseWriter, request *http.Request, operationID string) {
	approver, ok := HumanApproverFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "human_authentication_required")
		return
	}
	var input struct {
		TenantID     string    `json:"tenant_id"`
		ApprovalID   string    `json:"approval_id"`
		PacketHash   string    `json:"packet_hash"`
		ManifestHash string    `json:"manifest_hash"`
		HeadSHA      string    `json:"head_sha"`
		Nonce        string    `json:"nonce"`
		ExpiresAt    time.Time `json:"expires_at"`
	}
	if err := handler.decode(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_approval")
		return
	}
	if input.TenantID != approver.TenantID {
		writeError(response, http.StatusForbidden, "tenant_mismatch")
		return
	}
	result, err := handler.broker.Approve(request.Context(), server.DurableApprovalRequest{
		TenantID: input.TenantID, OperationID: operationID, ApprovalID: input.ApprovalID,
		PacketHash: input.PacketHash, ManifestHash: input.ManifestHash, HeadSHA: input.HeadSHA,
		Approver: approver.ID, Nonce: input.Nonce, ExpiresAt: input.ExpiresAt,
	})
	if err != nil {
		writeError(response, http.StatusConflict, "approval_rejected")
		return
	}
	// The human has decided, so the item leaves their queue either way — an
	// authorized operation proceeds to execute, and any other settled result is
	// equally no longer awaiting them.
	handler.completeQueueEntry(request.Context(), input.TenantID, operationID)
	if result.State == server.DurableAuthorized {
		handler.execute(response, request, server.DurableIdentity{TenantID: result.TenantID, AgentID: result.AgentID}, result.ID, http.StatusOK)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

// declineOperation lets a reviewer refuse an agent's pending public action.
//
// Deliberately NOT symmetric with approve's input: approve carries the full
// approval binding because it authorizes a specific packet, while a decline
// authorizes nothing. Requiring the binding here would let a lapsed approval
// window block refusal — see DurableBroker.Decline.
func (handler *AuthorityHandler) declineOperation(response http.ResponseWriter, request *http.Request, operationID string) {
	approver, ok := HumanApproverFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "human_authentication_required")
		return
	}
	var input struct {
		Reason string `json:"reason"`
	}
	// An empty body is a valid decline: the page's Decline button sends `{}`.
	if request.ContentLength > 0 {
		if err := handler.decode(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, "invalid_decline")
			return
		}
	}
	result, err := handler.broker.Decline(request.Context(), approver.TenantID, operationID, approver.ID, input.Reason)
	if err != nil {
		// Distinguishable causes get distinguishable codes — one opaque token
		// for several conditions is the defect this project keeps re-finding.
		switch {
		case errors.Is(err, server.ErrDurableNotFound):
			writeError(response, http.StatusNotFound, "operation_not_found")
		case errors.Is(err, server.ErrDurableForbidden):
			writeError(response, http.StatusForbidden, "not_an_approver_for_this_repository")
		case errors.Is(err, server.ErrDurableState):
			writeError(response, http.StatusConflict, "operation_not_declinable")
		default:
			writeError(response, http.StatusServiceUnavailable, "decline_unavailable")
		}
		return
	}
	// A declined operation is terminal, so it leaves the queue for the same
	// reason an approved one does.
	handler.completeQueueEntry(request.Context(), approver.TenantID, operationID)
	writeJSON(response, http.StatusOK, result)
}

func (handler *AuthorityHandler) execute(response http.ResponseWriter, request *http.Request, identity server.DurableIdentity, operationID string, successStatus int) {
	if handler.executor == nil {
		writeError(response, http.StatusServiceUnavailable, "execution_unavailable")
		return
	}
	result, err := handler.executor.Execute(request.Context(), identity, operationID)
	handler.writeExecutionResult(response, result, err, successStatus)
}

func (handler *AuthorityHandler) writeExecutionResult(response http.ResponseWriter, result server.DurableResult, err error, successStatus int) {
	if err != nil {
		if result.ID != "" {
			writeJSON(response, http.StatusBadGateway, result)
			return
		}
		switch {
		case errors.Is(err, server.ErrDurableForbidden):
			writeActionError(response, http.StatusForbidden, "operation_forbidden", "stop")
		case errors.Is(err, server.ErrDurableNotFound):
			writeActionError(response, http.StatusNotFound, "operation_not_found", "stop")
		case errors.Is(err, server.ErrDurableInvalid):
			writeActionError(response, http.StatusBadRequest, "invalid_operation", "stop")
		case errors.Is(err, server.ErrCapabilityExpired):
			writeActionError(response, http.StatusConflict, "operation_expired", "status")
		case errors.Is(err, server.ErrDurableState):
			writeActionError(response, http.StatusConflict, "operation_not_executable", "status")
		default:
			writeError(response, http.StatusServiceUnavailable, "execution_unavailable")
		}
		return
	}
	writeJSON(response, successStatus, result)
}

func writeActionError(response http.ResponseWriter, status int, code, nextAction string) {
	writeJSON(response, status, map[string]string{"error": code, "next_action": nextAction})
}

func (handler *AuthorityHandler) decode(request *http.Request, destination any) error {
	if request.Header.Get("Content-Type") != "application/json" {
		return errors.New("application/json is required")
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, handler.maxBodyBytes+1))
	if err != nil || int64(len(payload)) > handler.maxBodyBytes {
		return errors.New("request body exceeds configured limit")
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
