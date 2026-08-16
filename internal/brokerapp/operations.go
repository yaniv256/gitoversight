// Package brokerapp exposes adapter-neutral application services over the
// durable broker. HTTP and MCP adapters should translate their wire formats at
// the edge and share these operation semantics.
package brokerapp

import (
	"context"
	"errors"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/server"
)

var (
	ErrExecutionUnavailable      = errors.New("operation execution unavailable")
	ErrReconciliationUnavailable = errors.New("operation reconciliation unavailable")
)

// Identity is the authenticated agent context supplied by a protocol adapter.
// CredentialID participates in submission audit attribution but is
// intentionally omitted from execution, status, and reconciliation identity.
type Identity struct {
	TenantID     string
	AgentID      string
	CredentialID string
}

// OperationRequest is the canonical application input for a governed
// operation. It deliberately carries no HTTP- or MCP-specific fields.
type OperationRequest struct {
	ID                string
	Repository        string
	Operation         string
	Branch            string
	Title             string
	Body              string
	HeadSHA           string
	ManifestHash      string
	ApprovalID        string
	ApprovalNonce     string
	ApprovalExpiresAt time.Time
	Approver          string
	Payload           map[string]any
}

// SubmitResult records whether submission advanced immediately into worker
// execution. Adapters use Executed to preserve their transport-specific success
// status while returning the durable result unchanged.
type SubmitResult struct {
	Result   server.DurableResult
	Executed bool
}

type Authority interface {
	Submit(context.Context, server.DurableIdentity, server.DurableOperationRequest) (server.DurableResult, error)
	Status(context.Context, server.DurableIdentity, string) (server.DurableResult, error)
}

type OperationExecutor interface {
	Execute(context.Context, server.DurableIdentity, string) (server.DurableResult, error)
}

type OperationReconciler interface {
	Reconcile(context.Context, server.DurableIdentity, string) (server.DurableResult, error)
}

type OperationService struct {
	authority Authority
	executor  OperationExecutor
}

func NewOperationService(authority Authority, executor OperationExecutor) *OperationService {
	return &OperationService{authority: authority, executor: executor}
}

func (service *OperationService) Submit(ctx context.Context, identity Identity, request OperationRequest) (SubmitResult, error) {
	result, err := service.authority.Submit(ctx, submitIdentity(identity), server.DurableOperationRequest{
		ID: request.ID, Repository: request.Repository, Operation: request.Operation, Branch: request.Branch,
		Title: request.Title, Body: request.Body, HeadSHA: request.HeadSHA, ManifestHash: request.ManifestHash,
		ApprovalID: request.ApprovalID, ApprovalNonce: request.ApprovalNonce,
		ApprovalExpiresAt: request.ApprovalExpiresAt, Approver: request.Approver, Payload: request.Payload,
	})
	if err != nil || result.State != server.DurableAuthorized {
		return SubmitResult{Result: result}, err
	}
	if service.executor == nil {
		return SubmitResult{Result: result, Executed: true}, ErrExecutionUnavailable
	}
	executed, err := service.executor.Execute(ctx, scopedIdentity(identity), result.ID)
	return SubmitResult{Result: executed, Executed: true}, err
}

func (service *OperationService) Status(ctx context.Context, identity Identity, operationID string) (server.DurableResult, error) {
	return service.authority.Status(ctx, scopedIdentity(identity), operationID)
}

func (service *OperationService) Reconcile(ctx context.Context, identity Identity, operationID string) (server.DurableResult, error) {
	reconciler, ok := service.executor.(OperationReconciler)
	if !ok {
		return server.DurableResult{}, ErrReconciliationUnavailable
	}
	return reconciler.Reconcile(ctx, scopedIdentity(identity), operationID)
}

func submitIdentity(identity Identity) server.DurableIdentity {
	return server.DurableIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID, CredentialID: identity.CredentialID}
}

func scopedIdentity(identity Identity) server.DurableIdentity {
	return server.DurableIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}
