package brokerapp

import (
	"context"
	"errors"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/server"
)

type authorityStub struct {
	submitIdentity server.DurableIdentity
	submitRequest  server.DurableOperationRequest
	submitResult   server.DurableResult
	submitErr      error
	statusIdentity server.DurableIdentity
	statusID       string
	statusResult   server.DurableResult
	statusErr      error
}

func (stub *authorityStub) Submit(_ context.Context, identity server.DurableIdentity, request server.DurableOperationRequest) (server.DurableResult, error) {
	stub.submitIdentity = identity
	stub.submitRequest = request
	return stub.submitResult, stub.submitErr
}

func (stub *authorityStub) Status(_ context.Context, identity server.DurableIdentity, operationID string) (server.DurableResult, error) {
	stub.statusIdentity = identity
	stub.statusID = operationID
	return stub.statusResult, stub.statusErr
}

type executorStub struct {
	executeIdentity    server.DurableIdentity
	executeOperation   string
	executeResult      server.DurableResult
	executeErr         error
	reconcileIdentity  server.DurableIdentity
	reconcileOperation string
	reconcileResult    server.DurableResult
	reconcileErr       error
}

func (stub *executorStub) Execute(_ context.Context, identity server.DurableIdentity, operationID string) (server.DurableResult, error) {
	stub.executeIdentity = identity
	stub.executeOperation = operationID
	return stub.executeResult, stub.executeErr
}

func (stub *executorStub) Reconcile(_ context.Context, identity server.DurableIdentity, operationID string) (server.DurableResult, error) {
	stub.reconcileIdentity = identity
	stub.reconcileOperation = operationID
	return stub.reconcileResult, stub.reconcileErr
}

func TestSubmitExecutesAuthorizedOperationWithCanonicalIdentity(t *testing.T) {
	authority := &authorityStub{submitResult: server.DurableResult{ID: "op-1", State: server.DurableAuthorized}}
	executor := &executorStub{executeResult: server.DurableResult{ID: "op-1", State: server.DurableVerified}}
	service := NewOperationService(authority, executor)
	identity := Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "credential-1"}
	request := OperationRequest{ID: "op-1", Repository: "yaniv256/private", Operation: "branch.push"}

	result, err := service.Submit(context.Background(), identity, request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Executed || result.Result.State != server.DurableVerified {
		t.Fatalf("result = %+v", result)
	}
	if authority.submitIdentity != (server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "credential-1"}) {
		t.Fatalf("submit identity = %+v", authority.submitIdentity)
	}
	if executor.executeIdentity != (server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}) || executor.executeOperation != "op-1" {
		t.Fatalf("execute identity=%+v operation=%q", executor.executeIdentity, executor.executeOperation)
	}
}

func TestSubmitReturnsNonAuthorizedDecisionWithoutExecution(t *testing.T) {
	for _, state := range []server.DurableState{server.DurableAwaitingApproval, server.DurableDenied} {
		t.Run(string(state), func(t *testing.T) {
			authority := &authorityStub{submitResult: server.DurableResult{ID: "op-1", State: state}}
			executor := &executorStub{}
			result, err := NewOperationService(authority, executor).Submit(context.Background(), Identity{TenantID: "tenant-a", AgentID: "zara"}, OperationRequest{ID: "op-1"})
			if err != nil || result.Executed || result.Result.State != state {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if executor.executeOperation != "" {
				t.Fatalf("unexpected execution %q", executor.executeOperation)
			}
		})
	}
}

func TestSubmitPreservesExecutionEvidenceOnError(t *testing.T) {
	wantErr := errors.New("delivery failed")
	authority := &authorityStub{submitResult: server.DurableResult{ID: "op-1", State: server.DurableAuthorized}}
	executor := &executorStub{executeResult: server.DurableResult{ID: "op-1", State: server.DurableExecuting}, executeErr: wantErr}

	result, err := NewOperationService(authority, executor).Submit(context.Background(), Identity{TenantID: "tenant-a", AgentID: "zara"}, OperationRequest{ID: "op-1"})
	if !errors.Is(err, wantErr) || !result.Executed || result.Result.ID != "op-1" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestStatusAndReconcileUseAgentScopedIdentity(t *testing.T) {
	authority := &authorityStub{statusResult: server.DurableResult{ID: "op-1", State: server.DurableExecuting}}
	executor := &executorStub{reconcileResult: server.DurableResult{ID: "op-1", State: server.DurableVerified}}
	service := NewOperationService(authority, executor)
	identity := Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "credential-1"}

	status, err := service.Status(context.Background(), identity, "op-1")
	if err != nil || status.State != server.DurableExecuting {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	reconciled, err := service.Reconcile(context.Background(), identity, "op-1")
	if err != nil || reconciled.State != server.DurableVerified {
		t.Fatalf("reconciled=%+v err=%v", reconciled, err)
	}
	want := server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}
	if authority.statusIdentity != want || executor.reconcileIdentity != want {
		t.Fatalf("status identity=%+v reconcile identity=%+v", authority.statusIdentity, executor.reconcileIdentity)
	}
}

func TestStatusPreservesAuthorityError(t *testing.T) {
	wantErr := server.ErrDurableForbidden
	authority := &authorityStub{statusErr: wantErr}

	_, err := NewOperationService(authority, nil).Status(context.Background(), Identity{TenantID: "tenant-a", AgentID: "zara"}, "op-1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err=%v", err)
	}
}

func TestReconcilePreservesResultAlongsideWorkerError(t *testing.T) {
	wantErr := errors.New("independent read unavailable")
	executor := &executorStub{
		reconcileResult: server.DurableResult{ID: "op-1", State: server.DurableIndeterminate},
		reconcileErr:    wantErr,
	}

	result, err := NewOperationService(&authorityStub{}, executor).Reconcile(context.Background(), Identity{TenantID: "tenant-a", AgentID: "zara"}, "op-1")
	if !errors.Is(err, wantErr) || result.ID != "op-1" || result.State != server.DurableIndeterminate {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestReconcileReportsUnavailableExecutor(t *testing.T) {
	service := NewOperationService(&authorityStub{}, nil)
	_, err := service.Reconcile(context.Background(), Identity{TenantID: "tenant-a", AgentID: "zara"}, "op-1")
	if !errors.Is(err, ErrReconciliationUnavailable) {
		t.Fatalf("err=%v", err)
	}
}
