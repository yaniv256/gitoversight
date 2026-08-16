package api

import (
	"context"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

type readyWriteGate struct{}

func (readyWriteGate) Verify() error                        { return nil }
func (readyWriteGate) Commit(context.Context, string) error { return nil }

type committedExecutor struct{ calls int }

func (executor *committedExecutor) Execute(worker.Request) (worker.Result, error) {
	executor.calls++
	return worker.Result{ResourceID: "untrusted"}, nil
}

func (executor *committedExecutor) Reconcile(worker.Request) (worker.Reconciliation, error) {
	return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: "verified-pr-42"}, nil
}

type localRunner struct{ worker *worker.Worker }

func (runner localRunner) Run(request worker.Request) (worker.Result, error) {
	return runner.worker.Handle(request, time.Now().UTC())
}

func (runner localRunner) Reconcile(request worker.Request) (worker.Result, error) {
	return runner.worker.Reconcile(request, time.Now().UTC())
}

type unavailableRunner struct{}

func (unavailableRunner) Run(worker.Request) (worker.Result, error) {
	return worker.Result{}, context.DeadlineExceeded
}

func (unavailableRunner) Reconcile(worker.Request) (worker.Result, error) {
	return worker.Result{}, context.DeadlineExceeded
}

type testExecutionActivities struct {
	active map[string]int
	block  bool
}

func newTestExecutionActivities() *testExecutionActivities {
	return &testExecutionActivities{active: map[string]int{}}
}

func (activities *testExecutionActivities) BeginMaintenanceActivity(_ context.Context, kind string, _ time.Time) error {
	if activities.block {
		return context.Canceled
	}
	activities.active[kind]++
	return nil
}

func (activities *testExecutionActivities) EndMaintenanceActivity(_ context.Context, kind string, _ time.Time) error {
	activities.active[kind]--
	return nil
}

type directAuthority struct {
	broker   *server.DurableBroker
	workerID string
}

func (authority directAuthority) ConsumeCapability(token, repository, operation, mutationHash string, now time.Time) (server.Capability, error) {
	return authority.broker.ConsumeCapability(token, repository, operation, mutationHash, now)
}

func (authority directAuthority) FinalizeCapability(token, outcome, resourceID, reason string, now time.Time) error {
	return authority.broker.FinalizeCapability(token, outcome, resourceID, reason, now)
}

func (authority directAuthority) AuthorizeReconciliation(tenantID, requestID, repository, operation, mutationHash string, _ time.Time) (server.Capability, error) {
	return authority.broker.AuthorizeReconciliationForWorker(tenantID, requestID, authority.workerID, repository, operation, mutationHash)
}

func (authority directAuthority) FinalizeReconciliation(tenantID, requestID, outcome, resourceID string, now time.Time) error {
	return authority.broker.FinalizeReconciliationForWorker(tenantID, requestID, authority.workerID, outcome, resourceID, now)
}

type laterCommittedExecutor struct {
	executions      int
	reconciliations int
}

func (executor *laterCommittedExecutor) Execute(worker.Request) (worker.Result, error) {
	executor.executions++
	return worker.Result{}, context.DeadlineExceeded
}

func (executor *laterCommittedExecutor) Reconcile(worker.Request) (worker.Reconciliation, error) {
	executor.reconciliations++
	if executor.reconciliations == 1 {
		return worker.Reconciliation{State: worker.ReconciliationUnknown}, context.DeadlineExceeded
	}
	return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: "verified-later-pr-42"}, nil
}

func TestExecutionCoordinatorIssuesOneGrantAndReturnsTerminalState(t *testing.T) {
	ctx := context.Background()
	broker := operationTestBroker(t)
	broker.SetWriteGate(readyWriteGate{})
	request := server.DurableOperationRequest{ID: "execute-1", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "feat/execute", Title: "Private", Body: "Body", ManifestHash: "manifest", Payload: map[string]any{"base": "dev", "head_sha": "abc123"}}
	if _, err := broker.Submit(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request); err != nil {
		t.Fatal(err)
	}
	github := &committedExecutor{}
	activities := newTestExecutionActivities()
	coordinator := NewExecutionCoordinator(broker, localRunner{worker: worker.New(broker, github)}, ExecutionCoordinatorConfig{WorkerID: "worker-a", GrantTTL: time.Minute, ActivityStore: activities})
	result, err := coordinator.Execute(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != server.DurableVerified || result.ResourceID != "verified-pr-42" || github.calls != 1 {
		t.Fatalf("result = %+v, GitHub calls = %d", result, github.calls)
	}
	if activities.active["execution"] != 0 {
		t.Fatalf("execution activity leaked: %v", activities.active)
	}
}

func TestExecutionCoordinatorRejectsExecutionAndReconciliationWhenBarrierBlocksActivity(t *testing.T) {
	ctx := context.Background()
	broker := operationTestBroker(t)
	broker.SetWriteGate(readyWriteGate{})
	request := server.DurableOperationRequest{
		ID: "blocked-1", Repository: "yaniv256/private", Operation: "pull_request.create",
		Branch: "feat/blocked", Title: "Private", Body: "Body", ManifestHash: "manifest",
		Payload: map[string]any{"base": "dev", "head_sha": "abc123"},
	}
	identity := server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}
	if _, err := broker.Submit(ctx, identity, request); err != nil {
		t.Fatal(err)
	}
	activities := newTestExecutionActivities()
	activities.block = true
	github := &committedExecutor{}
	coordinator := NewExecutionCoordinator(
		broker, localRunner{worker: worker.New(broker, github)},
		ExecutionCoordinatorConfig{WorkerID: "worker-a", GrantTTL: time.Minute, ActivityStore: activities},
	)
	if _, err := coordinator.Execute(ctx, identity, request.ID); err == nil {
		t.Fatal("execution succeeded while activity acquisition was blocked")
	}
	if _, err := coordinator.Reconcile(ctx, identity, request.ID); err == nil {
		t.Fatal("reconciliation succeeded while activity acquisition was blocked")
	}
	if github.calls != 0 {
		t.Fatalf("privileged runner calls = %d, want 0", github.calls)
	}
}

func TestExecutionCoordinatorAllowsRetryOnlyWhenWorkerNeverConsumedGrant(t *testing.T) {
	ctx := context.Background()
	broker := operationTestBroker(t)
	broker.SetWriteGate(readyWriteGate{})
	request := server.DurableOperationRequest{ID: "retry-1", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "feat/retry", Title: "Private", Body: "Body", ManifestHash: "manifest", Payload: map[string]any{"base": "dev", "head_sha": "abc123"}}
	if _, err := broker.Submit(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request); err != nil {
		t.Fatal(err)
	}
	activities := newTestExecutionActivities()
	failed := NewExecutionCoordinator(broker, unavailableRunner{}, ExecutionCoordinatorConfig{WorkerID: "worker-a", GrantTTL: time.Minute, ActivityStore: activities})
	status, err := failed.Execute(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID)
	if err == nil || status.State != server.DurableAuthorized {
		t.Fatalf("failed delivery status = %+v, err = %v", status, err)
	}
	github := &committedExecutor{}
	retry := NewExecutionCoordinator(broker, localRunner{worker: worker.New(broker, github)}, ExecutionCoordinatorConfig{WorkerID: "worker-a", GrantTTL: time.Minute, ActivityStore: activities})
	status, err = retry.Execute(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID)
	if err != nil || status.State != server.DurableVerified || github.calls != 1 {
		t.Fatalf("retry status = %+v, calls = %d, err = %v", status, github.calls, err)
	}
}

func TestExecutionCoordinatorLaterReconcilesWithoutRepeatingMutation(t *testing.T) {
	ctx := context.Background()
	broker := operationTestBroker(t)
	broker.SetWriteGate(readyWriteGate{})
	request := server.DurableOperationRequest{ID: "later-1", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "feat/later", Title: "Private", Body: "Body", ManifestHash: "manifest", Payload: map[string]any{"base": "dev", "head_sha": "abc123"}}
	identity := server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}
	if _, err := broker.Submit(ctx, identity, request); err != nil {
		t.Fatal(err)
	}
	executor := &laterCommittedExecutor{}
	authority := directAuthority{broker: broker, workerID: "worker-a"}
	activities := newTestExecutionActivities()
	coordinator := NewExecutionCoordinator(broker, localRunner{worker: worker.New(authority, executor)}, ExecutionCoordinatorConfig{WorkerID: "worker-a", GrantTTL: time.Minute, ActivityStore: activities})
	result, err := coordinator.Execute(ctx, identity, request.ID)
	if err == nil || result.State != server.DurableIndeterminate || executor.executions != 1 {
		t.Fatalf("initial result = %+v, executions = %d, err = %v", result, executor.executions, err)
	}
	result, err = coordinator.Reconcile(ctx, identity, request.ID)
	if err != nil || result.State != server.DurableVerified || result.ResourceID != "verified-later-pr-42" || executor.executions != 1 || executor.reconciliations != 2 {
		t.Fatalf("later result = %+v, executions = %d, reconciliations = %d, err = %v", result, executor.executions, executor.reconciliations, err)
	}
	if activities.active["execution"] != 0 || activities.active["reconciliation"] != 0 {
		t.Fatalf("execution activities leaked: %v", activities.active)
	}
}
