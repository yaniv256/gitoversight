package security_test

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/mutation"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

type allowingWriteGate struct{}

func (allowingWriteGate) Verify() error                        { return nil }
func (allowingWriteGate) Commit(context.Context, string) error { return nil }

type failingCommitGate struct{}

func (failingCommitGate) Verify() error { return nil }
func (failingCommitGate) Commit(context.Context, string) error {
	return context.DeadlineExceeded
}

type durableExecutor struct {
	executions atomic.Int32
	state      string
}

func (executor *durableExecutor) Execute(worker.Request) (worker.Result, error) {
	executor.executions.Add(1)
	return worker.Result{ResourceID: "untrusted-response"}, nil
}

func (executor *durableExecutor) Reconcile(worker.Request) (worker.Reconciliation, error) {
	return worker.Reconciliation{State: executor.state, ResourceID: "independently-read-resource"}, nil
}

func TestDurableWorkerConsumesOneGrantAndPersistsIndependentOutcome(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error { return tx.EnsureTenant(ctx, "tenant-a", time.Now().UTC()) }); err != nil {
		t.Fatal(err)
	}
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(allowingWriteGate{})
	snapshot := policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}, Approvers: []string{"yaniv"}}}}
	if err := broker.InstallPolicy(ctx, "tenant-a", snapshot); err != nil {
		t.Fatal(err)
	}
	operationRequest := server.DurableOperationRequest{ID: "worker-1", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "feat/worker", Title: "Private change", Body: "Body", ManifestHash: "manifest", Payload: map[string]any{"base": "dev", "head_sha": "abc123"}}
	if _, err := broker.Submit(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, operationRequest); err != nil {
		t.Fatal(err)
	}
	capability, err := broker.PrepareExecution(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, operationRequest.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := worker.Request{TenantID: "tenant-a", Capability: capability, RequestID: operationRequest.ID, Repository: operationRequest.Repository, Operation: operationRequest.Operation, Payload: operationRequest.Payload, Branch: operationRequest.Branch, Title: operationRequest.Title, Body: operationRequest.Body, ManifestHash: operationRequest.ManifestHash, ActorMode: server.ActorAppInstallation}
	executor := &durableExecutor{state: worker.ReconciliationCommitted}
	workerService := worker.New(broker, executor)
	type attempt struct {
		result worker.Result
		err    error
	}
	attempts := make(chan attempt, 2)
	for range 2 {
		go func() {
			result, handleErr := workerService.Handle(request, time.Now().UTC())
			attempts <- attempt{result: result, err: handleErr}
		}()
	}
	successes := 0
	for range 2 {
		result := <-attempts
		if result.err == nil {
			successes++
			if result.result.ResourceID != "independently-read-resource" {
				t.Fatalf("worker trusted mutation response: %+v", result.result)
			}
		}
	}
	if successes != 1 || executor.executions.Load() != 1 {
		t.Fatalf("successes = %d, executions = %d", successes, executor.executions.Load())
	}
	status, err := broker.Status(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, operationRequest.ID)
	if err != nil || status.State != server.DurableVerified || status.ResourceID != "independently-read-resource" {
		t.Fatalf("status = %+v, err = %v", status, err)
	}
	if _, err := workerService.Handle(request, time.Now().UTC()); err == nil || executor.executions.Load() != 1 {
		t.Fatalf("replay executed: executions = %d, err = %v", executor.executions.Load(), err)
	}
}

func TestDurableExecutionPacketCarriesOnlyPersistedBoundMutation(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error { return tx.EnsureTenant(ctx, "tenant-a", time.Now().UTC()) }); err != nil {
		t.Fatal(err)
	}
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(allowingWriteGate{})
	snapshot := policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}}}
	if err := broker.InstallPolicy(ctx, "tenant-a", snapshot); err != nil {
		t.Fatal(err)
	}
	request := server.DurableOperationRequest{ID: "packet-1", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "feat/packet", Title: "Private", Body: "Body", ManifestHash: "manifest", Payload: map[string]any{"base": "dev", "head_sha": "abc123"}}
	if _, err := broker.Submit(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request); err != nil {
		t.Fatal(err)
	}
	packet, err := broker.PrepareExecutionPacket(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Capability == "" || packet.RequestID != request.ID || packet.Repository != request.Repository || packet.Operation != request.Operation || packet.Branch != request.Branch || packet.Title != request.Title || packet.Body != request.Body || packet.ManifestHash != request.ManifestHash || packet.ActorMode != server.ActorAppInstallation || packet.Payload["base"] != "dev" {
		t.Fatalf("execution packet = %#v", packet)
	}
}

func TestConsumedGrantCanOnlyBeRecoveredByItsExactDeliveryAttempt(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error { return tx.EnsureTenant(ctx, "tenant-a", time.Now().UTC()) }); err != nil {
		t.Fatal(err)
	}
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(allowingWriteGate{})
	snapshot := policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}}}
	if err := broker.InstallPolicy(ctx, "tenant-a", snapshot); err != nil {
		t.Fatal(err)
	}
	request := server.DurableOperationRequest{ID: "delivery-1", Repository: "yaniv256/private", Operation: "pull_request.create", Branch: "feat/delivery", Title: "Private", Body: "Body", ManifestHash: "manifest", Payload: map[string]any{"base": "dev", "head_sha": "abc123"}}
	if _, err := broker.Submit(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request); err != nil {
		t.Fatal(err)
	}
	packet, err := broker.PrepareExecutionPacket(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	mutationHash, err := mutation.Hash(mutation.Packet{RequestID: packet.RequestID, Repository: packet.Repository, Operation: packet.Operation, Branch: packet.Branch, Title: packet.Title, Body: packet.Body, ManifestHash: packet.ManifestHash, ActorMode: packet.ActorMode, ActorSubject: packet.ActorSubject, Payload: packet.Payload})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := broker.ConsumeCapabilityForWorker(packet.Capability, "worker-a", "delivery-attempt-one", packet.Repository, packet.Operation, mutationHash, now); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ConsumeCapabilityForWorker(packet.Capability, "worker-a", "delivery-attempt-one", packet.Repository, packet.Operation, mutationHash, now); err != nil {
		t.Fatalf("same delivery attempt could not recover consumed grant: %v", err)
	}
	if _, err := broker.ConsumeCapabilityForWorker(packet.Capability, "worker-a", "delivery-attempt-two", packet.Repository, packet.Operation, mutationHash, now); err == nil {
		t.Fatal("distinct delivery attempt recovered an already consumed grant")
	}
}

func TestDurableBrokerRequiresCheckpointGateBeforeGrant(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error { return tx.EnsureTenant(ctx, "tenant-a", time.Now().UTC()) }); err != nil {
		t.Fatal(err)
	}
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(allowingWriteGate{})
	snapshot := policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}}}
	if err := broker.InstallPolicy(ctx, "tenant-a", snapshot); err != nil {
		t.Fatal(err)
	}
	request := server.DurableOperationRequest{ID: "gated-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feat/gated", ManifestHash: "manifest", Payload: map[string]any{"sha": "abc123"}}
	if _, err := broker.Submit(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request); err != nil {
		t.Fatal(err)
	}
	broker.SetWriteGate(nil)
	if _, err := broker.PrepareExecution(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID, "worker-a", time.Minute); err == nil {
		t.Fatal("execution grant issued without checkpoint gate")
	}
}

func TestCheckpointFailureBeforeCapabilityDeliveryRollsOperationBackForRetry(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(allowingWriteGate{})
	if err := broker.InstallPolicy(ctx, "tenant-a", policy.Snapshot{
		Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}},
	}); err != nil {
		t.Fatal(err)
	}
	identity := server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}
	request := server.DurableOperationRequest{ID: "checkpoint-retry", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feat/checkpoint", ManifestHash: "manifest", Payload: map[string]any{"sha": "abc123"}}
	if _, err := broker.Submit(ctx, identity, request); err != nil {
		t.Fatal(err)
	}
	packet, err := broker.PrepareExecutionPacket(ctx, identity, request.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	workerRequest := worker.Request{
		TenantID: packet.TenantID, Capability: packet.Capability, RequestID: packet.RequestID, Repository: packet.Repository,
		Operation: packet.Operation, Payload: packet.Payload, Branch: packet.Branch, Title: packet.Title,
		Body: packet.Body, ManifestHash: packet.ManifestHash, ActorMode: packet.ActorMode, ActorSubject: packet.ActorSubject,
	}
	executor := &durableExecutor{state: worker.ReconciliationCommitted}
	broker.SetWriteGate(failingCommitGate{})
	if _, err := worker.New(broker, executor).Handle(workerRequest, time.Now().UTC()); err == nil {
		t.Fatal("capability was delivered despite checkpoint failure")
	}
	if executor.executions.Load() != 0 {
		t.Fatalf("GitHub mutation ran before checkpoint commit: %d", executor.executions.Load())
	}
	status, err := broker.Status(ctx, identity, request.ID)
	if err != nil || status.State != server.DurableAuthorized {
		t.Fatalf("status after rollback = %+v, err = %v", status, err)
	}

	broker.SetWriteGate(allowingWriteGate{})
	retry, err := broker.PrepareExecutionPacket(ctx, identity, request.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	workerRequest.Capability = retry.Capability
	if _, err := worker.New(broker, executor).Handle(workerRequest, time.Now().UTC()); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
	if executor.executions.Load() != 1 {
		t.Fatalf("retry executions = %d", executor.executions.Load())
	}
}

func TestStartupRecoveryMarksInterruptedMutationIndeterminateWithoutRetry(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(allowingWriteGate{})
	if err := broker.InstallPolicy(ctx, "tenant-a", policy.Snapshot{
		Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}},
	}); err != nil {
		t.Fatal(err)
	}
	identity := server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}
	request := server.DurableOperationRequest{ID: "interrupted-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feat/interrupted", ManifestHash: "manifest", Payload: map[string]any{"sha": "abc123"}}
	if _, err := broker.Submit(ctx, identity, request); err != nil {
		t.Fatal(err)
	}
	packet, err := broker.PrepareExecutionPacket(ctx, identity, request.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	mutationHash, err := mutation.Hash(mutation.Packet{RequestID: packet.RequestID, Repository: packet.Repository, Operation: packet.Operation, Branch: packet.Branch, ManifestHash: packet.ManifestHash, ActorMode: packet.ActorMode, Payload: packet.Payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ConsumeCapabilityForWorker(packet.Capability, "worker-a", "delivery-crashed", packet.Repository, packet.Operation, mutationHash, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if recovered, err := broker.RecoverInterruptedExecutions(ctx, "tenant-a"); err != nil || recovered != 1 {
		t.Fatalf("recovered=%d err=%v", recovered, err)
	}
	status, err := broker.Status(ctx, identity, request.ID)
	if err != nil || status.State != server.DurableIndeterminate || status.ResourceID != "" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if recovered, err := broker.RecoverInterruptedExecutions(ctx, "tenant-a"); err != nil || recovered != 0 {
		t.Fatalf("second recovery=%d err=%v", recovered, err)
	}
}
