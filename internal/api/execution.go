package api

import (
	"context"
	"errors"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

type PrivilegedRunner interface {
	Run(worker.Request) (worker.Result, error)
	Reconcile(worker.Request) (worker.Result, error)
}

type ExecutionCoordinatorConfig struct {
	WorkerID      string
	GrantTTL      time.Duration
	ActivityStore ExecutionActivityStore
}

type ExecutionActivityStore interface {
	BeginMaintenanceActivity(context.Context, string, time.Time) error
	EndMaintenanceActivity(context.Context, string, time.Time) error
}

type ExecutionCoordinator struct {
	broker        *server.DurableBroker
	runner        PrivilegedRunner
	activityStore ExecutionActivityStore
	workerID      string
	grantTTL      time.Duration
}

func NewExecutionCoordinator(broker *server.DurableBroker, runner PrivilegedRunner, config ExecutionCoordinatorConfig) *ExecutionCoordinator {
	return &ExecutionCoordinator{
		broker: broker, runner: runner, activityStore: config.ActivityStore,
		workerID: config.WorkerID, grantTTL: config.GrantTTL,
	}
}

func (coordinator *ExecutionCoordinator) Execute(ctx context.Context, identity server.DurableIdentity, operationID string) (result server.DurableResult, resultErr error) {
	if coordinator == nil || coordinator.broker == nil || coordinator.runner == nil || coordinator.activityStore == nil ||
		coordinator.workerID == "" || coordinator.grantTTL <= 0 {
		return server.DurableResult{}, errors.New("execution coordinator is unavailable")
	}
	if err := coordinator.activityStore.BeginMaintenanceActivity(ctx, "execution", time.Now().UTC()); err != nil {
		return server.DurableResult{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr,
			coordinator.activityStore.EndMaintenanceActivity(context.Background(), "execution", time.Now().UTC()))
	}()
	packet, err := coordinator.broker.PrepareExecutionPacket(ctx, identity, operationID, coordinator.workerID, coordinator.grantTTL)
	if err != nil {
		return server.DurableResult{}, err
	}
	runResult, runErr := coordinator.runner.Run(worker.Request{
		TenantID: packet.TenantID, Capability: packet.Capability, RequestID: packet.RequestID, Repository: packet.Repository,
		Operation: packet.Operation, Payload: packet.Payload, Branch: packet.Branch, Title: packet.Title,
		Body: packet.Body, ManifestHash: packet.ManifestHash, ActorMode: packet.ActorMode,
		ActorSubject: packet.ActorSubject,
	})
	var abandonErr error
	if runErr != nil {
		abandonErr = coordinator.broker.AbandonUnconsumedExecution(ctx, packet.Capability, time.Now().UTC())
		if abandonErr == nil {
			status, statusErr := coordinator.broker.Status(ctx, identity, operationID)
			return withRunDetail(status, runResult), errors.Join(runErr, statusErr)
		}
	}
	status, statusErr := coordinator.broker.Status(ctx, identity, operationID)
	if statusErr != nil {
		return server.DurableResult{}, errors.Join(runErr, abandonErr, statusErr)
	}
	return withRunDetail(status, runResult), errors.Join(runErr, abandonErr)
}

// withRunDetail surfaces the privileged worker's diagnostic Detail (e.g. the
// GitHub refusal message behind an `absent`) into the DurableResult the agent
// reads. The broker Status is a fresh DB read that only knows the terminal STATE
// (absent), not WHY the mutation did not land — the reason lives only in the
// worker Result, which the coordinator would otherwise discard. We append it to
// Reason so an opaque `absent` becomes actionable ("... Pull Request is not
// mergeable"). Detail is diagnostic only; it never changes state or decision.
// (Investigation: pr-operations-absent-masks-execute-error.md)
func withRunDetail(status server.DurableResult, runResult worker.Result) server.DurableResult {
	if runResult.Detail == "" {
		return status
	}
	if status.Reason == "" {
		status.Reason = runResult.Detail
	} else {
		status.Reason = status.Reason + ": " + runResult.Detail
	}
	return status
}

func (coordinator *ExecutionCoordinator) Reconcile(ctx context.Context, identity server.DurableIdentity, operationID string) (result server.DurableResult, resultErr error) {
	if coordinator == nil || coordinator.broker == nil || coordinator.runner == nil || coordinator.activityStore == nil ||
		coordinator.workerID == "" {
		return server.DurableResult{}, errors.New("execution coordinator is unavailable")
	}
	if err := coordinator.activityStore.BeginMaintenanceActivity(ctx, "reconciliation", time.Now().UTC()); err != nil {
		return server.DurableResult{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr,
			coordinator.activityStore.EndMaintenanceActivity(context.Background(), "reconciliation", time.Now().UTC()))
	}()
	packet, err := coordinator.broker.ReconciliationPacket(ctx, identity, operationID)
	if err != nil {
		return server.DurableResult{}, err
	}
	_, reconcileErr := coordinator.runner.Reconcile(worker.Request{
		TenantID: packet.TenantID, RequestID: packet.RequestID, Repository: packet.Repository,
		Operation: packet.Operation, Payload: packet.Payload, Branch: packet.Branch, Title: packet.Title,
		Body: packet.Body, ManifestHash: packet.ManifestHash, ActorMode: packet.ActorMode,
		ActorSubject: packet.ActorSubject,
	})
	status, statusErr := coordinator.broker.Status(ctx, identity, operationID)
	if statusErr != nil {
		return server.DurableResult{}, errors.Join(reconcileErr, statusErr)
	}
	return status, reconcileErr
}
