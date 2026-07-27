package worker_test

import (
	"errors"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

type authorizer struct {
	capability     server.Capability
	err            error
	finalized      string
	finalizeReason string
}

func (a authorizer) ConsumeCapability(string, string, string, string, time.Time) (server.Capability, error) {
	return a.capability, a.err
}

func (a *authorizer) FinalizeCapability(_ string, outcome, _ string, reason string, _ time.Time) error {
	a.finalized = outcome
	a.finalizeReason = reason
	return nil
}

type executor struct {
	called         int
	result         worker.Result
	err            error
	reconciliation worker.Reconciliation
	reconcileErr   error
}

func (e *executor) Execute(worker.Request) (worker.Result, error) {
	e.called++
	return e.result, e.err
}

func (e *executor) Reconcile(worker.Request) (worker.Reconciliation, error) {
	return e.reconciliation, e.reconcileErr
}

func TestWorkerExecutesOnlyAfterExactCapabilityConsumption(t *testing.T) {
	t.Parallel()
	exec := &executor{result: worker.Result{ResourceID: "pr-17"}, reconciliation: worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: "pr-17"}}
	auth := &authorizer{capability: server.Capability{RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create"}}
	w := worker.New(auth, exec)
	result, err := w.Handle(worker.Request{Capability: "cap", RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create"}, time.Now())
	if err != nil || result.ResourceID != "pr-17" || exec.called != 1 || auth.finalized != worker.OutcomeVerified {
		t.Fatalf("result = %#v, calls = %d, err = %v", result, exec.called, err)
	}
}

func TestSuccessfulMutationRequiresIndependentReconciliation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, state, finalized string
		wantErr                bool
	}{
		{"committed", worker.ReconciliationCommitted, worker.OutcomeVerified, false},
		// A successful execute contradicted by an immediate absent read is replica
		// lag until a later re-probe says otherwise (card #356) — indeterminate,
		// never terminal absent.
		{"absent", worker.ReconciliationAbsent, worker.OutcomeIndeterminate, true},
		{"unknown", worker.ReconciliationUnknown, worker.OutcomeIndeterminate, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec := &executor{result: worker.Result{ResourceID: "mutation-response"}, reconciliation: worker.Reconciliation{State: tc.state, ResourceID: "verified-resource"}}
			auth := &authorizer{capability: server.Capability{RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create"}}
			w := worker.New(auth, exec)
			result, err := w.Handle(worker.Request{Capability: "cap", RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create"}, time.Now())
			if (err != nil) != tc.wantErr || auth.finalized != tc.finalized {
				t.Fatalf("result = %#v, finalized = %s, err = %v", result, auth.finalized, err)
			}
			if tc.state == worker.ReconciliationCommitted && result.ResourceID != "verified-resource" {
				t.Fatalf("resource id = %q, want independently verified id", result.ResourceID)
			}
		})
	}
}

// TestExecuteErrorReasonSurvivesAbsentReconcile guards the fix for the
// pr-operations-absent-masks-execute-error incident. When Execute fails with a
// definitive GitHub refusal (e.g. "Pull Request is not mergeable") and Reconcile
// independently finds the object absent, STATE stays absent (reconcile is truth —
// the mutation provably did not land, so no retry/double-apply), but the REASON
// must survive: result.Detail carries the execute error text and Handle returns
// that error, so the agent learns WHY instead of reading a bare, opaque `absent`.
func TestExecuteErrorReasonSurvivesAbsentReconcile(t *testing.T) {
	t.Parallel()
	executeErr := errors.New("github did not merge pull request: Pull Request is not mergeable")
	exec := &executor{result: worker.Result{ResourceID: "mutation-response"}, err: executeErr, reconciliation: worker.Reconciliation{State: worker.ReconciliationAbsent}}
	auth := &authorizer{capability: server.Capability{RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.merge"}}
	w := worker.New(auth, exec)
	result, err := w.Handle(worker.Request{Capability: "cap", RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.merge"}, time.Now())
	if !errors.Is(err, executeErr) {
		t.Fatalf("err = %v, want the execute error surfaced (not masked)", err)
	}
	// State semantics preserved: absent is honest, no retry/double-apply.
	if auth.finalized != worker.OutcomeAbsent {
		t.Fatalf("finalized = %s, want %s (reconcile-as-truth preserved)", auth.finalized, worker.OutcomeAbsent)
	}
	// The reason rides out on the result...
	if result.Detail != executeErr.Error() {
		t.Fatalf("result.Detail = %q, want the execute error reason %q", result.Detail, executeErr.Error())
	}
	// ...AND is passed to finalize so it persists to the operation record and a
	// later status read surfaces it (not just the transient execute response).
	if auth.finalizeReason != executeErr.Error() {
		t.Fatalf("finalizeReason = %q, want the execute error persisted %q", auth.finalizeReason, executeErr.Error())
	}
}

// TestSuccessfulExecuteWithAbsentReadParksIndeterminate guards the fix for
// card #356: GitHub's read replicas lag their writes, so a branch.push whose
// PATCH succeeded can still read the OLD tip on the immediate reconcile GET.
// Recording that as terminal `absent` marks a successful publish as failed and
// blocks the request id forever. When Execute reported no error, an absent
// read is parked as indeterminate for a later re-probe instead.
func TestSuccessfulExecuteWithAbsentReadParksIndeterminate(t *testing.T) {
	t.Parallel()
	exec := &executor{result: worker.Result{ResourceID: "refs/heads/dev"}, reconciliation: worker.Reconciliation{State: worker.ReconciliationAbsent}}
	auth := &authorizer{capability: server.Capability{RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push"}}
	w := worker.New(auth, exec)
	result, err := w.Handle(worker.Request{Capability: "cap", RequestID: "request-1", Repository: "yaniv256/private", Operation: "branch.push"}, time.Now())
	if err == nil || auth.finalized != worker.OutcomeIndeterminate {
		t.Fatalf("finalized = %s, err = %v, want indeterminate parking", auth.finalized, err)
	}
	if !result.Indeterminate || result.Detail == "" {
		t.Fatalf("result = %#v, want indeterminate with a parked-for-re-probe detail", result)
	}
	if auth.finalizeReason != result.Detail {
		t.Fatalf("finalizeReason = %q, want persisted detail %q", auth.finalizeReason, result.Detail)
	}
}

func TestWorkerDenialProducesZeroMutation(t *testing.T) {
	t.Parallel()
	exec := &executor{}
	w := worker.New(&authorizer{err: server.ErrCapabilityConsumed}, exec)
	if _, err := w.Handle(worker.Request{Capability: "cap", RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create"}, time.Now()); err == nil {
		t.Fatal("expected denial")
	}
	if exec.called != 0 {
		t.Fatalf("executor called %d times", exec.called)
	}
}

func TestWorkerRejectsActorDifferentFromCapability(t *testing.T) {
	t.Parallel()
	exec := &executor{}
	auth := &authorizer{capability: server.Capability{
		RequestID: "request-1", Repository: "yaniv256/public", Operation: "pull_request.create",
		ActorMode: "human_user", ActorSubject: "yaniv",
	}}
	w := worker.New(auth, exec)
	_, err := w.Handle(worker.Request{
		Capability: "cap", RequestID: "request-1", Repository: "yaniv256/public", Operation: "pull_request.create",
		ActorMode: "app_installation",
	}, time.Now())
	if !errors.Is(err, server.ErrCapabilityBinding) || exec.called != 0 {
		t.Fatalf("calls = %d, err = %v", exec.called, err)
	}
}

func TestWorkerReconcilesTransportFailureWithoutRetry(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, state, finalized string
		wantErr                bool
	}{
		{"committed", worker.ReconciliationCommitted, worker.OutcomeVerified, false},
		{"absent", worker.ReconciliationAbsent, worker.OutcomeAbsent, true},
		{"unknown", worker.ReconciliationUnknown, worker.OutcomeIndeterminate, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec := &executor{err: errors.New("connection reset"), reconciliation: worker.Reconciliation{State: tc.state, ResourceID: "pr-17"}}
			auth := &authorizer{capability: server.Capability{RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create"}}
			w := worker.New(auth, exec)
			result, err := w.Handle(worker.Request{Capability: "cap", RequestID: "request-1", Repository: "yaniv256/private", Operation: "pull_request.create"}, time.Now())
			if (err != nil) != tc.wantErr || exec.called != 1 || auth.finalized != tc.finalized {
				t.Fatalf("result = %#v, calls = %d, finalized = %s, err = %v", result, exec.called, auth.finalized, err)
			}
		})
	}
}
