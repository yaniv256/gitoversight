package worker

import (
	"errors"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/mutation"
	"github.com/yaniv256/gitoversight.dev/internal/server"
)

type CapabilityAuthorizer interface {
	ConsumeCapability(token, repository, operation, mutationHash string, now time.Time) (server.Capability, error)
	FinalizeCapability(token, outcome, resourceID, reason string, now time.Time) error
}

type ReconciliationAuthorizer interface {
	AuthorizeReconciliation(tenantID, requestID, repository, operation, mutationHash string, now time.Time) (server.Capability, error)
	FinalizeReconciliation(tenantID, requestID, outcome, resourceID string, now time.Time) error
}

type Executor interface {
	Execute(Request) (Result, error)
	Reconcile(Request) (Reconciliation, error)
}

const (
	ReconciliationCommitted = "committed"
	ReconciliationAbsent    = "absent"
	ReconciliationUnknown   = "unknown"
	OutcomeVerified         = "verified"
	OutcomeAbsent           = "reconciled_absent"
	OutcomeIndeterminate    = "indeterminate"
)

type Reconciliation struct {
	State      string `json:"state"`
	ResourceID string `json:"resource_id,omitempty"`
}

type Request struct {
	TenantID     string         `json:"tenant_id,omitempty"`
	Capability   string         `json:"capability"`
	RequestID    string         `json:"request_id"`
	Repository   string         `json:"repository"`
	Operation    string         `json:"operation"`
	Payload      map[string]any `json:"payload,omitempty"`
	Branch       string         `json:"branch,omitempty"`
	Title        string         `json:"title,omitempty"`
	Body         string         `json:"body,omitempty"`
	ManifestHash string         `json:"manifest_hash,omitempty"`
	ActorMode    string         `json:"actor_mode"`
	ActorSubject string         `json:"actor_subject,omitempty"`
}

func (w *Worker) Reconcile(request Request, now time.Time) (Result, error) {
	authorizer, ok := w.authorizer.(ReconciliationAuthorizer)
	if !ok || request.TenantID == "" || request.RequestID == "" || request.Repository == "" || request.Operation == "" {
		return Result{}, errors.New("later reconciliation is unavailable")
	}
	mutationHash, err := mutation.Hash(mutation.Packet{RequestID: request.RequestID, Repository: request.Repository, Operation: request.Operation, Branch: request.Branch, Title: request.Title, Body: request.Body, ManifestHash: request.ManifestHash, ActorMode: request.ActorMode, ActorSubject: request.ActorSubject, Payload: request.Payload})
	if err != nil {
		return Result{}, err
	}
	capability, err := authorizer.AuthorizeReconciliation(request.TenantID, request.RequestID, request.Repository, request.Operation, mutationHash, now)
	if err != nil {
		return Result{}, err
	}
	if capability.TenantID != request.TenantID || capability.RequestID != request.RequestID || capability.Repository != request.Repository || capability.Operation != request.Operation || capability.MutationHash != mutationHash || capability.ActorMode != request.ActorMode || capability.ActorSubject != request.ActorSubject {
		return Result{}, server.ErrCapabilityBinding
	}
	reconciliation, err := w.executor.Reconcile(request)
	if err != nil || reconciliation.State == ReconciliationUnknown {
		return Result{Indeterminate: true}, errors.Join(errors.New("later reconciliation remains indeterminate"), err)
	}
	result := Result{ResourceID: reconciliation.ResourceID}
	switch reconciliation.State {
	case ReconciliationCommitted:
		err = authorizer.FinalizeReconciliation(request.TenantID, request.RequestID, OutcomeVerified, reconciliation.ResourceID, now)
	case ReconciliationAbsent:
		err = authorizer.FinalizeReconciliation(request.TenantID, request.RequestID, OutcomeAbsent, "", now)
	default:
		err = errors.New("reconciliation state is invalid")
	}
	return result, err
}

type Result struct {
	ResourceID    string `json:"resource_id,omitempty"`
	Indeterminate bool   `json:"indeterminate,omitempty"`
	// Detail carries a human-readable reason when an operation did not land as
	// intended — e.g. the GitHub refusal message behind an `absent` state. It is
	// diagnostic only; it never changes the authorization outcome or state.
	Detail string `json:"detail,omitempty"`
}

type Worker struct {
	authorizer CapabilityAuthorizer
	executor   Executor
}

func New(authorizer CapabilityAuthorizer, executor Executor) *Worker {
	return &Worker{authorizer: authorizer, executor: executor}
}

func (w *Worker) Handle(request Request, now time.Time) (Result, error) {
	if request.Capability == "" || request.RequestID == "" || request.Repository == "" || request.Operation == "" {
		return Result{}, errors.New("worker request is incomplete")
	}
	mutationHash, err := mutation.Hash(mutation.Packet{RequestID: request.RequestID, Repository: request.Repository, Operation: request.Operation, Branch: request.Branch, Title: request.Title, Body: request.Body, ManifestHash: request.ManifestHash, ActorMode: request.ActorMode, ActorSubject: request.ActorSubject, Payload: request.Payload})
	if err != nil {
		return Result{}, err
	}
	capability, err := w.authorizer.ConsumeCapability(request.Capability, request.Repository, request.Operation, mutationHash, now)
	if err != nil {
		return Result{}, err
	}
	if (capability.TenantID != "" && capability.TenantID != request.TenantID) || capability.RequestID != request.RequestID || capability.Repository != request.Repository || capability.Operation != request.Operation || capability.ActorMode != request.ActorMode || capability.ActorSubject != request.ActorSubject {
		return Result{}, server.ErrCapabilityBinding
	}
	result, executeErr := w.executor.Execute(request)
	reconciliation, reconcileErr := w.executor.Reconcile(request)
	if reconcileErr != nil || reconciliation.State == ReconciliationUnknown {
		result.Indeterminate = true
		if executeErr != nil {
			result.Detail = executeErr.Error()
		}
		if finalizeErr := w.authorizer.FinalizeCapability(request.Capability, OutcomeIndeterminate, "", result.Detail, now); finalizeErr != nil {
			return result, finalizeErr
		}
		if reconcileErr != nil {
			return result, errors.Join(executeErr, reconcileErr)
		}
		if executeErr != nil {
			return result, executeErr
		}
		return result, errors.New("mutation outcome is indeterminate")
	}
	result.ResourceID = reconciliation.ResourceID
	if reconciliation.State == ReconciliationCommitted {
		if finalizeErr := w.authorizer.FinalizeCapability(request.Capability, OutcomeVerified, reconciliation.ResourceID, "", now); finalizeErr != nil {
			return result, finalizeErr
		}
		return result, nil
	}
	if reconciliation.State == ReconciliationAbsent {
		if executeErr == nil {
			// Execute succeeded with no error, yet the immediate read-back says
			// the object is missing. GitHub's read replicas lag their writes, so
			// this shape has recorded a SUCCESSFUL push as terminal absent (card
			// #356: the remote ref was already at the pushed sha while reconcile
			// read the old tip). One immediate read contradicting the executor's
			// own success witness is not terminal evidence — park the operation
			// indeterminate so a later re-probe decides once replicas converge.
			result.Indeterminate = true
			result.Detail = "execute succeeded but immediate reconciliation read absent; parked for re-probe"
			if finalizeErr := w.authorizer.FinalizeCapability(request.Capability, OutcomeIndeterminate, "", result.Detail, now); finalizeErr != nil {
				return result, finalizeErr
			}
			return result, errors.New("mutation outcome is indeterminate")
		}
		// Reconcile is the source of truth for STATE when Execute itself failed:
		// an object that independently is not present is honestly `absent` (a
		// transport blip where reconcile proves the mutation did not land — no
		// retry, no double-apply). But the REASON must not be lost. When Execute
		// failed with a definitive message (e.g. GitHub refused the merge:
		// "Pull Request is not mergeable", a 405/409/422), carry that text out in
		// result.Detail so the agent learns WHY instead of reading a bare, opaque
		// `absent`. State = absent (honest); Detail = the reason.
		// (Investigation: pr-operations-absent-masks-execute-error.md)
		result.Detail = executeErr.Error()
		if finalizeErr := w.authorizer.FinalizeCapability(request.Capability, OutcomeAbsent, "", result.Detail, now); finalizeErr != nil {
			return result, finalizeErr
		}
		return result, executeErr
	}
	return result, errors.New("reconciliation state is invalid")
}
