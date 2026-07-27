package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/approval"
	"github.com/yaniv256/gitoversight.dev/internal/audit"
	"github.com/yaniv256/gitoversight.dev/internal/gitref"
	"github.com/yaniv256/gitoversight.dev/internal/mutation"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

const (
	ReplayDenied         policy.Code = "request_replay_denied"
	ApprovalConflict     policy.Code = "approval_expectation_conflict"
	AllowedByApproval    policy.Code = "allowed_exact_approval"
	AuditUnavailable     policy.Code = "audit_unavailable"
	ActorAppInstallation             = "app_installation"
	ActorHumanUser                   = "human_user"
)

var (
	ErrCapabilityNotFound  = errors.New("capability not found")
	ErrCapabilityConsumed  = errors.New("capability already consumed")
	ErrCapabilityExpired   = errors.New("capability expired")
	ErrCapabilityBinding   = errors.New("capability binding mismatch")
	ErrCapabilityRevoked   = errors.New("capability revoked")
	ErrCapabilityForbidden = errors.New("capability is not owned by caller")
	ErrAuditUnavailable    = errors.New("audit journal unavailable")
	ErrReceiptForbidden    = errors.New("receipt is not visible to caller")
	ErrApprovalExpectation = errors.New("approval expectation rejected")
	ErrOAuthBegin          = errors.New("oauth begin rejected")
)

type recorder interface {
	Append(audit.Event) (audit.Event, error)
}

type historyReader interface{ Events() ([]audit.Event, error) }
type receiptReader interface {
	ReadFor(string) ([]audit.Event, error)
}
type journalVerifier interface{ Verify() error }

type MutationRequest struct {
	RequestID   string
	CallerClaim string
	Repository  string
	Operation   string
	Branch      string
	Title       string
	Body        string
	ApprovalID  string
	Payload     map[string]any
}

type Authorization struct {
	Code         policy.Code `json:"code"`
	Caller       string      `json:"caller"`
	Reason       string      `json:"reason"`
	Capability   string      `json:"capability,omitempty"`
	ExpiresAt    time.Time   `json:"expires_at,omitempty"`
	ActorMode    string      `json:"-"`
	ActorSubject string      `json:"-"`
}

type Capability struct {
	TenantID     string
	RequestID    string
	Caller       string
	Repository   string
	Operation    string
	ExpiresAt    time.Time
	Consumed     bool
	Revoked      bool
	MutationHash string
	ApprovalID   string
	ActorMode    string
	ActorSubject string
}

func (b *Broker) RevokeCapability(authenticatedCaller, token string, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	capability, ok := b.capabilities[token]
	if !ok {
		return ErrCapabilityNotFound
	}
	if capability.Caller != authenticatedCaller {
		return ErrCapabilityForbidden
	}
	if capability.Consumed {
		return ErrCapabilityConsumed
	}
	if capability.Revoked {
		return ErrCapabilityRevoked
	}
	if capability.ApprovalID != "" {
		if err := b.approvals.Release(capability.ApprovalID, capability.RequestID); err != nil {
			return err
		}
	}
	capability.Revoked = true
	b.capabilities[token] = capability
	return b.record(capability.RequestID, "revoked", "capability_revoked", now)
}

func (b *Broker) PrepareApproval(authenticatedCaller string, request MutationRequest, requestID, manifestHash, approvalID, approver, head string, expiresAt, now time.Time) (approval.Packet, error) {
	originalBranch := request.Branch
	request.Branch = gitref.BranchName(request.Branch)
	if originalBranch != "" && request.Branch == "" {
		return approval.Packet{}, ErrApprovalExpectation
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if requestID == "" || request.RequestID != requestID || manifestHash == "" || approvalID == "" || approver == "" || head == "" || !expiresAt.After(now) || expiresAt.After(now.Add(24*time.Hour)) {
		return approval.Packet{}, ErrApprovalExpectation
	}
	if _, used := b.requests[requestID]; used {
		return approval.Packet{}, ErrApprovalExpectation
	}
	repository, ok := b.policy.Repositories[request.Repository]
	if !ok || !containsString(repository.Approvers, approver) {
		return approval.Packet{}, ErrApprovalExpectation
	}
	decision := policy.Evaluate(b.policy, policy.Request{Caller: authenticatedCaller, Repository: request.Repository, Operation: request.Operation, Branch: request.Branch, Title: request.Title, Body: request.Body, Payload: request.Payload})
	if decision.Code != policy.ApprovalRequired || !policy.Executable(request.Operation) {
		return approval.Packet{}, ErrApprovalExpectation
	}
	nonce, err := randomToken()
	if err != nil {
		return approval.Packet{}, ErrApprovalExpectation
	}
	b.requests[requestID] = struct{}{}
	b.requestOwners[requestID] = authenticatedCaller
	if err := b.record(requestID, "approval_expected", "exact_human_approval_required", now); err != nil {
		return approval.Packet{}, ErrAuditUnavailable
	}
	return approval.Packet{ID: approvalID, ManifestHash: manifestHash, Repository: request.Repository, Operations: []string{request.Operation}, Approver: approver, Nonce: nonce, ExpiresAt: expiresAt, PolicyGeneration: b.policy.Generation}, nil
}

func (b *Broker) BeginOAuth(authenticatedCaller, requestID, repositoryName, approver string, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if requestID == "" || authenticatedCaller == "" || repositoryName == "" || approver == "" {
		return ErrOAuthBegin
	}
	if _, registered := b.policy.Agents[authenticatedCaller]; !registered {
		return ErrOAuthBegin
	}
	if _, used := b.requests[requestID]; used {
		return ErrOAuthBegin
	}
	b.requests[requestID] = struct{}{}
	b.requestOwners[requestID] = authenticatedCaller
	repository, ok := b.policy.Repositories[repositoryName]
	if !ok || !containsString(repository.Approvers, approver) {
		_ = b.record(requestID, "denied", "oauth_approver_forbidden", now)
		return ErrOAuthBegin
	}
	if err := b.record(requestID, "oauth_requested", "exact_human_oauth_requested", now); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

type Broker struct {
	mu            sync.Mutex
	policy        policy.Snapshot
	approvals     *approval.Store
	journal       recorder
	capabilityTTL time.Duration
	requests      map[string]struct{}
	requestOwners map[string]string
	capabilities  map[string]Capability
	humanLogins   map[string]string
}

// SetHumanLogins installs the enrolled-human map (governance human id ->
// GitHub login); see DurableBroker.SetHumanLogins.
func (b *Broker) SetHumanLogins(logins map[string]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.humanLogins = logins
}

func New(snapshot policy.Snapshot, approvals *approval.Store, journal recorder, capabilityTTL time.Duration) *Broker {
	broker := &Broker{policy: snapshot, approvals: approvals, journal: journal, capabilityTTL: capabilityTTL, requests: make(map[string]struct{}), requestOwners: make(map[string]string), capabilities: make(map[string]Capability)}
	if reader, ok := journal.(historyReader); ok {
		if events, err := reader.Events(); err == nil {
			for _, event := range events {
				broker.requests[event.RequestID] = struct{}{}
				if event.Caller != "" {
					broker.requestOwners[event.RequestID] = event.Caller
				}
			}
		}
	}
	return broker
}

func (b *Broker) Authorize(authenticatedCaller string, request MutationRequest, manifestHash string, now time.Time) Authorization {
	originalBranch := request.Branch
	request.Branch = gitref.BranchName(request.Branch)
	b.mu.Lock()
	defer b.mu.Unlock()
	if request.RequestID == "" {
		return Authorization{Code: ReplayDenied, Caller: authenticatedCaller, Reason: "request_id is required"}
	}
	if originalBranch != "" && request.Branch == "" {
		return Authorization{Code: policy.OperationUnknown, Caller: authenticatedCaller, Reason: "branch ref is invalid"}
	}
	if _, used := b.requests[request.RequestID]; used {
		if err := b.record(request.RequestID, "denied", string(ReplayDenied), now); err != nil {
			return Authorization{Code: AuditUnavailable, Caller: authenticatedCaller, Reason: ErrAuditUnavailable.Error()}
		}
		return Authorization{Code: ReplayDenied, Caller: authenticatedCaller, Reason: "request_id was already used"}
	}
	b.requests[request.RequestID] = struct{}{}
	b.requestOwners[request.RequestID] = authenticatedCaller
	if err := b.record(request.RequestID, "requested", "request_received", now); err != nil {
		return Authorization{Code: AuditUnavailable, Caller: authenticatedCaller, Reason: ErrAuditUnavailable.Error()}
	}

	decision := policy.Evaluate(b.policy, policy.Request{Caller: authenticatedCaller, Repository: request.Repository, Operation: request.Operation, Branch: request.Branch, Title: request.Title, Body: request.Body, Payload: request.Payload})
	if !policy.Executable(request.Operation) {
		decision = policy.Decision{Code: policy.OperationUnknown, Reason: "operation has no complete privileged adapter"}
	}
	actorMode, actorSubject := ActorAppInstallation, ""
	if decision.Code == policy.ApprovalRequired && request.ApprovalID != "" {
		repository := b.policy.Repositories[request.Repository]
		if packet, err := b.approvals.ReservePacket(request.ApprovalID, request.RequestID, manifestHash, request.Repository, request.Operation, b.policy.Generation, repository.Approvers, now); err == nil {
			decision = policy.Decision{Code: AllowedByApproval, Reason: "exact single-use approval reserved"}
			if repository.Visibility == "public" {
				actorMode, actorSubject = ActorHumanUser, packet.Approver
			}
		} else {
			decision.Reason = err.Error()
		}
	}
	if !allowed(decision.Code) {
		if err := b.record(request.RequestID, "denied", string(decision.Code), now); err != nil {
			return Authorization{Code: AuditUnavailable, Caller: authenticatedCaller, Reason: ErrAuditUnavailable.Error()}
		}
		return Authorization{Code: decision.Code, Caller: authenticatedCaller, Reason: decision.Reason}
	}

	// GitHub only lets a USER token create a user-owned repository, so an allowed
	// repository.create executes as the enrolled human whose GitHub login owns
	// the target namespace (mirrors the durable submit path). The approval path
	// above already set an exact human actor when one was reserved; keep it.
	if request.Operation == "repository.create" && actorMode != ActorHumanUser {
		humanID, ok := humanForRepositoryOwner(b.humanLogins, request.Repository)
		if !ok {
			_ = b.record(request.RequestID, "denied", "namespace_owner_not_enrolled", now)
			return Authorization{Code: policy.ApprovalRequired, Caller: authenticatedCaller, Reason: "no enrolled human owns the target namespace"}
		}
		actorMode, actorSubject = ActorHumanUser, humanID
	}

	if repository, ok := b.policy.Repositories[request.Repository]; ok && repository.Visibility == "public" && (actorMode != ActorHumanUser || actorSubject == "") {
		_ = b.record(request.RequestID, "denied", "public_human_actor_required", now)
		return Authorization{Code: policy.ApprovalRequired, Caller: authenticatedCaller, Reason: "public mutation requires exact approving human actor"}
	}
	mutationHash, err := mutation.Hash(mutation.Packet{RequestID: request.RequestID, Repository: request.Repository, Operation: request.Operation, Branch: request.Branch, Title: request.Title, Body: request.Body, ManifestHash: manifestHash, ActorMode: actorMode, ActorSubject: actorSubject, Payload: request.Payload})
	if err != nil {
		_ = b.record(request.RequestID, "denied", "mutation_binding_failed", now)
		return Authorization{Code: policy.ApprovalRequired, Caller: authenticatedCaller, Reason: "mutation binding failed"}
	}
	token, err := randomToken()
	if err != nil {
		_ = b.record(request.RequestID, "denied", "capability_generation_failed", now)
		return Authorization{Code: policy.ApprovalRequired, Caller: authenticatedCaller, Reason: "capability generation failed"}
	}
	expires := now.Add(b.capabilityTTL)
	if err := b.record(request.RequestID, "authorized", string(decision.Code), now); err != nil {
		return Authorization{Code: AuditUnavailable, Caller: authenticatedCaller, Reason: ErrAuditUnavailable.Error()}
	}
	b.capabilities[token] = Capability{RequestID: request.RequestID, Caller: authenticatedCaller, Repository: request.Repository, Operation: request.Operation, ExpiresAt: expires, MutationHash: mutationHash, ApprovalID: request.ApprovalID, ActorMode: actorMode, ActorSubject: actorSubject}
	return Authorization{Code: decision.Code, Caller: authenticatedCaller, Reason: decision.Reason, Capability: token, ExpiresAt: expires, ActorMode: actorMode, ActorSubject: actorSubject}
}

func (b *Broker) Receipt(authenticatedCaller, requestID string) ([]audit.Event, error) {
	b.mu.Lock()
	owner := b.requestOwners[requestID]
	b.mu.Unlock()
	if owner == "" || owner != authenticatedCaller {
		return nil, ErrReceiptForbidden
	}
	reader, ok := b.journal.(receiptReader)
	if !ok {
		return nil, ErrAuditUnavailable
	}
	return reader.ReadFor(requestID)
}

func (b *Broker) Status(authenticatedCaller, requestID string) (audit.Event, error) {
	events, err := b.Receipt(authenticatedCaller, requestID)
	if err != nil || len(events) == 0 {
		if err != nil {
			return audit.Event{}, err
		}
		return audit.Event{}, ErrReceiptForbidden
	}
	return events[len(events)-1], nil
}

func (b *Broker) VerifyReceipt(authenticatedCaller, requestID string) error {
	if _, err := b.Receipt(authenticatedCaller, requestID); err != nil {
		return err
	}
	verifier, ok := b.journal.(journalVerifier)
	if !ok {
		return ErrAuditUnavailable
	}
	if err := verifier.Verify(); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func (b *Broker) FinalizeCapability(token, outcome, _ string, _ string, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	capability, ok := b.capabilities[token]
	if !ok {
		return ErrCapabilityNotFound
	}
	if !capability.Consumed {
		return ErrCapabilityBinding
	}
	switch outcome {
	case "verified":
		if capability.ApprovalID != "" {
			if err := b.approvals.Commit(capability.ApprovalID, capability.RequestID); err != nil {
				return err
			}
		}
	case "reconciled_absent":
		if capability.ApprovalID != "" {
			if err := b.approvals.Release(capability.ApprovalID, capability.RequestID); err != nil {
				return err
			}
		}
	case "indeterminate":
		// Keep exact approval reserved until a later independent read resolves the outcome.
	default:
		return errors.New("capability outcome is invalid")
	}
	return b.record(capability.RequestID, outcome, "independent_reconciliation", now)
}

func (b *Broker) ConsumeCapability(token, repository, operation, mutationHash string, now time.Time) (Capability, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	capability, ok := b.capabilities[token]
	if !ok {
		return Capability{}, ErrCapabilityNotFound
	}
	if capability.Consumed {
		return Capability{}, ErrCapabilityConsumed
	}
	if capability.Revoked {
		return Capability{}, ErrCapabilityRevoked
	}
	if !now.Before(capability.ExpiresAt) {
		if capability.ApprovalID != "" {
			_ = b.approvals.Release(capability.ApprovalID, capability.RequestID)
		}
		_ = b.record(capability.RequestID, "expired", "capability_expired", now)
		return Capability{}, ErrCapabilityExpired
	}
	if capability.Repository != repository || capability.Operation != operation || capability.MutationHash != mutationHash {
		return Capability{}, ErrCapabilityBinding
	}
	capability.Consumed = true
	b.capabilities[token] = capability
	if err := b.record(capability.RequestID, "executed", "capability_consumed", now); err != nil {
		return Capability{}, ErrAuditUnavailable
	}
	return capability, nil
}

func (b *Broker) record(requestID, state, code string, at time.Time) error {
	_, err := b.journal.Append(audit.Event{RequestID: requestID, Caller: b.requestOwners[requestID], State: state, Code: code, At: at})
	return err
}

func allowed(code policy.Code) bool {
	return code == policy.Allowed || code == policy.AllowedStanding || code == policy.AllowedBranchGrant || code == policy.AllowedPrivateContributor || code == policy.AllowedPrivateReview || code == AllowedByApproval
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func randomToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
