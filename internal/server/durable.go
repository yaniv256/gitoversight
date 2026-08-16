package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/gitref"
	"github.com/yaniv256/gitoversight.dev/internal/mutation"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type DurableState string

const (
	DurableDenied           DurableState = "denied"
	DurableAwaitingApproval DurableState = "awaiting_approval"
	DurableAuthorized       DurableState = "authorized"
	DurableExecuting        DurableState = "executing"
	DurableVerified         DurableState = "verified"
	DurableAbsent           DurableState = "absent"
	DurableIndeterminate    DurableState = "indeterminate"
	DurableRevoked          DurableState = "revoked"
	DurableExpired          DurableState = "expired"
)

var (
	ErrDurableNotFound       = errors.New("durable operation not found")
	ErrDurableForbidden      = errors.New("durable operation is not visible to caller")
	ErrDurableApproval       = errors.New("durable approval rejected")
	ErrDurableInvalid        = errors.New("durable request is invalid")
	ErrDurableState          = errors.New("durable operation state does not permit this action")
	ErrDurablePolicy         = errors.New("durable policy promotion rejected")
	ErrStreamedAssetRequired = errors.New("streamed release asset required")
)

type DurableIdentity struct {
	TenantID     string
	AgentID      string
	CredentialID string
}

type DurableOperationRequest struct {
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

type DurableApprovalRequest struct {
	TenantID     string
	OperationID  string
	ApprovalID   string
	PacketHash   string
	ManifestHash string
	HeadSHA      string
	Approver     string
	Nonce        string
	ExpiresAt    time.Time
}

type DurableResult struct {
	ID               string       `json:"id"`
	TenantID         string       `json:"tenant_id"`
	AgentID          string       `json:"agent_id"`
	Repository       string       `json:"repository"`
	Operation        string       `json:"operation"`
	Branch           string       `json:"branch,omitempty"`
	Title            string       `json:"title,omitempty"`
	HeadSHA          string       `json:"head_sha,omitempty"`
	ManifestHash     string       `json:"manifest_hash,omitempty"`
	State            DurableState `json:"state"`
	Decision         policy.Code  `json:"decision"`
	Reason           string       `json:"reason"`
	PacketHash       string       `json:"packet_hash"`
	PolicyGeneration uint64       `json:"policy_generation"`
	ActorMode        string       `json:"actor_mode,omitempty"`
	ActorSubject     string       `json:"actor_subject,omitempty"`
	ResourceID       string       `json:"resource_id,omitempty"`
	NextAction       string       `json:"next_action"`
	CreatedAt        time.Time    `json:"created_at,omitempty"`
	UpdatedAt        time.Time    `json:"updated_at,omitempty"`
	ExpiresAt        time.Time    `json:"expires_at,omitempty"`
}

type DurablePolicyStatus struct {
	TenantID    string    `json:"tenant_id"`
	Generation  uint64    `json:"generation"`
	PolicyHash  string    `json:"policy_hash"`
	ActivatedAt time.Time `json:"activated_at"`
}

// WorkAgentEnrollment is the human-reviewed policy portion of a remote Work
// enrollment. RepositoryScope is persisted by the OAuth grant; policy only
// registers the agent, preserving the existing repository authority rules.
type WorkAgentEnrollment struct {
	AgentID            string
	DisplayName        string
	RepositoryScope    []string
	AllPrivate         bool
	ExpectedGeneration uint64
	ExpectedPolicyHash string
}

type DurableExecutionPacket struct {
	TenantID     string
	Capability   string
	RequestID    string
	Repository   string
	Operation    string
	Payload      map[string]any
	Branch       string
	Title        string
	Body         string
	ManifestHash string
	ActorMode    string
	ActorSubject string
}

type DurableBroker struct {
	db          *sqlite.DB
	now         func() time.Time
	writeGate   DurableWriteGate
	humanLogins map[string]string
}

type DurableWriteGate interface {
	Verify() error
	Commit(context.Context, string) error
}

func NewDurableBroker(db *sqlite.DB) *DurableBroker {
	return &DurableBroker{db: db, now: func() time.Time { return time.Now().UTC() }}
}

func (broker *DurableBroker) SetWriteGate(gate DurableWriteGate) {
	broker.writeGate = gate
}

// SetHumanLogins installs the enrolled-human map (governance human id ->
// GitHub login) used to resolve which stored human credential owns a target
// repository namespace.
func (broker *DurableBroker) SetHumanLogins(logins map[string]string) {
	broker.humanLogins = logins
}

// humanForRepositoryOwner returns the governance human id whose GitHub login
// owns the repository's namespace, or false when no enrolled human does.
func humanForRepositoryOwner(logins map[string]string, repository string) (string, bool) {
	owner, _, found := strings.Cut(repository, "/")
	if !found || owner == "" {
		return "", false
	}
	for humanID, login := range logins {
		if strings.EqualFold(login, owner) {
			return humanID, true
		}
	}
	return "", false
}

func (broker *DurableBroker) RecoverInterruptedExecutions(ctx context.Context, tenantID string) (int, error) {
	if broker == nil || broker.db == nil || tenantID == "" {
		return 0, ErrDurableInvalid
	}
	if err := broker.verifyWrite(); err != nil {
		return 0, err
	}
	recovered, err := broker.db.RecoverInterruptedExecutions(ctx, tenantID, broker.now().UTC())
	if err != nil || len(recovered) == 0 {
		return len(recovered), err
	}
	if err := broker.commitWrite(ctx, tenantID); err != nil {
		return len(recovered), err
	}
	return len(recovered), nil
}

func (broker *DurableBroker) PrepareExecution(ctx context.Context, identity DurableIdentity, operationID, workerID string, ttl time.Duration) (string, error) {
	if broker == nil || broker.db == nil || broker.writeGate == nil || identity.TenantID == "" || identity.AgentID == "" || operationID == "" || workerID == "" || ttl <= 0 || ttl > 5*time.Minute {
		return "", errors.New("durable execution grant request is invalid")
	}
	if err := broker.writeGate.Verify(); err != nil {
		return "", fmt.Errorf("audit checkpoint gate rejected write: %w", err)
	}
	operation, err := broker.db.Operation(ctx, identity.TenantID, operationID)
	if errors.Is(err, sqlite.ErrNotFound) {
		return "", ErrDurableNotFound
	}
	if err != nil {
		return "", err
	}
	if operation.AgentID != identity.AgentID {
		return "", ErrDurableForbidden
	}
	if operation.State != string(DurableAuthorized) {
		return "", fmt.Errorf("%w: state is %s", ErrDurableState, operation.State)
	}
	if err := validateExecutableOperation(operation); err != nil {
		return "", err
	}
	now := broker.now().UTC()
	if !now.Before(operation.ExpiresAt) {
		return "", ErrCapabilityExpired
	}
	rawToken, err := randomToken()
	if err != nil {
		return "", err
	}
	tokenHash := hashDurableGrant(rawToken)
	expiresAt := now.Add(ttl)
	if expiresAt.After(operation.ExpiresAt) {
		expiresAt = operation.ExpiresAt
	}
	grant := storage.ExecutionGrant{
		TenantID: identity.TenantID, ID: tokenHash, OperationID: operation.ID,
		PacketHash: operation.PacketHash, MutationHash: operation.MutationHash, WorkerID: workerID,
		Repository: operation.Repository, Operation: operation.Kind, ActorMode: operation.ActorMode, ActorSubject: operation.ActorSubject,
		ApprovalID: operation.ApprovalID, CreatedAt: now, ExpiresAt: expiresAt,
	}
	err = broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.PutExecutionGrant(ctx, grant); err != nil {
			return err
		}
		eventID := operationID + ":grant:" + tokenHash[:12]
		event := map[string]any{"state": DurableAuthorized, "worker_id": workerID, "expires_at": expiresAt}
		if err := tx.AppendAuthorityTransition(ctx, identity.TenantID, eventID, "execution_grant_issued", operationID, event, now); err != nil {
			return err
		}
		payload, _ := json.Marshal(event)
		return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: identity.TenantID, ID: eventID, Kind: "execution_grant_issued", AudienceAgentID: identity.AgentID, PayloadJSON: payload, State: "pending", CreatedAt: now})
	})
	if err != nil {
		return "", err
	}
	if err := broker.writeGate.Commit(ctx, identity.TenantID); err != nil {
		return "", fmt.Errorf("anchor execution grant: %w", err)
	}
	return rawToken, nil
}

func (broker *DurableBroker) PrepareExecutionPacket(ctx context.Context, identity DurableIdentity, operationID, workerID string, ttl time.Duration) (DurableExecutionPacket, error) {
	if broker == nil || broker.db == nil {
		return DurableExecutionPacket{}, errors.New("durable broker is unavailable")
	}
	operation, err := broker.db.Operation(ctx, identity.TenantID, operationID)
	if err != nil {
		return DurableExecutionPacket{}, err
	}
	if operation.AgentID != identity.AgentID {
		return DurableExecutionPacket{}, ErrDurableForbidden
	}
	payload := map[string]any{}
	if len(operation.PayloadJSON) != 0 {
		if err := json.Unmarshal(operation.PayloadJSON, &payload); err != nil {
			return DurableExecutionPacket{}, err
		}
	}
	capability, err := broker.PrepareExecution(ctx, identity, operationID, workerID, ttl)
	if err != nil {
		return DurableExecutionPacket{}, err
	}
	return DurableExecutionPacket{
		TenantID: operation.TenantID, Capability: capability, RequestID: operation.ID, Repository: operation.Repository,
		Operation: operation.Kind, Payload: payload, Branch: operation.Branch, Title: operation.Title,
		Body: operation.Body, ManifestHash: operation.ManifestHash, ActorMode: operation.ActorMode,
		ActorSubject: operation.ActorSubject,
	}, nil
}

func (broker *DurableBroker) ReconciliationPacket(ctx context.Context, identity DurableIdentity, operationID string) (DurableExecutionPacket, error) {
	if identity.TenantID == "" || identity.AgentID == "" || operationID == "" {
		return DurableExecutionPacket{}, ErrDurableInvalid
	}
	operation, err := broker.db.Operation(ctx, identity.TenantID, operationID)
	if errors.Is(err, sqlite.ErrNotFound) {
		return DurableExecutionPacket{}, ErrDurableNotFound
	}
	if err != nil {
		return DurableExecutionPacket{}, err
	}
	if operation.AgentID != identity.AgentID {
		return DurableExecutionPacket{}, ErrDurableForbidden
	}
	if DurableState(operation.State) != DurableIndeterminate {
		return DurableExecutionPacket{}, errors.New("operation is not indeterminate")
	}
	var payload map[string]any
	if len(operation.PayloadJSON) != 0 {
		if err := json.Unmarshal(operation.PayloadJSON, &payload); err != nil {
			return DurableExecutionPacket{}, err
		}
	}
	return DurableExecutionPacket{
		TenantID: operation.TenantID, RequestID: operation.ID, Repository: operation.Repository,
		Operation: operation.Kind, Payload: payload, Branch: operation.Branch, Title: operation.Title,
		Body: operation.Body, ManifestHash: operation.ManifestHash, ActorMode: operation.ActorMode,
		ActorSubject: operation.ActorSubject,
	}, nil
}

func (broker *DurableBroker) AuthorizeReconciliationForWorker(tenantID, operationID, workerID, repository, operation, mutationHash string) (Capability, error) {
	grant, err := broker.db.IndeterminateExecutionGrantForWorker(context.Background(), tenantID, operationID, workerID, repository, operation, mutationHash)
	if err != nil {
		return Capability{}, fmt.Errorf("%w: %v", ErrCapabilityNotFound, err)
	}
	return durableCapability(grant), nil
}

func (broker *DurableBroker) FinalizeReconciliationForWorker(tenantID, operationID, workerID, outcome, resourceID string, now time.Time) error {
	if tenantID == "" || operationID == "" || workerID == "" || now.IsZero() {
		return ErrCapabilityBinding
	}
	if err := broker.verifyWrite(); err != nil {
		return err
	}
	ctx := context.Background()
	if err := broker.db.FinalizeIndeterminateReconciliation(ctx, tenantID, operationID, workerID, outcome, resourceID, now.UTC()); err != nil {
		return err
	}
	return broker.commitWrite(ctx, tenantID)
}

func (broker *DurableBroker) ConsumeCapability(token, repository, operation, mutationHash string, now time.Time) (Capability, error) {
	return broker.consumeCapability(token, "", "", repository, operation, mutationHash, now)
}

func (broker *DurableBroker) ConsumeCapabilityForWorker(token, workerID, deliveryID, repository, operation, mutationHash string, now time.Time) (Capability, error) {
	if workerID == "" || deliveryID == "" {
		return Capability{}, ErrCapabilityBinding
	}
	return broker.consumeCapability(token, workerID, deliveryID, repository, operation, mutationHash, now)
}

func (broker *DurableBroker) consumeCapability(token, workerID, deliveryID, repository, operation, mutationHash string, now time.Time) (Capability, error) {
	if token == "" || repository == "" || operation == "" || mutationHash == "" || now.IsZero() {
		return Capability{}, ErrCapabilityBinding
	}
	if err := broker.verifyWrite(); err != nil {
		return Capability{}, err
	}
	ctx := context.Background()
	var grant storage.ExecutionGrant
	var err error
	if workerID == "" {
		grant, err = broker.db.ConsumeExecutionGrant(ctx, hashDurableGrant(token), repository, operation, mutationHash, now.UTC())
	} else {
		grant, err = broker.db.ConsumeExecutionGrantForWorker(ctx, hashDurableGrant(token), workerID, deliveryID, repository, operation, mutationHash, now.UTC())
	}
	if err != nil {
		if workerID != "" {
			grant, err = broker.db.ActiveConsumedExecutionGrantForWorker(ctx, hashDurableGrant(token), workerID, deliveryID, repository, operation, mutationHash, now.UTC())
		}
		if err != nil {
			return Capability{}, fmt.Errorf("%w: %v", ErrCapabilityNotFound, err)
		}
		return durableCapability(grant), nil
	}
	if err := broker.commitWrite(ctx, grant.TenantID); err != nil {
		rollbackErr := broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
			rolledBack, rollbackErr := tx.RollbackUndeliveredConsumedExecutionGrant(ctx, hashDurableGrant(token), now.UTC())
			if rollbackErr != nil {
				return rollbackErr
			}
			eventID := rolledBack.OperationID + ":delivery-rollback:" + rolledBack.ID[:12]
			event := map[string]any{"state": DurableAuthorized, "worker_id": rolledBack.WorkerID}
			if err := tx.AppendAuthorityTransition(ctx, rolledBack.TenantID, eventID, "execution_delivery_rolled_back", rolledBack.OperationID, event, now.UTC()); err != nil {
				return err
			}
			payload, _ := json.Marshal(event)
			agentID, agentErr := tx.OperationAgent(ctx, rolledBack.TenantID, rolledBack.OperationID)
			if agentErr != nil {
				return agentErr
			}
			return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: rolledBack.TenantID, ID: eventID, Kind: "execution_delivery_rolled_back", AudienceAgentID: agentID, PayloadJSON: payload, State: "pending", CreatedAt: now.UTC()})
		})
		if rollbackErr != nil {
			return Capability{}, errors.Join(err, rollbackErr)
		}
		return Capability{}, err
	}
	return durableCapability(grant), nil
}

func durableCapability(grant storage.ExecutionGrant) Capability {
	return Capability{
		TenantID: grant.TenantID, RequestID: grant.OperationID, Repository: grant.Repository, Operation: grant.Operation,
		ExpiresAt: grant.ExpiresAt, Consumed: true, MutationHash: grant.MutationHash,
		ApprovalID: grant.ApprovalID, ActorMode: grant.ActorMode, ActorSubject: grant.ActorSubject,
	}
}

func (broker *DurableBroker) FinalizeCapability(token, outcome, resourceID, reason string, now time.Time) error {
	if token == "" || now.IsZero() {
		return ErrCapabilityBinding
	}
	switch outcome {
	case "verified", "reconciled_absent", "indeterminate":
	default:
		return errors.New("capability outcome is invalid")
	}
	if err := broker.verifyWrite(); err != nil {
		return err
	}
	ctx := context.Background()
	grant, err := broker.db.FinalizeExecutionGrant(ctx, hashDurableGrant(token), outcome, resourceID, reason, now.UTC())
	if err != nil {
		return fmt.Errorf("finalize durable capability: %w", err)
	}
	return broker.commitWrite(ctx, grant.TenantID)
}

func (broker *DurableBroker) AbandonUnconsumedExecution(ctx context.Context, token string, now time.Time) error {
	if broker == nil || broker.db == nil || token == "" || now.IsZero() {
		return errors.New("execution abandonment is invalid")
	}
	tokenHash := hashDurableGrant(token)
	tenantID := ""
	if err := broker.verifyWrite(); err != nil {
		return err
	}
	err := broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		grant, err := tx.RevokeUnconsumedExecutionGrant(ctx, tokenHash, now.UTC())
		if err != nil {
			return err
		}
		tenantID = grant.TenantID
		eventID := grant.OperationID + ":grant-abandoned:" + tokenHash[:12]
		event := map[string]any{"state": DurableAuthorized, "worker_id": grant.WorkerID, "reason": "worker delivery failed before capability consumption"}
		if err := tx.AppendAuthorityTransition(ctx, grant.TenantID, eventID, "execution_grant_abandoned", grant.OperationID, event, now.UTC()); err != nil {
			return err
		}
		payload, _ := json.Marshal(event)
		agentID, agentErr := tx.OperationAgent(ctx, grant.TenantID, grant.OperationID)
		if agentErr != nil {
			return agentErr
		}
		return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: grant.TenantID, ID: eventID, Kind: "execution_grant_abandoned", AudienceAgentID: agentID, PayloadJSON: payload, State: "pending", CreatedAt: now.UTC()})
	})
	if err != nil {
		return err
	}
	return broker.commitWrite(ctx, tenantID)
}

func hashDurableGrant(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func (broker *DurableBroker) InstallPolicy(ctx context.Context, tenantID string, snapshot policy.Snapshot) error {
	return broker.installPolicy(ctx, tenantID, snapshot, "", "")
}

func (broker *DurableBroker) PromotePolicy(ctx context.Context, tenantID, approver string, expectedGeneration uint64, expectedHash string, snapshot policy.Snapshot) error {
	if approver == "" || expectedGeneration == 0 || expectedHash == "" || snapshot.Generation != expectedGeneration+1 {
		return fmt.Errorf("%w: promotion binding is incomplete", ErrDurablePolicy)
	}
	status, err := broker.PolicyStatus(ctx, tenantID)
	if err != nil {
		return err
	}
	if status.Generation != expectedGeneration || status.PolicyHash != expectedHash {
		return fmt.Errorf("%w: active generation does not match reviewed predecessor", ErrDurablePolicy)
	}
	return broker.installPolicy(ctx, tenantID, snapshot, approver, expectedHash)
}

// EnrollWorkAgent registers one remote agent through the same durable,
// generation-bound policy promotion path used for human-reviewed policy
// changes. It deliberately adds no repository writer or owner grants.
func (broker *DurableBroker) EnrollWorkAgent(ctx context.Context, tenantID, approver string, enrollment WorkAgentEnrollment) (DurablePolicyStatus, error) {
	if broker == nil || broker.db == nil || tenantID == "" || approver == "" ||
		enrollment.AgentID == "" || enrollment.DisplayName == "" ||
		enrollment.AgentID != strings.TrimSpace(enrollment.AgentID) ||
		enrollment.DisplayName != strings.TrimSpace(enrollment.DisplayName) ||
		enrollment.ExpectedGeneration == 0 || enrollment.ExpectedPolicyHash == "" {
		return DurablePolicyStatus{}, fmt.Errorf("%w: work enrollment binding is incomplete", ErrDurableInvalid)
	}
	if enrollment.AllPrivate == (len(enrollment.RepositoryScope) > 0) {
		return DurablePolicyStatus{}, fmt.Errorf("%w: choose either all private repositories or an exact repository scope", ErrDurableInvalid)
	}

	status, err := broker.PolicyStatus(ctx, tenantID)
	if err != nil {
		return DurablePolicyStatus{}, err
	}
	if status.Generation != enrollment.ExpectedGeneration || status.PolicyHash != enrollment.ExpectedPolicyHash {
		return DurablePolicyStatus{}, fmt.Errorf("%w: active generation does not match reviewed predecessor", ErrDurablePolicy)
	}
	current, err := broker.policy(ctx, tenantID)
	if err != nil {
		return DurablePolicyStatus{}, err
	}
	if _, exists := current.Agents[enrollment.AgentID]; exists {
		return DurablePolicyStatus{}, fmt.Errorf("%w: agent identity %q is already registered", ErrDurableInvalid, enrollment.AgentID)
	}

	seenRepositories := make(map[string]struct{}, len(enrollment.RepositoryScope))
	for _, repositoryName := range enrollment.RepositoryScope {
		if repositoryName == "" || repositoryName != strings.TrimSpace(repositoryName) {
			return DurablePolicyStatus{}, fmt.Errorf("%w: repository scope must contain exact names", ErrDurableInvalid)
		}
		if _, duplicate := seenRepositories[repositoryName]; duplicate {
			return DurablePolicyStatus{}, fmt.Errorf("%w: repository scope contains duplicate %q", ErrDurableInvalid, repositoryName)
		}
		seenRepositories[repositoryName] = struct{}{}
		repository, exists := current.Repositories[repositoryName]
		if !exists {
			return DurablePolicyStatus{}, fmt.Errorf("%w: repository %q is not registered", ErrDurableInvalid, repositoryName)
		}
		if repository.Visibility != "private" {
			return DurablePolicyStatus{}, fmt.Errorf("%w: repository %q is not private", ErrDurableInvalid, repositoryName)
		}
	}

	next := clonePolicySnapshot(current)
	next.Generation = current.Generation + 1
	next.Agents[enrollment.AgentID] = policy.Agent{Kind: policy.AgentKindRemote, FirstName: enrollment.DisplayName}
	if err := broker.PromotePolicy(ctx, tenantID, approver, enrollment.ExpectedGeneration, enrollment.ExpectedPolicyHash, next); err != nil {
		return DurablePolicyStatus{}, err
	}
	return broker.PolicyStatus(ctx, tenantID)
}

func clonePolicySnapshot(snapshot policy.Snapshot) policy.Snapshot {
	clone := snapshot
	clone.Agents = make(map[string]policy.Agent, len(snapshot.Agents)+1)
	for name, agent := range snapshot.Agents {
		agent.Emails = append([]string(nil), agent.Emails...)
		clone.Agents[name] = agent
	}
	clone.Repositories = make(map[string]policy.Repository, len(snapshot.Repositories))
	for name, repository := range snapshot.Repositories {
		repository.Owners = append([]string(nil), repository.Owners...)
		repository.Writers = append([]string(nil), repository.Writers...)
		repository.Approvers = append([]string(nil), repository.Approvers...)
		repository.Standing = append([]string(nil), repository.Standing...)
		if repository.Permissions != nil {
			permissions := *repository.Permissions
			repository.Permissions = &permissions
		}
		clone.Repositories[name] = repository
	}
	clone.BranchGrants = append([]policy.BranchGrant(nil), snapshot.BranchGrants...)
	return clone
}

func (broker *DurableBroker) installPolicy(ctx context.Context, tenantID string, snapshot policy.Snapshot, approver, previousHash string) error {
	if broker == nil || broker.db == nil || tenantID == "" {
		return errors.New("durable broker and tenant are required")
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	now := broker.now().UTC()
	err = broker.verifyWrite()
	if err != nil {
		return err
	}
	err = broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.EnsureTenant(ctx, tenantID, now); err != nil {
			return err
		}
		for agentID := range snapshot.Agents {
			if err := tx.EnsureAgent(ctx, tenantID, agentID, now); err != nil {
				return err
			}
		}
		seenApprovers := make(map[string]struct{})
		for _, repository := range snapshot.Repositories {
			for _, approver := range repository.Approvers {
				if _, exists := seenApprovers[approver]; exists {
					continue
				}
				if err := tx.EnsureHuman(ctx, tenantID, approver, approver, now); err != nil {
					return err
				}
				seenApprovers[approver] = struct{}{}
			}
		}
		if err := tx.PutPolicyGeneration(ctx, storage.PolicyGeneration{
			TenantID: tenantID, Generation: snapshot.Generation, PolicyHash: hex.EncodeToString(digest[:]),
			SnapshotJSON: payload, ActivatedAt: now,
		}); err != nil {
			return err
		}
		eventID := fmt.Sprintf("policy:%d", snapshot.Generation)
		event := map[string]any{"generation": snapshot.Generation, "policy_hash": hex.EncodeToString(digest[:])}
		if approver != "" {
			event["approver"] = approver
			event["previous_policy_hash"] = previousHash
		}
		return tx.AppendAuthorityTransition(ctx, tenantID, eventID, "policy_generation_installed", eventID, event, now)
	})
	if err != nil {
		return err
	}
	return broker.commitWrite(ctx, tenantID)
}

func (broker *DurableBroker) PolicyStatus(ctx context.Context, tenantID string) (DurablePolicyStatus, error) {
	generation, err := broker.db.LatestPolicyGeneration(ctx, tenantID)
	if err != nil {
		return DurablePolicyStatus{}, err
	}
	return DurablePolicyStatus{TenantID: generation.TenantID, Generation: generation.Generation, PolicyHash: generation.PolicyHash, ActivatedAt: generation.ActivatedAt}, nil
}

// PolicySnapshot returns the active validated snapshot for adapters that must
// intersect a narrower credential scope with current policy state.
func (broker *DurableBroker) PolicySnapshot(ctx context.Context, tenantID string) (policy.Snapshot, error) {
	if broker == nil || broker.db == nil || tenantID == "" {
		return policy.Snapshot{}, ErrDurableInvalid
	}
	return broker.policy(ctx, tenantID)
}

func (broker *DurableBroker) ResolveRepository(ctx context.Context, tenantID, repository string) (policy.Repository, bool, error) {
	snapshot, err := broker.policy(ctx, tenantID)
	if err != nil {
		return policy.Repository{}, false, err
	}
	value, ok := snapshot.Repositories[repository]
	return value, ok, nil
}

func (broker *DurableBroker) Submit(ctx context.Context, identity DurableIdentity, request DurableOperationRequest) (DurableResult, error) {
	if broker == nil || broker.db == nil || identity.TenantID == "" || identity.AgentID == "" || request.ID == "" {
		return DurableResult{}, fmt.Errorf("%w: operation identity and id are required", ErrDurableInvalid)
	}
	if !request.ApprovalExpiresAt.IsZero() {
		request.ApprovalExpiresAt = time.Unix(request.ApprovalExpiresAt.UTC().Unix(), 0).UTC()
	}
	originalBranch := request.Branch
	request.Branch = gitref.BranchName(request.Branch)
	if originalBranch != "" && request.Branch == "" {
		return DurableResult{}, fmt.Errorf("%w: branch ref is invalid", ErrDurableInvalid)
	}
	if err := broker.verifyWrite(); err != nil {
		return DurableResult{}, err
	}
	var stagedAssets []storage.StagedAsset
	if request.Operation == "release.asset.upload" {
		if err := rejectNewInlineReleaseAsset(request.Payload); err != nil {
			return DurableResult{}, err
		}
		if identity.CredentialID == "" {
			return DurableResult{}, fmt.Errorf("%w: release asset credential binding is required", ErrDurableInvalid)
		}
		descriptor, err := parseReleaseAssetDescriptor(request.Payload)
		if err != nil {
			return DurableResult{}, err
		}
		stagedAssets = append(stagedAssets, storage.StagedAsset{
			TenantID: identity.TenantID, ID: descriptor.StageID, AgentID: identity.AgentID,
			CredentialID: identity.CredentialID, Repository: request.Repository,
			Name: descriptor.Name, ContentType: descriptor.ContentType,
			ExpectedSHA256: descriptor.SHA256, ExpectedSize: descriptor.Size,
		})
	} else if request.Operation == "release.assets.upload" {
		if identity.CredentialID == "" {
			return DurableResult{}, fmt.Errorf("%w: release asset credential binding is required", ErrDurableInvalid)
		}
		descriptors, err := parseReleaseAssetDescriptors(request.Payload)
		if err != nil {
			return DurableResult{}, err
		}
		for _, descriptor := range descriptors {
			stagedAssets = append(stagedAssets, storage.StagedAsset{
				TenantID: identity.TenantID, ID: descriptor.StageID, AgentID: identity.AgentID,
				CredentialID: identity.CredentialID, Repository: request.Repository,
				Name: descriptor.Name, ContentType: descriptor.ContentType,
				ExpectedSHA256: descriptor.SHA256, ExpectedSize: descriptor.Size,
			})
		}
	}
	snapshot, err := broker.policy(ctx, identity.TenantID)
	if err != nil {
		return DurableResult{}, err
	}
	decision := policy.Evaluate(snapshot, policy.Request{
		Caller: identity.AgentID, Repository: request.Repository, Operation: request.Operation,
		Branch: request.Branch, Title: request.Title, Body: request.Body, Payload: request.Payload,
	})
	if !policy.Executable(request.Operation) {
		decision = policy.Decision{Code: policy.OperationUnknown, Reason: "operation has no complete privileged adapter"}
	}
	now := broker.now().UTC()
	state, actorMode, actorSubject := DurableDenied, "", ""
	if durableAllowed(decision.Code) {
		state, actorMode = DurableAuthorized, ActorAppInstallation
		// For a private repository in an enrolled human's namespace, an owner
		// operation may use that owner's vaulted user token without a new human
		// interaction. This keeps newly-created repositories operable before the
		// GitHub App installation can discover or select them, while the durable
		// packet still binds the exact repository, operation, and payload.
		if decision.Code == policy.Allowed {
			if humanID, ok := humanForRepositoryOwner(broker.humanLogins, request.Repository); ok {
				actorMode, actorSubject = ActorHumanUser, humanID
			}
		}
		// GitHub only lets a USER token create a user-owned repository, so an
		// allowed (private-scope) create executes as the enrolled human whose
		// GitHub login owns the target namespace. Actor subjects are governance
		// human ids (the vault key), not GitHub logins; the executor separately
		// verifies the credential's login against the namespace before writing.
		if request.Operation == "repository.create" {
			if humanID, ok := humanForRepositoryOwner(broker.humanLogins, request.Repository); ok {
				actorMode, actorSubject = ActorHumanUser, humanID
			} else {
				state, actorMode = DurableDenied, ""
				decision = policy.Decision{Code: policy.ApprovalRequired, Reason: "no enrolled human owns the target namespace"}
			}
		}
	} else if decision.Code == policy.ApprovalRequired {
		repository := snapshot.Repositories[request.Repository]
		if request.ApprovalID != "" && request.ApprovalNonce != "" && request.Approver != "" && request.HeadSHA != "" && request.ManifestHash != "" && request.ApprovalExpiresAt.After(now) && !request.ApprovalExpiresAt.After(now.Add(24*time.Hour)) && containsString(repository.Approvers, request.Approver) {
			state, actorMode, actorSubject = DurableAwaitingApproval, ActorHumanUser, request.Approver
		} else {
			decision.Reason = "exact approval id, nonce, expiry, approver, head, and manifest are required"
		}
	}
	packetHash, mutationHash, payloadJSON, err := bindDurableOperation(identity, request, actorMode, actorSubject)
	if err != nil {
		return DurableResult{}, err
	}
	expiresAt := now.Add(24 * time.Hour)
	if state == DurableAwaitingApproval {
		expiresAt = request.ApprovalExpiresAt.UTC()
	}
	record := storage.Operation{
		TenantID: identity.TenantID, ID: request.ID, AgentID: identity.AgentID,
		Repository: request.Repository, Kind: request.Operation, PacketHash: packetHash,
		State: string(state), PolicyGeneration: snapshot.Generation, CreatedAt: now, ExpiresAt: expiresAt,
		Branch: request.Branch, Title: request.Title, Body: request.Body, HeadSHA: request.HeadSHA,
		ManifestHash: request.ManifestHash, ApprovalID: request.ApprovalID, ApprovalNonce: request.ApprovalNonce,
		ApprovalExpiresAt: request.ApprovalExpiresAt.UTC(), Approver: request.Approver,
		DecisionCode: string(decision.Code), Reason: decision.Reason, ActorMode: actorMode,
		ActorSubject: actorSubject, MutationHash: mutationHash, PayloadJSON: payloadJSON, UpdatedAt: now,
	}
	if err := validateExecutableOperation(record); err != nil {
		return DurableResult{}, err
	}
	err = broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.PutOperation(ctx, record); err != nil {
			return err
		}
		if state == DurableAuthorized || state == DurableAwaitingApproval {
			for _, stagedAsset := range stagedAssets {
				if err := tx.PinStagedAsset(ctx, stagedAsset, request.ID, now); err != nil {
					return err
				}
			}
		}
		event := map[string]any{"state": state, "decision": decision.Code, "packet_hash": packetHash}
		if err := tx.AppendAuthorityTransition(ctx, identity.TenantID, request.ID+":submitted", "operation_submitted", request.ID, event, now); err != nil {
			return err
		}
		outboxPayload, _ := json.Marshal(event)
		return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: identity.TenantID, ID: request.ID + ":submitted", Kind: "operation_submitted", AudienceAgentID: identity.AgentID, PayloadJSON: outboxPayload, State: "pending", CreatedAt: now})
	})
	if sqlite.IsUniqueViolation(err) {
		if _, lookupErr := broker.db.Operation(ctx, identity.TenantID, request.ID); lookupErr == nil {
			return DurableResult{ID: request.ID, TenantID: identity.TenantID, AgentID: identity.AgentID, State: DurableDenied, Decision: ReplayDenied, Reason: "operation id was already submitted", NextAction: "status"}, nil
		} else if !errors.Is(lookupErr, sqlite.ErrNotFound) {
			return DurableResult{}, lookupErr
		}
		if existingID, lookupErr := broker.db.OperationIDByPacketHash(ctx, identity.TenantID, packetHash); lookupErr == nil {
			return DurableResult{ID: request.ID, TenantID: identity.TenantID, AgentID: identity.AgentID, State: DurableDenied, Decision: ReplayDenied, Reason: "exact operation packet was already submitted", ResourceID: existingID, NextAction: "status"}, nil
		} else if !errors.Is(lookupErr, sqlite.ErrNotFound) {
			return DurableResult{}, lookupErr
		}
		if existingID, lookupErr := broker.db.AwaitingApprovalOperationID(ctx, identity.TenantID, request.Repository, request.HeadSHA, request.Approver); lookupErr == nil {
			return DurableResult{ID: request.ID, TenantID: identity.TenantID, AgentID: identity.AgentID, Repository: request.Repository, Operation: request.Operation, State: DurableDenied, Decision: ApprovalConflict, Reason: "another exact approval is pending for this repository, head, and approver", ResourceID: existingID, NextAction: "approve_or_revoke_existing_approval"}, nil
		} else if !errors.Is(lookupErr, sqlite.ErrNotFound) {
			return DurableResult{}, lookupErr
		}
		return DurableResult{ID: request.ID, TenantID: identity.TenantID, AgentID: identity.AgentID, State: DurableDenied, Decision: ReplayDenied, Reason: "operation uniqueness was already consumed", NextAction: "stop"}, nil
	}
	if errors.Is(err, storage.ErrStagedAssetState) {
		return DurableResult{}, fmt.Errorf("%w: staged release asset is unavailable or does not match the operation", ErrDurableInvalid)
	}
	if err != nil {
		return DurableResult{}, err
	}
	if err := broker.commitWrite(ctx, identity.TenantID); err != nil {
		return DurableResult{}, err
	}
	return durableResult(record), nil
}

func (broker *DurableBroker) Approve(ctx context.Context, request DurableApprovalRequest) (DurableResult, error) {
	if broker == nil || broker.db == nil || request.TenantID == "" || request.OperationID == "" || request.ApprovalID == "" || request.Approver == "" || request.Nonce == "" {
		return DurableResult{}, ErrDurableApproval
	}
	now := broker.now().UTC()
	if !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(24*time.Hour)) {
		return DurableResult{}, ErrDurableApproval
	}
	if err := broker.verifyWrite(); err != nil {
		return DurableResult{}, err
	}
	operation, err := broker.db.Operation(ctx, request.TenantID, request.OperationID)
	if err != nil {
		return DurableResult{}, ErrDurableApproval
	}
	snapshot, err := broker.policy(ctx, request.TenantID)
	if err != nil {
		return DurableResult{}, err
	}
	repository, exists := snapshot.Repositories[operation.Repository]
	if !exists || !containsString(repository.Approvers, request.Approver) || !now.Before(operation.ExpiresAt) || operation.PolicyGeneration != snapshot.Generation || operation.State != string(DurableAwaitingApproval) || operation.ApprovalID != request.ApprovalID || operation.ApprovalNonce != request.Nonce || operation.ApprovalExpiresAt.Unix() != request.ExpiresAt.UTC().Unix() || operation.Approver != request.Approver || operation.PacketHash != request.PacketHash || operation.ManifestHash != request.ManifestHash || operation.HeadSHA != request.HeadSHA {
		return DurableResult{}, ErrDurableApproval
	}
	approval := storage.Approval{
		TenantID: request.TenantID, ID: request.ApprovalID, OperationID: request.OperationID,
		ApproverID: request.Approver, PacketHash: request.PacketHash, ManifestHash: request.ManifestHash,
		Repository: operation.Repository, Operation: operation.Kind, HeadSHA: request.HeadSHA,
		Nonce: request.Nonce, PolicyGeneration: operation.PolicyGeneration, CreatedAt: now, ExpiresAt: request.ExpiresAt,
	}
	err = broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.ApproveOperation(ctx, approval, ActorHumanUser, request.Approver, string(AllowedByApproval), "exact human approval consumed", now); err != nil {
			return err
		}
		event := map[string]any{"state": DurableAuthorized, "approver": request.Approver, "packet_hash": request.PacketHash}
		if err := tx.AppendAuthorityTransition(ctx, request.TenantID, request.OperationID+":approved", "operation_approved", request.OperationID, event, now); err != nil {
			return err
		}
		outboxPayload, _ := json.Marshal(event)
		return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: request.TenantID, ID: request.OperationID + ":approved", Kind: "operation_approved", AudienceAgentID: operation.AgentID, PayloadJSON: outboxPayload, State: "pending", CreatedAt: now})
	})
	if err != nil {
		return DurableResult{}, fmt.Errorf("%w: %v", ErrDurableApproval, err)
	}
	if err := broker.commitWrite(ctx, request.TenantID); err != nil {
		return DurableResult{}, err
	}
	return broker.Status(ctx, DurableIdentity{TenantID: request.TenantID, AgentID: operation.AgentID}, request.OperationID)
}

// Decline records a human refusing a pending operation outright.
//
// The mirror of Approve, and gated by the same authority: only a policy-listed
// approver for the repository may decline, because refusing an agent's public
// action is a governance decision and the receipt must name who made it.
//
// Unlike Approve it does NOT re-verify the approval binding (nonce, packet
// hash, expiry). That binding exists to guarantee the human authorized exactly
// the packet the agent submitted — a safeguard against publishing something
// unintended. Declining publishes nothing, so requiring a fresh, unexpired
// binding would mean an operation whose approval window had lapsed could no
// longer be refused, only left to rot. Saying no must never be harder than
// saying yes.
func (broker *DurableBroker) Decline(ctx context.Context, tenantID, operationID, approver, reason string) (DurableResult, error) {
	if broker == nil || broker.db == nil || tenantID == "" || operationID == "" || approver == "" {
		return DurableResult{}, ErrDurableInvalid
	}
	if err := broker.verifyWrite(); err != nil {
		return DurableResult{}, err
	}
	operation, err := broker.db.Operation(ctx, tenantID, operationID)
	if errors.Is(err, sqlite.ErrNotFound) {
		return DurableResult{}, ErrDurableNotFound
	}
	if err != nil {
		return DurableResult{}, err
	}
	if operation.State != string(DurableAwaitingApproval) {
		return DurableResult{}, ErrDurableState
	}
	snapshot, err := broker.policy(ctx, tenantID)
	if err != nil {
		return DurableResult{}, err
	}
	repository, exists := snapshot.Repositories[operation.Repository]
	if !exists || !containsString(repository.Approvers, approver) {
		return DurableResult{}, ErrDurableForbidden
	}
	if strings.TrimSpace(reason) == "" {
		reason = "declined by human reviewer"
	}
	now := broker.now().UTC()
	err = broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.DeclineOperation(ctx, tenantID, operationID, approver, reason, now); err != nil {
			return err
		}
		event := map[string]any{"state": DurableDenied, "approver": approver, "reason": reason}
		if err := tx.AppendAuthorityTransition(ctx, tenantID, operationID+":declined", "operation_declined", operationID, event, now); err != nil {
			return err
		}
		// The agent is told, so it stops waiting on an approval that will
		// never come. A decline the requester never learns about is an expiry
		// with extra steps.
		outboxPayload, _ := json.Marshal(event)
		return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: tenantID, ID: operationID + ":declined",
			Kind: "operation_declined", AudienceAgentID: operation.AgentID, PayloadJSON: outboxPayload, State: "pending", CreatedAt: now})
	})
	if err != nil {
		return DurableResult{}, fmt.Errorf("%w: %v", ErrDurableState, err)
	}
	if err := broker.commitWrite(ctx, tenantID); err != nil {
		return DurableResult{}, err
	}
	return broker.Status(ctx, DurableIdentity{TenantID: tenantID, AgentID: operation.AgentID}, operationID)
}

func (broker *DurableBroker) Status(ctx context.Context, identity DurableIdentity, operationID string) (DurableResult, error) {
	operation, err := broker.db.Operation(ctx, identity.TenantID, operationID)
	if errors.Is(err, sqlite.ErrNotFound) {
		return DurableResult{}, ErrDurableNotFound
	}
	if err != nil {
		return DurableResult{}, err
	}
	if operation.AgentID != identity.AgentID {
		return DurableResult{}, ErrDurableForbidden
	}
	now := broker.now().UTC()
	if (operation.State == string(DurableAwaitingApproval) || operation.State == string(DurableAuthorized)) && !now.Before(operation.ExpiresAt) {
		if err := broker.verifyWrite(); err != nil {
			return DurableResult{}, err
		}
		err := broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
			if err := tx.ExpireOperation(ctx, identity.TenantID, operationID, identity.AgentID, now); err != nil {
				return err
			}
			event := map[string]any{"state": DurableExpired, "expired_at": now}
			if err := tx.AppendAuthorityTransition(ctx, identity.TenantID, operationID+":expired", "operation_expired", operationID, event, now); err != nil {
				return err
			}
			outboxPayload, _ := json.Marshal(event)
			return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: identity.TenantID, ID: operationID + ":expired", Kind: "operation_expired", AudienceAgentID: identity.AgentID, PayloadJSON: outboxPayload, State: "pending", CreatedAt: now})
		})
		if err != nil {
			return DurableResult{}, err
		}
		if err := broker.commitWrite(ctx, identity.TenantID); err != nil {
			return DurableResult{}, err
		}
		operation, err = broker.db.Operation(ctx, identity.TenantID, operationID)
		if err != nil {
			return DurableResult{}, err
		}
	}
	return durableResult(operation), nil
}

func (broker *DurableBroker) Revoke(ctx context.Context, identity DurableIdentity, operationID string) (DurableResult, error) {
	operation, err := broker.db.Operation(ctx, identity.TenantID, operationID)
	if errors.Is(err, sqlite.ErrNotFound) {
		return DurableResult{}, ErrDurableNotFound
	}
	if err != nil {
		return DurableResult{}, err
	}
	if operation.AgentID != identity.AgentID {
		return DurableResult{}, ErrDurableForbidden
	}
	if err := broker.verifyWrite(); err != nil {
		return DurableResult{}, err
	}
	now := broker.now().UTC()
	err = broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.RevokeOperation(ctx, identity.TenantID, operationID, identity.AgentID, "operation revoked by owner", now); err != nil {
			return err
		}
		event := map[string]any{"state": DurableRevoked, "agent_id": identity.AgentID}
		if err := tx.AppendAuthorityTransition(ctx, identity.TenantID, operationID+":revoked", "operation_revoked", operationID, event, now); err != nil {
			return err
		}
		outboxPayload, _ := json.Marshal(event)
		return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: identity.TenantID, ID: operationID + ":revoked", Kind: "operation_revoked", AudienceAgentID: identity.AgentID, PayloadJSON: outboxPayload, State: "pending", CreatedAt: now})
	})
	if err != nil {
		return DurableResult{}, err
	}
	if err := broker.commitWrite(ctx, identity.TenantID); err != nil {
		return DurableResult{}, err
	}
	return broker.Status(ctx, identity, operationID)
}

func (broker *DurableBroker) verifyWrite() error {
	if broker.writeGate == nil {
		return errors.New("durable authority checkpoint gate is not configured")
	}
	return broker.writeGate.Verify()
}

func (broker *DurableBroker) commitWrite(ctx context.Context, tenantID string) error {
	if broker.writeGate == nil {
		return errors.New("durable authority checkpoint gate is not configured")
	}
	return broker.writeGate.Commit(ctx, tenantID)
}

func (broker *DurableBroker) Receipt(ctx context.Context, identity DurableIdentity, operationID string) ([]storage.AuditEvent, error) {
	if _, err := broker.Status(ctx, identity, operationID); err != nil {
		return nil, err
	}
	events, err := broker.db.AuthorityAuditEvents(ctx, identity.TenantID, operationID)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, ErrDurableNotFound
	}
	return events, nil
}

func (broker *DurableBroker) policy(ctx context.Context, tenantID string) (policy.Snapshot, error) {
	generation, err := broker.db.LatestPolicyGeneration(ctx, tenantID)
	if err != nil {
		return policy.Snapshot{}, err
	}
	var snapshot policy.Snapshot
	if err := json.Unmarshal(generation.SnapshotJSON, &snapshot); err != nil {
		return policy.Snapshot{}, err
	}
	if snapshot.Generation != generation.Generation {
		return policy.Snapshot{}, errors.New("stored policy generation mismatch")
	}
	digest := sha256.Sum256(generation.SnapshotJSON)
	if generation.PolicyHash != hex.EncodeToString(digest[:]) {
		return policy.Snapshot{}, errors.New("stored policy hash mismatch")
	}
	derived, err := broker.db.DerivedRepositories(ctx, tenantID)
	if err != nil {
		return policy.Snapshot{}, err
	}
	for _, item := range derived {
		if _, configured := snapshot.Repositories[item.Repository]; configured {
			continue
		}
		snapshot.Repositories[item.Repository] = policy.Repository{
			Visibility:   item.Visibility,
			Owners:       []string{item.OwnerAgentID},
			Derived:      true,
			ActorSubject: item.ActorSubject,
		}
	}
	return snapshot, snapshot.Validate()
}

func bindDurableOperation(identity DurableIdentity, request DurableOperationRequest, actorMode, actorSubject string) (string, string, []byte, error) {
	payloadJSON, err := json.Marshal(request.Payload)
	if err != nil {
		return "", "", nil, err
	}
	mutationHash, err := mutation.Hash(mutation.Packet{
		RequestID: request.ID, Repository: request.Repository, Operation: request.Operation,
		Branch: request.Branch, Title: request.Title, Body: request.Body, ManifestHash: request.ManifestHash,
		ActorMode: actorMode, ActorSubject: actorSubject, Payload: request.Payload,
	})
	if err != nil {
		return "", "", nil, err
	}
	canonical, err := json.Marshal(struct {
		TenantID, AgentID, RequestID, MutationHash, ApprovalID, ApprovalNonce, Approver, HeadSHA string
		ApprovalExpiresAt                                                                        time.Time
	}{identity.TenantID, identity.AgentID, request.ID, mutationHash, request.ApprovalID, request.ApprovalNonce, request.Approver, request.HeadSHA, request.ApprovalExpiresAt.UTC()})
	if err != nil {
		return "", "", nil, err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), mutationHash, payloadJSON, nil
}

func durableResult(operation storage.Operation) DurableResult {
	return DurableResult{
		ID: operation.ID, TenantID: operation.TenantID, AgentID: operation.AgentID,
		Repository: operation.Repository, Operation: operation.Kind, State: DurableState(operation.State),
		Branch: operation.Branch, Title: operation.Title, HeadSHA: operation.HeadSHA, ManifestHash: operation.ManifestHash,
		Decision: policy.Code(operation.DecisionCode), Reason: operation.Reason, PacketHash: operation.PacketHash,
		PolicyGeneration: operation.PolicyGeneration, ActorMode: operation.ActorMode, ActorSubject: operation.ActorSubject,
		ResourceID: operation.ResourceID,
		NextAction: nextDurableAction(DurableState(operation.State)),
		CreatedAt:  operation.CreatedAt, UpdatedAt: operation.UpdatedAt, ExpiresAt: operation.ExpiresAt,
	}
}

func nextDurableAction(state DurableState) string {
	switch state {
	case DurableAwaitingApproval, DurableExecuting:
		return "status"
	case DurableAuthorized:
		return "execute"
	case DurableIndeterminate:
		return "reconcile"
	case DurableVerified:
		return "receipt"
	case DurableAbsent, DurableDenied, DurableRevoked, DurableExpired:
		return "stop"
	default:
		return "stop"
	}
}

func durableAllowed(code policy.Code) bool {
	return code == policy.Allowed || code == policy.AllowedStanding || code == policy.AllowedBranchGrant || code == policy.AllowedPrivateContributor || code == policy.AllowedPrivateReview
}
