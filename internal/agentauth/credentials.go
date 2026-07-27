package agentauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

var (
	ErrCredentialNotFound = errors.New("agent credential not found")
	ErrCredentialRevoked  = errors.New("agent credential revoked")
	ErrEnrollmentNotFound = errors.New("agent enrollment not found")
	ErrEnrollmentExpired  = errors.New("agent enrollment expired")
	ErrInvalidProof       = errors.New("invalid proof of possession")
	ErrApprovalRequired   = errors.New("human approval required")
)

type CredentialServiceConfig struct {
	ChallengeTTL time.Duration
	Now          func() time.Time
	WriteGate    CredentialWriteGate
}

type CredentialWriteGate interface {
	Verify() error
	Commit(context.Context, string) error
}

type CredentialService struct {
	db           *sqlite.DB
	challengeTTL time.Duration
	now          func() time.Time
	writeGate    CredentialWriteGate
}

type EnrollmentRequest struct {
	TenantID               string
	AgentID                string
	CredentialID           string
	PublicKey              ed25519.PublicKey
	SupersedesCredentialID string
}

type EnrollmentChallenge struct {
	TenantID     string
	ID           string
	ProofMessage []byte
	ExpiresAt    time.Time
}

type Credential struct {
	TenantID               string
	AgentID                string
	ID                     string
	PublicKey              ed25519.PublicKey
	CreatedAt              time.Time
	ApprovedAt             time.Time
	ApprovedBy             string
	SupersedesCredentialID string
	RevokedAt              *time.Time
}

func NewCredentialService(db *sqlite.DB, config CredentialServiceConfig) *CredentialService {
	ttl := config.ChallengeTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &CredentialService{db: db, challengeTTL: ttl, now: now, writeGate: config.WriteGate}
}

func (service *CredentialService) Begin(ctx context.Context, request EnrollmentRequest) (EnrollmentChallenge, error) {
	if service == nil || service.db == nil {
		return EnrollmentChallenge{}, errors.New("credential service is not configured")
	}
	if strings.TrimSpace(request.TenantID) == "" || strings.TrimSpace(request.AgentID) == "" || strings.TrimSpace(request.CredentialID) == "" {
		return EnrollmentChallenge{}, errors.New("tenant, agent, and credential ids are required")
	}
	if len(request.PublicKey) != ed25519.PublicKeySize {
		return EnrollmentChallenge{}, errors.New("invalid Ed25519 public key")
	}
	if err := service.verifyWrite(); err != nil {
		return EnrollmentChallenge{}, err
	}
	generation, err := service.db.LatestPolicyGeneration(ctx, request.TenantID)
	if err != nil {
		return EnrollmentChallenge{}, errors.New("tenant policy is unavailable")
	}
	var snapshot policy.Snapshot
	if err := json.Unmarshal(generation.SnapshotJSON, &snapshot); err != nil {
		return EnrollmentChallenge{}, errors.New("tenant policy is invalid")
	}
	if _, exists := snapshot.Agents[request.AgentID]; !exists {
		return EnrollmentChallenge{}, errors.New("agent is not registered by policy")
	}
	id, challenge, err := randomEnrollmentValues()
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	createdAt := service.now().UTC()
	expiresAt := createdAt.Add(service.challengeTTL)
	proofMessage := enrollmentProofMessage(request, id, challenge, expiresAt)
	enrollment := storage.AgentEnrollment{
		TenantID: request.TenantID, ID: id, AgentID: request.AgentID,
		CredentialID: request.CredentialID, PublicKey: append([]byte(nil), request.PublicKey...),
		ProofMessage: proofMessage, SupersedesCredentialID: request.SupersedesCredentialID,
		CreatedAt: createdAt, ExpiresAt: expiresAt,
	}
	if err := service.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.PruneAndLimitPendingEnrollments(ctx, request.TenantID, createdAt, 100); err != nil {
			return err
		}
		if err := tx.PutAgentEnrollment(ctx, enrollment); err != nil {
			return err
		}
		return tx.AppendAuthorityTransition(ctx, request.TenantID, "enrollment:"+id+":created", "agent_enrollment_created", id, map[string]any{
			"agent_id": request.AgentID, "credential_id": request.CredentialID, "expires_at": expiresAt,
		}, createdAt)
	}); err != nil {
		return EnrollmentChallenge{}, fmt.Errorf("persist enrollment: %w", err)
	}
	if err := service.commitWrite(ctx, request.TenantID); err != nil {
		return EnrollmentChallenge{}, fmt.Errorf("anchor enrollment: %w", err)
	}
	return EnrollmentChallenge{TenantID: request.TenantID, ID: id, ProofMessage: append([]byte(nil), proofMessage...), ExpiresAt: expiresAt}, nil
}

func (service *CredentialService) Complete(ctx context.Context, tenantID, enrollmentID string, proof []byte) error {
	enrollment, err := service.enrollment(ctx, tenantID, enrollmentID)
	if err != nil {
		return err
	}
	if !service.now().Before(enrollment.ExpiresAt) {
		return ErrEnrollmentExpired
	}
	if enrollment.ProofVerifiedAt != nil {
		return nil
	}
	if !ed25519.Verify(ed25519.PublicKey(enrollment.PublicKey), enrollment.ProofMessage, proof) {
		return ErrInvalidProof
	}
	if err := service.verifyWrite(); err != nil {
		return err
	}
	provedAt := service.now().UTC()
	if err := service.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.MarkAgentEnrollmentProved(ctx, tenantID, enrollmentID, provedAt); err != nil {
			return err
		}
		return tx.AppendAuthorityTransition(ctx, tenantID, "enrollment:"+enrollmentID+":proved", "agent_enrollment_proved", enrollmentID, map[string]any{
			"agent_id": enrollment.AgentID, "credential_id": enrollment.CredentialID,
		}, provedAt)
	}); err != nil {
		return fmt.Errorf("record proof: %w", err)
	}
	return service.commitWrite(ctx, tenantID)
}

func (service *CredentialService) Approve(ctx context.Context, tenantID, enrollmentID, approvedBy string) (Credential, error) {
	if strings.TrimSpace(approvedBy) == "" {
		return Credential{}, errors.New("human approver is required")
	}
	enrollment, err := service.enrollment(ctx, tenantID, enrollmentID)
	if err != nil {
		return Credential{}, err
	}
	if !service.now().Before(enrollment.ExpiresAt) {
		return Credential{}, ErrEnrollmentExpired
	}
	if enrollment.ProofVerifiedAt == nil {
		return Credential{}, ErrApprovalRequired
	}
	if enrollment.ApprovedAt == nil {
		if err := service.verifyWrite(); err != nil {
			return Credential{}, err
		}
		approvedAt := service.now().UTC()
		if err := service.db.WithTx(ctx, func(tx *sqlite.Tx) error {
			if err := tx.ApproveAgentEnrollment(ctx, enrollment, approvedBy, approvedAt); err != nil {
				return err
			}
			return tx.AppendAuthorityTransition(ctx, tenantID, "enrollment:"+enrollmentID+":approved", "agent_credential_approved", enrollmentID, map[string]any{
				"agent_id": enrollment.AgentID, "credential_id": enrollment.CredentialID, "approved_by": approvedBy,
			}, approvedAt)
		}); err != nil {
			return Credential{}, fmt.Errorf("approve enrollment: %w", err)
		}
		if err := service.commitWrite(ctx, tenantID); err != nil {
			return Credential{}, fmt.Errorf("anchor credential approval: %w", err)
		}
	}
	return service.Resolve(ctx, tenantID, enrollment.CredentialID)
}

func (service *CredentialService) Resolve(ctx context.Context, tenantID, credentialID string) (Credential, error) {
	record, err := service.db.AgentCredential(ctx, tenantID, credentialID)
	if errors.Is(err, sqlite.ErrNotFound) {
		return Credential{}, ErrCredentialNotFound
	}
	if err != nil {
		return Credential{}, err
	}
	credential := credentialFromStorage(record)
	if credential.RevokedAt != nil {
		return Credential{}, ErrCredentialRevoked
	}
	return credential, nil
}

func (service *CredentialService) Revoke(ctx context.Context, tenantID, credentialID, revokedBy string) error {
	credential, err := service.Resolve(ctx, tenantID, credentialID)
	if err != nil {
		return err
	}
	if err := service.verifyWrite(); err != nil {
		return err
	}
	revokedAt := service.now().UTC()
	if err := service.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.RevokeAgentCredential(ctx, tenantID, credentialID, revokedBy, revokedAt); err != nil {
			return err
		}
		return tx.AppendAuthorityTransition(ctx, tenantID, "credential:"+credentialID+":revoked", "agent_credential_revoked", credentialID, map[string]any{
			"agent_id": credential.AgentID, "credential_id": credentialID, "revoked_by": revokedBy,
		}, revokedAt)
	}); err != nil {
		return err
	}
	return service.commitWrite(ctx, tenantID)
}

func (service *CredentialService) ConsumeNonce(ctx context.Context, tenantID, credentialID, nonce string, expiresAt time.Time) error {
	if err := service.verifyWrite(); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(nonce))
	eventID := "nonce:" + hex.EncodeToString(digest[:12])
	now := service.now().UTC()
	if err := service.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.ConsumeNonce(ctx, tenantID, credentialID, nonce, expiresAt); err != nil {
			return err
		}
		return tx.AppendAuthorityTransition(ctx, tenantID, eventID, "request_nonce_consumed", credentialID, map[string]any{
			"credential_id": credentialID, "expires_at": expiresAt,
		}, now)
	}); err != nil {
		return err
	}
	return service.commitWrite(ctx, tenantID)
}

func (service *CredentialService) verifyWrite() error {
	if service.writeGate == nil {
		return errors.New("credential authority checkpoint gate is not configured")
	}
	return service.writeGate.Verify()
}

func (service *CredentialService) commitWrite(ctx context.Context, tenantID string) error {
	if service.writeGate == nil {
		return errors.New("credential authority checkpoint gate is not configured")
	}
	return service.writeGate.Commit(ctx, tenantID)
}

func (service *CredentialService) enrollment(ctx context.Context, tenantID, enrollmentID string) (storage.AgentEnrollment, error) {
	enrollment, err := service.db.AgentEnrollment(ctx, tenantID, enrollmentID)
	if errors.Is(err, sqlite.ErrNotFound) {
		return storage.AgentEnrollment{}, ErrEnrollmentNotFound
	}
	return enrollment, err
}

func credentialFromStorage(record storage.AgentCredential) Credential {
	return Credential{
		TenantID: record.TenantID, AgentID: record.AgentID, ID: record.ID,
		PublicKey: ed25519.PublicKey(append([]byte(nil), record.PublicKey...)), CreatedAt: record.CreatedAt,
		ApprovedAt: record.ApprovedAt, ApprovedBy: record.ApprovedBy,
		SupersedesCredentialID: record.SupersedesCredentialID, RevokedAt: record.RevokedAt,
	}
}

func randomEnrollmentValues() (string, []byte, error) {
	idBytes := make([]byte, 16)
	challenge := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return "", nil, err
	}
	if _, err := rand.Read(challenge); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(idBytes), challenge, nil
}

func enrollmentProofMessage(request EnrollmentRequest, id string, challenge []byte, expiresAt time.Time) []byte {
	return []byte(fmt.Sprintf(
		"gitoversight-agent-enrollment-v1\ntenant=%s\nagent=%s\ncredential=%s\npublic-key=%s\nenrollment=%s\nchallenge=%s\nexpires=%d\n",
		request.TenantID, request.AgentID, request.CredentialID,
		base64.RawURLEncoding.EncodeToString(request.PublicKey), id,
		base64.RawURLEncoding.EncodeToString(challenge), expiresAt.Unix(),
	))
}
