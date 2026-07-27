package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
	modernsqlite "modernc.org/sqlite"
)

type Tx struct {
	tx *sql.Tx
}

func (tx *Tx) EnsureTenant(ctx context.Context, id string, createdAt time.Time) error {
	if strings.TrimSpace(id) == "" || createdAt.IsZero() {
		return errors.New("tenant id and created time are required")
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO tenants (id, created_at) VALUES (?, ?) ON CONFLICT(id) DO NOTHING`, id, unix(createdAt))
	return err
}

func (tx *Tx) EnsureAgent(ctx context.Context, tenantID, agentID string, createdAt time.Time) error {
	if tenantID == "" || agentID == "" || createdAt.IsZero() {
		return errors.New("tenant, agent, and created time are required")
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO agents (tenant_id, id, created_at) VALUES (?, ?, ?) ON CONFLICT(tenant_id, id) DO NOTHING`, tenantID, agentID, unix(createdAt))
	return err
}

func (tx *Tx) PutAgentCredential(ctx context.Context, credential storage.AgentCredential) error {
	if credential.TenantID == "" || credential.AgentID == "" || credential.ID == "" || len(credential.PublicKey) == 0 || credential.CreatedAt.IsZero() {
		return errors.New("agent credential is incomplete")
	}
	if _, err := tx.tx.ExecContext(ctx, `INSERT INTO agents (tenant_id, id, created_at) VALUES (?, ?, ?) ON CONFLICT(tenant_id, id) DO NOTHING`, credential.TenantID, credential.AgentID, unix(credential.CreatedAt)); err != nil {
		return err
	}
	var revokedAt any
	if credential.RevokedAt != nil {
		revokedAt = unix(*credential.RevokedAt)
	}
	var approvedAt any
	if !credential.ApprovedAt.IsZero() {
		approvedAt = unix(credential.ApprovedAt)
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO agent_credentials (tenant_id, id, agent_id, public_key, created_at, revoked_at, approved_at, approved_by, supersedes_credential_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, credential.TenantID, credential.ID, credential.AgentID, credential.PublicKey, unix(credential.CreatedAt), revokedAt, approvedAt, credential.ApprovedBy, nullableString(credential.SupersedesCredentialID))
	return err
}

func (tx *Tx) PutAgentEnrollment(ctx context.Context, enrollment storage.AgentEnrollment) error {
	if enrollment.TenantID == "" || enrollment.ID == "" || enrollment.AgentID == "" || enrollment.CredentialID == "" || len(enrollment.PublicKey) == 0 || len(enrollment.ProofMessage) == 0 || enrollment.CreatedAt.IsZero() || enrollment.ExpiresAt.IsZero() {
		return errors.New("agent enrollment is incomplete")
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO agent_enrollments (tenant_id, id, agent_id, credential_id, public_key, proof_message, supersedes_credential_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, enrollment.TenantID, enrollment.ID, enrollment.AgentID, enrollment.CredentialID, enrollment.PublicKey, enrollment.ProofMessage, nullableString(enrollment.SupersedesCredentialID), unix(enrollment.CreatedAt), unix(enrollment.ExpiresAt))
	return err
}

func (tx *Tx) PruneAndLimitPendingEnrollments(ctx context.Context, tenantID string, now time.Time, maximum int) error {
	if tenantID == "" || now.IsZero() || maximum <= 0 {
		return errors.New("pending enrollment limit is invalid")
	}
	if _, err := tx.tx.ExecContext(ctx, `DELETE FROM agent_enrollments WHERE tenant_id = ? AND approved_at IS NULL AND expires_at <= ?`, tenantID, unix(now)); err != nil {
		return err
	}
	var count int
	if err := tx.tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_enrollments WHERE tenant_id = ? AND approved_at IS NULL AND expires_at > ?`, tenantID, unix(now)).Scan(&count); err != nil {
		return err
	}
	if count >= maximum {
		return errors.New("pending enrollment quota exceeded")
	}
	return nil
}

func (tx *Tx) MarkAgentEnrollmentProved(ctx context.Context, tenantID, enrollmentID string, provedAt time.Time) error {
	result, err := tx.tx.ExecContext(ctx, `UPDATE agent_enrollments SET proof_verified_at = ? WHERE tenant_id = ? AND id = ? AND proof_verified_at IS NULL AND approved_at IS NULL`, unix(provedAt), tenantID, enrollmentID)
	if err != nil {
		return err
	}
	return requireOneRow(result, "agent enrollment")
}

func (tx *Tx) ApproveAgentEnrollment(ctx context.Context, enrollment storage.AgentEnrollment, approvedBy string, approvedAt time.Time) error {
	if strings.TrimSpace(approvedBy) == "" || approvedAt.IsZero() {
		return errors.New("approval identity and time are required")
	}
	if _, err := tx.tx.ExecContext(ctx, `INSERT INTO agents (tenant_id, id, created_at) VALUES (?, ?, ?) ON CONFLICT(tenant_id, id) DO NOTHING`, enrollment.TenantID, enrollment.AgentID, unix(approvedAt)); err != nil {
		return err
	}
	if enrollment.SupersedesCredentialID != "" {
		result, err := tx.tx.ExecContext(ctx, `UPDATE agent_credentials SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND agent_id = ? AND revoked_at IS NULL`, unix(approvedAt), enrollment.TenantID, enrollment.SupersedesCredentialID, enrollment.AgentID)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "superseded credential"); err != nil {
			return err
		}
	}
	credential := storage.AgentCredential{TenantID: enrollment.TenantID, AgentID: enrollment.AgentID, ID: enrollment.CredentialID, PublicKey: enrollment.PublicKey, CreatedAt: approvedAt, ApprovedAt: approvedAt, ApprovedBy: approvedBy, SupersedesCredentialID: enrollment.SupersedesCredentialID}
	if err := tx.PutAgentCredential(ctx, credential); err != nil {
		return err
	}
	result, err := tx.tx.ExecContext(ctx, `UPDATE agent_enrollments SET approved_at = ?, approved_by = ? WHERE tenant_id = ? AND id = ? AND proof_verified_at IS NOT NULL AND approved_at IS NULL`, unix(approvedAt), approvedBy, enrollment.TenantID, enrollment.ID)
	if err != nil {
		return err
	}
	return requireOneRow(result, "agent enrollment")
}

func (tx *Tx) PutOperation(ctx context.Context, operation storage.Operation) error {
	if operation.TenantID == "" || operation.ID == "" || operation.AgentID == "" || operation.Repository == "" || operation.Kind == "" || operation.PacketHash == "" || operation.State == "" || operation.CreatedAt.IsZero() || operation.ExpiresAt.IsZero() {
		return errors.New("operation is incomplete")
	}
	updatedAt := operation.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = operation.CreatedAt
	}
	var approvalExpiresAt any
	if !operation.ApprovalExpiresAt.IsZero() {
		approvalExpiresAt = unix(operation.ApprovalExpiresAt)
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO operation_packets (tenant_id, id, agent_id, repository, operation, packet_hash, state, policy_generation, created_at, expires_at, branch, title, body, head_sha, manifest_hash, approval_id, approver, decision_code, reason, actor_mode, actor_subject, mutation_hash, payload_json, updated_at, approval_nonce, approval_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, operation.TenantID, operation.ID, operation.AgentID, operation.Repository, operation.Kind, operation.PacketHash, operation.State, operation.PolicyGeneration, unix(operation.CreatedAt), unix(operation.ExpiresAt), operation.Branch, operation.Title, operation.Body, operation.HeadSHA, operation.ManifestHash, operation.ApprovalID, operation.Approver, operation.DecisionCode, operation.Reason, operation.ActorMode, operation.ActorSubject, operation.MutationHash, operation.PayloadJSON, unix(updatedAt), nullableString(operation.ApprovalNonce), approvalExpiresAt)
	return err
}

func (tx *Tx) PutWebhookReceipt(ctx context.Context, receipt storage.WebhookReceipt) error {
	if receipt.TenantID == "" || receipt.Provider == "" || receipt.DeliveryID == "" || receipt.EventType == "" || receipt.BodyHash == "" || receipt.ReceivedAt.IsZero() {
		return errors.New("webhook receipt is incomplete")
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO webhook_receipts (tenant_id, provider, delivery_id, event_type, body_hash, received_at) VALUES (?, ?, ?, ?, ?, ?)`, receipt.TenantID, receipt.Provider, receipt.DeliveryID, receipt.EventType, receipt.BodyHash, unix(receipt.ReceivedAt))
	if isUniqueConstraint(err) {
		return storage.ErrDuplicateWebhook
	}
	return err
}

func (tx *Tx) ConsumeNonce(ctx context.Context, tenantID, credentialID, nonce string, expiresAt time.Time) error {
	if tenantID == "" || credentialID == "" || nonce == "" || expiresAt.IsZero() {
		return errors.New("nonce binding is incomplete")
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO request_nonces (tenant_id, credential_id, nonce, expires_at) VALUES (?, ?, ?, ?)`, tenantID, credentialID, nonce, unix(expiresAt))
	if isUniqueConstraint(err) {
		return storage.ErrDuplicateNonce
	}
	return err
}

func (tx *Tx) RevokeAgentCredential(ctx context.Context, tenantID, credentialID, revokedBy string, revokedAt time.Time) error {
	if tenantID == "" || credentialID == "" || revokedBy == "" || revokedAt.IsZero() {
		return errors.New("credential revocation is incomplete")
	}
	result, err := tx.tx.ExecContext(ctx, `UPDATE agent_credentials SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`, unix(revokedAt), tenantID, credentialID)
	if err != nil {
		return err
	}
	return requireOneRow(result, "agent credential")
}

func (tx *Tx) AppendAudit(ctx context.Context, event storage.AuditEvent) error {
	if event.TenantID == "" || event.ID == "" || event.Kind == "" || event.SubjectID == "" || len(event.PayloadJSON) == 0 || event.PreviousHash == "" || event.Hash == "" || event.CreatedAt.IsZero() {
		return errors.New("audit event is incomplete")
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO audit_events (tenant_id, id, event_type, subject_id, payload_json, previous_hash, event_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, event.TenantID, event.ID, event.Kind, event.SubjectID, event.PayloadJSON, event.PreviousHash, event.Hash, unix(event.CreatedAt))
	return err
}

func (tx *Tx) AppendOutbox(ctx context.Context, event storage.OutboxEvent) error {
	if event.TenantID == "" || event.ID == "" || event.Kind == "" || event.AudienceAgentID == "" || len(event.PayloadJSON) == 0 || event.State == "" || event.CreatedAt.IsZero() {
		return errors.New("outbox event is incomplete")
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO outbox_deliveries (tenant_id, id, event_type, audience_agent_id, payload_json, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, event.TenantID, event.ID, event.Kind, event.AudienceAgentID, event.PayloadJSON, event.State, unix(event.CreatedAt))
	return err
}

func (tx *Tx) OperationAgent(ctx context.Context, tenantID, operationID string) (string, error) {
	var agentID string
	err := tx.tx.QueryRowContext(ctx, `SELECT agent_id FROM operation_packets WHERE tenant_id = ? AND id = ?`, tenantID, operationID).Scan(&agentID)
	return agentID, err
}

func unix(value time.Time) int64 { return value.UTC().Unix() }

func isUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	var sqliteErr *modernsqlite.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.Code() == 1555 || sqliteErr.Code() == 2067
	}
	return strings.Contains(strings.ToLower(fmt.Sprint(err)), "unique constraint")
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func requireOneRow(result sql.Result, subject string) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("%s not found or state transition rejected", subject)
	}
	return nil
}

var _ storage.Transaction = (*Tx)(nil)
