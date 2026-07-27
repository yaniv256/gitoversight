package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

func (tx *Tx) EnsureHuman(ctx context.Context, tenantID, humanID, githubLogin string, createdAt time.Time) error {
	if tenantID == "" || humanID == "" || githubLogin == "" || createdAt.IsZero() {
		return errors.New("tenant, human, login, and created time are required")
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO humans (tenant_id, id, github_login, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(tenant_id, id) DO UPDATE SET github_login = excluded.github_login`, tenantID, humanID, githubLogin, unix(createdAt))
	return err
}

func (tx *Tx) PutPolicyGeneration(ctx context.Context, generation storage.PolicyGeneration) error {
	if generation.TenantID == "" || generation.Generation == 0 || generation.PolicyHash == "" || len(generation.SnapshotJSON) == 0 || generation.ActivatedAt.IsZero() {
		return errors.New("policy generation is incomplete")
	}
	var latest int64
	err := tx.tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation), 0) FROM policy_generations WHERE tenant_id = ?`, generation.TenantID).Scan(&latest)
	if err != nil {
		return err
	}
	if generation.Generation <= uint64(latest) {
		return errors.New("policy generation must increase monotonically")
	}
	_, err = tx.tx.ExecContext(ctx, `INSERT INTO policy_generations (tenant_id, generation, policy_hash, activated_at, snapshot_json) VALUES (?, ?, ?, ?, ?)`, generation.TenantID, generation.Generation, generation.PolicyHash, unix(generation.ActivatedAt), generation.SnapshotJSON)
	return err
}

func (db *DB) LatestPolicyGeneration(ctx context.Context, tenantID string) (storage.PolicyGeneration, error) {
	var generation storage.PolicyGeneration
	var rawGeneration, activatedAt int64
	err := db.sql.QueryRowContext(ctx, `SELECT tenant_id, generation, policy_hash, snapshot_json, activated_at FROM policy_generations WHERE tenant_id = ? ORDER BY generation DESC LIMIT 1`, tenantID).Scan(&generation.TenantID, &rawGeneration, &generation.PolicyHash, &generation.SnapshotJSON, &activatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.PolicyGeneration{}, ErrNotFound
	}
	if err != nil {
		return storage.PolicyGeneration{}, err
	}
	generation.Generation = uint64(rawGeneration)
	generation.ActivatedAt = fromUnix(activatedAt)
	return generation, nil
}

func (db *DB) Operation(ctx context.Context, tenantID, operationID string) (storage.Operation, error) {
	var operation storage.Operation
	var policyGeneration, createdAt, expiresAt, updatedAt int64
	var branch, title, body, headSHA, manifestHash, approvalID, approvalNonce, approver sql.NullString
	var approvalExpiresAt sql.NullInt64
	var decisionCode, reason, actorMode, actorSubject, mutationHash, resourceID sql.NullString
	var payloadJSON []byte
	err := db.sql.QueryRowContext(ctx, `SELECT tenant_id, id, agent_id, repository, operation, packet_hash, state, policy_generation, created_at, expires_at, branch, title, body, head_sha, manifest_hash, approval_id, approver, decision_code, reason, actor_mode, actor_subject, mutation_hash, payload_json, COALESCE(updated_at, created_at), approval_nonce, approval_expires_at, resource_id FROM operation_packets WHERE tenant_id = ? AND id = ?`, tenantID, operationID).Scan(
		&operation.TenantID, &operation.ID, &operation.AgentID, &operation.Repository, &operation.Kind,
		&operation.PacketHash, &operation.State, &policyGeneration, &createdAt, &expiresAt,
		&branch, &title, &body, &headSHA, &manifestHash, &approvalID, &approver,
		&decisionCode, &reason, &actorMode, &actorSubject, &mutationHash, &payloadJSON, &updatedAt,
		&approvalNonce, &approvalExpiresAt, &resourceID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.Operation{}, ErrNotFound
	}
	if err != nil {
		return storage.Operation{}, err
	}
	operation.PolicyGeneration = uint64(policyGeneration)
	operation.CreatedAt, operation.ExpiresAt, operation.UpdatedAt = fromUnix(createdAt), fromUnix(expiresAt), fromUnix(updatedAt)
	operation.Branch, operation.Title, operation.Body = branch.String, title.String, body.String
	operation.HeadSHA, operation.ManifestHash, operation.ApprovalID, operation.Approver = headSHA.String, manifestHash.String, approvalID.String, approver.String
	operation.ApprovalNonce = approvalNonce.String
	if approvalExpiresAt.Valid {
		operation.ApprovalExpiresAt = fromUnix(approvalExpiresAt.Int64)
	}
	operation.DecisionCode, operation.Reason = decisionCode.String, reason.String
	operation.ActorMode, operation.ActorSubject, operation.MutationHash = actorMode.String, actorSubject.String, mutationHash.String
	operation.ResourceID = resourceID.String
	operation.PayloadJSON = payloadJSON
	return operation, nil
}

func (db *DB) OperationIDByPacketHash(ctx context.Context, tenantID, packetHash string) (string, error) {
	var operationID string
	err := db.sql.QueryRowContext(ctx, `SELECT id FROM operation_packets WHERE tenant_id = ? AND packet_hash = ?`, tenantID, packetHash).Scan(&operationID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return operationID, err
}

func (db *DB) AwaitingApprovalOperationID(ctx context.Context, tenantID, repository, headSHA, approver string) (string, error) {
	var operationID string
	err := db.sql.QueryRowContext(ctx, `SELECT id FROM operation_packets WHERE tenant_id = ? AND repository = ? AND head_sha = ? AND approver = ? AND state = 'awaiting_approval'`, tenantID, repository, headSHA, approver).Scan(&operationID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return operationID, err
}

func (db *DB) WebhookReceiptExists(ctx context.Context, tenantID, provider, deliveryID string) (bool, error) {
	var exists int
	err := db.sql.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM webhook_receipts WHERE tenant_id = ? AND provider = ? AND delivery_id = ?)`, tenantID, provider, deliveryID).Scan(&exists)
	return exists == 1, err
}

func (db *DB) AuthorityAuditEvents(ctx context.Context, tenantID, subjectID string) ([]storage.AuditEvent, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT tenant_id, id, event_type, subject_id, payload_json, previous_hash, event_hash, created_at FROM audit_events WHERE tenant_id = ? AND subject_id = ? ORDER BY sequence`, tenantID, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []storage.AuditEvent
	for rows.Next() {
		var event storage.AuditEvent
		var createdAt int64
		if err := rows.Scan(&event.TenantID, &event.ID, &event.Kind, &event.SubjectID, &event.PayloadJSON, &event.PreviousHash, &event.Hash, &createdAt); err != nil {
			return nil, err
		}
		event.CreatedAt = fromUnix(createdAt)
		events = append(events, event)
	}
	return events, rows.Err()
}

func (db *DB) AuthorityAuditTrail(ctx context.Context, tenantID string) ([]storage.AuditEvent, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT tenant_id, id, event_type, subject_id, payload_json, previous_hash, event_hash, created_at FROM audit_events WHERE tenant_id = ? ORDER BY sequence`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []storage.AuditEvent
	for rows.Next() {
		var event storage.AuditEvent
		var createdAt int64
		if err := rows.Scan(&event.TenantID, &event.ID, &event.Kind, &event.SubjectID, &event.PayloadJSON, &event.PreviousHash, &event.Hash, &createdAt); err != nil {
			return nil, err
		}
		event.CreatedAt = fromUnix(createdAt)
		events = append(events, event)
	}
	return events, rows.Err()
}

func (db *DB) VerifyAuthorityAuditChain(ctx context.Context, tenantID string) error {
	if db == nil || tenantID == "" {
		return errors.New("database and tenant are required")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT id, event_type, subject_id, payload_json, previous_hash, event_hash, created_at FROM audit_events WHERE tenant_id = ? ORDER BY sequence`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	previous := "GENESIS"
	for rows.Next() {
		var id, kind, subjectID, storedPrevious, storedHash string
		var payload []byte
		var createdAt int64
		if err := rows.Scan(&id, &kind, &subjectID, &payload, &storedPrevious, &storedHash, &createdAt); err != nil {
			return err
		}
		if storedPrevious != previous {
			return errors.New("authority audit chain predecessor mismatch")
		}
		digest := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%d", previous, tenantID, id, kind, subjectID, payload, createdAt)))
		if hex.EncodeToString(digest[:]) != storedHash {
			return errors.New("authority audit chain hash mismatch")
		}
		previous = storedHash
	}
	return rows.Err()
}

func (db *DB) AuthorityAuditTail(ctx context.Context, tenantID string) (string, error) {
	if db == nil || tenantID == "" {
		return "", errors.New("database and tenant are required")
	}
	var tail string
	err := db.sql.QueryRowContext(ctx, `SELECT event_hash FROM audit_events WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1`, tenantID).Scan(&tail)
	if errors.Is(err, sql.ErrNoRows) {
		return "GENESIS", nil
	}
	return tail, err
}

func (db *DB) AuthorityAuditHashExists(ctx context.Context, tenantID, hash string) (bool, error) {
	if hash == "GENESIS" {
		return true, nil
	}
	var exists int
	err := db.sql.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE tenant_id = ? AND event_hash = ?)`, tenantID, hash).Scan(&exists)
	return exists == 1, err
}

// VerifyAuthorityAuditSuffix verifies every event appended after a tail that
// was already fully verified by this process. Startup and restore still run the
// full-chain verifier; this method keeps steady-state readiness and writes
// proportional to new authority transitions.
func (db *DB) VerifyAuthorityAuditSuffix(ctx context.Context, tenantID, verifiedTail string) (string, error) {
	if db == nil || tenantID == "" || verifiedTail == "" {
		return "", errors.New("database, tenant, and verified tail are required")
	}
	var sequence int64
	if verifiedTail != "GENESIS" {
		if err := db.sql.QueryRowContext(ctx, `SELECT sequence FROM audit_events WHERE tenant_id = ? AND event_hash = ?`, tenantID, verifiedTail).Scan(&sequence); err != nil {
			return "", errors.New("verified authority audit tail is absent")
		}
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT id, event_type, subject_id, payload_json, previous_hash, event_hash, created_at FROM audit_events WHERE tenant_id = ? AND sequence > ? ORDER BY sequence`, tenantID, sequence)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	previous := verifiedTail
	for rows.Next() {
		var id, kind, subjectID, storedPrevious, storedHash string
		var payload []byte
		var createdAt int64
		if err := rows.Scan(&id, &kind, &subjectID, &payload, &storedPrevious, &storedHash, &createdAt); err != nil {
			return "", err
		}
		if storedPrevious != previous {
			return "", errors.New("authority audit suffix predecessor mismatch")
		}
		digest := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%d", previous, tenantID, id, kind, subjectID, payload, createdAt)))
		if hex.EncodeToString(digest[:]) != storedHash {
			return "", errors.New("authority audit suffix hash mismatch")
		}
		previous = storedHash
	}
	return previous, rows.Err()
}

func (tx *Tx) ApproveOperation(ctx context.Context, approval storage.Approval, actorMode, actorSubject, decisionCode, reason string, approvedAt time.Time) error {
	if approval.TenantID == "" || approval.ID == "" || approval.OperationID == "" || approval.ApproverID == "" || approval.PacketHash == "" || approval.ManifestHash == "" || approval.Repository == "" || approval.Operation == "" || approval.HeadSHA == "" || approval.Nonce == "" || approval.PolicyGeneration == 0 || approval.CreatedAt.IsZero() || approval.ExpiresAt.IsZero() {
		return errors.New("approval is incomplete")
	}
	result, err := tx.tx.ExecContext(ctx, `UPDATE operation_packets SET state = 'authorized', decision_code = ?, reason = ?, actor_mode = ?, actor_subject = ?, updated_at = ? WHERE tenant_id = ? AND id = ? AND state = 'awaiting_approval' AND packet_hash = ? AND manifest_hash = ? AND repository = ? AND operation = ? AND head_sha = ? AND approval_id = ? AND approver = ? AND policy_generation = ? AND approval_nonce = ? AND approval_expires_at = ?`, decisionCode, reason, actorMode, actorSubject, unix(approvedAt), approval.TenantID, approval.OperationID, approval.PacketHash, approval.ManifestHash, approval.Repository, approval.Operation, approval.HeadSHA, approval.ID, approval.ApproverID, approval.PolicyGeneration, approval.Nonce, unix(approval.ExpiresAt))
	if err != nil {
		return err
	}
	if err := requireOneRow(result, "awaiting operation approval"); err != nil {
		return err
	}
	_, err = tx.tx.ExecContext(ctx, `INSERT INTO approvals (tenant_id, id, operation_id, approver_id, packet_hash, nonce, policy_generation, created_at, expires_at, consumed_at, manifest_hash, repository, operation, head_sha) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)`, approval.TenantID, approval.ID, approval.OperationID, approval.ApproverID, approval.PacketHash, approval.Nonce, approval.PolicyGeneration, unix(approval.CreatedAt), unix(approval.ExpiresAt), approval.ManifestHash, approval.Repository, approval.Operation, approval.HeadSHA)
	return err
}

func (tx *Tx) RevokeOperation(ctx context.Context, tenantID, operationID, agentID, reason string, revokedAt time.Time) error {
	result, err := tx.tx.ExecContext(ctx, `UPDATE operation_packets SET state = 'revoked', reason = ?, updated_at = ? WHERE tenant_id = ? AND id = ? AND agent_id = ? AND state IN ('awaiting_approval', 'authorized')`, reason, unix(revokedAt), tenantID, operationID, agentID)
	if err != nil {
		return err
	}
	return requireOneRow(result, "revocable operation")
}

// DeclineOperation records a HUMAN refusing a pending operation.
//
// Distinct from RevokeOperation, which is the AGENT withdrawing its own
// request, and from ExpireOperation, which is nobody deciding anything. Without
// this, the only way for a reviewer to say no was to let the approval lapse —
// indistinguishable in the audit trail from not having looked.
//
// Only `awaiting_approval` is declinable: once authorized, the agent may already
// have executed, and revoke is the correct verb for that window.
func (tx *Tx) DeclineOperation(ctx context.Context, tenantID, operationID, approver, reason string, declinedAt time.Time) error {
	result, err := tx.tx.ExecContext(ctx, `UPDATE operation_packets SET state = 'denied', decision_code = 'declined_by_human', reason = ?, actor_mode = ?, actor_subject = ?, updated_at = ? WHERE tenant_id = ? AND id = ? AND state = 'awaiting_approval'`,
		reason, "human_user", approver, unix(declinedAt), tenantID, operationID)
	if err != nil {
		return err
	}
	return requireOneRow(result, "declinable operation")
}

func (tx *Tx) ExpireOperation(ctx context.Context, tenantID, operationID, agentID string, expiredAt time.Time) error {
	result, err := tx.tx.ExecContext(ctx, `UPDATE operation_packets SET state = 'expired', reason = 'operation deadline expired', updated_at = ? WHERE tenant_id = ? AND id = ? AND agent_id = ? AND state IN ('awaiting_approval', 'authorized') AND expires_at <= ?`, unix(expiredAt), tenantID, operationID, agentID, unix(expiredAt))
	if err != nil {
		return err
	}
	return requireOneRow(result, "expirable operation")
}

func (tx *Tx) AppendAuthorityTransition(ctx context.Context, tenantID, eventID, kind, subjectID string, payload any, createdAt time.Time) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	previousHash := "GENESIS"
	var latest string
	err = tx.tx.QueryRowContext(ctx, `SELECT event_hash FROM audit_events WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1`, tenantID).Scan(&latest)
	if err == nil {
		previousHash = latest
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%d", previousHash, tenantID, eventID, kind, subjectID, payloadJSON, unix(createdAt))))
	eventHash := hex.EncodeToString(digest[:])
	return tx.AppendAudit(ctx, storage.AuditEvent{TenantID: tenantID, ID: eventID, Kind: kind, SubjectID: subjectID, PayloadJSON: payloadJSON, PreviousHash: previousHash, Hash: eventHash, CreatedAt: createdAt})
}

func IsUniqueViolation(err error) bool { return isUniqueConstraint(err) }
