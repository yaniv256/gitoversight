package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

var ErrNotFound = errors.New("storage record not found")

func (db *DB) AgentEnrollment(ctx context.Context, tenantID, enrollmentID string) (storage.AgentEnrollment, error) {
	var enrollment storage.AgentEnrollment
	var supersedes, approvedBy sql.NullString
	var createdAt, expiresAt int64
	var proofVerifiedAt, approvedAt sql.NullInt64
	err := db.sql.QueryRowContext(ctx, `SELECT tenant_id, id, agent_id, credential_id, public_key, proof_message, supersedes_credential_id, created_at, expires_at, proof_verified_at, approved_at, approved_by FROM agent_enrollments WHERE tenant_id = ? AND id = ?`, tenantID, enrollmentID).Scan(
		&enrollment.TenantID, &enrollment.ID, &enrollment.AgentID, &enrollment.CredentialID,
		&enrollment.PublicKey, &enrollment.ProofMessage, &supersedes, &createdAt, &expiresAt,
		&proofVerifiedAt, &approvedAt, &approvedBy,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.AgentEnrollment{}, ErrNotFound
	}
	if err != nil {
		return storage.AgentEnrollment{}, err
	}
	enrollment.SupersedesCredentialID = supersedes.String
	enrollment.CreatedAt = fromUnix(createdAt)
	enrollment.ExpiresAt = fromUnix(expiresAt)
	if proofVerifiedAt.Valid {
		value := fromUnix(proofVerifiedAt.Int64)
		enrollment.ProofVerifiedAt = &value
	}
	if approvedAt.Valid {
		value := fromUnix(approvedAt.Int64)
		enrollment.ApprovedAt = &value
	}
	enrollment.ApprovedBy = approvedBy.String
	return enrollment, nil
}

func (db *DB) AgentCredential(ctx context.Context, tenantID, credentialID string) (storage.AgentCredential, error) {
	var credential storage.AgentCredential
	var createdAt int64
	var revokedAt, approvedAt sql.NullInt64
	var approvedBy, supersedes sql.NullString
	err := db.sql.QueryRowContext(ctx, `SELECT tenant_id, agent_id, id, public_key, created_at, revoked_at, approved_at, approved_by, supersedes_credential_id FROM agent_credentials WHERE tenant_id = ? AND id = ?`, tenantID, credentialID).Scan(
		&credential.TenantID, &credential.AgentID, &credential.ID, &credential.PublicKey,
		&createdAt, &revokedAt, &approvedAt, &approvedBy, &supersedes,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.AgentCredential{}, ErrNotFound
	}
	if err != nil {
		return storage.AgentCredential{}, err
	}
	credential.CreatedAt = fromUnix(createdAt)
	if revokedAt.Valid {
		value := fromUnix(revokedAt.Int64)
		credential.RevokedAt = &value
	}
	if approvedAt.Valid {
		credential.ApprovedAt = fromUnix(approvedAt.Int64)
	}
	credential.ApprovedBy = approvedBy.String
	credential.SupersedesCredentialID = supersedes.String
	return credential, nil
}

func fromUnix(value int64) time.Time { return time.Unix(value, 0).UTC() }
