package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

func (tx *Tx) PutHumanSession(ctx context.Context, session storage.HumanSession) error {
	if session.TenantID == "" || session.IDHash == "" || session.CSRFHash == "" || session.CreatedAt.IsZero() || session.ExpiresAt.IsZero() {
		return errors.New("human session is incomplete")
	}
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO human_sessions (tenant_id, id_hash, human_id, csrf_hash, created_at, authenticated_at, recent_auth_until, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, session.TenantID, session.IDHash, nullableString(session.HumanID), session.CSRFHash, unix(session.CreatedAt), nullableTime(session.AuthenticatedAt), nullableTime(session.RecentAuthUntil), unix(session.ExpiresAt), nullableTime(session.RevokedAt))
	return err
}

func (tx *Tx) RotateHumanSession(ctx context.Context, tenantID, oldIDHash string, replacement storage.HumanSession, rotatedAt time.Time) error {
	result, err := tx.tx.ExecContext(ctx, `UPDATE human_sessions SET revoked_at = ? WHERE tenant_id = ? AND id_hash = ? AND human_id IS NULL AND revoked_at IS NULL AND expires_at > ?`, unix(rotatedAt), tenantID, oldIDHash, unix(rotatedAt))
	if err != nil {
		return err
	}
	if err := requireOneRow(result, "pending human session"); err != nil {
		return err
	}
	return tx.PutHumanSession(ctx, replacement)
}

func (db *DB) HumanSession(ctx context.Context, tenantID, idHash string) (storage.HumanSession, error) {
	var session storage.HumanSession
	var humanID sql.NullString
	var createdAt, expiresAt int64
	var authenticatedAt, recentAuthUntil, revokedAt sql.NullInt64
	err := db.sql.QueryRowContext(ctx, `SELECT tenant_id, id_hash, human_id, csrf_hash, created_at, authenticated_at, recent_auth_until, expires_at, revoked_at FROM human_sessions WHERE tenant_id = ? AND id_hash = ?`, tenantID, idHash).Scan(&session.TenantID, &session.IDHash, &humanID, &session.CSRFHash, &createdAt, &authenticatedAt, &recentAuthUntil, &expiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.HumanSession{}, ErrNotFound
	}
	if err != nil {
		return storage.HumanSession{}, err
	}
	session.HumanID = humanID.String
	session.CreatedAt, session.ExpiresAt = fromUnix(createdAt), fromUnix(expiresAt)
	session.AuthenticatedAt = optionalTime(authenticatedAt)
	session.RecentAuthUntil = optionalTime(recentAuthUntil)
	session.RevokedAt = optionalTime(revokedAt)
	return session, nil
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return unix(*value)
}

func optionalTime(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	result := fromUnix(value.Int64)
	return &result
}
