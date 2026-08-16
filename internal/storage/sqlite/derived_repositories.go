package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type DerivedRepository struct {
	TenantID, Repository, Visibility, OwnerAgentID, SourceOperationID, ActorSubject string
	CreatedAt                                                                       time.Time
}

func (db *DB) DerivedRepositories(ctx context.Context, tenantID string) ([]DerivedRepository, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT tenant_id, repository, visibility, owner_agent_id, source_operation_id, actor_subject, created_at FROM derived_repositories WHERE tenant_id = ? ORDER BY repository`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var repositories []DerivedRepository
	for rows.Next() {
		var item DerivedRepository
		var createdAt int64
		if err := rows.Scan(&item.TenantID, &item.Repository, &item.Visibility, &item.OwnerAgentID, &item.SourceOperationID, &item.ActorSubject, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt = fromUnix(createdAt)
		repositories = append(repositories, item)
	}
	return repositories, rows.Err()
}

func registerDerivedRepository(ctx context.Context, tx *sql.Tx, tenantID, operationID string, at time.Time) error {
	var repository, operation, agentID string
	var actorSubject sql.NullString
	var payload []byte
	if err := tx.QueryRowContext(ctx, `SELECT repository, operation, agent_id, actor_subject, payload_json FROM operation_packets WHERE tenant_id = ? AND id = ?`, tenantID, operationID).Scan(&repository, &operation, &agentID, &actorSubject, &payload); err != nil {
		return err
	}
	if operation != "repository.create" {
		return nil
	}
	var visibility sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT json_extract(?, '$.visibility')`, payload).Scan(&visibility); err != nil {
		return err
	}
	if visibility.String != "private" {
		return nil
	}
	var snapshotJSON []byte
	if err := tx.QueryRowContext(ctx, `SELECT snapshot_json FROM policy_generations WHERE tenant_id = ? ORDER BY generation DESC LIMIT 1`, tenantID).Scan(&snapshotJSON); err != nil {
		return err
	}
	var snapshot struct {
		Repositories map[string]json.RawMessage `json:"repositories"`
	}
	if err := json.Unmarshal(snapshotJSON, &snapshot); err != nil {
		return err
	}
	if _, configured := snapshot.Repositories[repository]; configured {
		return errors.New("derived repository conflicts with configured policy")
	}
	if actorSubject.String == "" {
		return errors.New("derived repository human actor is unavailable")
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO derived_repositories (tenant_id, repository, visibility, owner_agent_id, source_operation_id, actor_subject, created_at)
		VALUES (?, ?, 'private', ?, ?, ?, ?)
		ON CONFLICT(tenant_id, repository) DO NOTHING`, tenantID, repository, agentID, operationID, actorSubject.String, unix(at))
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows > 1 {
		return errors.New("derived repository registration failed")
	}
	var storedOwner, storedSource, storedVisibility, storedActor string
	if err := tx.QueryRowContext(ctx, `SELECT owner_agent_id, source_operation_id, visibility, actor_subject FROM derived_repositories WHERE tenant_id = ? AND repository = ?`, tenantID, repository).Scan(&storedOwner, &storedSource, &storedVisibility, &storedActor); err != nil {
		return err
	}
	if storedOwner != agentID || storedSource != operationID || storedVisibility != "private" || storedActor != actorSubject.String {
		return errors.New("derived repository registration conflicts with existing authority")
	}
	return nil
}
