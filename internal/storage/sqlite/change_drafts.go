package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
)

func (db *DB) PutChangeDraft(ctx context.Context, draft changedraft.StoredDraft) error {
	if draft.TenantID == "" || draft.AgentID == "" || draft.ID == "" ||
		!draft.ExpiresAt.After(draft.CreatedAt) {
		return errors.New("change draft is incomplete")
	}
	if err := changedraft.VerifyPreview(draft.Preview); err != nil {
		return fmt.Errorf("verify change draft preview: %w", err)
	}
	previewJSON, err := json.Marshal(draft.Preview)
	if err != nil {
		return err
	}
	changesJSON, err := json.Marshal(draft.Changes)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx, `INSERT INTO change_drafts
		(tenant_id, agent_id, id, repository, base_commit, preview_hash, preview_json, changes_json, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		draft.TenantID, draft.AgentID, draft.ID, draft.Preview.Repository,
		string(draft.Preview.BaseCommit), draft.Preview.Hash, previewJSON, changesJSON,
		unix(draft.CreatedAt), unix(draft.ExpiresAt))
	return err
}

// ChangeDraft returns a draft owned by the exact tenant and agent. Expiry is
// returned to the application service so it can distinguish an expired draft
// from an unknown identifier; DeleteExpiredChangeDrafts performs reclamation.
// Scope mismatches return ErrNotFound to avoid leaking IDs across principals.
func (db *DB) ChangeDraft(ctx context.Context, tenantID, agentID, id string) (changedraft.StoredDraft, error) {
	var draft changedraft.StoredDraft
	var repository, baseCommit, previewHash string
	var previewJSON, changesJSON []byte
	var createdAt, expiresAt int64
	err := db.sql.QueryRowContext(ctx, `SELECT repository, base_commit, preview_hash, preview_json, changes_json, created_at, expires_at
		FROM change_drafts WHERE tenant_id = ? AND agent_id = ? AND id = ?`,
		tenantID, agentID, id).Scan(
		&repository, &baseCommit, &previewHash, &previewJSON, &changesJSON, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return changedraft.StoredDraft{}, fmt.Errorf("%w: %w", ErrNotFound, changedraft.ErrStoredDraftNotFound)
	}
	if err != nil {
		return changedraft.StoredDraft{}, err
	}
	if err := json.Unmarshal(previewJSON, &draft.Preview); err != nil {
		return changedraft.StoredDraft{}, fmt.Errorf("decode change draft preview: %w", err)
	}
	if err := json.Unmarshal(changesJSON, &draft.Changes); err != nil {
		return changedraft.StoredDraft{}, fmt.Errorf("decode change draft changes: %w", err)
	}
	if draft.Preview.Repository != repository || string(draft.Preview.BaseCommit) != baseCommit || draft.Preview.Hash != previewHash {
		return changedraft.StoredDraft{}, changedraft.ErrPreviewTampered
	}
	if err := changedraft.VerifyPreview(draft.Preview); err != nil {
		return changedraft.StoredDraft{}, err
	}
	draft.ID, draft.TenantID, draft.AgentID = id, tenantID, agentID
	draft.CreatedAt, draft.ExpiresAt = fromUnix(createdAt), fromUnix(expiresAt)
	return draft, nil
}

func (db *DB) DeleteExpiredChangeDrafts(ctx context.Context, now time.Time) (int64, error) {
	result, err := db.sql.ExecContext(ctx, `DELETE FROM change_drafts WHERE expires_at <= ?`, unix(now))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) PutChangeDraftPublication(ctx context.Context, binding changedraft.PublicationBinding) error {
	if binding.TenantID == "" || binding.AgentID == "" || binding.OperationID == "" || binding.RequestHash == "" || binding.HeadSHA == "" || binding.CreatedAt.IsZero() {
		return errors.New("change draft publication binding is incomplete")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO change_draft_publications
		(tenant_id, agent_id, operation_id, request_hash, head_sha, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		binding.TenantID, binding.AgentID, binding.OperationID, binding.RequestHash, binding.HeadSHA, unix(binding.CreatedAt))
	return err
}

func (db *DB) ChangeDraftPublication(ctx context.Context, tenantID, agentID, operationID string) (changedraft.PublicationBinding, error) {
	var binding changedraft.PublicationBinding
	var createdAt int64
	err := db.sql.QueryRowContext(ctx, `SELECT request_hash, head_sha, created_at FROM change_draft_publications
		WHERE tenant_id = ? AND agent_id = ? AND operation_id = ?`, tenantID, agentID, operationID).
		Scan(&binding.RequestHash, &binding.HeadSHA, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return changedraft.PublicationBinding{}, fmt.Errorf("%w: %w", ErrNotFound, changedraft.ErrStoredPublicationNotFound)
	}
	if err != nil {
		return changedraft.PublicationBinding{}, err
	}
	binding.TenantID, binding.AgentID, binding.OperationID = tenantID, agentID, operationID
	binding.CreatedAt = fromUnix(createdAt)
	return binding, nil
}
