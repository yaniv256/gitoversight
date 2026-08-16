package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

func (tx *Tx) PutStagedAsset(ctx context.Context, asset storage.StagedAsset) error {
	if asset.TenantID == "" || asset.ID == "" || asset.AgentID == "" || asset.CredentialID == "" ||
		asset.Repository == "" || asset.Name == "" || asset.ContentType == "" ||
		len(asset.ExpectedSHA256) != 64 || asset.ExpectedSize < 0 ||
		asset.ReservedSize != asset.ExpectedSize || asset.State != storage.StagedAssetCreated ||
		asset.CapabilityHash == "" || asset.CapabilityExpiresAt.IsZero() ||
		asset.CreatedAt.IsZero() || asset.UpdatedAt.IsZero() || asset.ExpiresAt.IsZero() {
		return errors.New("staged asset is incomplete")
	}
	_, err := tx.tx.ExecContext(ctx, `
		INSERT INTO staged_assets (
			tenant_id, id, agent_id, credential_id, repository, name, content_type,
			expected_sha256, expected_size, reserved_size, state, capability_hash,
			capability_expires_at, created_at, updated_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		asset.TenantID, asset.ID, asset.AgentID, asset.CredentialID, asset.Repository,
		asset.Name, asset.ContentType, strings.ToLower(asset.ExpectedSHA256),
		asset.ExpectedSize, asset.ReservedSize, asset.State, asset.CapabilityHash,
		unix(asset.CapabilityExpiresAt), unix(asset.CreatedAt), unix(asset.UpdatedAt), unix(asset.ExpiresAt))
	return err
}

func (tx *Tx) BeginStagedAssetUpload(ctx context.Context, tenantID, stageID, tempID string, at time.Time) error {
	if tenantID == "" || stageID == "" || tempID == "" || at.IsZero() {
		return errors.New("staged asset upload transition is incomplete")
	}
	result, err := tx.tx.ExecContext(ctx, `
		UPDATE staged_assets
		   SET state = ?, temp_id = ?, capability_used_at = ?, updated_at = ?
		 WHERE tenant_id = ? AND id = ? AND state = ?
		   AND capability_used_at IS NULL AND capability_expires_at > ?`,
		storage.StagedAssetUploading, tempID, unix(at), unix(at), tenantID, stageID,
		storage.StagedAssetCreated, unix(at))
	if err != nil {
		return err
	}
	return requireStageTransition(result)
}

func (tx *Tx) MarkStagedAssetReady(ctx context.Context, tenantID, stageID, objectKey string, at time.Time) error {
	if tenantID == "" || stageID == "" || objectKey == "" || at.IsZero() {
		return errors.New("staged asset ready transition is incomplete")
	}
	result, err := tx.tx.ExecContext(ctx, `
		UPDATE staged_assets
		   SET state = ?, object_key = ?, temp_id = NULL, reserved_size = 0, updated_at = ?
		 WHERE tenant_id = ? AND id = ? AND state = ? AND object_key IS NULL`,
		storage.StagedAssetReady, objectKey, unix(at), tenantID, stageID, storage.StagedAssetUploading)
	if err != nil {
		return err
	}
	return requireStageTransition(result)
}

func (tx *Tx) PinStagedAsset(ctx context.Context, asset storage.StagedAsset, operationID string, at time.Time) error {
	if asset.TenantID == "" || asset.ID == "" || asset.AgentID == "" || asset.CredentialID == "" ||
		asset.Repository == "" || asset.Name == "" || asset.ContentType == "" ||
		len(asset.ExpectedSHA256) != 64 || asset.ExpectedSize < 0 || operationID == "" || at.IsZero() {
		return errors.New("staged asset pin transition is incomplete")
	}
	result, err := tx.tx.ExecContext(ctx, `
			UPDATE staged_assets
			   SET state = ?, operation_id = ?, updated_at = ?
			 WHERE tenant_id = ? AND id = ? AND state = ? AND operation_id IS NULL
			   AND agent_id = ? AND credential_id = ? AND repository = ?
			   AND name = ? AND content_type = ? AND expected_sha256 = ? AND expected_size = ?
			   AND object_key IS NOT NULL AND expires_at > ?`,
		storage.StagedAssetPinned, operationID, unix(at), asset.TenantID, asset.ID,
		storage.StagedAssetReady, asset.AgentID, asset.CredentialID, asset.Repository,
		asset.Name, asset.ContentType, strings.ToLower(asset.ExpectedSHA256), asset.ExpectedSize, unix(at))
	if err != nil {
		return err
	}
	return requireStageTransition(result)
}

func (tx *Tx) AbandonStagedAsset(ctx context.Context, tenantID, stageID string, at time.Time) error {
	return tx.finishUnpinnedStagedAsset(ctx, tenantID, stageID, storage.StagedAssetAbandoned, at)
}

func (tx *Tx) ExpireStagedAsset(ctx context.Context, tenantID, stageID string, at time.Time) error {
	return tx.finishUnpinnedStagedAsset(ctx, tenantID, stageID, storage.StagedAssetExpired, at)
}

func (tx *Tx) finishUnpinnedStagedAsset(ctx context.Context, tenantID, stageID string, state storage.StagedAssetState, at time.Time) error {
	if tenantID == "" || stageID == "" || at.IsZero() {
		return errors.New("staged asset terminal transition is incomplete")
	}
	result, err := tx.tx.ExecContext(ctx, `
		UPDATE staged_assets
		   SET state = ?, reserved_size = 0, temp_id = NULL, updated_at = ?
		 WHERE tenant_id = ? AND id = ? AND operation_id IS NULL
		   AND state IN (?, ?, ?)`,
		state, unix(at), tenantID, stageID, storage.StagedAssetCreated,
		storage.StagedAssetUploading, storage.StagedAssetReady)
	if err != nil {
		return err
	}
	return requireStageTransition(result)
}

func (db *DB) StagedAssetForOwner(ctx context.Context, tenantID, stageID, agentID, credentialID, repository string) (storage.StagedAsset, error) {
	var asset storage.StagedAsset
	var state string
	var capabilityExpiresAt, createdAt, updatedAt, expiresAt int64
	var capabilityUsedAt sql.NullInt64
	var tempID, objectKey, operationID sql.NullString
	err := db.sql.QueryRowContext(ctx, `
		SELECT tenant_id, id, agent_id, credential_id, repository, name, content_type,
		       expected_sha256, expected_size, reserved_size, state, capability_hash,
		       capability_expires_at, capability_used_at, temp_id, object_key, operation_id,
		       created_at, updated_at, expires_at
		  FROM staged_assets
		 WHERE tenant_id = ? AND id = ? AND agent_id = ? AND credential_id = ? AND repository = ?`,
		tenantID, stageID, agentID, credentialID, repository).Scan(
		&asset.TenantID, &asset.ID, &asset.AgentID, &asset.CredentialID, &asset.Repository,
		&asset.Name, &asset.ContentType, &asset.ExpectedSHA256, &asset.ExpectedSize,
		&asset.ReservedSize, &state, &asset.CapabilityHash, &capabilityExpiresAt,
		&capabilityUsedAt, &tempID, &objectKey, &operationID, &createdAt, &updatedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.StagedAsset{}, storage.ErrStagedAssetNotFound
	}
	if err != nil {
		return storage.StagedAsset{}, err
	}
	asset.State = storage.StagedAssetState(state)
	asset.CapabilityExpiresAt = time.Unix(capabilityExpiresAt, 0).UTC()
	asset.CreatedAt = time.Unix(createdAt, 0).UTC()
	asset.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	asset.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	if capabilityUsedAt.Valid {
		value := time.Unix(capabilityUsedAt.Int64, 0).UTC()
		asset.CapabilityUsedAt = &value
	}
	asset.TempID = tempID.String
	asset.ObjectKey = objectKey.String
	asset.OperationID = operationID.String
	return asset, nil
}

func requireStageTransition(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return storage.ErrStagedAssetState
	}
	return nil
}

var _ releaseasset.MetadataTransaction = (*Tx)(nil)
var _ releaseasset.MetadataReader = (*DB)(nil)
