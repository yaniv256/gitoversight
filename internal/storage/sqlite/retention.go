package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

// Terminal packet states whose payload_json is no longer consulted by any
// execution path: authorization binds to packet_hash/manifest_hash/head_sha,
// the audit chain records transitions, and only Execute (which runs on
// 'authorized' packets) forwards the payload to the worker. 'indeterminate'
// stays out of this list because reconciliation may still need the payload.
var terminalPayloadStates = []any{"verified", "denied", "revoked", "expired", "absent"}

// PruneTerminalPacketPayloads clears payload_json on operation packets that
// reached a terminal state before the cutoff. The payload carries commit
// packets whose object packages embed entire repository trees (production,
// 2026-07-22: 279MB of a 283MB database), and terminal packets keep every
// authorization-relevant field — only the redundant blob is dropped. Returns
// the number of packets pruned.
func (db *DB) PruneTerminalPacketPayloads(ctx context.Context, cutoff time.Time) (int64, error) {
	args := append([]any{unix(cutoff)}, terminalPayloadStates...)
	args = append(args, unix(cutoff))
	result, err := db.sql.ExecContext(ctx, `UPDATE operation_packets
		SET payload_json = NULL, updated_at = ?
		WHERE state IN (?, ?, ?, ?, ?)
		  AND payload_json IS NOT NULL
		  AND COALESCE(updated_at, created_at) <= ?`, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ClaimStagedAssetCleanup atomically releases a terminal operation pin and
// claims exactly one object for deletion. Nonterminal operation states never
// satisfy the join, and a stale crashed claim becomes retryable without
// changing the operation's durable state.
func (db *DB) ClaimStagedAssetCleanup(ctx context.Context, now, terminalCutoff, staleClaimCutoff time.Time) (storage.StagedAssetCleanup, bool, error) {
	var claim storage.StagedAssetCleanup
	err := db.WithTx(ctx, func(tx *Tx) error {
		if _, err := tx.tx.ExecContext(ctx, `
			UPDATE staged_assets
			   SET cleanup_claimed_at = NULL,
			       cleanup_attempts = cleanup_attempts + 1,
			       cleanup_error = 'cleanup owner interrupted'
			 WHERE state = 'releasable' AND cleanup_claimed_at IS NOT NULL
			   AND cleanup_claimed_at <= ?`,
			unix(staleClaimCutoff)); err != nil {
			return err
		}
		var tenantID, stageID, objectKey, digest string
		var size int64
		var attempts int
		err := tx.tx.QueryRowContext(ctx, `
			SELECT s.tenant_id, s.id, s.object_key, s.expected_size,
			       s.expected_sha256, s.cleanup_attempts
			  FROM staged_assets s
			  LEFT JOIN operation_packets o
			    ON o.tenant_id = s.tenant_id AND o.id = s.operation_id
			 WHERE s.object_key IS NOT NULL AND s.cleanup_claimed_at IS NULL
			   AND (
			        (s.state = 'releasable'
			         AND (s.cleanup_error IS NULL OR s.updated_at < ?))
			     OR (s.state IN ('abandoned','expired') AND s.updated_at <= ?)
			     OR (s.state = 'ready' AND s.expires_at <= ?)
			     OR (s.state = 'pinned'
			         AND o.state IN ('verified','denied','revoked','expired','absent')
			         AND COALESCE(o.updated_at, o.created_at) <= ?)
			   )
			 ORDER BY s.updated_at, s.tenant_id, s.id
			 LIMIT 1`,
			unix(now), unix(terminalCutoff), unix(now), unix(terminalCutoff)).
			Scan(&tenantID, &stageID, &objectKey, &size, &digest, &attempts)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result, err := tx.tx.ExecContext(ctx, `
			UPDATE staged_assets
			   SET state = 'releasable', operation_id = NULL,
			       cleanup_claimed_at = ?, cleanup_error = NULL, updated_at = ?
			 WHERE tenant_id = ? AND id = ? AND cleanup_claimed_at IS NULL
			   AND object_key = ?`,
			unix(now), unix(now), tenantID, stageID, objectKey)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "staged asset cleanup claim"); err != nil {
			return err
		}
		claim = storage.StagedAssetCleanup{
			TenantID: tenantID, StageID: stageID, ObjectKey: objectKey,
			ExpectedSize: size, ExpectedSHA256: digest, Attempts: attempts,
		}
		return nil
	})
	return claim, claim.StageID != "", err
}

func (db *DB) CompleteStagedAssetCleanup(ctx context.Context, claim storage.StagedAssetCleanup) error {
	result, err := db.sql.ExecContext(ctx, `
		DELETE FROM staged_assets
		 WHERE tenant_id = ? AND id = ? AND object_key = ?
		   AND state = 'releasable' AND operation_id IS NULL
		   AND cleanup_claimed_at IS NOT NULL`,
		claim.TenantID, claim.StageID, claim.ObjectKey)
	if err != nil {
		return err
	}
	return requireOneRow(result, "claimed staged asset cleanup")
}

func (db *DB) FailStagedAssetCleanup(ctx context.Context, claim storage.StagedAssetCleanup, reason string, failedAt time.Time) error {
	reason = strings.TrimSpace(reason)
	if len(reason) > 300 {
		reason = reason[:300]
	}
	result, err := db.sql.ExecContext(ctx, `
		UPDATE staged_assets
		   SET cleanup_claimed_at = NULL,
		       cleanup_attempts = cleanup_attempts + 1,
		       cleanup_error = ?, updated_at = ?
		 WHERE tenant_id = ? AND id = ? AND object_key = ?
		   AND state = 'releasable' AND operation_id IS NULL
		   AND cleanup_claimed_at IS NOT NULL`,
		reason, unix(failedAt), claim.TenantID, claim.StageID, claim.ObjectKey)
	if err != nil {
		return err
	}
	return requireOneRow(result, "failed staged asset cleanup")
}

// PruneExpiredEmptyStages removes issued stages that never published bytes.
// Uploading rows are intentionally excluded: crash repair must first decide
// whether an immutable object was published before its ready checkpoint.
func (db *DB) PruneExpiredEmptyStages(ctx context.Context, now time.Time) (int64, error) {
	result, err := db.sql.ExecContext(ctx, `
		DELETE FROM staged_assets
		 WHERE state IN ('created','abandoned','expired')
		   AND object_key IS NULL AND operation_id IS NULL AND expires_at <= ?`,
		unix(now))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) StaleUploadingStages(ctx context.Context, cutoff time.Time) ([]storage.StagedAsset, error) {
	rows, err := db.sql.QueryContext(ctx, `
		SELECT tenant_id, id, expected_size, expected_sha256
		  FROM staged_assets
		 WHERE state = 'uploading' AND operation_id IS NULL AND updated_at <= ?
		 ORDER BY updated_at LIMIT 100`, unix(cutoff))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assets []storage.StagedAsset
	for rows.Next() {
		var asset storage.StagedAsset
		if err := rows.Scan(&asset.TenantID, &asset.ID, &asset.ExpectedSize, &asset.ExpectedSHA256); err != nil {
			return nil, err
		}
		assets = append(assets, asset)
	}
	return assets, rows.Err()
}

func (db *DB) RecoverStagedAssetReady(ctx context.Context, tenantID, stageID, objectKey string, recoveredAt time.Time) error {
	result, err := db.sql.ExecContext(ctx, `
		UPDATE staged_assets
		   SET state = 'ready', object_key = ?, temp_id = NULL,
		       reserved_size = 0, updated_at = ?
		 WHERE tenant_id = ? AND id = ? AND state = 'uploading'
		   AND operation_id IS NULL AND object_key IS NULL`,
		objectKey, unix(recoveredAt), tenantID, stageID)
	if err != nil {
		return err
	}
	return requireOneRow(result, "recoverable staged asset")
}

func (db *DB) ExpireStaleUploadingStage(ctx context.Context, tenantID, stageID string, expiredAt time.Time) error {
	result, err := db.sql.ExecContext(ctx, `
		UPDATE staged_assets
		   SET state = 'expired', temp_id = NULL, reserved_size = 0, updated_at = ?
		 WHERE tenant_id = ? AND id = ? AND state = 'uploading'
		   AND operation_id IS NULL AND object_key IS NULL`,
		unix(expiredAt), tenantID, stageID)
	if err != nil {
		return err
	}
	return requireOneRow(result, "stale staged upload")
}

func (db *DB) StagedAssetObjectKeys(ctx context.Context) (map[string]struct{}, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT object_key FROM staged_assets WHERE object_key IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := map[string]struct{}{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys[key] = struct{}{}
	}
	return keys, rows.Err()
}

func (db *DB) MaintenanceOpen(ctx context.Context) (bool, uint64, error) {
	state, generation, err := db.MaintenanceBarrier(ctx)
	return state == "open", generation, err
}

func (db *DB) MaintenanceBarrier(ctx context.Context) (string, uint64, error) {
	var state string
	var generation uint64
	err := db.sql.QueryRowContext(ctx, `
		SELECT state, generation FROM maintenance_barrier WHERE singleton = 1`).
		Scan(&state, &generation)
	return state, generation, err
}

func (db *DB) BeginMaintenanceActivity(ctx context.Context, kind string, now time.Time) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `
			UPDATE maintenance_activity
			   SET active_count = active_count + 1, updated_at = ?
			 WHERE kind = ?
			   AND (SELECT state FROM maintenance_barrier WHERE singleton = 1) = 'open'`,
			unix(now), kind)
		if err != nil {
			return err
		}
		return requireOneRow(result, "open maintenance activity")
	})
}

func (db *DB) EndMaintenanceActivity(ctx context.Context, kind string, now time.Time) error {
	result, err := db.sql.ExecContext(ctx, `
		UPDATE maintenance_activity
		   SET active_count = active_count - 1, updated_at = ?
		 WHERE kind = ? AND active_count > 0`, unix(now), kind)
	if err != nil {
		return err
	}
	return requireOneRow(result, "active maintenance activity")
}

func (db *DB) StagedAssetBackupObjects(ctx context.Context) ([]storage.StagedAssetBackupObject, error) {
	rows, err := db.sql.QueryContext(ctx, `
		SELECT object_key, expected_size, expected_sha256
		  FROM staged_assets
		 WHERE object_key IS NOT NULL
		 ORDER BY object_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var objects []storage.StagedAssetBackupObject
	for rows.Next() {
		var object storage.StagedAssetBackupObject
		if err := rows.Scan(&object.Key, &object.Size, &object.SHA256); err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}
	return objects, rows.Err()
}
