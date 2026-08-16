package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

// CreateStagedAsset records metadata only behind the durable authority
// checkpoint. The one-use capability itself is never included in audit or
// outbox payloads.
func (broker *DurableBroker) CreateStagedAsset(ctx context.Context, stage releaseasset.Stage) error {
	if err := broker.verifyWrite(); err != nil {
		return err
	}
	if err := releaseasset.ValidateStage(stage); err != nil {
		return err
	}
	if err := broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.PutStagedAsset(ctx, stage); err != nil {
			return err
		}
		return appendStagedAssetTransition(ctx, tx, stage, "staged_asset_created", stage.CreatedAt)
	}); err != nil {
		return err
	}
	return broker.commitWrite(ctx, stage.TenantID)
}

func (broker *DurableBroker) BeginStagedAssetUpload(ctx context.Context, stage releaseasset.Stage, attemptID, nonce string, nonceExpiresAt, at time.Time) error {
	if err := broker.verifyWrite(); err != nil {
		return err
	}
	if attemptID == "" || nonce == "" || nonceExpiresAt.IsZero() || at.IsZero() {
		return errors.New("staged asset upload attempt is incomplete")
	}
	if err := broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.ConsumeNonce(ctx, stage.TenantID, stage.CredentialID, nonce, nonceExpiresAt); err != nil {
			return err
		}
		nonceDigest := sha256.Sum256([]byte(nonce))
		if err := tx.AppendAuthorityTransition(ctx, stage.TenantID, "nonce:"+hex.EncodeToString(nonceDigest[:12]),
			"request_nonce_consumed", stage.CredentialID,
			map[string]any{"credential_id": stage.CredentialID, "expires_at": nonceExpiresAt}, at); err != nil {
			return err
		}
		if err := tx.BeginStagedAssetUpload(ctx, stage.TenantID, stage.ID, attemptID, at); err != nil {
			return err
		}
		return appendStagedAssetTransition(ctx, tx, stage, "staged_asset_upload_started", at)
	}); err != nil {
		return err
	}
	return broker.commitWrite(ctx, stage.TenantID)
}

func (broker *DurableBroker) MarkStagedAssetReady(ctx context.Context, stage releaseasset.Stage, objectKey string, at time.Time) error {
	if err := broker.verifyWrite(); err != nil {
		return err
	}
	if objectKey == "" || at.IsZero() {
		return errors.New("staged asset ready transition is incomplete")
	}
	if err := broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.MarkStagedAssetReady(ctx, stage.TenantID, stage.ID, objectKey, at); err != nil {
			return err
		}
		return appendStagedAssetTransition(ctx, tx, stage, "staged_asset_ready", at)
	}); err != nil {
		return err
	}
	return broker.commitWrite(ctx, stage.TenantID)
}

func (broker *DurableBroker) AbandonStagedAsset(ctx context.Context, stage releaseasset.Stage, at time.Time) error {
	if err := broker.verifyWrite(); err != nil {
		return err
	}
	if at.IsZero() {
		return errors.New("staged asset abandon transition is incomplete")
	}
	if err := broker.db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.AbandonStagedAsset(ctx, stage.TenantID, stage.ID, at); err != nil {
			return err
		}
		return appendStagedAssetTransition(ctx, tx, stage, "staged_asset_abandoned", at)
	}); err != nil {
		return err
	}
	return broker.commitWrite(ctx, stage.TenantID)
}

func appendStagedAssetTransition(ctx context.Context, tx *sqlite.Tx, stage releaseasset.Stage, kind string, at time.Time) error {
	payload := map[string]any{
		"stage_id": stage.ID, "repository": stage.Repository, "name": stage.Name,
		"content_type": stage.ContentType, "size": stage.ExpectedSize,
		"sha256": stage.ExpectedSHA256, "expires_at": stage.ExpiresAt,
	}
	eventID := stage.ID + ":" + kind
	if err := tx.AppendAuthorityTransition(ctx, stage.TenantID, eventID, kind, stage.ID, payload, at); err != nil {
		return err
	}
	outboxPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return tx.AppendOutbox(ctx, storage.OutboxEvent{
		TenantID: stage.TenantID, ID: eventID, Kind: kind, AudienceAgentID: stage.AgentID,
		PayloadJSON: outboxPayload, State: "pending", CreatedAt: at,
	})
}
