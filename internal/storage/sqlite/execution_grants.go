package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

type InterruptedExecution struct {
	TenantID, OperationID, AgentID string
}

func (db *DB) RecoverInterruptedExecutions(ctx context.Context, tenantID string, recoveredAt time.Time) ([]InterruptedExecution, error) {
	if tenantID == "" || recoveredAt.IsZero() {
		return nil, errors.New("interrupted execution recovery is incomplete")
	}
	var recovered []InterruptedExecution
	err := db.WithTx(ctx, func(tx *Tx) error {
		rows, err := tx.tx.QueryContext(ctx, `SELECT o.tenant_id, o.id, o.agent_id
			FROM operation_packets o JOIN execution_grants g ON g.tenant_id = o.tenant_id AND g.operation_id = o.id
			WHERE o.tenant_id = ? AND o.state = 'executing' AND g.consumed_at IS NOT NULL AND g.finalized_at IS NULL AND g.revoked_at IS NULL`, tenantID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var item InterruptedExecution
			if err := rows.Scan(&item.TenantID, &item.OperationID, &item.AgentID); err != nil {
				rows.Close()
				return err
			}
			recovered = append(recovered, item)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, item := range recovered {
			if result, err := tx.tx.ExecContext(ctx, `UPDATE operation_packets SET state = 'indeterminate', updated_at = ? WHERE tenant_id = ? AND id = ? AND state = 'executing'`, unix(recoveredAt), item.TenantID, item.OperationID); err != nil {
				return err
			} else if err := requireOneRow(result, "interrupted operation"); err != nil {
				return err
			}
			if result, err := tx.tx.ExecContext(ctx, `UPDATE execution_grants SET outcome = 'indeterminate', finalized_at = ? WHERE tenant_id = ? AND operation_id = ? AND consumed_at IS NOT NULL AND finalized_at IS NULL AND revoked_at IS NULL`, unix(recoveredAt), item.TenantID, item.OperationID); err != nil {
				return err
			} else if err := requireOneRow(result, "interrupted execution grant"); err != nil {
				return err
			}
			eventID := item.OperationID + ":startup-indeterminate"
			evidence, _ := json.Marshal(map[string]any{"source": "startup_recovery"})
			if _, err := tx.tx.ExecContext(ctx, `INSERT INTO reconciliations (tenant_id, id, operation_id, state, evidence_json, created_at) VALUES (?, ?, ?, 'indeterminate', ?, ?)`, item.TenantID, eventID, item.OperationID, evidence, unix(recoveredAt)); err != nil {
				return err
			}
			event := map[string]any{"state": "indeterminate", "source": "startup_recovery", "blind_retry_forbidden": true}
			if err := tx.AppendAuthorityTransition(ctx, item.TenantID, eventID, "execution_interrupted", item.OperationID, event, recoveredAt); err != nil {
				return err
			}
			payload, _ := json.Marshal(event)
			if err := tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: item.TenantID, ID: eventID, Kind: "execution_interrupted", AudienceAgentID: item.AgentID, PayloadJSON: payload, State: "pending", CreatedAt: recoveredAt}); err != nil {
				return err
			}
		}
		return nil
	})
	return recovered, err
}

func (tx *Tx) PutExecutionGrant(ctx context.Context, grant storage.ExecutionGrant) error {
	if grant.TenantID == "" || grant.ID == "" || grant.OperationID == "" || grant.PacketHash == "" || grant.MutationHash == "" || grant.WorkerID == "" || grant.Repository == "" || grant.Operation == "" || grant.ActorMode == "" || grant.CreatedAt.IsZero() || grant.ExpiresAt.IsZero() {
		return errors.New("execution grant is incomplete")
	}
	result, err := tx.tx.ExecContext(ctx, `INSERT INTO execution_grants (tenant_id, id, operation_id, packet_hash, worker_id, repository, operation, actor_mode, actor_subject, created_at, expires_at, mutation_hash, approval_id)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		FROM operation_packets
		WHERE tenant_id = ? AND id = ? AND state = 'authorized' AND packet_hash = ? AND mutation_hash = ? AND repository = ? AND operation = ? AND actor_mode = ? AND actor_subject = ?`,
		grant.TenantID, grant.ID, grant.OperationID, grant.PacketHash, grant.WorkerID, grant.Repository, grant.Operation, grant.ActorMode, grant.ActorSubject, unix(grant.CreatedAt), unix(grant.ExpiresAt), grant.MutationHash, nullableString(grant.ApprovalID),
		grant.TenantID, grant.OperationID, grant.PacketHash, grant.MutationHash, grant.Repository, grant.Operation, grant.ActorMode, grant.ActorSubject)
	if err != nil {
		return err
	}
	return requireOneRow(result, "authorized operation execution grant")
}

func (db *DB) ConsumeExecutionGrant(ctx context.Context, tokenHash, repository, operation, mutationHash string, consumedAt time.Time) (storage.ExecutionGrant, error) {
	return db.consumeExecutionGrant(ctx, tokenHash, "", "", repository, operation, mutationHash, consumedAt)
}

func (db *DB) ConsumeExecutionGrantForWorker(ctx context.Context, tokenHash, workerID, deliveryID, repository, operation, mutationHash string, consumedAt time.Time) (storage.ExecutionGrant, error) {
	if workerID == "" || deliveryID == "" {
		return storage.ExecutionGrant{}, errors.New("worker and delivery id are required")
	}
	return db.consumeExecutionGrant(ctx, tokenHash, workerID, deliveryID, repository, operation, mutationHash, consumedAt)
}

func (db *DB) ActiveConsumedExecutionGrantForWorker(ctx context.Context, tokenHash, workerID, deliveryID, repository, operation, mutationHash string, now time.Time) (storage.ExecutionGrant, error) {
	if tokenHash == "" || workerID == "" || deliveryID == "" || repository == "" || operation == "" || mutationHash == "" || now.IsZero() {
		return storage.ExecutionGrant{}, errors.New("consumed execution grant binding is incomplete")
	}
	return scanExecutionGrant(db.sql.QueryRowContext(ctx, `SELECT g.tenant_id, g.id, g.operation_id, g.packet_hash, g.mutation_hash, g.worker_id, g.repository, g.operation, g.actor_mode, g.actor_subject, g.approval_id, g.created_at, g.expires_at, g.consumed_at, g.revoked_at, g.outcome, g.finalized_at
		FROM execution_grants g
		JOIN operation_packets o ON o.tenant_id = g.tenant_id AND o.id = g.operation_id
		WHERE g.id = ? AND g.worker_id = ? AND g.delivery_id = ? AND g.repository = ? AND g.operation = ? AND g.mutation_hash = ?
		AND g.consumed_at IS NOT NULL AND g.revoked_at IS NULL AND g.finalized_at IS NULL AND g.expires_at > ? AND o.state = 'executing'`,
		tokenHash, workerID, deliveryID, repository, operation, mutationHash, unix(now)))
}

func (db *DB) IndeterminateExecutionGrantForWorker(ctx context.Context, tenantID, operationID, workerID, repository, operation, mutationHash string) (storage.ExecutionGrant, error) {
	if tenantID == "" || operationID == "" || workerID == "" || repository == "" || operation == "" || mutationHash == "" {
		return storage.ExecutionGrant{}, errors.New("reconciliation binding is incomplete")
	}
	return scanExecutionGrant(db.sql.QueryRowContext(ctx, `SELECT g.tenant_id, g.id, g.operation_id, g.packet_hash, g.mutation_hash, g.worker_id, g.repository, g.operation, g.actor_mode, g.actor_subject, g.approval_id, g.created_at, g.expires_at, g.consumed_at, g.revoked_at, g.outcome, g.finalized_at
		FROM execution_grants g
		JOIN operation_packets o ON o.tenant_id = g.tenant_id AND o.id = g.operation_id
		WHERE g.tenant_id = ? AND g.operation_id = ? AND g.worker_id = ? AND g.repository = ? AND g.operation = ? AND g.mutation_hash = ?
		AND g.outcome = 'indeterminate' AND g.finalized_at IS NOT NULL AND g.revoked_at IS NULL AND o.state = 'indeterminate'`,
		tenantID, operationID, workerID, repository, operation, mutationHash))
}

func (db *DB) FinalizeIndeterminateReconciliation(ctx context.Context, tenantID, operationID, workerID, outcome, resourceID string, finalizedAt time.Time) error {
	if outcome != "verified" && outcome != "reconciled_absent" {
		return errors.New("later reconciliation outcome is invalid")
	}
	if outcome == "verified" && resourceID == "" {
		return errors.New("verified reconciliation requires resource id")
	}
	return db.WithTx(ctx, func(tx *Tx) error {
		grant, err := scanExecutionGrant(tx.tx.QueryRowContext(ctx, `SELECT g.tenant_id, g.id, g.operation_id, g.packet_hash, g.mutation_hash, g.worker_id, g.repository, g.operation, g.actor_mode, g.actor_subject, g.approval_id, g.created_at, g.expires_at, g.consumed_at, g.revoked_at, g.outcome, g.finalized_at
			FROM execution_grants g JOIN operation_packets o ON o.tenant_id = g.tenant_id AND o.id = g.operation_id
			WHERE g.tenant_id = ? AND g.operation_id = ? AND g.worker_id = ? AND g.outcome = 'indeterminate' AND g.revoked_at IS NULL AND o.state = 'indeterminate'`, tenantID, operationID, workerID))
		if err != nil {
			return err
		}
		state := outcome
		if outcome == "reconciled_absent" {
			state = "absent"
		}
		result, err := tx.tx.ExecContext(ctx, `UPDATE operation_packets SET state = ?, resource_id = ?, updated_at = ? WHERE tenant_id = ? AND id = ? AND state = 'indeterminate'`, state, nullableString(resourceID), unix(finalizedAt), tenantID, operationID)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "indeterminate operation"); err != nil {
			return err
		}
		if outcome == "verified" && grant.ApprovalID != "" {
			// No expires_at check here: the approval already authorized the
			// execution inside its window (the grant is consumed), and GitHub has
			// independently verified the mutation landed. Finalization is
			// bookkeeping of an accomplished fact; an approval that expired while
			// the operation sat indeterminate must not strand it forever. A
			// revoked approval is a live human counter-signal and still blocks.
			approvalResult, err := tx.tx.ExecContext(ctx, `UPDATE approvals SET consumed_at = ? WHERE tenant_id = ? AND id = ? AND consumed_at IS NULL AND revoked_at IS NULL`, unix(finalizedAt), tenantID, grant.ApprovalID)
			if err != nil {
				return err
			}
			if err := requireOneRow(approvalResult, "later reconciled approval"); err != nil {
				return err
			}
		}
		evidence, _ := json.Marshal(map[string]any{"source": "later_independent_read", "worker_id": workerID})
		eventID := operationID + ":later:" + outcome
		if _, err := tx.tx.ExecContext(ctx, `INSERT INTO reconciliations (tenant_id, id, operation_id, state, evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`, tenantID, eventID, operationID, reconciliationState(outcome), evidence, unix(finalizedAt)); err != nil {
			return err
		}
		event := map[string]any{"state": state, "outcome": outcome, "source": "later_independent_read", "resource_id": resourceID}
		if err := tx.AppendAuthorityTransition(ctx, tenantID, eventID, "execution_later_reconciled", operationID, event, finalizedAt); err != nil {
			return err
		}
		payload, _ := json.Marshal(event)
		agentID, agentErr := tx.OperationAgent(ctx, tenantID, operationID)
		if agentErr != nil {
			return agentErr
		}
		return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: tenantID, ID: eventID, Kind: "execution_later_reconciled", AudienceAgentID: agentID, PayloadJSON: payload, State: "pending", CreatedAt: finalizedAt})
	})
}

func (db *DB) consumeExecutionGrant(ctx context.Context, tokenHash, workerID, deliveryID, repository, operation, mutationHash string, consumedAt time.Time) (storage.ExecutionGrant, error) {
	var grant storage.ExecutionGrant
	err := db.WithTx(ctx, func(tx *Tx) error {
		query := `UPDATE execution_grants SET consumed_at = ? WHERE id = ? AND repository = ? AND operation = ? AND mutation_hash = ? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?`
		args := []any{unix(consumedAt), tokenHash, repository, operation, mutationHash, unix(consumedAt)}
		if workerID != "" {
			query = `UPDATE execution_grants SET consumed_at = ?, delivery_id = ? WHERE id = ? AND repository = ? AND operation = ? AND mutation_hash = ? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ? AND worker_id = ?`
			args = []any{unix(consumedAt), deliveryID, tokenHash, repository, operation, mutationHash, unix(consumedAt), workerID}
		}
		result, err := tx.tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "consumable execution grant"); err != nil {
			return err
		}
		grant, err = scanExecutionGrant(tx.tx.QueryRowContext(ctx, `SELECT tenant_id, id, operation_id, packet_hash, mutation_hash, worker_id, repository, operation, actor_mode, actor_subject, approval_id, created_at, expires_at, consumed_at, revoked_at, outcome, finalized_at FROM execution_grants WHERE id = ?`, tokenHash))
		if err != nil {
			return err
		}
		result, err = tx.tx.ExecContext(ctx, `UPDATE operation_packets SET state = 'executing', updated_at = ? WHERE tenant_id = ? AND id = ? AND state = 'authorized'`, unix(consumedAt), grant.TenantID, grant.OperationID)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "authorized operation"); err != nil {
			return err
		}
		event := map[string]any{"state": "executing", "worker_id": grant.WorkerID}
		eventID := grant.OperationID + ":executing:" + grant.ID[:12]
		if err := tx.AppendAuthorityTransition(ctx, grant.TenantID, eventID, "execution_grant_consumed", grant.OperationID, event, consumedAt); err != nil {
			return err
		}
		payload, _ := json.Marshal(event)
		agentID, agentErr := tx.OperationAgent(ctx, grant.TenantID, grant.OperationID)
		if agentErr != nil {
			return agentErr
		}
		return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: grant.TenantID, ID: eventID, Kind: "execution_grant_consumed", AudienceAgentID: agentID, PayloadJSON: payload, State: "pending", CreatedAt: consumedAt})
	})
	return grant, err
}

func (db *DB) FinalizeExecutionGrant(ctx context.Context, tokenHash, outcome, resourceID, reason string, finalizedAt time.Time) (storage.ExecutionGrant, error) {
	if outcome == "verified" && resourceID == "" {
		return storage.ExecutionGrant{}, errors.New("verified execution requires resource id")
	}
	var grant storage.ExecutionGrant
	err := db.WithTx(ctx, func(tx *Tx) error {
		var err error
		grant, err = scanExecutionGrant(tx.tx.QueryRowContext(ctx, `SELECT tenant_id, id, operation_id, packet_hash, mutation_hash, worker_id, repository, operation, actor_mode, actor_subject, approval_id, created_at, expires_at, consumed_at, revoked_at, outcome, finalized_at FROM execution_grants WHERE id = ?`, tokenHash))
		if err != nil {
			return err
		}
		if grant.ConsumedAt == nil || grant.RevokedAt != nil || grant.FinalizedAt != nil {
			return errors.New("execution grant cannot be finalized")
		}
		result, err := tx.tx.ExecContext(ctx, `UPDATE execution_grants SET outcome = ?, finalized_at = ? WHERE id = ? AND consumed_at IS NOT NULL AND finalized_at IS NULL`, outcome, unix(finalizedAt), tokenHash)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "consumed execution grant"); err != nil {
			return err
		}
		state := outcome
		if outcome == "reconciled_absent" {
			state = "absent"
		}
		// When the worker reports WHY the mutation did not land (e.g. GitHub's merge
		// refusal), persist it into operation_packets.reason so a later status read
		// surfaces it — otherwise the reason lives only in the transient execute
		// response and any subsequent status GET shows the stale policy reason. An
		// empty reason preserves the existing policy reason (COALESCE keeps current).
		// (Investigation: pr-operations-absent-masks-execute-error.md)
		if reason != "" {
			result, err = tx.tx.ExecContext(ctx, `UPDATE operation_packets SET state = ?, resource_id = ?, reason = ?, updated_at = ? WHERE tenant_id = ? AND id = ? AND state = 'executing'`, state, nullableString(resourceID), reason, unix(finalizedAt), grant.TenantID, grant.OperationID)
		} else {
			result, err = tx.tx.ExecContext(ctx, `UPDATE operation_packets SET state = ?, resource_id = ?, updated_at = ? WHERE tenant_id = ? AND id = ? AND state = 'executing'`, state, nullableString(resourceID), unix(finalizedAt), grant.TenantID, grant.OperationID)
		}
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "executing operation"); err != nil {
			return err
		}
		if outcome == "verified" && grant.ApprovalID != "" {
			approvalResult, err := tx.tx.ExecContext(ctx, `UPDATE approvals SET consumed_at = ? WHERE tenant_id = ? AND id = ? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, unix(finalizedAt), grant.TenantID, grant.ApprovalID, unix(finalizedAt))
			if err != nil {
				return err
			}
			if err := requireOneRow(approvalResult, "approved execution"); err != nil {
				return err
			}
		}
		evidence := []byte(`{"source":"independent_read"}`)
		if reason != "" {
			if marshaled, marshalErr := json.Marshal(map[string]any{"source": "independent_read", "execute_error": reason}); marshalErr == nil {
				evidence = marshaled
			}
		}
		_, err = tx.tx.ExecContext(ctx, `INSERT INTO reconciliations (tenant_id, id, operation_id, state, evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`, grant.TenantID, grant.OperationID+":"+outcome, grant.OperationID, reconciliationState(outcome), evidence, unix(finalizedAt))
		if err != nil {
			return err
		}
		event := map[string]any{"state": state, "outcome": outcome, "resource_id": resourceID}
		if err := tx.AppendAuthorityTransition(ctx, grant.TenantID, grant.OperationID+":"+outcome, "execution_reconciled", grant.OperationID, event, finalizedAt); err != nil {
			return err
		}
		payload, _ := json.Marshal(event)
		agentID, agentErr := tx.OperationAgent(ctx, grant.TenantID, grant.OperationID)
		if agentErr != nil {
			return agentErr
		}
		return tx.AppendOutbox(ctx, storage.OutboxEvent{TenantID: grant.TenantID, ID: grant.OperationID + ":" + outcome, Kind: "execution_reconciled", AudienceAgentID: agentID, PayloadJSON: payload, State: "pending", CreatedAt: finalizedAt})
	})
	if err == nil {
		grant.Outcome = outcome
		grant.FinalizedAt = &finalizedAt
	}
	return grant, err
}

func (tx *Tx) RevokeUnconsumedExecutionGrant(ctx context.Context, tokenHash string, revokedAt time.Time) (storage.ExecutionGrant, error) {
	grant, err := scanExecutionGrant(tx.tx.QueryRowContext(ctx, `SELECT tenant_id, id, operation_id, packet_hash, mutation_hash, worker_id, repository, operation, actor_mode, actor_subject, approval_id, created_at, expires_at, consumed_at, revoked_at, outcome, finalized_at FROM execution_grants WHERE id = ?`, tokenHash))
	if err != nil {
		return storage.ExecutionGrant{}, err
	}
	result, err := tx.tx.ExecContext(ctx, `UPDATE execution_grants SET revoked_at = ? WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL AND finalized_at IS NULL`, unix(revokedAt), tokenHash)
	if err != nil {
		return storage.ExecutionGrant{}, err
	}
	if err := requireOneRow(result, "unconsumed execution grant"); err != nil {
		return storage.ExecutionGrant{}, err
	}
	grant.RevokedAt = &revokedAt
	return grant, nil
}

func (tx *Tx) RollbackUndeliveredConsumedExecutionGrant(ctx context.Context, tokenHash string, rolledBackAt time.Time) (storage.ExecutionGrant, error) {
	grant, err := scanExecutionGrant(tx.tx.QueryRowContext(ctx, `SELECT tenant_id, id, operation_id, packet_hash, mutation_hash, worker_id, repository, operation, actor_mode, actor_subject, approval_id, created_at, expires_at, consumed_at, revoked_at, outcome, finalized_at FROM execution_grants WHERE id = ?`, tokenHash))
	if err != nil {
		return storage.ExecutionGrant{}, err
	}
	result, err := tx.tx.ExecContext(ctx, `UPDATE execution_grants SET revoked_at = ? WHERE id = ? AND consumed_at IS NOT NULL AND revoked_at IS NULL AND finalized_at IS NULL`, unix(rolledBackAt), tokenHash)
	if err != nil {
		return storage.ExecutionGrant{}, err
	}
	if err := requireOneRow(result, "undelivered consumed execution grant"); err != nil {
		return storage.ExecutionGrant{}, err
	}
	result, err = tx.tx.ExecContext(ctx, `UPDATE operation_packets SET state = 'authorized', updated_at = ? WHERE tenant_id = ? AND id = ? AND state = 'executing'`, unix(rolledBackAt), grant.TenantID, grant.OperationID)
	if err != nil {
		return storage.ExecutionGrant{}, err
	}
	if err := requireOneRow(result, "undelivered executing operation"); err != nil {
		return storage.ExecutionGrant{}, err
	}
	grant.RevokedAt = &rolledBackAt
	return grant, nil
}

func scanExecutionGrant(row *sql.Row) (storage.ExecutionGrant, error) {
	var grant storage.ExecutionGrant
	var actorSubject, approvalID, outcome sql.NullString
	var createdAt, expiresAt int64
	var consumedAt, revokedAt, finalizedAt sql.NullInt64
	err := row.Scan(&grant.TenantID, &grant.ID, &grant.OperationID, &grant.PacketHash, &grant.MutationHash, &grant.WorkerID, &grant.Repository, &grant.Operation, &grant.ActorMode, &actorSubject, &approvalID, &createdAt, &expiresAt, &consumedAt, &revokedAt, &outcome, &finalizedAt)
	if err != nil {
		return storage.ExecutionGrant{}, err
	}
	grant.ActorSubject, grant.ApprovalID, grant.Outcome = actorSubject.String, approvalID.String, outcome.String
	grant.CreatedAt, grant.ExpiresAt = fromUnix(createdAt), fromUnix(expiresAt)
	grant.ConsumedAt, grant.RevokedAt, grant.FinalizedAt = optionalTime(consumedAt), optionalTime(revokedAt), optionalTime(finalizedAt)
	return grant, nil
}

func reconciliationState(outcome string) string {
	switch outcome {
	case "verified":
		return "committed"
	case "reconciled_absent":
		return "absent"
	default:
		return "indeterminate"
	}
}
