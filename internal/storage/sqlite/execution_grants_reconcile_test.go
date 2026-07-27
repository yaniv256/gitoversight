package sqlite

import (
	"context"
	"testing"
	"time"
)

// A later reconciliation records what GitHub already proves. The approval was
// consumed to EXECUTE inside its window; its expiry afterwards must not make a
// stranded-but-landed operation permanently unfinalizable (live incident:
// agent-kanban-wip-limit-push, 2026-07-24 — approval TTL lapsed while the
// operation sat indeterminate, and every retry died on
// reconciliation_finalization_rejected).
func TestFinalizeIndeterminateReconciliationConsumesExpiredApproval(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	now := time.Unix(1_784_860_000, 0).UTC()
	past := now.Add(-2 * time.Hour)

	if err := db.WithTx(ctx, func(tx *Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO agents (tenant_id, id, created_at) VALUES (?, ?, ?)`, []any{"tenant-a", "zara", unix(past)}},
			{`INSERT INTO humans (tenant_id, id, github_login, created_at) VALUES (?, ?, ?, ?)`, []any{"tenant-a", "yaniv", "yaniv256", unix(past)}},
			{`INSERT INTO operation_packets (tenant_id, id, agent_id, repository, operation, packet_hash, state, policy_generation, created_at, expires_at, branch, actor_mode, actor_subject, mutation_hash) VALUES (?, ?, ?, ?, ?, ?, 'indeterminate', 1, ?, ?, ?, 'human_user', 'yaniv', ?)`,
				[]any{"tenant-a", "op-1", "zara", "yaniv256/agent-kanban", "branch.push", "packet-hash-1", unix(past), unix(past.Add(15 * time.Minute)), "sync/op-1", "mutation-hash-1"}},
			{`INSERT INTO approvals (tenant_id, id, operation_id, approver_id, packet_hash, nonce, policy_generation, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
				[]any{"tenant-a", "ap-1", "op-1", "yaniv", "packet-hash-1", "nonce-1", unix(past), unix(past.Add(15 * time.Minute))}},
			{`INSERT INTO execution_grants (tenant_id, id, operation_id, packet_hash, worker_id, repository, operation, actor_subject, created_at, expires_at, consumed_at, mutation_hash, approval_id, outcome, finalized_at, actor_mode) VALUES (?, ?, ?, ?, ?, ?, ?, 'yaniv', ?, ?, ?, ?, 'ap-1', 'indeterminate', ?, 'human_user')`,
				[]any{"tenant-a", "grant-1", "op-1", "packet-hash-1", "worker-a", "yaniv256/agent-kanban", "branch.push", unix(past), unix(past.Add(time.Minute)), unix(past), "mutation-hash-1", unix(past)}},
		} {
			if _, err := tx.tx.ExecContext(ctx, statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.FinalizeIndeterminateReconciliation(ctx, "tenant-a", "op-1", "worker-a", "verified", "refs/heads/sync/op-1", now); err != nil {
		t.Fatalf("finalization of a GitHub-verified reconcile must not fail on approval expiry: %v", err)
	}

	var state string
	var consumed *int64
	if err := db.sql.QueryRowContext(ctx, `SELECT o.state, a.consumed_at FROM operation_packets o JOIN approvals a ON a.tenant_id = o.tenant_id AND a.operation_id = o.id WHERE o.tenant_id = 'tenant-a' AND o.id = 'op-1'`).Scan(&state, &consumed); err != nil {
		t.Fatal(err)
	}
	if state != "verified" || consumed == nil || *consumed != unix(now) {
		t.Fatalf("state = %q, approval consumed_at = %v; want verified consumed at %d", state, consumed, unix(now))
	}
}

// A revoked approval is a live human counter-signal and must still block.
func TestFinalizeIndeterminateReconciliationStillRejectsRevokedApproval(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	now := time.Unix(1_784_860_000, 0).UTC()
	past := now.Add(-2 * time.Hour)

	if err := db.WithTx(ctx, func(tx *Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO agents (tenant_id, id, created_at) VALUES (?, ?, ?)`, []any{"tenant-a", "zara", unix(past)}},
			{`INSERT INTO humans (tenant_id, id, github_login, created_at) VALUES (?, ?, ?, ?)`, []any{"tenant-a", "yaniv", "yaniv256", unix(past)}},
			{`INSERT INTO operation_packets (tenant_id, id, agent_id, repository, operation, packet_hash, state, policy_generation, created_at, expires_at, branch, actor_mode, actor_subject, mutation_hash) VALUES (?, ?, ?, ?, ?, ?, 'indeterminate', 1, ?, ?, ?, 'human_user', 'yaniv', ?)`,
				[]any{"tenant-a", "op-2", "zara", "yaniv256/agent-kanban", "branch.push", "packet-hash-2", unix(past), unix(past.Add(15 * time.Minute)), "sync/op-2", "mutation-hash-2"}},
			{`INSERT INTO approvals (tenant_id, id, operation_id, approver_id, packet_hash, nonce, policy_generation, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
				[]any{"tenant-a", "ap-2", "op-2", "yaniv", "packet-hash-2", "nonce-2", unix(past), unix(past.Add(15 * time.Minute)), unix(past.Add(5 * time.Minute))}},
			{`INSERT INTO execution_grants (tenant_id, id, operation_id, packet_hash, worker_id, repository, operation, actor_subject, created_at, expires_at, consumed_at, mutation_hash, approval_id, outcome, finalized_at, actor_mode) VALUES (?, ?, ?, ?, ?, ?, ?, 'yaniv', ?, ?, ?, ?, 'ap-2', 'indeterminate', ?, 'human_user')`,
				[]any{"tenant-a", "grant-2", "op-2", "packet-hash-2", "worker-a", "yaniv256/agent-kanban", "branch.push", unix(past), unix(past.Add(time.Minute)), unix(past), "mutation-hash-2", unix(past)}},
		} {
			if _, err := tx.tx.ExecContext(ctx, statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.FinalizeIndeterminateReconciliation(ctx, "tenant-a", "op-2", "worker-a", "verified", "refs/heads/sync/op-2", now); err == nil {
		t.Fatal("finalization must still reject a revoked approval")
	}
}
