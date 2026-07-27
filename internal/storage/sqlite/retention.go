package sqlite

import (
	"context"
	"time"
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
