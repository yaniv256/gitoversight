package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// QueueItem is one entry in the human's curated review queue. The curator
// agent supplies the full ordering; the Now view reads the top item.
type QueueItem struct {
	TenantID, ItemID, Kind, Ref, State string
	Position                           int64
}

// ReplaceQueueOrder installs the curator's full ordering in one transaction.
// Every (kind, ref) must resolve to an existing broker record: kind "sync"
// validates against sync_requests, kind "approval" against operation_packets.
// Kind "review" refs cannot be resolved inside sqlite (they name PRs on
// GitHub); the API handler must validate them against the worker PR read
// BEFORE calling this method — the store still rejects unknown kinds. An
// ordering containing any unresolvable ref is rejected whole.
func (db *DB) ReplaceQueueOrder(ctx context.Context, tenantID string, items []QueueItem, now time.Time) error {
	if tenantID == "" {
		return errors.New("queue ordering requires a tenant")
	}
	return db.WithTx(ctx, func(tx *Tx) error {
		for _, item := range items {
			if item.ItemID == "" || item.Ref == "" {
				return errors.New("queue item is incomplete")
			}
			switch item.Kind {
			case "sync":
				var one int
				if err := tx.tx.QueryRowContext(ctx, `SELECT 1 FROM sync_requests WHERE tenant_id = ? AND id = ?`, tenantID, item.Ref).Scan(&one); err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return fmt.Errorf("unknown_queue_ref: sync %q is not a broker record", item.Ref)
					}
					return err
				}
			case "approval":
				var one int
				if err := tx.tx.QueryRowContext(ctx, `SELECT 1 FROM operation_packets WHERE tenant_id = ? AND id = ?`, tenantID, item.Ref).Scan(&one); err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return fmt.Errorf("unknown_queue_ref: approval %q is not a broker record", item.Ref)
					}
					return err
				}
			case "review":
				// Validated by the API handler against the worker PR read.
			default:
				return fmt.Errorf("unknown_queue_ref: kind %q is not recognized", item.Kind)
			}
		}
		if _, err := tx.tx.ExecContext(ctx, `DELETE FROM human_queue WHERE tenant_id = ? AND state = 'queued'`, tenantID); err != nil {
			return err
		}
		for index, item := range items {
			if _, err := tx.tx.ExecContext(ctx, `INSERT INTO human_queue (tenant_id, item_id, kind, ref, position, state, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, 'queued', ?, ?)
				ON CONFLICT(tenant_id, item_id) DO UPDATE SET kind = excluded.kind, ref = excluded.ref, position = excluded.position, state = 'queued', updated_at = excluded.updated_at`,
				tenantID, item.ItemID, item.Kind, item.Ref, index+1, unix(now), unix(now)); err != nil {
				return err
			}
		}
		event := map[string]any{"count": len(items)}
		return tx.AppendAuthorityTransition(ctx, tenantID, fmt.Sprintf("queue:reorder:%d", unix(now)), "queue_reordered", "human_queue", event, now)
	})
}

// DeferQueueItem applies one of the graduated deferrals the human can take on
// the top item: "skip" pushes it one position down, "later" pushes it five
// down (bottom when shorter), "shelve" retires it from the queue entirely.
func (db *DB) DeferQueueItem(ctx context.Context, tenantID, itemID, mode string, now time.Time) error {
	offset := 0
	switch mode {
	case "skip":
		offset = 1
	case "later":
		offset = 5
	case "shelve":
	default:
		return fmt.Errorf("unknown deferral mode %q", mode)
	}
	return db.WithTx(ctx, func(tx *Tx) error {
		rows, err := tx.tx.QueryContext(ctx, `SELECT item_id FROM human_queue WHERE tenant_id = ? AND state = 'queued' ORDER BY position`, tenantID)
		if err != nil {
			return err
		}
		var order []string
		found := -1
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			if id == itemID {
				found = len(order)
			}
			order = append(order, id)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if found < 0 {
			return fmt.Errorf("queue item %q is not queued", itemID)
		}
		if mode == "shelve" {
			if _, err := tx.tx.ExecContext(ctx, `UPDATE human_queue SET state = 'shelved', updated_at = ? WHERE tenant_id = ? AND item_id = ?`, unix(now), tenantID, itemID); err != nil {
				return err
			}
			order = append(order[:found], order[found+1:]...)
		} else {
			target := found + offset
			if target > len(order)-1 {
				target = len(order) - 1
			}
			moved := order[found]
			order = append(order[:found], order[found+1:]...)
			order = append(order[:target], append([]string{moved}, order[target:]...)...)
		}
		for index, id := range order {
			if _, err := tx.tx.ExecContext(ctx, `UPDATE human_queue SET position = ?, updated_at = ? WHERE tenant_id = ? AND item_id = ?`, index+1, unix(now), tenantID, id); err != nil {
				return err
			}
		}
		event := map[string]any{"item": itemID, "mode": mode}
		return tx.AppendAuthorityTransition(ctx, tenantID, fmt.Sprintf("queue:%s:%s:%d", mode, itemID, unix(now)), "queue_deferred", itemID, event, now)
	})
}

// TopQueueItem returns the current head of the queue and the total queued
// depth (including the head). Depth 0 with an empty item means nothing is
// queued.
func (db *DB) TopQueueItem(ctx context.Context, tenantID string) (QueueItem, int64, error) {
	var depth int64
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM human_queue WHERE tenant_id = ? AND state = 'queued'`, tenantID).Scan(&depth); err != nil {
		return QueueItem{}, 0, err
	}
	if depth == 0 {
		return QueueItem{}, 0, nil
	}
	var item QueueItem
	err := db.sql.QueryRowContext(ctx, `SELECT tenant_id, item_id, kind, ref, position, state FROM human_queue
		WHERE tenant_id = ? AND state = 'queued' ORDER BY position LIMIT 1`, tenantID).
		Scan(&item.TenantID, &item.ItemID, &item.Kind, &item.Ref, &item.Position, &item.State)
	if err != nil {
		return QueueItem{}, 0, err
	}
	return item, depth, nil
}

// CompleteQueueItemForRef drops a queue entry once the record it points at has
// reached a terminal state (e.g. a sync tapped Done). Absent or already
// completed entries are a no-op: the queue is a view over broker records, not
// their source of truth, so completion here is best-effort bookkeeping.
func (db *DB) CompleteQueueItemForRef(ctx context.Context, tenantID, kind, ref string, now time.Time) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE human_queue SET state = 'done', updated_at = ? WHERE tenant_id = ? AND kind = ? AND ref = ? AND state = 'queued'`, unix(now), tenantID, kind, ref)
	return err
}

// UnsurfacedApproval is one operation a human cannot actually act on, and why.
//
// The two failures need DIFFERENT responses, so the type keeps them apart
// rather than collapsing them into one list: an unqueued-but-live operation
// wants enrolling, while an expired one wants re-issuing or discarding.
// Enrolling an expired packet would put a button in front of the reviewer that
// fails when pressed — trading an invisible operation for a lying one.
type UnsurfacedApproval struct {
	OperationID string
	ExpiresAt   time.Time
	// Expired means the deadline has passed, so approval would be REJECTED by
	// the authorize path's binding check even though state still reads
	// awaiting_approval. Nothing sweeps these to 'expired' proactively.
	Expired bool
	// Queued means the reviewer can see it. An expired-but-queued operation is
	// still a defect: it is visible and unusable.
	Queued bool
}

// UnsurfacedApprovals names operations that are waiting on a human but cannot
// be acted on — either absent from that human's queue, or past their deadline — so nothing the reviewer can see says they exist.
//
// The queue is deliberately CURATED: an agent installs a full ordering through
// ReplaceQueueOrder, and nothing auto-enrols an operation when it reaches
// awaiting_approval. That is a defensible design for a scarce attention budget,
// but it makes enrolment a step that can simply be forgotten, with no signal
// that it was — and a forgotten enrolment is indistinguishable, from the
// reviewer's side, from having no pending work at all.
//
// Observed live 2026-07-26: `u4-live-closed-1` sat at awaiting_approval while
// the Now page read "1 in your queue" and listed an unrelated request. The
// operation was blocked ON a human and invisible TO that human.
//
// `awaiting_approval` is a claim about ONE COLUMN. Whether anyone can act on the
// operation depends on the queue (can they see it?) and on expires_at (would
// the approval still bind?). This query is the only thing that compares all
// three.
//
// The expiry half was added after the first version shipped: asked what the
// pending approval was, I read `state` — which still said awaiting_approval —
// and told the reviewer to go tap a button whose binding had expired 34 minutes
// earlier. Reading the field that confirms an expectation while skipping the one
// that would refute it is the same defect this whole plan is about.
//
// Shelved and deferred entries count as surfaced: the human saw them and chose
// to postpone. Only a total absence from the queue is a defect.
func (db *DB) UnsurfacedApprovals(ctx context.Context, tenantID string, now time.Time) ([]UnsurfacedApproval, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT p.id, p.expires_at,
		    EXISTS (SELECT 1 FROM human_queue q
		            WHERE q.tenant_id = p.tenant_id AND q.kind = 'approval' AND q.ref = p.id) AS queued
		FROM operation_packets p
		WHERE p.tenant_id = ? AND p.state = 'awaiting_approval'
		  AND (
		      p.expires_at <= ?
		      OR NOT EXISTS (SELECT 1 FROM human_queue q
		                     WHERE q.tenant_id = p.tenant_id AND q.kind = 'approval' AND q.ref = p.id)
		  )
		ORDER BY p.id`, tenantID, unix(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []UnsurfacedApproval
	for rows.Next() {
		var finding UnsurfacedApproval
		var expiresAt int64
		var queued bool
		if err := rows.Scan(&finding.OperationID, &expiresAt, &queued); err != nil {
			return nil, err
		}
		finding.ExpiresAt = fromUnix(expiresAt)
		finding.Expired = !finding.ExpiresAt.After(now)
		finding.Queued = queued
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}
