package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/syncproposal"
)

// SyncRequest is the durable record of one private-mirror→public sync
// proposal moving through the human-authorized publication state machine.
type SyncRequest struct {
	TenantID, ID, PrivateRepository, PublicRepository, State string
	ProposalText, ProposalHash, AuthorizedText, CreatedBy    string
	CommitPacketJSON, PacketHeadSHA                          string
	FileManifest                                             []string
	PrivatePRNumber, PublicPRNumber                          int64
}

// SyncProposalHash canonically binds everything a human authorization covers:
// the proposal text, the derived file manifest, the asserted head SHA, and the
// COMMIT PACKET ITSELF.
//
// The packet is the load-bearing addition. The hash previously covered only
// text, manifest, and packetSHA — and packetSHA is a value the submitting agent
// asserts, not one derived from the stored bytes. A stored packet could
// therefore be replaced with different content while the hash still verified,
// so long as the asserted head SHA was unchanged: an approval could be
// transferred to bytes nobody reviewed. Publication is driven entirely by
// commit_packet_json, so that is precisely the field that must be bound.
//
// Fields are LENGTH-PREFIXED rather than separator-joined. A bare separator is
// only unambiguous when it cannot occur inside a field, and file paths are
// attacker-influenced: with "\x00" joining, a single manifest entry containing
// that byte hashes identically to two separate entries, so two different
// proposals could share one authorization. Length prefixes make the encoding
// injective whatever the content.
func SyncProposalHash(text string, files []string, packetSHA, packetJSON string) string {
	return syncproposal.Hash(text, files, packetSHA, packetJSON)
}

// legalSyncEdges DECLARES the post-authorization pipeline. It does not enforce
// it: AdvanceSync is its only reader and nothing calls AdvanceSync, because
// every real transition carries its own `WHERE ... AND state = ?` guard.
//
// So adding an edge here changes NOTHING at runtime, and a test asserting an
// edge is present would pass against a completely broken feature. Enforcement
// for `abandoned` lives in AbandonSync, and its tests assert database state
// after calling that function — never membership in this map.
var legalSyncEdges = map[[2]string]struct{}{
	{"authorized", "public_pr_created"}:    {},
	{"public_pr_created", "merged_public"}: {},
	{"merged_public", "done"}:              {},
	{"public_pr_created", "abandoned"}:     {},
	{"proposed", "closed"}:                 {},
	{"changes_requested", "closed"}:        {},
}

// CreateSyncProposal inserts a new proposal in state "proposed". When
// notifyAgent is non-empty a "sync.proposed" outbox event addressed to that
// agent (the queue curator) is appended in the same transaction, so the
// curator's notification can never exist without the proposal or vice versa.
func (db *DB) CreateSyncProposal(ctx context.Context, req SyncRequest, notifyAgent string, now time.Time) error {
	if req.TenantID == "" || req.ID == "" || req.PrivateRepository == "" || req.PublicRepository == "" ||
		req.CreatedBy == "" || req.ProposalText == "" || len(req.FileManifest) == 0 ||
		req.CommitPacketJSON == "" || req.PacketHeadSHA == "" {
		return errors.New("sync proposal is incomplete")
	}
	manifest, err := json.Marshal(req.FileManifest)
	if err != nil {
		return err
	}
	hash := SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	return db.WithTx(ctx, func(tx *Tx) error {
		if _, err := tx.tx.ExecContext(ctx, `INSERT INTO sync_requests
			(tenant_id, id, private_repository, public_repository, state, proposal_text, file_manifest_json, proposal_hash, commit_packet_json, packet_head_sha, created_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, 'proposed', ?, ?, ?, ?, ?, ?, ?, ?)`,
			req.TenantID, req.ID, req.PrivateRepository, req.PublicRepository,
			req.ProposalText, string(manifest), hash, req.CommitPacketJSON, req.PacketHeadSHA,
			req.CreatedBy, unix(now), unix(now)); err != nil {
			return err
		}
		event := map[string]any{"state": "proposed", "proposal_hash": hash, "packet_head_sha": req.PacketHeadSHA, "by": req.CreatedBy}
		if err := tx.AppendAuthorityTransition(ctx, req.TenantID, req.ID+":proposed", "sync_transition", req.ID, event, now); err != nil {
			return err
		}
		if notifyAgent == "" {
			return nil
		}
		payload, err := json.Marshal(map[string]any{"sync_id": req.ID, "private_repository": req.PrivateRepository, "public_repository": req.PublicRepository, "by": req.CreatedBy})
		if err != nil {
			return err
		}
		return tx.AppendOutbox(ctx, storage.OutboxEvent{
			TenantID: req.TenantID, ID: req.ID + ":sync.proposed", Kind: "sync.proposed",
			AudienceAgentID: notifyAgent, PayloadJSON: payload, State: "pending", CreatedAt: now,
		})
	})
}

func (db *DB) ReviseSyncProposal(ctx context.Context, tenantID, id, text string, files []string, packetJSON, packetSHA string, now time.Time) error {
	if tenantID == "" || id == "" || text == "" || len(files) == 0 || packetJSON == "" || packetSHA == "" {
		return errors.New("sync revision is incomplete")
	}
	manifest, err := json.Marshal(files)
	if err != nil {
		return err
	}
	hash := SyncProposalHash(text, files, packetSHA, packetJSON)
	return db.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE sync_requests
			SET state = 'proposed', proposal_text = ?, file_manifest_json = ?, proposal_hash = ?, commit_packet_json = ?, packet_head_sha = ?, updated_at = ?
			WHERE tenant_id = ? AND id = ? AND state = 'changes_requested'`,
			text, string(manifest), hash, packetJSON, packetSHA, unix(now), tenantID, id)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "sync revision"); err != nil {
			return err
		}
		event := map[string]any{"state": "proposed", "proposal_hash": hash, "packet_head_sha": packetSHA, "revised": true}
		return tx.AppendAuthorityTransition(ctx, tenantID, fmt.Sprintf("%s:proposed:%d", id, unix(now)), "sync_transition", id, event, now)
	})
}

func (db *DB) RequestSyncChanges(ctx context.Context, tenantID, id string, now time.Time) error {
	return db.syncEdge(ctx, tenantID, id, "proposed", "changes_requested", now, nil)
}

// AuthorizeSync moves proposed→authorized only when the caller-presented
// packet hash matches the stored proposal hash, freezing authorized_text.
// A sync already sitting at authorized re-authorizes idempotently (same hash
// required): a publish that died mid-flight leaves the state at authorized,
// and the human's retry tap must be able to resume it rather than draw
// authorization_stale (agent-kanban-wip-limit, 2026-07-24).
func (db *DB) AuthorizeSync(ctx context.Context, tenantID, id, packetHash string, now time.Time) error {
	if packetHash == "" {
		return errors.New("authorization requires the proposal packet hash")
	}
	return db.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE sync_requests
			SET state = 'authorized', authorized_text = proposal_text, updated_at = ?
			WHERE tenant_id = ? AND id = ? AND state IN ('proposed','authorized') AND proposal_hash = ?`,
			unix(now), tenantID, id, packetHash)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "sync authorization"); err != nil {
			return err
		}
		event := map[string]any{"state": "authorized", "packet_hash": packetHash}
		// The transition id carries the attempt time: an idempotent
		// re-authorize appends a new audit event instead of colliding with the
		// first tap's fixed id and aborting the whole transaction.
		return tx.AppendAuthorityTransition(ctx, tenantID, fmt.Sprintf("%s:authorized:%d", id, now.UnixNano()), "sync_transition", id, event, now)
	})
}

// AdvanceSync performs one legal forward edge of the post-authorization
// pipeline; every other transition is rejected.
func (db *DB) AdvanceSync(ctx context.Context, tenantID, id, from, to string, now time.Time) error {
	if _, ok := legalSyncEdges[[2]string{from, to}]; !ok {
		return fmt.Errorf("illegal sync transition %s→%s", from, to)
	}
	return db.syncEdge(ctx, tenantID, id, from, to, now, nil)
}

func (db *DB) syncEdge(ctx context.Context, tenantID, id, from, to string, now time.Time, extra map[string]any) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE sync_requests SET state = ?, updated_at = ?
			WHERE tenant_id = ? AND id = ? AND state = ?`, to, unix(now), tenantID, id, from)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "sync transition"); err != nil {
			return err
		}
		event := map[string]any{"state": to, "from": from}
		for k, v := range extra {
			event[k] = v
		}
		return tx.AppendAuthorityTransition(ctx, tenantID, fmt.Sprintf("%s:%s:%d", id, to, unix(now)), "sync_transition", id, event, now)
	})
}

func (db *DB) GetSyncRequest(ctx context.Context, tenantID, id string) (SyncRequest, error) {
	var item SyncRequest
	var manifest string
	var privatePR, publicPR sql.NullInt64
	var authorized, packetJSON, packetSHA sql.NullString
	err := db.sql.QueryRowContext(ctx, `SELECT tenant_id, id, private_repository, public_repository, state,
		COALESCE(proposal_text, ''), COALESCE(file_manifest_json, '[]'), COALESCE(proposal_hash, ''),
		commit_packet_json, packet_head_sha, authorized_text, private_pr_number, public_pr_number, created_by
		FROM sync_requests WHERE tenant_id = ? AND id = ?`, tenantID, id).
		Scan(&item.TenantID, &item.ID, &item.PrivateRepository, &item.PublicRepository, &item.State,
			&item.ProposalText, &manifest, &item.ProposalHash, &packetJSON, &packetSHA, &authorized, &privatePR, &publicPR, &item.CreatedBy)
	if err != nil {
		return SyncRequest{}, err
	}
	item.CommitPacketJSON, item.PacketHeadSHA, item.AuthorizedText = packetJSON.String, packetSHA.String, authorized.String
	item.PrivatePRNumber, item.PublicPRNumber = privatePR.Int64, publicPR.Int64
	if err := json.Unmarshal([]byte(manifest), &item.FileManifest); err != nil {
		return SyncRequest{}, err
	}
	return item, nil
}

// RequestSyncChangesNotify transitions proposed→changes_requested and, when
// notifyAgent is non-empty, appends a "sync.changes_requested" outbox event to
// the proposing agent in the same transaction.
func (db *DB) RequestSyncChangesNotify(ctx context.Context, tenantID, id, notifyAgent string, now time.Time) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE sync_requests SET state = 'changes_requested', updated_at = ?
			WHERE tenant_id = ? AND id = ? AND state = 'proposed'`, unix(now), tenantID, id)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "sync transition"); err != nil {
			return err
		}
		event := map[string]any{"state": "changes_requested", "from": "proposed"}
		if err := tx.AppendAuthorityTransition(ctx, tenantID, fmt.Sprintf("%s:changes_requested:%d", id, unix(now)), "sync_transition", id, event, now); err != nil {
			return err
		}
		if notifyAgent == "" {
			return nil
		}
		payload, err := json.Marshal(map[string]any{"sync_id": id})
		if err != nil {
			return err
		}
		return tx.AppendOutbox(ctx, storage.OutboxEvent{
			TenantID: tenantID, ID: fmt.Sprintf("%s:sync.changes_requested:%d", id, unix(now)), Kind: "sync.changes_requested",
			AudienceAgentID: notifyAgent, PayloadJSON: payload, State: "pending", CreatedAt: now,
		})
	})
}

// RecordSyncPublicPR advances authorized→public_pr_created and records the
// public PR number in one receipted transaction.
func (db *DB) RecordSyncPublicPR(ctx context.Context, tenantID, id string, number int64, now time.Time) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE sync_requests SET state = 'public_pr_created', public_pr_number = ?, updated_at = ?
			WHERE tenant_id = ? AND id = ? AND state = 'authorized'`, number, unix(now), tenantID, id)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "sync public pr"); err != nil {
			return err
		}
		event := map[string]any{"state": "public_pr_created", "from": "authorized", "public_pr_number": number}
		return tx.AppendAuthorityTransition(ctx, tenantID, id+":public_pr_created", "sync_transition", id, event, now)
	})
}

// AbandonSync moves a sync whose public pull request was closed WITHOUT being
// merged to its terminal state.
//
// Before this edge existed, `public_pr_created` had exactly one exit —
// `merged_public` — so a closed-unmerged PR left the row with no representable
// state and no code path, however correct, could move it.
//
// `abandoned` is deliberately not `done`: done means the shape reached the
// public repository, and an abandoned sync reached nothing. Collapsing them
// would make the receipt log lie about what happened.
func (db *DB) AbandonSync(ctx context.Context, tenantID, id string, publicPRNumber int64, now time.Time) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE sync_requests SET state = 'abandoned', updated_at = ?
			WHERE tenant_id = ? AND id = ? AND state = 'public_pr_created'`, unix(now), tenantID, id)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "abandonable sync"); err != nil {
			return err
		}
		event := map[string]any{"state": "abandoned", "from": "public_pr_created", "public_pr_number": publicPRNumber,
			"reason": "public pull request was closed without merging"}
		return tx.AppendAuthorityTransition(ctx, tenantID, id+":abandoned", "sync_transition", id, event, now)
	})
}

// CloseSync records a HUMAN declining a pre-PR outright.
//
// Distinct from AbandonSync, and deliberately a different state: `abandoned`
// means the public pull request died, `closed` means the reviewer said no.
// Collapsing them would make the audit trail unable to answer "did we decide
// this, or did it just fall over" — the same argument KTD2 makes against
// collapsing either into `done`.
//
// Closable from the states where a reviewer is actually looking at it. NOT from
// `authorized` or `public_pr_created`: by then publication is underway or done,
// and closing the pre-PR would not retract what is already on GitHub — a
// control that appears to undo something it cannot.
func (db *DB) CloseSync(ctx context.Context, tenantID, id, approver, reason string, now time.Time) error {
	if strings.TrimSpace(reason) == "" {
		reason = "declined by human reviewer"
	}
	return db.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE sync_requests SET state = 'closed', updated_at = ?
			WHERE tenant_id = ? AND id = ? AND state IN ('proposed','changes_requested')`, unix(now), tenantID, id)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "closable sync"); err != nil {
			return err
		}
		event := map[string]any{"state": "closed", "by": approver, "reason": reason}
		return tx.AppendAuthorityTransition(ctx, tenantID, id+":closed", "sync_transition", id, event, now)
	})
}

// AppendSyncEvent receipts an informational sync event (for example a failed
// publication attempt) without changing state.
func (db *DB) AppendSyncEvent(ctx context.Context, tenantID, id, kind string, payload map[string]any, now time.Time) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		return tx.AppendAuthorityTransition(ctx, tenantID, fmt.Sprintf("%s:%s:%d", id, kind, unix(now)), kind, id, payload, now)
	})
}

// CompleteSyncMerged advances public_pr_created→merged_public→done in one
// receipted transaction (both edges recorded, merge SHA captured) and, when
// notifyAgent is non-empty, appends the "sync.done" outbox event to it.
func (db *DB) CompleteSyncMerged(ctx context.Context, tenantID, id, mergeSHA, notifyAgent string, now time.Time) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE sync_requests SET state = 'done', updated_at = ?
			WHERE tenant_id = ? AND id = ? AND state = 'public_pr_created'`, unix(now), tenantID, id)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "sync completion"); err != nil {
			return err
		}
		merged := map[string]any{"state": "merged_public", "from": "public_pr_created", "merge_sha": mergeSHA}
		if err := tx.AppendAuthorityTransition(ctx, tenantID, id+":merged_public", "sync_transition", id, merged, now); err != nil {
			return err
		}
		done := map[string]any{"state": "done", "from": "merged_public"}
		if err := tx.AppendAuthorityTransition(ctx, tenantID, id+":done", "sync_transition", id, done, now); err != nil {
			return err
		}
		if notifyAgent == "" {
			return nil
		}
		payload, err := json.Marshal(map[string]any{"sync_id": id, "merge_sha": mergeSHA})
		if err != nil {
			return err
		}
		return tx.AppendOutbox(ctx, storage.OutboxEvent{
			TenantID: tenantID, ID: id + ":sync.done", Kind: "sync.done",
			AudienceAgentID: notifyAgent, PayloadJSON: payload, State: "pending", CreatedAt: now,
		})
	})
}

// ListOpenSyncRequests returns every sync request not yet done, newest first —
// the Everything view uses it to chip sync-linked pull requests.
func (db *DB) ListOpenSyncRequests(ctx context.Context, tenantID string) ([]SyncRequest, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT tenant_id, id, private_repository, public_repository, state,
		COALESCE(proposal_text, ''), COALESCE(file_manifest_json, '[]'), COALESCE(proposal_hash, ''),
		commit_packet_json, packet_head_sha, authorized_text, private_pr_number, public_pr_number, created_by
		FROM sync_requests WHERE tenant_id = ? AND state NOT IN ('done','abandoned','closed') ORDER BY updated_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SyncRequest
	for rows.Next() {
		var item SyncRequest
		var manifest string
		var privatePR, publicPR sql.NullInt64
		var authorized, packetJSON, packetSHA sql.NullString
		if err := rows.Scan(&item.TenantID, &item.ID, &item.PrivateRepository, &item.PublicRepository, &item.State,
			&item.ProposalText, &manifest, &item.ProposalHash, &packetJSON, &packetSHA, &authorized, &privatePR, &publicPR, &item.CreatedBy); err != nil {
			return nil, err
		}
		item.CommitPacketJSON, item.PacketHeadSHA, item.AuthorizedText = packetJSON.String, packetSHA.String, authorized.String
		item.PrivatePRNumber, item.PublicPRNumber = privatePR.Int64, publicPR.Int64
		if err := json.Unmarshal([]byte(manifest), &item.FileManifest); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
