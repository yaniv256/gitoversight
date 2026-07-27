package sqlite_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func seedSync(t *testing.T, db *sqlite.DB, id string, now time.Time) {
	t.Helper()
	if err := db.CreateSyncProposal(context.Background(), syncFixture(id), "", now); err != nil {
		t.Fatalf("seed sync %s: %v", id, err)
	}
}

func queueItems(ids ...string) []sqlite.QueueItem {
	items := make([]sqlite.QueueItem, 0, len(ids))
	for _, id := range ids {
		items = append(items, sqlite.QueueItem{ItemID: "q-" + id, Kind: "sync", Ref: id})
	}
	return items
}

func TestReplaceQueueOrderAndTop(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	for _, id := range []string{"s1", "s2", "s3"} {
		seedSync(t, db, id, now)
	}
	if err := db.ReplaceQueueOrder(context.Background(), "default", queueItems("s2", "s1", "s3"), now); err != nil {
		t.Fatalf("replace: %v", err)
	}
	top, depth, err := db.TopQueueItem(context.Background(), "default")
	if err != nil {
		t.Fatalf("top: %v", err)
	}
	if top.Ref != "s2" || depth != 3 {
		t.Fatalf("top=%q depth=%d, want s2/3", top.Ref, depth)
	}
}

func TestReplaceQueueOrderRejectsUnknownRef(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	seedSync(t, db, "s1", now)
	err := db.ReplaceQueueOrder(context.Background(), "default", queueItems("s1", "ghost"), now)
	if err == nil || !strings.Contains(err.Error(), "unknown_queue_ref") {
		t.Fatalf("unknown ref accepted (err=%v)", err)
	}
	// whole ordering rejected: queue stays empty
	_, depth, _ := db.TopQueueItem(context.Background(), "default")
	if depth != 0 {
		t.Fatalf("depth = %d after rejected ordering, want 0", depth)
	}
}

func TestDeferralModes(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	for _, id := range []string{"s1", "s2", "s3"} {
		seedSync(t, db, id, now)
	}
	if err := db.ReplaceQueueOrder(context.Background(), "default", queueItems("s1", "s2", "s3"), now); err != nil {
		t.Fatalf("replace: %v", err)
	}
	// skip: s1 moves one down -> top becomes s2
	if err := db.DeferQueueItem(context.Background(), "default", "q-s1", "skip", now.Add(time.Minute)); err != nil {
		t.Fatalf("skip: %v", err)
	}
	top, _, _ := db.TopQueueItem(context.Background(), "default")
	if top.Ref != "s2" {
		t.Fatalf("after skip top = %q, want s2", top.Ref)
	}
	// later: s2 moves ~5 down (bottom of a 3-item queue) -> top becomes s1
	if err := db.DeferQueueItem(context.Background(), "default", "q-s2", "later", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("later: %v", err)
	}
	top, _, _ = db.TopQueueItem(context.Background(), "default")
	if top.Ref != "s1" {
		t.Fatalf("after later top = %q, want s1", top.Ref)
	}
	// shelve: s1 leaves the queue -> top becomes s3, depth 2
	if err := db.DeferQueueItem(context.Background(), "default", "q-s1", "shelve", now.Add(3*time.Minute)); err != nil {
		t.Fatalf("shelve: %v", err)
	}
	top, depth, _ := db.TopQueueItem(context.Background(), "default")
	if top.Ref != "s3" || depth != 2 {
		t.Fatalf("after shelve top=%q depth=%d, want s3/2", top.Ref, depth)
	}
}

func TestEmptyQueueRead(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	item, depth, err := db.TopQueueItem(context.Background(), "default")
	if err != nil {
		t.Fatalf("top: %v", err)
	}
	if depth != 0 || item.ItemID != "" {
		t.Fatalf("empty queue returned %+v depth=%d", item, depth)
	}
}

func TestCompleteQueueItemForRefRemovesDoneSyncFromNow(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	for _, id := range []string{"s1", "s2"} {
		seedSync(t, db, id, now)
	}
	if err := db.ReplaceQueueOrder(context.Background(), "default", queueItems("s1", "s2"), now); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if err := db.CompleteQueueItemForRef(context.Background(), "default", "sync", "s1", now); err != nil {
		t.Fatalf("complete: %v", err)
	}
	top, depth, err := db.TopQueueItem(context.Background(), "default")
	if err != nil {
		t.Fatalf("top: %v", err)
	}
	if top.Ref != "s2" || depth != 1 {
		t.Fatalf("top=%q depth=%d, want s2/1 (done sync must leave the Now queue)", top.Ref, depth)
	}
	if err := db.CompleteQueueItemForRef(context.Background(), "default", "sync", "missing", now); err != nil {
		t.Fatalf("absent ref must be a no-op, got %v", err)
	}
}

func seedApprovalPacket(t *testing.T, db *sqlite.DB, id, repository, state string) {
	t.Helper()
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.PutOperation(context.Background(), storage.Operation{
			TenantID: "default", ID: id, AgentID: "zara", Repository: repository,
			Kind: "pull_request.reply", PacketHash: "hash-" + id, State: state,
			PolicyGeneration: 1, CreatedAt: time.Unix(1_800_000_000, 0), ExpiresAt: time.Unix(1_800_020_000, 0),
		})
	}); err != nil {
		t.Fatalf("seed packet %s: %v", id, err)
	}
}

// An operation blocked on a human must be findable BY that human. The queue is
// curated, so enrolment can be forgotten — and a forgotten enrolment looks,
// from the reviewer's side, exactly like having no pending work.
func TestUnsurfacedApprovalsNamesOperationsMissingFromTheQueue(t *testing.T) {
	t.Parallel()
	db := openDeclineTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	ctx := context.Background()

	// Distinct repositories: operation_packets is UNIQUE on
	// (tenant, repository, head_sha, approver), so same-repo fixtures collide.
	seedApprovalPacket(t, db, "op-queued", "yaniv256/one", "awaiting_approval")
	seedApprovalPacket(t, db, "op-forgotten", "yaniv256/two", "awaiting_approval")
	// A settled operation must never be reported: it is not waiting on anyone.
	seedApprovalPacket(t, db, "op-verified", "yaniv256/three", "verified")

	if err := db.ReplaceQueueOrder(ctx, "default",
		[]sqlite.QueueItem{{ItemID: "q-1", Kind: "approval", Ref: "op-queued"}}, now); err != nil {
		t.Fatalf("replace: %v", err)
	}

	missing, err := db.UnsurfacedApprovals(ctx, "default", now)
	if err != nil {
		t.Fatalf("unsurfaced: %v", err)
	}
	if len(missing) != 1 || missing[0].OperationID != "op-forgotten" {
		t.Fatalf("got %v, want exactly [op-forgotten] — the enrolled and the settled ones must not be reported", missing)
	}
	if missing[0].Expired || missing[0].Queued {
		t.Fatalf("op-forgotten: expired=%v queued=%v, want a live unqueued finding", missing[0].Expired, missing[0].Queued)
	}

	// Enrolling it clears the finding. Without this direction the query could
	// return a constant list and still pass everything above.
	if err := db.ReplaceQueueOrder(ctx, "default", []sqlite.QueueItem{
		{ItemID: "q-1", Kind: "approval", Ref: "op-queued"},
		{ItemID: "q-2", Kind: "approval", Ref: "op-forgotten"},
	}, now.Add(time.Minute)); err != nil {
		t.Fatalf("replace 2: %v", err)
	}
	cleared, err := db.UnsurfacedApprovals(ctx, "default", now)
	if err != nil {
		t.Fatalf("unsurfaced 2: %v", err)
	}
	if len(cleared) != 0 {
		t.Fatalf("after enrolling both, got %v, want none", cleared)
	}
}

// An expired operation is unusable even when the reviewer CAN see it: the
// authorize path matches approval_expires_at exactly, so the tap is rejected
// while state still reads awaiting_approval. Enrolling it would hand the human
// a button that fails when pressed.
func TestUnsurfacedApprovalsFlagsExpiredEvenWhenQueued(t *testing.T) {
	t.Parallel()
	db := openDeclineTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	ctx := context.Background()

	seedApprovalPacket(t, db, "op-live", "yaniv256/live", "awaiting_approval")
	seedApprovalPacket(t, db, "op-stale", "yaniv256/stale", "awaiting_approval")
	if err := db.ReplaceQueueOrder(ctx, "default", []sqlite.QueueItem{
		{ItemID: "q-live", Kind: "approval", Ref: "op-live"},
		{ItemID: "q-stale", Kind: "approval", Ref: "op-stale"},
	}, now); err != nil {
		t.Fatalf("replace: %v", err)
	}

	// Both are enrolled, so the queue check alone reports nothing. Read at a
	// moment past the fixtures' deadline (seedApprovalPacket expires at
	// 1_800_020_000) and the expired pair must surface anyway.
	after := time.Unix(1_800_020_001, 0)
	findings, err := db.UnsurfacedApprovals(ctx, "default", after)
	if err != nil {
		t.Fatalf("unsurfaced: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 — an expired operation is unusable even when queued", len(findings))
	}
	for _, finding := range findings {
		if !finding.Expired || !finding.Queued {
			t.Fatalf("%s: expired=%v queued=%v, want both true", finding.OperationID, finding.Expired, finding.Queued)
		}
	}

	// Before the deadline, the same enrolled pair is clean. Without this the
	// query could report every queued operation forever and still pass above.
	before := time.Unix(1_800_010_000, 0)
	clean, err := db.UnsurfacedApprovals(ctx, "default", before)
	if err != nil {
		t.Fatalf("unsurfaced before: %v", err)
	}
	if len(clean) != 0 {
		t.Fatalf("before the deadline got %v, want none", clean)
	}
}
