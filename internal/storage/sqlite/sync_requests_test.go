package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func openSyncTestDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "sync.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.EnsureTenant(context.Background(), "default", time.Unix(1_700_000_000, 0).UTC())
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return db
}

func syncFixture(id string) sqlite.SyncRequest {
	return sqlite.SyncRequest{
		TenantID: "default", ID: id,
		PrivateRepository: "yaniv256/agent-kanban.dev", PublicRepository: "yaniv256/agent-kanban",
		ProposalText: "Release the WIP-limit rules", FileManifest: []string{"SKILL.md", "CHANGELOG.md"},
		CommitPacketJSON: `{"commit":{"sha":"abc123"}}`, PacketHeadSHA: "abc123",
		CreatedBy: "zara",
	}
}

func TestCreateAndGetSyncProposal(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	req := syncFixture("sync-1")
	if err := db.CreateSyncProposal(context.Background(), req, "", now); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := db.GetSyncRequest(context.Background(), "default", "sync-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != "proposed" {
		t.Fatalf("state = %q, want proposed", got.State)
	}
	want := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	if got.ProposalHash != want {
		t.Fatal("stored hash does not match canonical hash")
	}
	if got.PacketHeadSHA != "abc123" || got.CommitPacketJSON == "" {
		t.Fatalf("packet not persisted: %+v", got)
	}
}

func TestReviseRequiresChangesRequested(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	if err := db.CreateSyncProposal(context.Background(), syncFixture("sync-2"), "", now); err != nil {
		t.Fatalf("create: %v", err)
	}
	// proposed → revise must FAIL (only changes_requested may revise)
	if err := db.ReviseSyncProposal(context.Background(), "default", "sync-2", "v2", []string{"SKILL.md"}, `{"commit":{"sha":"def456"}}`, "def456", now.Add(time.Minute)); err == nil {
		t.Fatal("revise allowed from state=proposed")
	}
	if err := db.RequestSyncChanges(context.Background(), "default", "sync-2", now.Add(time.Minute)); err != nil {
		t.Fatalf("request changes: %v", err)
	}
	if err := db.ReviseSyncProposal(context.Background(), "default", "sync-2", "v2", []string{"SKILL.md"}, `{"commit":{"sha":"def456"}}`, "def456", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("revise from changes_requested: %v", err)
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "sync-2")
	if got.State != "proposed" || got.PacketHeadSHA != "def456" {
		t.Fatalf("after revise: %+v", got)
	}
}

func TestAuthorizeBindsPacketHash(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	req := syncFixture("sync-3")
	if err := db.CreateSyncProposal(context.Background(), req, "", now); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.AuthorizeSync(context.Background(), "default", "sync-3", "wrong-hash", now.Add(time.Minute)); err == nil {
		t.Fatal("authorize accepted a stale packet hash")
	}
	good := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	if err := db.AuthorizeSync(context.Background(), "default", "sync-3", good, now.Add(time.Minute)); err != nil {
		t.Fatalf("authorize with correct hash: %v", err)
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "sync-3")
	if got.State != "authorized" || got.AuthorizedText != req.ProposalText {
		t.Fatalf("state=%q authorized_text=%q", got.State, got.AuthorizedText)
	}
}

func TestAdvanceOnlyLegalEdges(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	req := syncFixture("sync-4")
	if err := db.CreateSyncProposal(context.Background(), req, "", now); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.AdvanceSync(context.Background(), "default", "sync-4", "proposed", "done", now); err == nil {
		t.Fatal("illegal edge proposed→done allowed")
	}
	good := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	if err := db.AuthorizeSync(context.Background(), "default", "sync-4", good, now); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	for _, edge := range [][2]string{{"authorized", "public_pr_created"}, {"public_pr_created", "merged_public"}, {"merged_public", "done"}} {
		if err := db.AdvanceSync(context.Background(), "default", "sync-4", edge[0], edge[1], now.Add(time.Hour)); err != nil {
			t.Fatalf("legal edge %v: %v", edge, err)
		}
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "sync-4")
	if got.State != "done" {
		t.Fatalf("final state = %q, want done", got.State)
	}
}

// An approval must not be transferable to bytes nobody reviewed.
//
// Before the packet was bound, the hash covered only text, manifest, and the
// packet head SHA — a value the SUBMITTING AGENT asserts rather than one
// derived from the stored content. So the stored packet could be swapped for
// entirely different content while the asserted head SHA stayed the same, and
// the human's authorization hash would still verify. Publication reads
// commit_packet_json, so the swapped bytes are what would have published.
func TestSyncProposalHashBindsThePacketNotJustItsAssertedSHA(t *testing.T) {
	t.Parallel()
	reviewed := `{"object_package":{"blobs":[{"sha":"aa","content":"UkVBRE1F","encoding":"base64"}]}}`
	swapped := `{"object_package":{"blobs":[{"sha":"aa","content":"c2VjcmV0","encoding":"base64"}]}}`

	text, files, assertedSHA := "Release", []string{"README.md"}, "abc123"
	reviewedHash := sqlite.SyncProposalHash(text, files, assertedSHA, reviewed)
	swappedHash := sqlite.SyncProposalHash(text, files, assertedSHA, swapped)

	if reviewedHash == swappedHash {
		t.Fatal("swapping the packet under an unchanged head SHA must change the hash")
	}
	// Everything a human could SEE is identical between the two; only the bytes
	// that actually publish differ. That is exactly the case the binding covers.
	if sqlite.SyncProposalHash(text, files, assertedSHA, reviewed) != reviewedHash {
		t.Fatal("hash must be deterministic for identical inputs")
	}
}

// The field separator must not let one field's content impersonate another's,
// which would allow two different proposals to share an approval hash.
func TestSyncProposalHashSeparatesItsFields(t *testing.T) {
	t.Parallel()
	a := sqlite.SyncProposalHash("Release", []string{"a", "b"}, "sha", "pkt")
	b := sqlite.SyncProposalHash("Release", []string{"a\x00b"}, "sha", "pkt")
	if a == b {
		t.Fatal("a manifest entry containing the separator must not collide with two entries")
	}
}

// AbandonSync is exercised DIRECTLY here, below the API handler.
//
// The plan's KTD6 is the reason: legalSyncEdges is inert (AdvanceSync is its
// only reader and nothing calls it), so asserting the new edge is present in
// that map would pass against a completely broken feature. Enforcement lives in
// this function's own SQL guard, so that is what these tests exercise.
func TestAbandonSyncOnlyFromPublicPRCreated(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	req := syncFixture("s-ab")
	if err := db.CreateSyncProposal(context.Background(), req, "", now); err != nil {
		t.Fatal(err)
	}
	// A proposal that never reached a public PR cannot be abandoned: there is
	// no closed pull request to abandon it for.
	if err := db.AbandonSync(context.Background(), "default", "s-ab", 9, now); err == nil {
		t.Fatal("abandoned a sync that never opened a public pull request")
	}
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	if err := db.AuthorizeSync(context.Background(), "default", "s-ab", hash, now); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordSyncPublicPR(context.Background(), "default", "s-ab", 9, now); err != nil {
		t.Fatal(err)
	}
	if err := db.AbandonSync(context.Background(), "default", "s-ab", 9, now); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	got, err := db.GetSyncRequest(context.Background(), "default", "s-ab")
	if err != nil || got.State != "abandoned" {
		t.Fatalf("state = %q (%v)", got.State, err)
	}
	// Terminal: a second abandon must not re-transition or duplicate a receipt.
	if err := db.AbandonSync(context.Background(), "default", "s-ab", 9, now); err == nil {
		t.Fatal("abandoned an already-abandoned sync — the state is not terminal")
	}
}

// The closed-enum-by-negation: ListOpenSyncRequests filtered `state != 'done'`,
// so an abandoned row satisfied it and stayed "open" forever — silently
// defeating the requirement this whole change exists to satisfy.
func TestListOpenSyncRequestsExcludesAbandoned(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	req := syncFixture("s-hidden")
	if err := db.CreateSyncProposal(context.Background(), req, "", now); err != nil {
		t.Fatal(err)
	}
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	if err := db.AuthorizeSync(context.Background(), "default", "s-hidden", hash, now); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordSyncPublicPR(context.Background(), "default", "s-hidden", 12, now); err != nil {
		t.Fatal(err)
	}
	before, err := db.ListOpenSyncRequests(context.Background(), "default")
	if err != nil || len(before) != 1 {
		t.Fatalf("expected the sync to be open before abandoning: %d (%v)", len(before), err)
	}
	if err := db.AbandonSync(context.Background(), "default", "s-hidden", 12, now); err != nil {
		t.Fatal(err)
	}
	after, err := db.ListOpenSyncRequests(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Fatalf("abandoned sync still listed as open (%d rows) — the negation filter still selects it", len(after))
	}
}

// A revised pre-PR must carry its history. The loop already worked; what was
// missing is memory — the page rendered a revision identically to a first
// proposal, so the reviewer re-read it cold with no record of the change they
// themselves had requested.
func TestSyncProvenanceRecoversRevisionHistory(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	req := syncFixture("s-prov")
	if err := db.CreateSyncProposal(context.Background(), req, "", now); err != nil {
		t.Fatal(err)
	}

	// A FIRST proposal has no provenance. This is the false-positive guard: the
	// common case must not grow a banner announcing "revision 0".
	first, err := db.SyncProvenanceFor(context.Background(), "default", "s-prov")
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 0 || len(first.ChangeNotes) != 0 {
		t.Fatalf("a first proposal reported provenance: %+v", first)
	}

	if err := db.RequestSyncChanges(context.Background(), "default", "s-prov", now); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendSyncEvent(context.Background(), "default", "s-prov", "sync_change_note",
		map[string]any{"note": "drop the vendored binary", "by": "yaniv"}, now); err != nil {
		t.Fatal(err)
	}
	if err := db.ReviseSyncProposal(context.Background(), "default", "s-prov", "Revised text",
		[]string{"SKILL.md"}, `{"commit":{"sha":"def456"}}`, "def456", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	after, err := db.SyncProvenanceFor(context.Background(), "default", "s-prov")
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != 1 {
		t.Fatalf("revision = %d, want 1", after.Revision)
	}
	if after.LatestChangeNote() != "drop the vendored binary" {
		t.Fatalf("change note = %q — the reviewer's own request was lost", after.LatestChangeNote())
	}
}

// Two rounds must count as two, and the LATEST request is the one the current
// revision was written against.
func TestSyncProvenanceCountsEveryRound(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	req := syncFixture("s-prov2")
	if err := db.CreateSyncProposal(context.Background(), req, "", now); err != nil {
		t.Fatal(err)
	}
	for round, note := range []string{"first ask", "second ask"} {
		at := now.Add(time.Duration(round) * time.Hour)
		if err := db.RequestSyncChanges(context.Background(), "default", "s-prov2", at); err != nil {
			t.Fatalf("round %d request-changes: %v", round, err)
		}
		if err := db.AppendSyncEvent(context.Background(), "default", "s-prov2", "sync_change_note",
			map[string]any{"note": note, "by": "yaniv"}, at); err != nil {
			t.Fatalf("round %d note: %v", round, err)
		}
		if err := db.ReviseSyncProposal(context.Background(), "default", "s-prov2", "Revision",
			[]string{"SKILL.md"}, `{"commit":{"sha":"aaa"}}`, "aaa", at.Add(time.Minute)); err != nil {
			t.Fatalf("round %d revise: %v", round, err)
		}
	}
	got, err := db.SyncProvenanceFor(context.Background(), "default", "s-prov2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 2 {
		t.Fatalf("revision = %d, want 2", got.Revision)
	}
	if len(got.ChangeNotes) != 2 || got.LatestChangeNote() != "second ask" {
		t.Fatalf("change notes = %v, want the latest to be the second ask", got.ChangeNotes)
	}
}

// Closing is the reviewer saying no. Before it, the only options were approve
// or leave it in the queue forever — an absence of a decision, which the audit
// trail cannot distinguish from never having looked.
func TestCloseSyncIsTerminalAndOnlyFromReviewableStates(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	req := syncFixture("s-close")
	if err := db.CreateSyncProposal(context.Background(), req, "", now); err != nil {
		t.Fatal(err)
	}
	if err := db.CloseSync(context.Background(), "default", "s-close", "yaniv", "not wanted", now); err != nil {
		t.Fatalf("close: %v", err)
	}
	got, err := db.GetSyncRequest(context.Background(), "default", "s-close")
	if err != nil || got.State != "closed" {
		t.Fatalf("state = %q (%v)", got.State, err)
	}
	// Terminal: closing twice must not re-transition or duplicate a receipt.
	if err := db.CloseSync(context.Background(), "default", "s-close", "yaniv", "again", now); err == nil {
		t.Fatal("closed an already-closed pre-PR — the state is not terminal")
	}
	// And it must not be authorizable afterwards: a declined pre-PR that could
	// still publish would make the decline decorative.
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	if err := db.AuthorizeSync(context.Background(), "default", "s-close", hash, now); err == nil {
		t.Fatal("authorized a CLOSED pre-PR")
	}
	// The negation trap, third state: a closed pre-PR must leave the open list.
	open, err := db.ListOpenSyncRequests(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range open {
		if item.ID == "s-close" {
			t.Fatal("a closed pre-PR is still listed as open")
		}
	}
}

// Closing is offered only where a reviewer is actually deciding. Once
// publishing has started, closing the record would not retract what is already
// on GitHub — a control that appears to undo something it cannot.
func TestCloseSyncRefusedOncePublishingHasStarted(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	req := syncFixture("s-closelate")
	if err := db.CreateSyncProposal(context.Background(), req, "", now); err != nil {
		t.Fatal(err)
	}
	hash := sqlite.SyncProposalHash(req.ProposalText, req.FileManifest, req.PacketHeadSHA, req.CommitPacketJSON)
	if err := db.AuthorizeSync(context.Background(), "default", "s-closelate", hash, now); err != nil {
		t.Fatal(err)
	}
	if err := db.CloseSync(context.Background(), "default", "s-closelate", "yaniv", "", now); err == nil {
		t.Fatal("closed a pre-PR whose publication was already authorized")
	}
	got, _ := db.GetSyncRequest(context.Background(), "default", "s-closelate")
	if got.State != "authorized" {
		t.Fatalf("a refused close mutated the state to %q", got.State)
	}
}
