package ui_test

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/attribution"
	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/prpreview"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/ui"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

// prPreviewBases stands in for the worker's public-repository read.
type prPreviewBases struct {
	entries []githubapp.TreeEntry
	blobs   map[string]string
	err     error
}

func (b prPreviewBases) ReadBase(workerrpc.BaseReadRequest) (workerrpc.BaseRead, error) {
	if b.err != nil {
		return workerrpc.BaseRead{}, b.err
	}
	return workerrpc.BaseRead{CommitSHA: "basecommit", TreeSHA: "basetree", Entries: b.entries}, nil
}

func (b prPreviewBases) ReadBlob(_, sha string) ([]byte, error) {
	return []byte(b.blobs[sha]), nil
}

// seedPrePR stores a sync whose packet describes a real change against the base.
func seedPrePR(t *testing.T, db *sqlite.DB, entries []commitpacket.TreeEntry, blobs []commitpacket.Blob) sqlite.SyncRequest {
	t.Helper()
	author := commitpacket.Signature{Name: "Zara", Email: "zara@example.com", Date: "2026-07-26T10:00:00Z"}
	treeSHA := gitTreeSHA(entries)
	commitSHA := gitCommitSHA(treeSHA, "Release\n", author)
	packet := commitpacket.Packet{
		Tree:   commitpacket.Tree{SHA: treeSHA, Entries: entries},
		Blobs:  blobs,
		Commit: commitpacket.Commit{SHA: commitSHA, Message: "Release\n", Tree: treeSHA, Author: author, Committer: author},
	}
	encoded, err := json.Marshal(map[string]any{"sha": commitSHA, "object_package": packet})
	if err != nil {
		t.Fatal(err)
	}
	manifest := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.Delete {
			manifest = append(manifest, entry.Path)
		}
	}
	req := sqlite.SyncRequest{TenantID: "default", ID: "pre-1",
		PrivateRepository: "yaniv256/mirror.dev", PublicRepository: "yaniv256/mirror",
		ProposalText: "Release\n\nDetails.", FileManifest: manifest,
		CommitPacketJSON: string(encoded), PacketHeadSHA: commitSHA, CreatedBy: "zara"}
	if err := db.CreateSyncProposal(context.Background(), req, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, _ := db.GetSyncRequest(context.Background(), "default", "pre-1")
	return out
}

// renderPrePR returns the page with HTML entities decoded, so assertions match
// what a REVIEWER SEES rather than an incidental escaping choice. html/template
// escapes "+" to "&#43;" in text context — correct, and rendered as "+" by any
// browser — so asserting on raw serialized HTML would test the encoder, not the
// page.
func renderPrePR(t *testing.T, db *sqlite.DB, bases ui.Bases, identities []attribution.Identity) string {
	t.Helper()
	handler, err := ui.NewHandler(ui.Config{Store: db, Policy: everythingPolicy(), Pulls: &fakeLister{},
		Bases: bases, PrivateIdentities: identities})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, uiGet("/ui/sync/pre-1"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	return response.Body.String()
}

// visibleText is the page as a READER sees it: HTML entities resolved. Use it
// for content assertions ("+hello world"), because html/template escapes "+"
// to "&#43;" in text context — correct, and rendered as "+" by any browser.
// Use the raw body for escaping assertions, which are about the wire form.
func visibleText(body string) string { return html.UnescapeString(body) }

// gitBlobSHA computes git's real blob hash. commitpacket.Validate recomputes
// every hash from the bytes, so a fixture with placeholder SHAs is REJECTED —
// the page refuses it, correctly. These helpers build packets that validate.
func gitBlobSHA(content string) string {
	digest := sha1.New()
	fmt.Fprintf(digest, "blob %d\x00", len(content))
	digest.Write([]byte(content))
	return hex.EncodeToString(digest.Sum(nil))
}

func gitTreeSHA(entries []commitpacket.TreeEntry) string {
	var body []byte
	sorted := append([]commitpacket.TreeEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for _, entry := range sorted {
		raw, _ := hex.DecodeString(entry.SHA)
		body = append(body, []byte(entry.Mode+" "+entry.Path+"\x00")...)
		body = append(body, raw...)
	}
	digest := sha1.New()
	fmt.Fprintf(digest, "tree %d\x00", len(body))
	digest.Write(body)
	return hex.EncodeToString(digest.Sum(nil))
}

func gitCommitSHA(treeSHA, message string, author commitpacket.Signature) string {
	parsed, _ := time.Parse(time.RFC3339, author.Date)
	identity := fmt.Sprintf("%s <%s> %d %s", author.Name, author.Email, parsed.Unix(), parsed.Format("-0700"))
	body := fmt.Sprintf("tree %s\nauthor %s\ncommitter %s\n\n%s", treeSHA, identity, identity, message)
	digest := sha1.New()
	fmt.Fprintf(digest, "commit %d\x00", len(body))
	digest.Write([]byte(body))
	return hex.EncodeToString(digest.Sum(nil))
}

// prePRFile builds a matched tree entry and blob for one path.
func prePRFile(path, content string) (commitpacket.TreeEntry, commitpacket.Blob) {
	sha := gitBlobSHA(content)
	return commitpacket.TreeEntry{Path: path, Mode: "100644", Type: "blob", SHA: sha},
		commitpacket.Blob{SHA: sha, Content: base64.StdEncoding.EncodeToString([]byte(content)), Encoding: "base64"}
}

// The page must show the actual DIFF, not a bare filename list. This is the
// whole point: a human could previously authorize a public publication having
// seen no content at all.
func TestSyncPageRendersRealDiffLines(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	entry, blob := prePRFile("README.md", "hello world\n")
	seedPrePR(t, db, []commitpacket.TreeEntry{entry}, []commitpacket.Blob{blob})
	oldSHA := gitBlobSHA("hello there\n")
	bases := prPreviewBases{
		entries: []githubapp.TreeEntry{{Path: "README.md", Mode: "100644", Type: "blob", SHA: oldSHA}},
		blobs:   map[string]string{oldSHA: "hello there\n"},
	}
	body := visibleText(renderPrePR(t, db, bases, nil))

	if !strings.Contains(body, "+hello world") {
		t.Fatalf("page is missing the added line:\n%s", body)
	}
	if !strings.Contains(body, "-hello there") {
		t.Fatalf("page is missing the removed line:\n%s", body)
	}
	if !strings.Contains(body, "@@") {
		t.Fatal("page is missing hunk headers")
	}
	// The count is emphasised, so the words are split by markup.
	if !strings.Contains(body, "<strong>1</strong> file changed") {
		t.Fatalf("page is missing its summary:\n%s", body)
	}
}

// Warnings must render BEFORE the file list and the authorize control. On a
// phone a signal below the fold is one the reviewer taps past.
func TestSyncPageRendersWarningsAboveTheFileListAndControls(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	seedOne(t, db, ".github/workflows/ci.yml", "on: push\n")
	body := renderPrePR(t, db, prPreviewBases{blobs: map[string]string{}}, nil)

	warning := strings.Index(body, "governance-sensitive")
	fileList := strings.Index(body, "filediff")
	authorize := strings.Index(body, `data-action="authorize"`)
	if warning < 0 {
		t.Fatalf("no sensitive-path warning:\n%s", body)
	}
	if warning > fileList || warning > authorize {
		t.Fatalf("warning at %d must precede file list (%d) and authorize (%d)", warning, fileList, authorize)
	}
}

// A page that cannot show the change must REFUSE visibly rather than render an
// empty file list, which would read as "nothing to see" and invite approval.
func TestSyncPageRefusesWhenTheBaseCannotBeRead(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	seedOne(t, db, "README.md", "x\n")
	body := renderPrePR(t, db, nil, nil)
	if !strings.Contains(body, "Cannot show this change") {
		t.Fatalf("an unreadable base must produce a visible refusal:\n%s", body)
	}
	if !strings.Contains(body, "Do not authorize") {
		t.Fatal("the refusal must tell the reviewer what to do")
	}
}

// Diff content is authored by an agent. It must reach the page as TEXT.
func TestSyncPageEscapesDiffContent(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	seedOne(t, db, "evil<script>.md", "<script>alert(1)</script>\n")
	body := renderPrePR(t, db, prPreviewBases{blobs: map[string]string{}}, nil)
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("diff content must be escaped, never rendered as markup")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("escaped content missing:\n%s", body)
	}
}

// Request-changes must carry a written note. It previously posted a hardcoded
// empty string, so "what should change?" was unanswerable.
func TestSyncPageOffersARequestChangesNote(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	seedOne(t, db, "a.md", "a\n")
	body := renderPrePR(t, db, prPreviewBases{blobs: map[string]string{}}, nil)
	if !strings.Contains(body, `id="change-note"`) {
		t.Fatal("no note field for request-changes")
	}
	if !strings.Contains(body, `data-body-id="change-note"`) {
		t.Fatal("request-changes must submit the note field")
	}
	if strings.Contains(body, `data-body='{"note":""}'`) {
		t.Fatal("request-changes must not post a hardcoded empty note")
	}
}

// A private identifier that would publish must warn, naming the file.
func TestSyncPageWarnsOnIdentityLeak(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	seedOne(t, db, "docs/notes.md", "ping zara@internal.example for help\n")
	body := renderPrePR(t, db, prPreviewBases{blobs: map[string]string{}},
		[]attribution.Identity{{Name: "zara", Email: "zara@internal.example"}})
	if !strings.Contains(body, "Private identifiers would publish") {
		t.Fatalf("no identity-leak warning:\n%s", body)
	}
	if !strings.Contains(body, "docs/notes.md") {
		t.Fatal("the warning must name the file")
	}
}

// Files are ordered by path, as GitHub sorts a PR's Files-changed tab. A
// sensitive file is marked in place, never hoisted.
func TestSyncPageOrdersFilesByPath(t *testing.T) {
	t.Parallel()
	db := uiDB(t)
	zEntry, zBlob := prePRFile("zzz.md", "z\n")
	wEntry, wBlob := prePRFile(".github/workflows/ci.yml", "on: push\n")
	seedPrePR(t,
		db,
		[]commitpacket.TreeEntry{zEntry, wEntry},
		[]commitpacket.Blob{zBlob, wBlob},
	)
	body := renderPrePR(t, db, prPreviewBases{blobs: map[string]string{}}, nil)
	workflow := strings.Index(body, ".github/workflows/ci.yml")
	zzz := strings.Index(body, "zzz.md")
	if workflow < 0 || zzz < 0 {
		t.Fatal("both files must render")
	}
	if workflow > zzz {
		t.Fatal("files must sort by path")
	}
	if !strings.Contains(body, "sensitive") {
		t.Fatal("the workflow file must carry a sensitive marker")
	}
}

// seedOne seeds a pre-PR containing exactly one file.
func seedOne(t *testing.T, db *sqlite.DB, path, content string) sqlite.SyncRequest {
	t.Helper()
	entry, blob := prePRFile(path, content)
	return seedPrePR(t, db, []commitpacket.TreeEntry{entry}, []commitpacket.Blob{blob})
}

// seedRebased stores a rebased packet the way the propose path does: entries
// and blobs are the delta, tree.sha stays the SHAPE's tree, base_tree names the
// public tree the delta applies to.
func seedRebased(t *testing.T, db *sqlite.DB, rebased prpreview.Rebased) sqlite.SyncRequest {
	t.Helper()
	author := commitpacket.Signature{Name: "Zara", Email: "zara@example.com", Date: "2026-07-26T10:00:00Z"}
	writes := make([]commitpacket.TreeEntry, 0, len(rebased.Entries))
	for _, entry := range rebased.Entries {
		if !entry.Delete {
			writes = append(writes, entry)
		}
	}
	treeSHA := gitTreeSHA(writes)
	commitSHA := gitCommitSHA(treeSHA, "Release\n", author)
	packet := commitpacket.Packet{
		Tree:   commitpacket.Tree{SHA: treeSHA, BaseTree: rebased.BaseTreeSHA, Entries: rebased.Entries},
		Blobs:  rebased.Blobs,
		Commit: commitpacket.Commit{SHA: commitSHA, Message: "Release\n", Tree: treeSHA, Author: author, Committer: author},
	}
	encoded, err := json.Marshal(map[string]any{"sha": commitSHA, "object_package": packet})
	if err != nil {
		t.Fatal(err)
	}
	req := sqlite.SyncRequest{TenantID: "default", ID: "pre-1",
		PrivateRepository: "yaniv256/mirror.dev", PublicRepository: "yaniv256/mirror",
		ProposalText: "Add pre-PR review to the README\n\nDocuments the new flow and adds CI.",
		FileManifest: rebased.Manifest, CommitPacketJSON: string(encoded),
		PacketHeadSHA: commitSHA, CreatedBy: "zara"}
	if err := db.CreateSyncProposal(context.Background(), req, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, _ := db.GetSyncRequest(context.Background(), "default", "pre-1")
	return out
}
