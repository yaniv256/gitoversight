package prpreview_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/attribution"
	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/prpreview"
)

func packetWith(entries []commitpacket.TreeEntry, blobs []commitpacket.Blob) commitpacket.Packet {
	return commitpacket.Packet{Tree: commitpacket.Tree{Entries: entries}, Blobs: blobs,
		Commit: commitpacket.Commit{Message: "Release\n",
			Author:    commitpacket.Signature{Name: "Yaniv", Email: "yaniv@example.com"},
			Committer: commitpacket.Signature{Name: "Yaniv", Email: "yaniv@example.com"}}}
}

func b64(content string) string { return base64.StdEncoding.EncodeToString([]byte(content)) }

func emptyBase(string) ([]byte, bool, error) { return nil, false, nil }

// The file list a reviewer sees is derived from the packet, and ordered by path
// exactly as GitHub sorts a PR's Files-changed tab (KTD10).
func TestBuildOrdersFilesByPathLikeGitHub(t *testing.T) {
	t.Parallel()
	entries := []commitpacket.TreeEntry{
		{Path: "zebra.md", Mode: "100644", Type: "blob", SHA: "s3"},
		{Path: ".github/workflows/ci.yml", Mode: "100644", Type: "blob", SHA: "s1"},
		{Path: "README.md", Mode: "100644", Type: "blob", SHA: "s2"},
	}
	blobs := []commitpacket.Blob{
		{SHA: "s1", Content: b64("on: push\n"), Encoding: "base64"},
		{SHA: "s2", Content: b64("# readme\n"), Encoding: "base64"},
		{SHA: "s3", Content: b64("zebra\n"), Encoding: "base64"},
	}
	preview, err := prpreview.Build(packetWith(entries, blobs), "base", emptyBase, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{preview.Files[0].Path, preview.Files[1].Path, preview.Files[2].Path}
	want := []string{".github/workflows/ci.yml", "README.md", "zebra.md"}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("order = %v, want path order %v", got, want)
		}
	}
	// The sensitive file is FLAGGED, not moved to the top.
	if !preview.Files[0].Sensitive {
		t.Fatal("the workflow file must be flagged sensitive")
	}
}

// A safety scan must cover files whose diff body was omitted for size. A cap on
// what is RENDERED must never become a cap on what is CHECKED.
func TestBuildScansTruncatedFilesForIdentityLeaks(t *testing.T) {
	t.Parallel()
	// Large enough that DiffFile truncates the body.
	huge := strings.Repeat("filler line\n", 6000) + "contact zara@internal.example\n"
	entries := []commitpacket.TreeEntry{{Path: "big.txt", Mode: "100644", Type: "blob", SHA: "s1"}}
	blobs := []commitpacket.Blob{{SHA: "s1", Content: b64(huge), Encoding: "base64"}}
	identities := []attribution.Identity{{Name: "zara", Email: "zara@internal.example"}}

	preview, err := prpreview.Build(packetWith(entries, blobs), "base", emptyBase, nil, identities)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.Files[0].Truncated {
		t.Fatal("fixture must actually truncate for this test to mean anything")
	}
	found := false
	for _, warning := range preview.Warnings {
		if strings.Contains(warning, "big.txt") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a truncated file must still be scanned; warnings = %v", preview.Warnings)
	}
}

// The commit's author and committer publish with the commit and belong to no
// file, so a content-only scan would miss them.
func TestBuildScansTheCommitSignature(t *testing.T) {
	t.Parallel()
	entries := []commitpacket.TreeEntry{{Path: "a.md", Mode: "100644", Type: "blob", SHA: "s1"}}
	blobs := []commitpacket.Blob{{SHA: "s1", Content: b64("clean\n"), Encoding: "base64"}}
	packet := packetWith(entries, blobs)
	packet.Commit.Author = commitpacket.Signature{Name: "zara", Email: "zara@internal.example"}

	preview, err := prpreview.Build(packet, "base", emptyBase, nil,
		[]attribution.Identity{{Name: "zara", Email: "zara@internal.example"}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, warning := range preview.Warnings {
		if strings.Contains(warning, "author") {
			found = true
		}
	}
	if !found {
		t.Fatalf("commit signature leak must warn; warnings = %v", preview.Warnings)
	}
}

// Known-answer in the NEGATIVE direction: a clean pre-PR must produce no
// warnings, or the warning surface is noise a reviewer learns to ignore.
func TestBuildProducesNoWarningsForACleanPrePR(t *testing.T) {
	t.Parallel()
	entries := []commitpacket.TreeEntry{{Path: "docs/guide.md", Mode: "100644", Type: "blob", SHA: "s1"}}
	blobs := []commitpacket.Blob{{SHA: "s1", Content: b64("public docs\n"), Encoding: "base64"}}
	preview, err := prpreview.Build(packetWith(entries, blobs), "base", emptyBase, nil,
		[]attribution.Identity{{Name: "zara", Email: "zara@internal.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Warnings) != 0 {
		t.Fatalf("clean pre-PR produced warnings: %v", preview.Warnings)
	}
}

func TestBuildComputesTotalsAcrossFiles(t *testing.T) {
	t.Parallel()
	entries := []commitpacket.TreeEntry{
		{Path: "a.md", Mode: "100644", Type: "blob", SHA: "s1"},
		{Path: "b.md", Mode: "100644", Type: "blob", SHA: "s2"},
	}
	blobs := []commitpacket.Blob{
		{SHA: "s1", Content: b64("one\ntwo\n"), Encoding: "base64"},
		{SHA: "s2", Content: b64("three\n"), Encoding: "base64"},
	}
	preview, err := prpreview.Build(packetWith(entries, blobs), "base", emptyBase, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if preview.TotalAdded != 3 || preview.TotalRemoved != 0 {
		t.Fatalf("totals = +%d/-%d, want +3/-0", preview.TotalAdded, preview.TotalRemoved)
	}
}

// A path present in the base renders as a MODIFICATION with a real old side,
// which is the whole point of resolving the public base.
func TestBuildRendersModificationAgainstBaseContent(t *testing.T) {
	t.Parallel()
	base := func(path string) ([]byte, bool, error) {
		if path == "README.md" {
			return []byte("old line\n"), true, nil
		}
		return nil, false, nil
	}
	entries := []commitpacket.TreeEntry{{Path: "README.md", Mode: "100644", Type: "blob", SHA: "s1"}}
	blobs := []commitpacket.Blob{{SHA: "s1", Content: b64("new line\n"), Encoding: "base64"}}
	preview, err := prpreview.Build(packetWith(entries, blobs), "base", base, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Files[0].Kind != prpreview.ChangeModify {
		t.Fatalf("kind = %q, want modified", preview.Files[0].Kind)
	}
	if preview.Files[0].Added != 1 || preview.Files[0].Removed != 1 {
		t.Fatalf("+%d/-%d, want +1/-1", preview.Files[0].Added, preview.Files[0].Removed)
	}
}

func TestBuildRendersDeletionFromBaseContent(t *testing.T) {
	t.Parallel()
	base := func(string) ([]byte, bool, error) { return []byte("gone\n"), true, nil }
	entries := []commitpacket.TreeEntry{{Path: "old.md", Mode: "100644", Type: "blob", Delete: true}}
	preview, err := prpreview.Build(packetWith(entries, nil), "base", base, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Files[0].Kind != prpreview.ChangeDelete || preview.Files[0].Removed != 1 {
		t.Fatalf("deletion = %+v", preview.Files[0])
	}
}
