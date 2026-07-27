package prpreview_test

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/prpreview"
)

func blobSHA(content string) string {
	hash := sha1.New()
	fmt.Fprintf(hash, "blob %d\x00", len(content))
	hash.Write([]byte(content))
	return hex.EncodeToString(hash.Sum(nil))
}

func shapeBlob(content string) commitpacket.Blob {
	return commitpacket.Blob{SHA: blobSHA(content), Content: base64.StdEncoding.EncodeToString([]byte(content)), Encoding: "base64"}
}

func shapeEntry(path, content string) commitpacket.TreeEntry {
	return commitpacket.TreeEntry{Path: path, Mode: "100644", Type: "blob", SHA: blobSHA(content)}
}

func baseEntry(path, content string) githubapp.TreeEntry {
	return githubapp.TreeEntry{Path: path, Mode: "100644", Type: "blob", SHA: blobSHA(content)}
}

func paths(entries []commitpacket.TreeEntry) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		label := entry.Path
		if entry.Delete {
			label += " (delete)"
		}
		out = append(out, label)
	}
	return out
}

// An unchanged path is not part of the proposed change and must not appear in
// the entries, the manifest, or the uploaded blobs.
func TestRebaseDropsUnchangedPaths(t *testing.T) {
	t.Parallel()
	base := []githubapp.TreeEntry{baseEntry("README.md", "hello\n"), baseEntry("main.go", "package main\n")}
	shape := []commitpacket.TreeEntry{shapeEntry("README.md", "hello\n"), shapeEntry("main.go", "package main\n// new\n")}
	blobs := []commitpacket.Blob{shapeBlob("hello\n"), shapeBlob("package main\n// new\n")}

	result, err := prpreview.Rebase(base, "basetree", "basecommit", shape, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Path != "main.go" {
		t.Fatalf("entries = %v, want only main.go", paths(result.Entries))
	}
	if len(result.Manifest) != 1 || result.Manifest[0] != "main.go" {
		t.Fatalf("manifest = %v, want [main.go]", result.Manifest)
	}
	if len(result.Blobs) != 1 {
		t.Fatalf("blobs = %d, want 1 (unchanged content must not re-upload)", len(result.Blobs))
	}
}

// A path the shape omits and the base contains is a DELETION. This is the case
// that a private-parent delta cannot express, and the reason the shape must be a
// complete tree rather than a delta.
func TestRebaseDerivesDeletionFromAbsence(t *testing.T) {
	t.Parallel()
	base := []githubapp.TreeEntry{baseEntry("keep.md", "keep\n"), baseEntry("gone.md", "bye\n")}
	shape := []commitpacket.TreeEntry{shapeEntry("keep.md", "keep\n"), shapeEntry("new.md", "new\n")}
	blobs := []commitpacket.Blob{shapeBlob("keep\n"), shapeBlob("new\n")}

	result, err := prpreview.Rebase(base, "basetree", "basecommit", shape, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Deletions) != 1 || result.Deletions[0] != "gone.md" {
		t.Fatalf("deletions = %v, want [gone.md]", result.Deletions)
	}
	// Deletions must precede writes so a retyped path is removed before re-adding.
	if !result.Entries[0].Delete {
		t.Fatalf("entries = %v, want the deletion first", paths(result.Entries))
	}
	for _, path := range result.Manifest {
		if path == "gone.md" {
			t.Fatal("a deleted path must not appear in the publish manifest")
		}
	}
}

// The manifest is DERIVED. This is the property that closes the gap where an
// agent declared one file and published twenty.
func TestRebaseManifestEqualsWriteEntries(t *testing.T) {
	t.Parallel()
	base := []githubapp.TreeEntry{baseEntry("old.md", "old\n")}
	shape := []commitpacket.TreeEntry{
		shapeEntry("a.md", "a\n"), shapeEntry("b.md", "b\n"), shapeEntry("c.md", "c\n"),
	}
	blobs := []commitpacket.Blob{shapeBlob("a\n"), shapeBlob("b\n"), shapeBlob("c\n")}

	result, err := prpreview.Rebase(base, "basetree", "basecommit", shape, blobs)
	if err != nil {
		t.Fatal(err)
	}
	writes := make([]string, 0)
	for _, entry := range result.Entries {
		if !entry.Delete {
			writes = append(writes, entry.Path)
		}
	}
	if strings.Join(writes, ",") != strings.Join(result.Manifest, ",") {
		t.Fatalf("manifest %v != write entries %v", result.Manifest, writes)
	}
}

// Two commits of private divergence collapse into ONE shape. This is what
// retires the one-commit-at-a-time limitation.
func TestRebaseExpressesMultiCommitDivergenceAsOneShape(t *testing.T) {
	t.Parallel()
	base := []githubapp.TreeEntry{baseEntry("app.go", "v1\n")}
	// Private history went v1 -> v2 -> v3; only the final shape matters.
	shape := []commitpacket.TreeEntry{shapeEntry("app.go", "v3\n"), shapeEntry("added-in-v2.go", "helper\n")}
	blobs := []commitpacket.Blob{shapeBlob("v3\n"), shapeBlob("helper\n")}

	result, err := prpreview.Rebase(base, "basetree", "basecommit", shape, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("entries = %v, want both paths in one packet", paths(result.Entries))
	}
}

// base_tree must be the PUBLIC tree — the defect that made publication assemble
// against a tree the public repo had never seen.
func TestRebaseCarriesPublicBase(t *testing.T) {
	t.Parallel()
	base := []githubapp.TreeEntry{baseEntry("a.md", "a\n")}
	shape := []commitpacket.TreeEntry{shapeEntry("a.md", "b\n")}

	result, err := prpreview.Rebase(base, "public-tree-sha", "public-commit-sha", shape, []commitpacket.Blob{shapeBlob("b\n")})
	if err != nil {
		t.Fatal(err)
	}
	if result.BaseTreeSHA != "public-tree-sha" || result.BaseCommitSHA != "public-commit-sha" {
		t.Fatalf("base = %q/%q, want the public tree and commit", result.BaseTreeSHA, result.BaseCommitSHA)
	}
}

// A shape identical to the public repo is an empty pre-PR: there is nothing for
// a human to approve, and publishing it would create an empty commit.
func TestRebaseRefusesAnEmptyChange(t *testing.T) {
	t.Parallel()
	base := []githubapp.TreeEntry{baseEntry("a.md", "a\n")}
	shape := []commitpacket.TreeEntry{shapeEntry("a.md", "a\n")}

	_, err := prpreview.Rebase(base, "basetree", "basecommit", shape, []commitpacket.Blob{shapeBlob("a\n")})
	if err == nil {
		t.Fatal("a shape matching the public repo must be refused, not published as an empty commit")
	}
	if !strings.Contains(err.Error(), "already matches") {
		t.Fatalf("err = %v, want it to name the cause", err)
	}
}

// An empty public repository is a root-commit publication: everything is an add
// and there is no base tree.
func TestRebaseAgainstEmptyPublicRepoAddsEverything(t *testing.T) {
	t.Parallel()
	shape := []commitpacket.TreeEntry{shapeEntry("README.md", "hi\n")}

	result, err := prpreview.Rebase(nil, "", "", shape, []commitpacket.Blob{shapeBlob("hi\n")})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Delete {
		t.Fatalf("entries = %v, want one add", paths(result.Entries))
	}
	if result.BaseTreeSHA != "" {
		t.Fatalf("base tree = %q, want empty for a root commit", result.BaseTreeSHA)
	}
}

// A mode-only change (adding the executable bit) alters the tree even though the
// content hash is identical, so it must not be dropped as "unchanged".
func TestRebaseTreatsModeChangeAsAChange(t *testing.T) {
	t.Parallel()
	content := "#!/bin/sh\n"
	base := []githubapp.TreeEntry{{Path: "run.sh", Mode: "100644", Type: "blob", SHA: blobSHA(content)}}
	shape := []commitpacket.TreeEntry{{Path: "run.sh", Mode: "100755", Type: "blob", SHA: blobSHA(content)}}

	result, err := prpreview.Rebase(base, "basetree", "basecommit", shape, []commitpacket.Blob{shapeBlob(content)})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Mode != "100755" {
		t.Fatalf("entries = %v, want the mode change carried", paths(result.Entries))
	}
	// The object already exists publicly; only the tree entry changes.
	if len(result.Blobs) != 0 {
		t.Fatalf("blobs = %d, want 0 — the content object is unchanged", len(result.Blobs))
	}
}

// A submodule pointer is resolved by GitHub from its SHA and carries no blob.
func TestRebaseCarriesSubmodulePointerWithoutBlob(t *testing.T) {
	t.Parallel()
	base := []githubapp.TreeEntry{{Path: "vendor/lib", Mode: "160000", Type: "commit", SHA: strings.Repeat("a", 40)}}
	shape := []commitpacket.TreeEntry{{Path: "vendor/lib", Mode: "160000", Type: "commit", SHA: strings.Repeat("b", 40)}}

	result, err := prpreview.Rebase(base, "basetree", "basecommit", shape, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Type != "commit" {
		t.Fatalf("entries = %v, want the submodule pointer", paths(result.Entries))
	}
	if len(result.Blobs) != 0 {
		t.Fatalf("blobs = %d, want 0 — a gitlink has no blob", len(result.Blobs))
	}
}

// A shape entry whose content was not carried must fail loudly: silently
// dropping it would publish nothing while the manifest claimed the file shipped.
func TestRebaseRejectsEntryWithMissingContent(t *testing.T) {
	t.Parallel()
	shape := []commitpacket.TreeEntry{shapeEntry("a.md", "a\n")}

	_, err := prpreview.Rebase(nil, "", "", shape, nil)
	if err == nil {
		t.Fatal("an entry whose blob was not carried must be an error, not a skipped file")
	}
}

// The shape is a complete tree by contract; a delta arriving here would make
// every absent path look like a deletion.
func TestRebaseRejectsADeltaShape(t *testing.T) {
	t.Parallel()
	shape := []commitpacket.TreeEntry{{Path: "gone.md", Mode: "100644", Type: "blob", Delete: true}}

	_, err := prpreview.Rebase(nil, "", "", shape, nil)
	if err == nil {
		t.Fatal("a shape containing deletions must be refused — the shape is a complete tree")
	}
}

func TestSensitivePathFlagsGovernanceSurfaces(t *testing.T) {
	t.Parallel()
	sensitive := []string{
		".github/workflows/ci.yml",
		"policy/production.json",
		"internal/policy/rules.json",
		"deploy/.env",
		"config/.env.production",
		"internal/credentials.go",
		".gitmodules",
	}
	for _, path := range sensitive {
		if !prpreview.SensitivePath(path) {
			t.Errorf("SensitivePath(%q) = false, want true", path)
		}
	}
	ordinary := []string{"README.md", "internal/ui/page.go", "docs/guide.md"}
	for _, path := range ordinary {
		if prpreview.SensitivePath(path) {
			t.Errorf("SensitivePath(%q) = true, want false", path)
		}
	}
}
