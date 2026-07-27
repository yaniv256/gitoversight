package naming_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This repository is `.dev` in the three-repo shape: `.private` holds anything
// never meant to publish, `.dev` is public-minus-history, and the public repo
// is a squashed sync of `.dev`. The middle row is what this test enforces.
//
// The rule is not tidiness. GitOversight publishes `.dev` on request with no
// file list and no exclusion config — the manifest is DERIVED from the commit
// packet and ignores anything declared (internal/api/sync.go). An
// argument-free sync is only safe if `.dev` contains nothing unpublishable, so
// this test is the precondition that makes the sync's signature possible.
//
// A `.dev`-except-these-paths filter was the alternative and is worse: it is
// configuration that drifts from the tree it describes, and it fails in the one
// direction that cannot be undone. Stale in the *exclude* direction, it
// silently publishes the thing it was written to protect. Placement at commit
// time replaces filtering at publish time.
//
// The predecessor of this test was docs/PUBLIC-SURFACE.md, a hand-maintained
// manifest of what crosses. It recorded the right answers and enforced none of
// them — which is why it was deleted rather than updated.

// unpublishablePaths are path prefixes whose CONTENT is a record of a moment
// rather than a description of the present system. The distinguishing test is
// tense: a document that describes the current system belongs here and is a
// defect when stale; a document that describes a moment is supposed to go
// stale, and belongs in `.private`.
var unpublishablePaths = []string{
	"investigations/",
	"marketing/",
	"docs/plans/",
	"docs/investigations/",
	"docs/acceptance/",
	"docs/evidence/",
	"docs/solutions/",
	"docs/superpowers/",
	"docs/verification/",
	"docs/design/",
}

// unpublishableContent matches infrastructure that is real rather than
// illustrative. The hostnames come from the private-hostname scan in
// ci/workflow-ci.yml.pending, which cannot run: the GitOversight App lacks the
// `workflows` permission, so .github/workflows/ci.yml can never be written
// (see ci/README.md). A guard living only in a workflow file is a guard that
// never executes, so it lives here, where `go test ./...` runs it in every
// environment — local, CI, and any clone.
var unpublishableContent = []*regexp.Regexp{
	regexp.MustCompile(`\b3\.140\.105\.110\b`),
	regexp.MustCompile(`(?i)\bhey-code\.ai\b`),
	regexp.MustCompile(`(?i)\bbabel3\.com\b`),
	regexp.MustCompile(`(?i)\bseethegalaxy\.com\b`),
}

// TestEveryTrackedPathIsPublishable asserts the PROPERTY that nothing
// unpublishable is present, rather than comparing the tree against a known file
// list. A list-based guard passes the moment someone adds a file it was never
// told about — which is the failure the shape exists to prevent, so a guard
// with that shape would be decorative.
func TestEveryTrackedPathIsPublishable(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Clean("../..")
	// This file must name the patterns in order to search for them.
	thisTest := filepath.Clean("internal/naming/publishable_test.go")

	err := filepath.WalkDir(repoRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if relative == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if relative == thisTest {
			return nil
		}
		slashed := filepath.ToSlash(relative)
		for _, prefix := range unpublishablePaths {
			if strings.HasPrefix(slashed, prefix) {
				t.Errorf("%s belongs in the .private repository, not here: %q holds records of a moment, and this repository is published in full",
					slashed, prefix)
				return nil
			}
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, pattern := range unpublishableContent {
			if match := pattern.Find(payload); match != nil {
				t.Errorf("%s contains real infrastructure %q — publishing this repository would expose it", slashed, match)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
