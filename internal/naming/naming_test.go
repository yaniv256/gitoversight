package naming_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestActiveProductSurfacesUseGitOversightName(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Clean("../..")
	legacyContent := regexp.MustCompile(`(?i)github[-_ ]governance|githubgovernance|governance\.(?:example|test|db)|governance skill|\bgovernance(?:ctl|-api|-worker|-notify|-checkpoint|-bootstrap|-app-bootstrap|-restore-verify)\b|GOVERNANCE_`)
	// This test is the only permitted carrier of the legacy identifier: it has
	// to spell the pattern out in order to search for it.
	//
	// Two further exclusions lived here for the historical evidence files that
	// legitimately recorded the old name. Those files moved to the .private
	// repository, so the exclusions became unreachable and were deleted rather
	// than left in place — an exclusion that matches nothing still silently
	// excuses anything later added at that path.
	thisTest := filepath.Clean("internal/naming/naming_test.go")

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
		if relative == ".git" || relative == thisTest {
			return nil
		}
		if legacyContent.MatchString(relative) {
			t.Errorf("active filename retains a legacy product identifier: %s", relative)
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if legacyContent.Match(payload) {
			t.Errorf("active file retains a legacy product identifier: %s", relative)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	module, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(module), "module github.com/yaniv256/gitoversight.dev\n") {
		t.Fatal("Go module does not use the Git Oversight repository identity")
	}
}
