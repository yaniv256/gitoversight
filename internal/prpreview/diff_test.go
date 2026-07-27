package prpreview_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/prpreview"
)

func render(diff prpreview.FileDiff) string {
	var out strings.Builder
	for _, hunk := range diff.Hunks {
		fmt.Fprintln(&out, hunk.Header())
		for _, line := range hunk.Lines {
			fmt.Fprintf(&out, "%c%s\n", line.Op, line.Text)
		}
	}
	return out.String()
}

func lines(count int, prefix string) string {
	var out strings.Builder
	for index := 1; index <= count; index++ {
		fmt.Fprintf(&out, "%s%d\n", prefix, index)
	}
	return out.String()
}

// The scenario that motivates the whole unit: Yaniv's 500-line file with a
// 3-line change must render as a small diff, not 500 lines of noise.
func TestDiffFileShowsOnlyTheChangedLinesOfALargeFile(t *testing.T) {
	t.Parallel()
	base := lines(500, "line ")
	proposed := strings.Replace(base, "line 250\n", "CHANGED 250\n", 1)
	proposed = strings.Replace(proposed, "line 251\n", "CHANGED 251\n", 1)
	proposed = strings.Replace(proposed, "line 252\n", "CHANGED 252\n", 1)

	diff := prpreview.DiffFile("big.txt", []byte(base), []byte(proposed), prpreview.ChangeModify)
	if diff.Added != 3 || diff.Removed != 3 {
		t.Fatalf("added/removed = %d/%d, want 3/3", diff.Added, diff.Removed)
	}
	rendered := render(diff)
	if strings.Count(rendered, "\n") > 20 {
		t.Fatalf("a 3-line change rendered %d lines:\n%s", strings.Count(rendered, "\n"), rendered)
	}
	if !strings.Contains(rendered, "+CHANGED 250") || !strings.Contains(rendered, "-line 250") {
		t.Fatalf("diff missing the change:\n%s", rendered)
	}
	// Context must surround the change so a reviewer can place it.
	if !strings.Contains(rendered, " line 249") {
		t.Fatalf("diff missing context:\n%s", rendered)
	}
}

func TestDiffFileRendersAnAdditionAsAllAdded(t *testing.T) {
	t.Parallel()
	diff := prpreview.DiffFile("new.md", nil, []byte("alpha\nbeta\n"), prpreview.ChangeAdd)
	if diff.Added != 2 || diff.Removed != 0 {
		t.Fatalf("added/removed = %d/%d, want 2/0", diff.Added, diff.Removed)
	}
	rendered := render(diff)
	if !strings.Contains(rendered, "+alpha") || !strings.Contains(rendered, "+beta") {
		t.Fatalf("rendered:\n%s", rendered)
	}
}

func TestDiffFileRendersADeletionAsAllRemoved(t *testing.T) {
	t.Parallel()
	diff := prpreview.DiffFile("gone.md", []byte("alpha\nbeta\n"), nil, prpreview.ChangeDelete)
	if diff.Removed != 2 || diff.Added != 0 {
		t.Fatalf("added/removed = %d/%d, want 0/2", diff.Added, diff.Removed)
	}
}

func TestDiffFileDetectsBinaryAndDoesNotRenderIt(t *testing.T) {
	t.Parallel()
	diff := prpreview.DiffFile("logo.png", []byte("PNG\x00\x01\x02"), []byte("PNG\x00\x03\x04"), prpreview.ChangeModify)
	if !diff.Binary {
		t.Fatal("content with a NUL byte must be treated as binary")
	}
	if len(diff.Hunks) != 0 {
		t.Fatal("binary content must not render as text")
	}
}

// A CRLF file must not read as wholly rewritten when one line changed.
func TestDiffFileHandlesCRLFWithoutRewritingEveryLine(t *testing.T) {
	t.Parallel()
	base := "alpha\r\nbeta\r\ngamma\r\n"
	proposed := "alpha\r\nBETA\r\ngamma\r\n"
	diff := prpreview.DiffFile("windows.txt", []byte(base), []byte(proposed), prpreview.ChangeModify)
	if diff.Added != 1 || diff.Removed != 1 {
		t.Fatalf("added/removed = %d/%d, want 1/1 — CRLF must not rewrite every line", diff.Added, diff.Removed)
	}
}

// Gaining or losing a trailing newline is a real change; git reports it and so
// must we, or the page shows a diff with no visible difference.
func TestDiffFileMarksAMissingTrailingNewline(t *testing.T) {
	t.Parallel()
	diff := prpreview.DiffFile("f.txt", []byte("alpha\n"), []byte("alpha"), prpreview.ChangeModify)
	rendered := render(diff)
	if !strings.Contains(rendered, "No newline at end of file") {
		t.Fatalf("a lost trailing newline must be visible:\n%q", rendered)
	}
}

func TestDiffFileCountsMatchTheRenderedBody(t *testing.T) {
	t.Parallel()
	base := "a\nb\nc\nd\n"
	proposed := "a\nB\nc\nD\ne\n"
	diff := prpreview.DiffFile("f.txt", []byte(base), []byte(proposed), prpreview.ChangeModify)
	renderedAdded, renderedRemoved := 0, 0
	for _, hunk := range diff.Hunks {
		for _, line := range hunk.Lines {
			switch line.Op {
			case '+':
				renderedAdded++
			case '-':
				renderedRemoved++
			}
		}
	}
	if renderedAdded != diff.Added || renderedRemoved != diff.Removed {
		t.Fatalf("counts %d/%d disagree with rendered %d/%d — a summary must not contradict the body",
			diff.Added, diff.Removed, renderedAdded, renderedRemoved)
	}
}

func TestDiffFileIsIdempotent(t *testing.T) {
	t.Parallel()
	base, proposed := lines(40, "x "), lines(40, "x ")+"tail\n"
	first := render(prpreview.DiffFile("f.txt", []byte(base), []byte(proposed), prpreview.ChangeModify))
	second := render(prpreview.DiffFile("f.txt", []byte(base), []byte(proposed), prpreview.ChangeModify))
	if first != second {
		t.Fatal("diff computation must be deterministic")
	}
}

// Truncation omits the BODY, never the file's existence or its counts.
func TestDiffFileTruncationKeepsPathAndCounts(t *testing.T) {
	t.Parallel()
	base := lines(5000, "old ")
	proposed := lines(5000, "new ")
	diff := prpreview.DiffFile("huge.txt", []byte(base), []byte(proposed), prpreview.ChangeModify)
	if !diff.Truncated {
		t.Fatal("an oversized diff must be marked truncated")
	}
	if diff.Path != "huge.txt" || diff.Added == 0 || diff.Removed == 0 {
		t.Fatalf("truncation must preserve path and counts: %+v", diff)
	}
	if len(diff.Hunks) != 0 {
		t.Fatal("a truncated diff must omit its body")
	}
}

func TestDiffSubmoduleRendersPointerChange(t *testing.T) {
	t.Parallel()
	diff := prpreview.DiffSubmodule("vendor/lib", strings.Repeat("a", 40), strings.Repeat("b", 40))
	if diff.Kind != prpreview.ChangeSubmodule || diff.OldSHA == "" || diff.NewSHA == "" {
		t.Fatalf("submodule diff = %+v", diff)
	}
	if len(diff.Hunks) != 0 {
		t.Fatal("a gitlink has no text to diff")
	}
}

func TestDiffFileFlagsSensitivePaths(t *testing.T) {
	t.Parallel()
	diff := prpreview.DiffFile(".github/workflows/ci.yml", []byte("a\n"), []byte("b\n"), prpreview.ChangeModify)
	if !diff.Sensitive {
		t.Fatal("a workflow file must be flagged sensitive")
	}
	ordinary := prpreview.DiffFile("README.md", []byte("a\n"), []byte("b\n"), prpreview.ChangeModify)
	if ordinary.Sensitive {
		t.Fatal("an ordinary path must not be flagged")
	}
}

// Hunk headers must carry real line numbers so a reviewer can locate the change
// in the file, exactly as GitHub shows them.
func TestHunkHeaderCarriesLineNumbers(t *testing.T) {
	t.Parallel()
	base := lines(100, "l ")
	proposed := strings.Replace(base, "l 50\n", "CHANGED\n", 1)
	diff := prpreview.DiffFile("f.txt", []byte(base), []byte(proposed), prpreview.ChangeModify)
	if len(diff.Hunks) != 1 {
		t.Fatalf("hunks = %d, want 1", len(diff.Hunks))
	}
	header := diff.Hunks[0].Header()
	if !strings.HasPrefix(header, "@@ -4") {
		t.Fatalf("header = %q, want it to start near line 47", header)
	}
}

// The diff engine is hand-written, so its output is checked against an
// authority it cannot bend: git itself. Property tests assert what the author
// believed; `git diff --no-index` asserts what a reviewer will actually
// recognise. Hunk grouping in particular depends on context-merging rules that
// are easy to reimplement plausibly-but-wrongly — a diff with the right changed
// lines and the wrong hunk boundaries passes every hand-written assertion and
// still reads as "not quite GitHub".
func TestDiffMatchesGitDiffExactly(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	dir := t.TempDir()
	base := lines(200, "line ")
	proposedLines := strings.Split(strings.TrimSuffix(base, "\n"), "\n")
	proposedLines[49] = "CHANGED FIFTY"
	proposedLines = slices.Insert(proposedLines, 50, "inserted A", "inserted B")
	proposedLines = slices.Delete(proposedLines, 120, 123)
	proposedLines[180] = "TAIL EDIT"
	proposed := strings.Join(proposedLines, "\n") + "\n"

	basePath := filepath.Join(dir, "base.txt")
	newPath := filepath.Join(dir, "new.txt")
	if err := os.WriteFile(basePath, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte(proposed), 0o600); err != nil {
		t.Fatal(err)
	}
	// git diff exits 1 when files differ, which is the expected case here.
	output, _ := exec.Command("git", "diff", "--no-index", "-U3", basePath, newPath).Output()

	wantHeaders := make([]string, 0)
	wantAdded, wantRemoved := 0, 0
	for _, line := range strings.Split(string(output), "\n") {
		switch {
		case strings.HasPrefix(line, "@@"):
			// git appends the enclosing-context hint after the second @@;
			// compare only the line-number span.
			wantHeaders = append(wantHeaders, strings.Join(strings.Fields(line)[:4], " "))
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			wantAdded++
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			wantRemoved++
		}
	}
	if len(wantHeaders) == 0 {
		t.Fatalf("git produced no hunks:\n%s", output)
	}

	diff := DiffFileForTest(basePath, []byte(base), []byte(proposed))
	if diff.Added != wantAdded || diff.Removed != wantRemoved {
		t.Fatalf("counts = +%d/-%d, git says +%d/-%d", diff.Added, diff.Removed, wantAdded, wantRemoved)
	}
	if len(diff.Hunks) != len(wantHeaders) {
		t.Fatalf("hunks = %d, git says %d", len(diff.Hunks), len(wantHeaders))
	}
	for index, hunk := range diff.Hunks {
		if got := hunk.Header(); got != wantHeaders[index] {
			t.Fatalf("hunk %d header = %q, git says %q", index, got, wantHeaders[index])
		}
	}
}

func DiffFileForTest(path string, base, proposed []byte) prpreview.FileDiff {
	return prpreview.DiffFile(path, base, proposed, prpreview.ChangeModify)
}
