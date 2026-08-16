package prpreview

import (
	"bytes"
	"fmt"
	"strings"
)

// ChangeKind names how a path differs between the public base and the proposed
// shape, in GitHub's own vocabulary so the preview reads like the PR it becomes.
type ChangeKind string

const (
	ChangeAdd       ChangeKind = "added"
	ChangeModify    ChangeKind = "modified"
	ChangeDelete    ChangeKind = "deleted"
	ChangeSubmodule ChangeKind = "submodule"
)

// contextLines matches git's default unified-diff context.
const contextLines = 3

// FileDiff is one changed path as a reviewer sees it.
type FileDiff struct {
	Path      string
	Kind      ChangeKind
	Added     int
	Removed   int
	Hunks     []Hunk
	Binary    bool
	Sensitive bool
	// OldSHA/NewSHA carry a submodule pointer's before/after commits. A gitlink
	// has no text to diff, so the pointer change IS the diff.
	OldSHA string
	NewSHA string
	// Truncated marks a diff whose body was omitted for size. The path, kind,
	// and counts remain — a file's EXISTENCE is never hidden, only its content.
	Truncated bool
	// CountsUnavailable distinguishes a pre-computation safety refusal from a
	// normally truncated diff whose exact counts were already computed.
	CountsUnavailable bool
}

// Hunk is a contiguous run of changed lines with its surrounding context.
type Hunk struct {
	OldStart, OldCount int
	NewStart, NewCount int
	Lines              []DiffLine
}

// DiffLine carries one rendered line. Op is ' ' (context), '+' or '-'.
type DiffLine struct {
	Op   byte
	Text string
}

// maxDiffLines bounds one file's rendered body. Beyond it the body is omitted
// and Truncated is set — never the path itself (KTD8).
const maxDiffLines = 2000

// The LCS implementation is quadratic in line count. Refuse that computation
// before allocating its matrix; the file remains visible and reviewable by
// other means, but opening a crafted file cannot exhaust the review service.
const maxDiffWorkCells = 25_000_000

// DiffFile computes the unified diff between a path's base content and its
// proposed content. Either side may be nil: no base means an addition, no
// proposal means a deletion.
func DiffFile(path string, base, proposed []byte, kind ChangeKind) FileDiff {
	result := FileDiff{Path: path, Kind: kind, Sensitive: SensitivePath(path)}
	if isBinary(base) || isBinary(proposed) {
		result.Binary = true
		return result
	}
	oldLines := splitLines(base)
	newLines := splitLines(proposed)
	if len(oldLines) > 0 && len(newLines) > maxDiffWorkCells/len(oldLines) {
		result.Truncated = true
		result.CountsUnavailable = true
		return result
	}
	hunks, added, removed := unifiedHunks(oldLines, newLines)
	result.Added, result.Removed = added, removed

	total := 0
	for _, hunk := range hunks {
		total += len(hunk.Lines)
	}
	if total > maxDiffLines {
		result.Truncated = true
		return result
	}
	result.Hunks = hunks
	return result
}

// DiffSubmodule renders a gitlink pointer change. There is no content to diff:
// the old and new commit SHAs are the whole story.
func DiffSubmodule(path, oldSHA, newSHA string) FileDiff {
	return FileDiff{Path: path, Kind: ChangeSubmodule, OldSHA: oldSHA, NewSHA: newSHA, Sensitive: SensitivePath(path)}
}

// splitLines splits content into lines WITHOUT dropping the information of
// whether a trailing newline was present. A file that gains or loses its final
// newline is a real change and git reports it; silently normalising would show
// a diff with no visible difference.
func splitLines(content []byte) []string {
	if len(content) == 0 {
		return nil
	}
	text := string(content)
	trailing := strings.HasSuffix(text, "\n")
	if trailing {
		text = text[:len(text)-1]
	}
	lines := strings.Split(text, "\n")
	if !trailing && len(lines) > 0 {
		lines[len(lines)-1] += "\n\\ No newline at end of file"
	}
	return lines
}

// isBinary uses git's own heuristic: a NUL byte within the first 8000 bytes.
func isBinary(content []byte) bool {
	if len(content) > 8000 {
		content = content[:8000]
	}
	return bytes.IndexByte(content, 0) >= 0
}

// unifiedHunks produces git-shaped hunks from a longest-common-subsequence
// alignment, along with the added and removed line counts.
func unifiedHunks(oldLines, newLines []string) ([]Hunk, int, int) {
	ops := diffOps(oldLines, newLines)
	hunks := make([]Hunk, 0)
	added, removed := 0, 0
	for _, op := range ops {
		switch op.Op {
		case '+':
			added++
		case '-':
			removed++
		}
	}
	// Walk the op list, emitting a hunk around each run of changes with up to
	// contextLines of unchanged lines on either side.
	index := 0
	oldLine, newLine := 1, 1
	for index < len(ops) {
		if ops[index].Op == ' ' {
			oldLine++
			newLine++
			index++
			continue
		}
		start := index
		leading := min(contextLines, countPrecedingContext(ops, start))
		hunkOldStart := oldLine - leading
		hunkNewStart := newLine - leading

		lines := make([]DiffLine, 0, contextLines*2+8)
		for offset := start - leading; offset < start; offset++ {
			lines = append(lines, ops[offset])
		}
		oldCount, newCount := leading, leading
		for index < len(ops) {
			// A change run ends after contextLines consecutive context lines
			// that are not themselves followed by more changes.
			if ops[index].Op == ' ' && !changeWithin(ops, index, contextLines+1) {
				break
			}
			line := ops[index]
			lines = append(lines, line)
			switch line.Op {
			case ' ':
				oldCount++
				newCount++
				oldLine++
				newLine++
			case '-':
				oldCount++
				oldLine++
			case '+':
				newCount++
				newLine++
			}
			index++
		}
		trailing := 0
		for index < len(ops) && ops[index].Op == ' ' && trailing < contextLines {
			lines = append(lines, ops[index])
			oldCount++
			newCount++
			oldLine++
			newLine++
			index++
			trailing++
		}
		if hunkOldStart < 1 {
			hunkOldStart = 1
		}
		if hunkNewStart < 1 {
			hunkNewStart = 1
		}
		hunks = append(hunks, Hunk{OldStart: hunkOldStart, OldCount: oldCount, NewStart: hunkNewStart, NewCount: newCount, Lines: lines})
	}
	return hunks, added, removed
}

func countPrecedingContext(ops []DiffLine, index int) int {
	count := 0
	for cursor := index - 1; cursor >= 0 && ops[cursor].Op == ' ' && count < contextLines; cursor-- {
		count++
	}
	return count
}

func changeWithin(ops []DiffLine, index, window int) bool {
	for offset := index; offset < len(ops) && offset < index+window; offset++ {
		if ops[offset].Op != ' ' {
			return true
		}
	}
	return false
}

// diffOps aligns two line sequences by longest common subsequence and returns
// the flat op list: ' ' kept, '-' removed, '+' added.
func diffOps(oldLines, newLines []string) []DiffLine {
	// Trim the common prefix and suffix first. Real reviews are dominated by
	// small edits to large files, where this reduces the quadratic table to a
	// few lines and keeps a 500-line file with a 3-line change cheap.
	prefix := 0
	for prefix < len(oldLines) && prefix < len(newLines) && oldLines[prefix] == newLines[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(oldLines)-prefix && suffix < len(newLines)-prefix &&
		oldLines[len(oldLines)-1-suffix] == newLines[len(newLines)-1-suffix] {
		suffix++
	}
	oldCore := oldLines[prefix : len(oldLines)-suffix]
	newCore := newLines[prefix : len(newLines)-suffix]

	ops := make([]DiffLine, 0, len(oldLines)+len(newLines))
	for _, line := range oldLines[:prefix] {
		ops = append(ops, DiffLine{Op: ' ', Text: line})
	}
	ops = append(ops, lcsOps(oldCore, newCore)...)
	for _, line := range oldLines[len(oldLines)-suffix:] {
		ops = append(ops, DiffLine{Op: ' ', Text: line})
	}
	return ops
}

func lcsOps(oldLines, newLines []string) []DiffLine {
	rows, columns := len(oldLines), len(newLines)
	if rows == 0 && columns == 0 {
		return nil
	}
	if rows == 0 {
		ops := make([]DiffLine, 0, columns)
		for _, line := range newLines {
			ops = append(ops, DiffLine{Op: '+', Text: line})
		}
		return ops
	}
	if columns == 0 {
		ops := make([]DiffLine, 0, rows)
		for _, line := range oldLines {
			ops = append(ops, DiffLine{Op: '-', Text: line})
		}
		return ops
	}
	table := make([][]int, rows+1)
	for row := range table {
		table[row] = make([]int, columns+1)
	}
	for row := rows - 1; row >= 0; row-- {
		for column := columns - 1; column >= 0; column-- {
			if oldLines[row] == newLines[column] {
				table[row][column] = table[row+1][column+1] + 1
				continue
			}
			table[row][column] = max(table[row+1][column], table[row][column+1])
		}
	}
	ops := make([]DiffLine, 0, rows+columns)
	row, column := 0, 0
	for row < rows && column < columns {
		switch {
		case oldLines[row] == newLines[column]:
			ops = append(ops, DiffLine{Op: ' ', Text: oldLines[row]})
			row++
			column++
		case table[row+1][column] >= table[row][column+1]:
			ops = append(ops, DiffLine{Op: '-', Text: oldLines[row]})
			row++
		default:
			ops = append(ops, DiffLine{Op: '+', Text: newLines[column]})
			column++
		}
	}
	for ; row < rows; row++ {
		ops = append(ops, DiffLine{Op: '-', Text: oldLines[row]})
	}
	for ; column < columns; column++ {
		ops = append(ops, DiffLine{Op: '+', Text: newLines[column]})
	}
	return ops
}

// Header renders a hunk's @@ line in git's format.
func (h Hunk) Header() string {
	return fmt.Sprintf("@@ -%d,%d +%d,%d @@", h.OldStart, h.OldCount, h.NewStart, h.NewCount)
}
