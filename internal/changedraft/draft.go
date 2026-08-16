// Package changedraft builds deterministic, bounded previews of repository
// file changes. It is a pure local core: it performs no GitHub or network I/O.
package changedraft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

type ObjectID string
type Mode string
type Operation string

const (
	ModeFile       Mode = "100644"
	ModeExecutable Mode = "100755"
	ModeSymlink    Mode = "120000"

	Add        Operation = "add"
	Replace    Operation = "replace"
	Delete     Operation = "delete"
	ChangeMode Operation = "mode"
)

var (
	ErrInvalidSnapshot    = errors.New("invalid base snapshot")
	ErrInvalidPath        = errors.New("invalid repository path")
	ErrDuplicatePath      = errors.New("duplicate change path")
	ErrPathConflict       = errors.New("repository path conflicts with another path")
	ErrUnsupportedMode    = errors.New("unsupported file mode")
	ErrInvalidChange      = errors.New("invalid file change")
	ErrAlreadyExists      = errors.New("path already exists")
	ErrNotFound           = errors.New("path not found")
	ErrTooManyChanges     = errors.New("too many changes")
	ErrFileTooLarge       = errors.New("file content exceeds limit")
	ErrTotalTooLarge      = errors.New("total content exceeds limit")
	ErrTooManyResultFiles = errors.New("result contains too many files")
	ErrPreviewTampered    = errors.New("change preview is internally inconsistent")
)

type Entry struct {
	Path   string   `json:"path"`
	Mode   Mode     `json:"mode"`
	Object ObjectID `json:"object"`
}

// Snapshot is a complete flattened view of one exact repository tree.
// Commit and Tree are the independently observed base identities.
type Snapshot struct {
	Repository string
	Commit     ObjectID
	Tree       ObjectID
	Entries    []Entry
}

type Change struct {
	Operation Operation
	Path      string
	Mode      Mode
	Content   []byte
}

type ChangeSummary struct {
	Operation Operation `json:"operation"`
	Path      string    `json:"path"`
	Mode      Mode      `json:"mode,omitempty"`
	Object    ObjectID  `json:"object,omitempty"`
	Bytes     int       `json:"bytes,omitempty"`
}

type Limits struct {
	MaxChanges     int
	MaxFileBytes   int
	MaxTotalBytes  int
	MaxResultFiles int
}

func DefaultLimits() Limits {
	return Limits{
		MaxChanges:     256,
		MaxFileBytes:   1 << 20,
		MaxTotalBytes:  8 << 20,
		MaxResultFiles: 100_000,
	}
}

type Preview struct {
	Repository string          `json:"repository"`
	BaseCommit ObjectID        `json:"base_commit"`
	BaseTree   ObjectID        `json:"base_tree"`
	ResultTree ObjectID        `json:"result_tree"`
	Result     []Entry         `json:"result"`
	Changes    []ChangeSummary `json:"changes"`
	Hash       string          `json:"preview_hash"`
}

// ObjectBuilder isolates Git object construction so future adapters can store
// the resulting objects without changing preview semantics.
type ObjectBuilder interface {
	Blob(content []byte) ObjectID
	Tree(entries []TreeObject) (ObjectID, error)
}

func BuildPreview(base Snapshot, changes []Change, limits Limits) (Preview, error) {
	return BuildPreviewWithObjects(base, changes, limits, GitObjectBuilder{})
}

func BuildPreviewWithObjects(base Snapshot, changes []Change, limits Limits, objects ObjectBuilder) (Preview, error) {
	if objects == nil || !validRepository(base.Repository) || !validObjectID(base.Commit) || !validObjectID(base.Tree) {
		return Preview{}, ErrInvalidSnapshot
	}
	if limits.MaxChanges <= 0 || limits.MaxFileBytes < 0 || limits.MaxTotalBytes < 0 || limits.MaxResultFiles <= 0 {
		return Preview{}, fmt.Errorf("%w: invalid limits", ErrInvalidChange)
	}
	if len(changes) > limits.MaxChanges {
		return Preview{}, ErrTooManyChanges
	}

	result, err := validatedEntries(base.Entries)
	if err != nil {
		return Preview{}, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}
	seen := make(map[string]struct{}, len(changes))
	ordered := append([]Change(nil), changes...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	total := 0
	summaries := make([]ChangeSummary, 0, len(ordered))
	for _, change := range ordered {
		if err := validatePath(change.Path); err != nil {
			return Preview{}, err
		}
		if _, duplicate := seen[change.Path]; duplicate {
			return Preview{}, fmt.Errorf("%w: %s", ErrDuplicatePath, change.Path)
		}
		seen[change.Path] = struct{}{}
		if len(change.Content) > limits.MaxFileBytes {
			return Preview{}, fmt.Errorf("%w: %s", ErrFileTooLarge, change.Path)
		}
		total += len(change.Content)
		if total > limits.MaxTotalBytes {
			return Preview{}, ErrTotalTooLarge
		}

		summary, err := applyChange(result, change, objects)
		if err != nil {
			return Preview{}, err
		}
		summaries = append(summaries, summary)
	}

	entries := sortedEntries(result)
	if len(entries) > limits.MaxResultFiles {
		return Preview{}, ErrTooManyResultFiles
	}
	if err := rejectPrefixConflicts(entries); err != nil {
		return Preview{}, err
	}
	resultTree := base.Tree
	if len(changes) > 0 {
		resultTree, err = buildRootTree(entries, objects)
		if err != nil {
			return Preview{}, err
		}
	}
	preview := Preview{
		Repository: base.Repository,
		BaseCommit: base.Commit,
		BaseTree:   base.Tree,
		ResultTree: resultTree,
		Result:     entries,
		Changes:    summaries,
	}
	preview.Hash = previewHash(preview)
	return preview, nil
}

func applyChange(result map[string]Entry, change Change, objects ObjectBuilder) (ChangeSummary, error) {
	existing, exists := result[change.Path]
	switch change.Operation {
	case Add:
		if exists {
			return ChangeSummary{}, fmt.Errorf("%w: %s", ErrAlreadyExists, change.Path)
		}
		if !validMode(change.Mode) {
			return ChangeSummary{}, fmt.Errorf("%w: %s", ErrUnsupportedMode, change.Mode)
		}
		object := objects.Blob(change.Content)
		result[change.Path] = Entry{Path: change.Path, Mode: change.Mode, Object: object}
		return ChangeSummary{Operation: Add, Path: change.Path, Mode: change.Mode, Object: object, Bytes: len(change.Content)}, nil
	case Replace:
		if !exists {
			return ChangeSummary{}, fmt.Errorf("%w: %s", ErrNotFound, change.Path)
		}
		if change.Mode != "" {
			return ChangeSummary{}, fmt.Errorf("%w: replace cannot change mode", ErrInvalidChange)
		}
		object := objects.Blob(change.Content)
		existing.Object = object
		result[change.Path] = existing
		return ChangeSummary{Operation: Replace, Path: change.Path, Mode: existing.Mode, Object: object, Bytes: len(change.Content)}, nil
	case Delete:
		if !exists {
			return ChangeSummary{}, fmt.Errorf("%w: %s", ErrNotFound, change.Path)
		}
		if change.Mode != "" || len(change.Content) != 0 {
			return ChangeSummary{}, fmt.Errorf("%w: delete accepts only a path", ErrInvalidChange)
		}
		delete(result, change.Path)
		return ChangeSummary{Operation: Delete, Path: change.Path, Mode: existing.Mode, Object: existing.Object}, nil
	case ChangeMode:
		if !exists {
			return ChangeSummary{}, fmt.Errorf("%w: %s", ErrNotFound, change.Path)
		}
		if !validMode(change.Mode) {
			return ChangeSummary{}, fmt.Errorf("%w: %s", ErrUnsupportedMode, change.Mode)
		}
		if len(change.Content) != 0 {
			return ChangeSummary{}, fmt.Errorf("%w: mode change accepts no content", ErrInvalidChange)
		}
		existing.Mode = change.Mode
		result[change.Path] = existing
		return ChangeSummary{Operation: ChangeMode, Path: change.Path, Mode: change.Mode, Object: existing.Object}, nil
	default:
		return ChangeSummary{}, fmt.Errorf("%w: unknown operation %q", ErrInvalidChange, change.Operation)
	}
}

func VerifyPreview(preview Preview) error {
	if !validRepository(preview.Repository) || !validObjectID(preview.BaseCommit) || !validObjectID(preview.BaseTree) || !validObjectID(preview.ResultTree) {
		return ErrPreviewTampered
	}
	entries, err := validatedEntries(preview.Result)
	if err != nil || len(entries) != len(preview.Result) {
		return ErrPreviewTampered
	}
	ordered := sortedEntries(entries)
	if !entriesEqual(ordered, preview.Result) {
		return ErrPreviewTampered
	}
	if len(preview.Changes) > 0 {
		resultTree, err := buildRootTree(preview.Result, GitObjectBuilder{})
		if err != nil || resultTree != preview.ResultTree {
			return ErrPreviewTampered
		}
	}
	if previewHash(preview) != preview.Hash {
		return ErrPreviewTampered
	}
	return nil
}

func previewHash(preview Preview) string {
	contract := struct {
		Domain     string          `json:"domain"`
		Repository string          `json:"repository"`
		BaseCommit ObjectID        `json:"base_commit"`
		BaseTree   ObjectID        `json:"base_tree"`
		ResultTree ObjectID        `json:"result_tree"`
		Result     []Entry         `json:"result"`
		Changes    []ChangeSummary `json:"changes"`
	}{"gitoversight.changedraft.preview.v1", preview.Repository, preview.BaseCommit, preview.BaseTree, preview.ResultTree, preview.Result, preview.Changes}
	payload, _ := json.Marshal(contract)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func validatedEntries(entries []Entry) (map[string]Entry, error) {
	result := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		if err := validatePath(entry.Path); err != nil {
			return nil, err
		}
		if !validMode(entry.Mode) {
			return nil, ErrUnsupportedMode
		}
		if !validObjectID(entry.Object) {
			return nil, ErrInvalidSnapshot
		}
		if _, exists := result[entry.Path]; exists {
			return nil, ErrDuplicatePath
		}
		result[entry.Path] = entry
	}
	if err := rejectPrefixConflicts(sortedEntries(result)); err != nil {
		return nil, err
	}
	return result, nil
}

func sortedEntries(entries map[string]Entry) []Entry {
	result := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}

func entriesEqual(a, b []Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func rejectPrefixConflicts(entries []Entry) error {
	paths := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		paths[entry.Path] = struct{}{}
	}
	for _, entry := range entries {
		for index := strings.IndexByte(entry.Path, '/'); index >= 0; index = nextSlash(entry.Path, index+1) {
			parent := entry.Path[:index]
			if _, conflict := paths[parent]; conflict {
				return fmt.Errorf("%w: %s and %s", ErrPathConflict, parent, entry.Path)
			}
		}
	}
	return nil
}

func nextSlash(value string, start int) int {
	if start >= len(value) {
		return -1
	}
	relative := strings.IndexByte(value[start:], '/')
	if relative < 0 {
		return -1
	}
	return start + relative
}

func validatePath(value string) error {
	if value == "" || !utf8.ValidString(value) || strings.ContainsRune(value, 0) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return fmt.Errorf("%w: %q", ErrInvalidPath, value)
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." || segment == ".git" {
			return fmt.Errorf("%w: %q", ErrInvalidPath, value)
		}
	}
	return nil
}

func validMode(mode Mode) bool {
	return mode == ModeFile || mode == ModeExecutable || mode == ModeSymlink
}

func validObjectID(value ObjectID) bool {
	if len(value) != 40 || strings.ToLower(string(value)) != string(value) {
		return false
	}
	_, err := hex.DecodeString(string(value))
	return err == nil
}

func validRepository(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || strings.Count(value, "/") != 1 {
		return false
	}
	parts := strings.Split(value, "/")
	return parts[0] != "" && parts[1] != "" && !strings.ContainsAny(value, "\\\x00\r\n\t")
}

type BaseRef struct {
	Commit ObjectID
	Tree   ObjectID
}

type BaseResolver interface {
	CurrentBase(ctx context.Context, repository string) (BaseRef, error)
}

type BaseStatus string

const (
	BaseCurrent     BaseStatus = "current"
	BaseStale       BaseStatus = "stale"
	BaseUnavailable BaseStatus = "unavailable"
)

type BaseVerification struct {
	Status   BaseStatus
	Expected BaseRef
	Actual   BaseRef
	Err      error
}

func CheckBase(ctx context.Context, resolver BaseResolver, preview Preview) BaseVerification {
	expected := BaseRef{Commit: preview.BaseCommit, Tree: preview.BaseTree}
	if resolver == nil {
		return BaseVerification{Status: BaseUnavailable, Expected: expected, Err: errors.New("base resolver is nil")}
	}
	actual, err := resolver.CurrentBase(ctx, preview.Repository)
	if err != nil {
		return BaseVerification{Status: BaseUnavailable, Expected: expected, Err: err}
	}
	status := BaseCurrent
	if actual != expected {
		status = BaseStale
	}
	return BaseVerification{Status: status, Expected: expected, Actual: actual}
}
