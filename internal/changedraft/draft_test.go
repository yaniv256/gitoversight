package changedraft

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func oid(char byte) ObjectID { return ObjectID(strings.Repeat(string(char), 40)) }

func baseFixture() Snapshot {
	return Snapshot{
		Repository: "yaniv256/example",
		Commit:     oid('a'),
		Tree:       oid('b'),
		Entries: []Entry{
			{Path: "README.md", Mode: ModeFile, Object: oid('c')},
			{Path: "cmd/tool.sh", Mode: ModeExecutable, Object: oid('d')},
			{Path: "docs/old.md", Mode: ModeFile, Object: oid('e')},
		},
	}
}

func TestBuildPreviewAppliesAllOperationsDeterministically(t *testing.T) {
	base := baseFixture()
	changes := []Change{
		{Operation: Add, Path: "docs/new.md", Mode: ModeFile, Content: []byte("new\n")},
		{Operation: Replace, Path: "README.md", Content: []byte("replacement\n")},
		{Operation: ChangeMode, Path: "cmd/tool.sh", Mode: ModeFile},
		{Operation: Delete, Path: "docs/old.md"},
	}
	one, err := BuildPreview(base, changes, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildPreview(base, []Change{changes[3], changes[1], changes[0], changes[2]}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if one.Hash != two.Hash || one.ResultTree != two.ResultTree {
		t.Fatalf("preview is order-dependent: %#v %#v", one, two)
	}
	if one.BaseTree != base.Tree || one.BaseCommit != base.Commit || one.Repository != base.Repository {
		t.Fatalf("base binding lost: %#v", one)
	}
	entries := entryMap(one.Result)
	if _, ok := entries["docs/old.md"]; ok {
		t.Fatal("deleted path remains")
	}
	if entries["cmd/tool.sh"].Mode != ModeFile {
		t.Fatalf("mode=%s", entries["cmd/tool.sh"].Mode)
	}
	if entries["README.md"].Object != GitObjectID("blob", []byte("replacement\n")) {
		t.Fatalf("replacement blob=%s", entries["README.md"].Object)
	}
	if entries["docs/new.md"].Object != GitObjectID("blob", []byte("new\n")) {
		t.Fatalf("new blob=%s", entries["docs/new.md"].Object)
	}
	if err := VerifyPreview(one); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestBuildPreviewMatchesKnownGitObjectIDs(t *testing.T) {
	if got := GitObjectID("blob", []byte("hello\n")); got != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Fatalf("blob id=%s", got)
	}
	preview, err := BuildPreview(Snapshot{Repository: "o/r", Commit: oid('1'), Tree: oid('2')}, []Change{
		{Operation: Add, Path: "hello.txt", Mode: ModeFile, Content: []byte("hello\n")},
	}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if preview.ResultTree == "" || preview.ResultTree == preview.BaseTree {
		t.Fatalf("tree=%s", preview.ResultTree)
	}
	if preview.ResultTree != "aaa96ced2d9a1c8e72c56b253a0e2fe78393feb7" {
		t.Fatalf("tree id=%s", preview.ResultTree)
	}
}

func TestBuildPreviewRejectsUnsafePathsAndConflicts(t *testing.T) {
	base := baseFixture()
	badPaths := []string{"", ".", "../x", "a/../b", "/root", "a//b", "a\\b", ".git/config", "nul\x00path"}
	for _, bad := range badPaths {
		t.Run(bad, func(t *testing.T) {
			_, err := BuildPreview(base, []Change{{Operation: Add, Path: bad, Mode: ModeFile, Content: []byte("x")}}, DefaultLimits())
			if !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	_, err := BuildPreview(base, []Change{
		{Operation: Replace, Path: "README.md", Content: []byte("one")},
		{Operation: Delete, Path: "README.md"},
	}, DefaultLimits())
	if !errors.Is(err, ErrDuplicatePath) {
		t.Fatalf("duplicate error=%v", err)
	}
	_, err = BuildPreview(base, []Change{{Operation: Add, Path: "cmd", Mode: ModeFile, Content: []byte("x")}}, DefaultLimits())
	if !errors.Is(err, ErrPathConflict) {
		t.Fatalf("prefix conflict error=%v", err)
	}
	_, err = BuildPreview(Snapshot{
		Repository: "o/r",
		Commit:     oid('1'),
		Tree:       oid('2'),
		Entries: []Entry{
			{Path: "a", Mode: ModeFile, Object: oid('3')},
			{Path: "a-b", Mode: ModeFile, Object: oid('4')},
			{Path: "a/child", Mode: ModeFile, Object: oid('5')},
		},
	}, nil, DefaultLimits())
	if !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("non-adjacent prefix conflict error=%v", err)
	}
}

func TestBuildPreviewRejectsInvalidOperationSemantics(t *testing.T) {
	base := baseFixture()
	cases := []struct {
		name   string
		change Change
		target error
	}{
		{"add existing", Change{Operation: Add, Path: "README.md", Mode: ModeFile}, ErrAlreadyExists},
		{"replace missing", Change{Operation: Replace, Path: "missing", Content: []byte("x")}, ErrNotFound},
		{"delete missing", Change{Operation: Delete, Path: "missing"}, ErrNotFound},
		{"mode missing", Change{Operation: ChangeMode, Path: "missing", Mode: ModeFile}, ErrNotFound},
		{"unsupported mode", Change{Operation: Add, Path: "new", Mode: "100600"}, ErrUnsupportedMode},
		{"delete content", Change{Operation: Delete, Path: "README.md", Content: []byte("x")}, ErrInvalidChange},
		{"mode content", Change{Operation: ChangeMode, Path: "README.md", Mode: ModeExecutable, Content: []byte("x")}, ErrInvalidChange},
		{"unknown operation", Change{Operation: "copy", Path: "new", Mode: ModeFile}, ErrInvalidChange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildPreview(base, []Change{tc.change}, DefaultLimits())
			if !errors.Is(err, tc.target) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestBuildPreviewEnforcesEveryLimit(t *testing.T) {
	base := Snapshot{Repository: "o/r", Commit: oid('1'), Tree: oid('2')}
	limits := Limits{MaxChanges: 2, MaxFileBytes: 3, MaxTotalBytes: 5, MaxResultFiles: 2}
	_, err := BuildPreview(base, []Change{{Operation: Add, Path: "a", Mode: ModeFile, Content: []byte("1234")}}, limits)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("file limit error=%v", err)
	}
	_, err = BuildPreview(base, []Change{
		{Operation: Add, Path: "a", Mode: ModeFile, Content: []byte("123")},
		{Operation: Add, Path: "b", Mode: ModeFile, Content: []byte("123")},
	}, limits)
	if !errors.Is(err, ErrTotalTooLarge) {
		t.Fatalf("total limit error=%v", err)
	}
	_, err = BuildPreview(base, []Change{
		{Operation: Add, Path: "a", Mode: ModeFile},
		{Operation: Add, Path: "b", Mode: ModeFile},
		{Operation: Add, Path: "c", Mode: ModeFile},
	}, limits)
	if !errors.Is(err, ErrTooManyChanges) {
		t.Fatalf("change limit error=%v", err)
	}
	_, err = BuildPreview(base, []Change{
		{Operation: Add, Path: "a", Mode: ModeFile},
		{Operation: Add, Path: "b", Mode: ModeFile},
	}, Limits{MaxChanges: 2, MaxFileBytes: 3, MaxTotalBytes: 5, MaxResultFiles: 1})
	if !errors.Is(err, ErrTooManyResultFiles) {
		t.Fatalf("result limit error=%v", err)
	}
}

func TestVerifyPreviewDetectsTampering(t *testing.T) {
	preview, err := BuildPreview(baseFixture(), []Change{{Operation: Replace, Path: "README.md", Content: []byte("new")}}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Preview){
		func(p *Preview) { p.Repository = "other/repo" },
		func(p *Preview) { p.BaseCommit = oid('f') },
		func(p *Preview) { p.BaseTree = oid('f') },
		func(p *Preview) { p.Result[0].Mode = ModeExecutable },
		func(p *Preview) { p.ResultTree = oid('f') },
		func(p *Preview) { p.Changes[0].Path = "other" },
		func(p *Preview) { p.Hash = strings.Repeat("0", 64) },
	}
	for i, mutate := range mutations {
		copy := clonePreview(preview)
		mutate(&copy)
		if err := VerifyPreview(copy); !errors.Is(err, ErrPreviewTampered) {
			t.Fatalf("mutation %d: error=%v", i, err)
		}
	}
}

type staticBaseResolver struct {
	ref BaseRef
	err error
}

func (s staticBaseResolver) CurrentBase(context.Context, string) (BaseRef, error) {
	return s.ref, s.err
}

func TestCheckBaseReturnsCurrentStaleAndUnavailable(t *testing.T) {
	preview, err := BuildPreview(baseFixture(), nil, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	current := CheckBase(context.Background(), staticBaseResolver{ref: BaseRef{Commit: preview.BaseCommit, Tree: preview.BaseTree}}, preview)
	if current.Status != BaseCurrent {
		t.Fatalf("current=%#v", current)
	}
	stale := CheckBase(context.Background(), staticBaseResolver{ref: BaseRef{Commit: oid('f'), Tree: oid('0')}}, preview)
	if stale.Status != BaseStale || stale.Expected.Commit != preview.BaseCommit || stale.Actual.Commit != oid('f') {
		t.Fatalf("stale=%#v", stale)
	}
	unavailable := CheckBase(context.Background(), staticBaseResolver{err: errors.New("offline")}, preview)
	if unavailable.Status != BaseUnavailable || unavailable.Err == nil {
		t.Fatalf("unavailable=%#v", unavailable)
	}
}

func entryMap(entries []Entry) map[string]Entry {
	result := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		result[entry.Path] = entry
	}
	return result
}

func clonePreview(value Preview) Preview {
	value.Result = append([]Entry(nil), value.Result...)
	value.Changes = append([]ChangeSummary(nil), value.Changes...)
	return value
}
