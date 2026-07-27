package searchstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestLazyReaderOpensStoreCreatedAfterConstruction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "search.db")
	reader := NewLazyReader(path)

	// Before the sync job builds the corpus the file is absent: the open error
	// is the not-built sentinel and is NOT cached.
	if _, err := reader.Open(ctx); !IndexNotBuilt(err) {
		t.Fatalf("pre-build Open err = %v, want IndexNotBuilt", err)
	}

	writer, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	seedRepo(t, writer, Repo{FullName: "yaniv256/actions.json", Description: "voice agent"})

	// After the file appears the retry succeeds and the store is cached.
	store, err := reader.Open(ctx)
	if err != nil {
		t.Fatalf("post-build Open: %v", err)
	}
	if again, err := reader.Open(ctx); err != nil || again != store {
		t.Fatalf("second Open = %p, %v; want cached %p", again, err, store)
	}
	t.Cleanup(func() { _ = store.Close() })
}

func TestIndexNotBuilt(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"missing file", fmt.Errorf("wrap: %w", ErrNotExist), true},
		{"schema mismatch", fmt.Errorf("wrap: %w", ErrSchemaMismatch), true},
		{"other failure", errors.New("disk exploded"), false},
	}
	for _, tc := range cases {
		if got := IndexNotBuilt(tc.err); got != tc.want {
			t.Errorf("%s: IndexNotBuilt(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestSnippet(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		repo Repo
		want string
	}{
		{
			name: "readme wins and whitespace collapses",
			repo: Repo{ReadmeText: "  hello\n\tworld  ", Description: "ignored"},
			want: "hello world",
		},
		{
			name: "falls back to description when readme blank",
			repo: Repo{ReadmeText: "   ", Description: "just a desc"},
			want: "just a desc",
		},
		{
			name: "truncates to snippetRunes",
			repo: Repo{ReadmeText: strings.Repeat("x", snippetRunes+50)},
			want: strings.Repeat("x", snippetRunes),
		},
	}
	for _, tc := range cases {
		if got := Snippet(tc.repo); got != tc.want {
			t.Errorf("%s: Snippet = %q, want %q", tc.name, got, tc.want)
		}
	}
}
