package searchstore

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// snippetRunes bounds Snippet output: the first ~200 runes of README text.
const snippetRunes = 200

// LazyReader opens a read-only searchstore on first use and caches the open
// Store. The store file appears asynchronously — it legitimately does not
// exist until the sync job first builds the corpus — so open errors are NOT
// cached: the next call retries. Both the agent search endpoint and the human
// UI share this contract.
//
// The zero value is not usable; construct with NewLazyReader.
type LazyReader struct {
	path string

	mu    sync.Mutex
	store *Store
}

// NewLazyReader returns a LazyReader that opens the database at path on first
// successful Open.
func NewLazyReader(path string) *LazyReader {
	return &LazyReader{path: path}
}

// Open returns the cached read-only store, opening it on first success. Open
// errors are returned uncached so a later call retries once the sync job has
// built (or rebuilt) the corpus.
func (r *LazyReader) Open(ctx context.Context) (*Store, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store != nil {
		return r.store, nil
	}
	store, err := OpenReadOnly(ctx, r.path)
	if err != nil {
		return nil, err
	}
	r.store = store
	return store, nil
}

// IndexNotBuilt reports whether an open error means "the corpus has not been
// built (or rebuilt for this schema) yet" — a normal pre-sync state callers
// answer with an empty/building view rather than a hard failure. Both a
// missing file and a schema-version mismatch resolve on the next sync.
func IndexNotBuilt(err error) bool {
	return errors.Is(err, ErrNotExist) || errors.Is(err, ErrSchemaMismatch)
}

// Snippet is the first ~200 runes of a repo's README (falling back to the
// description) with whitespace collapsed to single spaces.
func Snippet(repo Repo) string {
	source := repo.ReadmeText
	if strings.TrimSpace(source) == "" {
		source = repo.Description
	}
	text := strings.Join(strings.Fields(source), " ")
	runes := []rune(text)
	if len(runes) > snippetRunes {
		runes = runes[:snippetRunes]
	}
	return string(runes)
}
