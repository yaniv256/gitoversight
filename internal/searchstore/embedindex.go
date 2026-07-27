package searchstore

import "context"

// EmbedIndex adapts a Store to the searchembed.Index read interface for a
// fixed context: it flattens TokenVector into (vec, idf, ok, err), binds ctx,
// and projects FTS hits down to their full names. Obtain one per request via
// Store.EmbedIndex.
type EmbedIndex struct {
	ctx   context.Context
	store *Store
}

// EmbedIndex returns a searchembed.Index view of the store bound to ctx.
func (s *Store) EmbedIndex(ctx context.Context) EmbedIndex {
	return EmbedIndex{ctx: ctx, store: s}
}

// GetTokenVector returns the enriched vector and IDF for token.
func (e EmbedIndex) GetTokenVector(token string) ([]byte, float64, bool, error) {
	tv, ok, err := e.store.GetTokenVector(e.ctx, token)
	return tv.Vector, tv.IDF, ok, err
}

// IterateVectors calls fn for every stored document vector.
func (e EmbedIndex) IterateVectors(fn func(fullName string, vec []byte) error) error {
	return e.store.IterateVectors(e.ctx, fn)
}

// FTSSearch runs the store's full-text search and returns just the matching
// repo full names, ranked best first.
func (e EmbedIndex) FTSSearch(tokens []string, limit int) ([]string, error) {
	repos, err := e.store.FTSSearch(e.ctx, tokens, limit)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(repos))
	for _, repo := range repos {
		names = append(names, repo.FullName)
	}
	return names, nil
}
