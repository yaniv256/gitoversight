package searchembed

import (
	"math"
	"sort"
)

// Index is the narrow read interface the ranking layer needs from a store.
// internal/searchstore satisfies it via its EmbedIndex adapter; tests use an
// in-memory fake.
type Index interface {
	GetTokenVector(token string) (vec []byte, idf float64, ok bool, err error)
	IterateVectors(fn func(fullName string, vec []byte) error) error
	FTSSearch(tokens []string, limit int) ([]string, error) // returns full_names
}

// Result is one ranked search hit.
type Result struct {
	FullName string
	Score    float64
}

// maxQueryTokens caps how many distinct keywords a query contributes.
const maxQueryTokens = 16

// ftsBoost is the fixed score bonus for a full-text hit, anchoring exact-name
// matches to the top of the ranking.
const ftsBoost = 0.25

// Query ranks documents in index against q plus extraKeywords:
//
//  1. Tokenize q and each extra keyword; dedupe, cap at maxQueryTokens.
//  2. Per keyword, use the corpus-enriched token vector from the index when
//     present, else fall back to the deterministic random-indexing base
//     vector (normalized, quantized).
//  3. Scan every document vector; a document's vector score is the MINIMUM
//     cosine across keywords, so a document must relate to all keywords.
//  4. Merge with full-text hits: each FTS match gains ftsBoost (documents
//     seen only by FTS enter with just the boost).
//  5. Return the top limit results by score (ties broken by name).
func Query(index Index, q string, extraKeywords []string, limit int) ([]Result, error) {
	if limit <= 0 {
		return nil, nil
	}
	seen := make(map[string]bool)
	var keywords []string
	addTokens := func(s string) {
		for _, tok := range Tokenize(s) {
			if len(keywords) >= maxQueryTokens {
				return
			}
			if !seen[tok] {
				seen[tok] = true
				keywords = append(keywords, tok)
			}
		}
	}
	addTokens(q)
	for _, kw := range extraKeywords {
		addTokens(kw)
	}
	if len(keywords) == 0 {
		return nil, nil
	}

	vecs := make([][]byte, len(keywords))
	for i, tok := range keywords {
		vec, _, ok, err := index.GetTokenVector(tok)
		if err != nil {
			return nil, err
		}
		if ok {
			vecs[i] = vec
			continue
		}
		fallback := BaseVector(tok)
		l2Normalize(fallback)
		vecs[i] = Quantize(fallback)
	}

	scores := make(map[string]float64)
	err := index.IterateVectors(func(fullName string, vec []byte) error {
		minCos := math.Inf(1)
		for _, kv := range vecs {
			c := CosineInt8(kv, vec)
			if c < minCos {
				minCos = c
			}
		}
		scores[fullName] = minCos
		return nil
	})
	if err != nil {
		return nil, err
	}

	ftsHits, err := index.FTSSearch(keywords, limit)
	if err != nil {
		return nil, err
	}
	for _, name := range ftsHits {
		scores[name] += ftsBoost // absent names enter at just the boost
	}

	results := make([]Result, 0, len(scores))
	for name, score := range scores {
		results = append(results, Result{FullName: name, Score: score})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].FullName < results[j].FullName
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}
