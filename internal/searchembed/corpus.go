package searchembed

import "math"

// Field weights: name and description tokens count ~3x readme tokens when
// summing a document vector.
const (
	nameDescWeight = 3.0
	readmeWeight   = 1.0
)

// Co-occurrence enrichment parameters: each sampled occurrence of a token
// pulls in coocWeight × the base vectors of neighbors within ±coocWindow
// positions; a token's occurrences are subsampled to maxOccurrences with an
// even stride so corpus-frequent tokens stay cheap.
const (
	coocWeight     = 0.3
	coocWindow     = 5
	maxOccurrences = 512
)

// Document is one searchable repo: token sequences per field (see
// NewDocument). Name and Description carry nameDescWeight; Readme carries
// readmeWeight. Co-occurrence windows never cross field boundaries.
type Document struct {
	ID          string
	Name        []string
	Description []string
	Readme      []string
}

// NewDocument tokenizes the raw fields of a repo into a Document.
func NewDocument(id, name, description, readme string) Document {
	return Document{
		ID:          id,
		Name:        Tokenize(name),
		Description: Tokenize(description),
		Readme:      Tokenize(readme),
	}
}

// TokenEntry is a trained token: enriched int8-quantized vector plus inverse
// document frequency. The shape mirrors searchstore.TokenVector so a sync
// job can feed Corpus.Tokens straight into ReplaceTokenVectors.
type TokenEntry struct {
	Vector []byte
	IDF    float64
}

// Corpus is the trained artifact set. Docs maps document ID (repo full_name)
// to its int8-quantized vector, shaped for searchstore.ReplaceVectors.
type Corpus struct {
	Tokens map[string]TokenEntry
	Docs   map[string][]byte
}

// occurrence points at one position of a token inside a field sequence.
type occurrence struct {
	seq []string
	pos int
}

// BuildCorpus trains token and document vectors over docs:
//
//  1. IDF per token = ln(1 + N/df) with df = number of documents containing
//     the token in any field.
//  2. Enriched token vector = L2-normalized (base + 0.3 × Σ base vectors of
//     neighbors within ±5 positions over evenly-strided sampled occurrences),
//     then int8-quantized.
//  3. Document vector = L2-normalized Σ weight × IDF(token) × enriched(token)
//     over every token occurrence, then int8-quantized.
func BuildCorpus(docs []Document) *Corpus {
	// Document frequency.
	df := make(map[string]int)
	for _, d := range docs {
		seen := make(map[string]bool)
		for _, seq := range [][]string{d.Name, d.Description, d.Readme} {
			for _, tok := range seq {
				if !seen[tok] {
					seen[tok] = true
					df[tok]++
				}
			}
		}
	}
	n := float64(len(docs))
	idf := make(map[string]float64, len(df))
	for tok, count := range df {
		idf[tok] = math.Log(1 + n/float64(count))
	}

	// Collect occurrences per token across every field sequence.
	occs := make(map[string][]occurrence, len(df))
	for _, d := range docs {
		for _, seq := range [][]string{d.Name, d.Description, d.Readme} {
			for i, tok := range seq {
				occs[tok] = append(occs[tok], occurrence{seq: seq, pos: i})
			}
		}
	}

	baseCache := make(map[string][]float64, len(df))
	base := func(tok string) []float64 {
		v, ok := baseCache[tok]
		if !ok {
			v = BaseVector(tok)
			baseCache[tok] = v
		}
		return v
	}

	// Enriched token vectors (kept in float for the doc sums).
	enriched := make(map[string][]float64, len(df))
	for tok, list := range occs {
		v := make([]float64, Dims)
		copy(v, base(tok))
		for _, o := range sampleStride(list, maxOccurrences) {
			lo := o.pos - coocWindow
			if lo < 0 {
				lo = 0
			}
			hi := o.pos + coocWindow
			if hi > len(o.seq)-1 {
				hi = len(o.seq) - 1
			}
			for j := lo; j <= hi; j++ {
				if j == o.pos {
					continue
				}
				nb := base(o.seq[j])
				for k, x := range nb {
					if x != 0 {
						v[k] += coocWeight * x
					}
				}
			}
		}
		l2Normalize(v)
		enriched[tok] = v
	}

	corpus := &Corpus{
		Tokens: make(map[string]TokenEntry, len(enriched)),
		Docs:   make(map[string][]byte, len(docs)),
	}
	for tok, v := range enriched {
		corpus.Tokens[tok] = TokenEntry{Vector: Quantize(v), IDF: idf[tok]}
	}

	for _, d := range docs {
		acc := make([]float64, Dims)
		addSeq := func(seq []string, weight float64) {
			for _, tok := range seq {
				w := weight * idf[tok]
				for k, x := range enriched[tok] {
					acc[k] += w * x
				}
			}
		}
		addSeq(d.Name, nameDescWeight)
		addSeq(d.Description, nameDescWeight)
		addSeq(d.Readme, readmeWeight)
		l2Normalize(acc)
		corpus.Docs[d.ID] = Quantize(acc)
	}
	return corpus
}

// sampleStride returns at most max elements of list, evenly strided across
// the whole list (all of them when list is short enough).
func sampleStride(list []occurrence, max int) []occurrence {
	if len(list) <= max {
		return list
	}
	out := make([]occurrence, 0, max)
	for i := 0; i < max; i++ {
		out = append(out, list[i*len(list)/max])
	}
	return out
}
