package searchembed

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// fakeIndex is an in-memory Index over a built Corpus, with a word-membership
// FTS stand-in mirroring searchstore's OR-of-phrases semantics.
type fakeIndex struct {
	corpus      *Corpus
	docTokens   map[string]map[string]bool // full_name -> token set over name+description+readme
	disableFTS  bool
	ftsOverride []string // when non-nil, FTSSearch returns exactly this (truncated to limit)
}

func newFakeIndex(corpus *Corpus, docTokens map[string]map[string]bool) *fakeIndex {
	return &fakeIndex{corpus: corpus, docTokens: docTokens}
}

func (f *fakeIndex) GetTokenVector(token string) ([]byte, float64, bool, error) {
	entry, ok := f.corpus.Tokens[token]
	if !ok {
		return nil, 0, false, nil
	}
	return entry.Vector, entry.IDF, true, nil
}

func (f *fakeIndex) IterateVectors(fn func(fullName string, vec []byte) error) error {
	names := make([]string, 0, len(f.corpus.Docs))
	for name := range f.corpus.Docs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := fn(name, f.corpus.Docs[name]); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeIndex) FTSSearch(tokens []string, limit int) ([]string, error) {
	if f.disableFTS || limit <= 0 {
		return nil, nil
	}
	if f.ftsOverride != nil {
		if len(f.ftsOverride) > limit {
			return f.ftsOverride[:limit], nil
		}
		return f.ftsOverride, nil
	}
	type hit struct {
		name  string
		count int
	}
	var hits []hit
	for name, set := range f.docTokens {
		count := 0
		for _, tok := range tokens {
			if set[tok] {
				count++
			}
		}
		if count > 0 {
			hits = append(hits, hit{name, count})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].count != hits[j].count {
			return hits[i].count > hits[j].count
		}
		return hits[i].name < hits[j].name
	})
	var names []string
	for _, h := range hits {
		if len(names) == limit {
			break
		}
		names = append(names, h.name)
	}
	return names, nil
}

func tokenSet(fields ...string) map[string]bool {
	set := map[string]bool{}
	for _, field := range fields {
		for _, tok := range Tokenize(field) {
			set[tok] = true
		}
	}
	return set
}

// TestMinAcrossKeywords: a doc matching only one of two keywords must rank
// below a doc matching both, on the vector leg alone.
func TestMinAcrossKeywords(t *testing.T) {
	docs := []Document{
		NewDocument("a/both", "a/both", "alpha beta", "alpha beta together always"),
		NewDocument("a/one", "a/one", "alpha gamma", "alpha gamma only here"),
		NewDocument("a/none", "a/none", "delta epsilon", "unrelated filler words"),
	}
	corpus := BuildCorpus(docs)
	idx := newFakeIndex(corpus, nil)
	idx.disableFTS = true

	results, err := Query(idx, "alpha beta", nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) < 2 {
		t.Fatalf("got %d results, want at least 2", len(results))
	}
	pos := map[string]int{}
	for i, r := range results {
		pos[r.FullName] = i
	}
	if pos["a/both"] >= pos["a/one"] {
		t.Fatalf("min-across-keywords failed: a/both at %d, a/one at %d (results %v)", pos["a/both"], pos["a/one"], results)
	}
}

// TestFTSBoostAnchorsExactName: an FTS hit gains a fixed boost that lifts it
// above a vector-only neighbor.
func TestFTSBoostAnchorsExactName(t *testing.T) {
	docs := []Document{
		NewDocument("a/widget", "a/widget", "widget", "small widget"),
		NewDocument("a/widget-farm", "a/widget-farm", "widget widget widget", "widget widget widget widget widget"),
	}
	corpus := BuildCorpus(docs)
	idx := newFakeIndex(corpus, nil)
	idx.ftsOverride = []string{"a/widget"} // only the exact-name doc is an FTS hit

	results, err := Query(idx, "widget", nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].FullName != "a/widget" {
		t.Fatalf("FTS boost did not anchor exact-name hit: %v", results)
	}

	// Without FTS the boost is gone; the boosted doc must not owe its rank to vectors.
	idx.ftsOverride = nil
	idx.disableFTS = true
	bare, err := Query(idx, "widget", nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(bare) < 2 {
		t.Fatalf("got %d results, want 2", len(bare))
	}
	boosted, plain := results[0], bare[0]
	if boosted.FullName == plain.FullName && boosted.Score <= plain.Score {
		t.Fatalf("boost had no observable effect: with FTS %v, without %v", results, bare)
	}
}

func TestQueryEmptyAndLimits(t *testing.T) {
	corpus := BuildCorpus([]Document{NewDocument("a/x", "a/x", "alpha", "alpha")})
	idx := newFakeIndex(corpus, nil)
	if res, err := Query(idx, "", nil, 5); err != nil || res != nil {
		t.Fatalf("empty query: got %v, %v", res, err)
	}
	if res, err := Query(idx, "alpha", nil, 0); err != nil || res != nil {
		t.Fatalf("zero limit: got %v, %v", res, err)
	}
	res, err := Query(idx, "alpha", []string{"alpha"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("limit not applied: %v", res)
	}
}

// --- Known-answer retrieval eval (the R7 gate) ---

type fixtureDoc struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Readme      string `json:"readme"`
}

type fixtureQuery struct {
	Query    string `json:"query"`
	Target   string `json:"target"`
	Semantic bool   `json:"semantic"`
}

type evalFixture struct {
	Docs       []fixtureDoc   `json:"docs"`
	Queries    []fixtureQuery `json:"queries"`
	Distractor string         `json:"distractor"`
}

func loadEvalFixture(t *testing.T) evalFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/eval_corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var fix evalFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatal(err)
	}
	if len(fix.Docs) < 25 {
		t.Fatalf("fixture has %d docs, want ~30", len(fix.Docs))
	}
	if len(fix.Queries) < 10 {
		t.Fatalf("fixture has %d labeled queries, want >= 10", len(fix.Queries))
	}
	if fix.Distractor == "" {
		t.Fatal("fixture missing planted distractor")
	}
	return fix
}

func buildEvalIndex(t *testing.T, fix evalFixture) *fakeIndex {
	t.Helper()
	var docs []Document
	docTokens := map[string]map[string]bool{}
	seenDistractor := false
	for _, d := range fix.Docs {
		docs = append(docs, NewDocument(d.Name, d.Name, d.Description, d.Readme))
		docTokens[d.Name] = tokenSet(d.Name, d.Description, d.Readme)
		if d.Name == fix.Distractor {
			seenDistractor = true
		}
	}
	if !seenDistractor {
		t.Fatalf("distractor %q not present in fixture docs", fix.Distractor)
	}
	return newFakeIndex(BuildCorpus(docs), docTokens)
}

func rankOf(results []Result, fullName string) int {
	for i, r := range results {
		if r.FullName == fullName {
			return i
		}
	}
	return -1
}

func inTop3(idx *fakeIndex, query, target string) (bool, []Result, error) {
	results, err := Query(idx, query, nil, 5)
	if err != nil {
		return false, nil, err
	}
	rank := rankOf(results, target)
	return rank >= 0 && rank < 3, results, nil
}

// TestEvalGreenLabeledQueriesTop3: every labeled query ranks its target in the
// top 3. Semantic queries (no token shared with the target's name) must ALSO
// pass with FTS disabled, proving the embedding leg carries them.
func TestEvalGreenLabeledQueriesTop3(t *testing.T) {
	fix := loadEvalFixture(t)
	idx := buildEvalIndex(t, fix)

	semanticCount := 0
	for _, q := range fix.Queries {
		ok, results, err := inTop3(idx, q.Query, q.Target)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("query %q: target %q not in top 3: %v", q.Query, q.Target, results)
		}
		if q.Semantic {
			semanticCount++
			nameTokens := tokenSet(q.Target)
			for _, tok := range Tokenize(q.Query) {
				if nameTokens[tok] {
					t.Errorf("query %q marked semantic but shares token %q with target name %q", q.Query, tok, q.Target)
				}
			}
			idx.disableFTS = true
			ok, results, err := inTop3(idx, q.Query, q.Target)
			idx.disableFTS = false
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Errorf("semantic query %q: target %q not in top 3 with FTS disabled (embedding leg failed): %v", q.Query, q.Target, results)
			}
		}
	}
	if semanticCount < 3 {
		t.Errorf("only %d semantic queries; eval barely exercises the embedding leg", semanticCount)
	}
}

// TestEvalRedDistractorNeverTop3: the planted clearly-irrelevant doc must not
// crack the top 3 for any labeled query.
func TestEvalRedDistractorNeverTop3(t *testing.T) {
	fix := loadEvalFixture(t)
	idx := buildEvalIndex(t, fix)
	for _, q := range fix.Queries {
		hit, results, err := inTop3(idx, q.Query, fix.Distractor)
		if err != nil {
			t.Fatal(err)
		}
		if hit {
			t.Errorf("distractor %q reached top 3 for query %q: %v", fix.Distractor, q.Query, results)
		}
	}
}

// TestEvalRedShuffledLabelsFail: instrument self-test. With query->target
// labels rotated by one, the pass rate must collapse well below the green
// bar, proving the eval can actually fire.
func TestEvalRedShuffledLabelsFail(t *testing.T) {
	fix := loadEvalFixture(t)
	idx := buildEvalIndex(t, fix)
	n := len(fix.Queries)
	passes := 0
	for i, q := range fix.Queries {
		wrongTarget := fix.Queries[(i+1)%n].Target
		if wrongTarget == q.Target {
			t.Fatalf("rotation degenerate at %d: query %q keeps its own target %q — reorder the fixture", i, q.Query, q.Target)
		}
		ok, _, err := inTop3(idx, q.Query, wrongTarget)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			passes++
		}
	}
	// Green requires n/n. A working instrument must reject shuffled labels.
	if passes*3 > n {
		t.Fatalf("shuffled labels still passed %d/%d (> 1/3): the eval cannot detect wrong answers", passes, n)
	}
	if passes == n {
		t.Fatal("shuffled labels passed everything: the eval measures nothing")
	}
	t.Logf("shuffled-label control: %d/%d passed (green bar is %d/%d)", passes, n, n, n)
}
