package searchembed

import (
	"testing"
)

func docFrom(id, name, description, readme string) Document {
	return NewDocument(id, name, description, readme)
}

func TestIDFRanksRareAboveCommon(t *testing.T) {
	docs := []Document{
		docFrom("a/one", "one", "common words everywhere", "common filler text"),
		docFrom("a/two", "two", "common words again", "common filler text"),
		docFrom("a/three", "three", "common words again", "common filler text"),
		docFrom("a/four", "four", "common diarization pipeline", "the only rare doc"),
	}
	corpus := BuildCorpus(docs)
	rare, ok := corpus.Tokens["diarization"]
	if !ok {
		t.Fatal("rare token missing from corpus")
	}
	common, ok := corpus.Tokens["common"]
	if !ok {
		t.Fatal("common token missing from corpus")
	}
	if rare.IDF <= common.IDF {
		t.Fatalf("IDF(rare)=%v should exceed IDF(common)=%v", rare.IDF, common.IDF)
	}
}

func TestCorpusShapesForPersistence(t *testing.T) {
	docs := []Document{
		docFrom("acme/agent-kanban", "acme/agent-kanban", "kanban board", "tracks agent tasks on a board"),
		docFrom("acme/lorem", "acme/lorem", "cooking recipes", "sourdough bread and pasta"),
	}
	corpus := BuildCorpus(docs)
	if len(corpus.Docs) != 2 {
		t.Fatalf("doc vectors = %d, want 2", len(corpus.Docs))
	}
	for id, vec := range corpus.Docs {
		if len(vec) != Dims {
			t.Fatalf("doc %q vector length %d, want %d", id, len(vec), Dims)
		}
	}
	if len(corpus.Tokens) == 0 {
		t.Fatal("no token vectors built")
	}
	for tok, entry := range corpus.Tokens {
		if len(entry.Vector) != Dims {
			t.Fatalf("token %q vector length %d, want %d", tok, len(entry.Vector), Dims)
		}
		if entry.IDF <= 0 {
			t.Fatalf("token %q IDF %v, want > 0", tok, entry.IDF)
		}
	}
}

// TestCooccurrenceEnrichment: a token that always appears next to another
// should have an enriched vector closer to that neighbor's base vector than
// to an unrelated token's base vector.
func TestCooccurrenceEnrichment(t *testing.T) {
	docs := []Document{
		docFrom("a/one", "one", "kanban board kanban board kanban board", ""),
		docFrom("a/two", "two", "kanban board again", "kanban board kanban board"),
		docFrom("a/three", "three", "sourdough rosemary carbonara", "guanciale pecorino"),
	}
	corpus := BuildCorpus(docs)
	enrichedKanban := corpus.Tokens["kanban"].Vector

	board := BaseVector("board")
	unrelated := BaseVector("sourdough")
	simBoard := CosineInt8(enrichedKanban, Quantize(board))
	simUnrelated := CosineInt8(enrichedKanban, Quantize(unrelated))
	if simBoard <= simUnrelated {
		t.Fatalf("enrichment missing: cos(kanban, board)=%v <= cos(kanban, sourdough)=%v", simBoard, simUnrelated)
	}
}

// TestDocVectorAlignsWithItsTokens: a document should be closer to a token it
// contains than a document that does not contain it.
func TestDocVectorAlignsWithItsTokens(t *testing.T) {
	docs := []Document{
		docFrom("a/kanban", "a/kanban", "kanban board agent tasks", "cards move across lists"),
		docFrom("a/cook", "a/cook", "cooking recipes", "sourdough rosemary carbonara pecorino"),
	}
	corpus := BuildCorpus(docs)
	kanbanTok := corpus.Tokens["kanban"].Vector
	simKanbanDoc := CosineInt8(kanbanTok, corpus.Docs["a/kanban"])
	simCookDoc := CosineInt8(kanbanTok, corpus.Docs["a/cook"])
	if simKanbanDoc <= simCookDoc {
		t.Fatalf("doc alignment wrong: cos(kanban, kanban-doc)=%v <= cos(kanban, cook-doc)=%v", simKanbanDoc, simCookDoc)
	}
}
