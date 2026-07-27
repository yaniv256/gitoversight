package searchstore

import (
	"context"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/searchembed"
)

// The adapter must satisfy the searchembed read interface.
var _ searchembed.Index = EmbedIndex{}

func TestEmbedIndexAdapter(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	if err := store.UpsertRepo(ctx, Repo{FullName: "acme/agent-kanban", Description: "kanban board"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceTokenVectors(ctx, map[string]TokenVector{
		"kanban": {Vector: []byte{1, 2, 3}, IDF: 1.5},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceVectors(ctx, map[string][]byte{
		"acme/agent-kanban": {4, 5, 6},
	}); err != nil {
		t.Fatal(err)
	}

	idx := store.EmbedIndex(ctx)

	vec, idf, ok, err := idx.GetTokenVector("kanban")
	if err != nil || !ok {
		t.Fatalf("GetTokenVector: ok=%v err=%v", ok, err)
	}
	if string(vec) != string([]byte{1, 2, 3}) || idf != 1.5 {
		t.Fatalf("GetTokenVector returned vec=%v idf=%v", vec, idf)
	}
	if _, _, ok, err := idx.GetTokenVector("missing"); err != nil || ok {
		t.Fatalf("missing token: ok=%v err=%v", ok, err)
	}

	var iterated []string
	if err := idx.IterateVectors(func(fullName string, vec []byte) error {
		iterated = append(iterated, fullName)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(iterated) != 1 || iterated[0] != "acme/agent-kanban" {
		t.Fatalf("IterateVectors saw %v", iterated)
	}

	names, err := idx.FTSSearch([]string{"kanban"}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "acme/agent-kanban" {
		t.Fatalf("FTSSearch returned %v", names)
	}
}
