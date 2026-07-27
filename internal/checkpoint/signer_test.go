package checkpoint_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/checkpoint"
)

func TestSignerExtendsMonotonicallyAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := checkpoint.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	one, err := signer.Extend(checkpoint.Extension{PreviousTail: "", NewTail: "tail-1", PolicyGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	signer, err = checkpoint.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	two, err := signer.Extend(checkpoint.Extension{PreviousTail: one.Tail, NewTail: "tail-2", PolicyGeneration: 2})
	if err != nil || two.Sequence != 2 {
		t.Fatalf("extend after restart = %#v, %v", two, err)
	}
}

func TestSignerRejectsForkRollbackAndReset(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	signer, err := checkpoint.Open(path, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Extend(checkpoint.Extension{NewTail: "tail-1", PolicyGeneration: 3}); err != nil {
		t.Fatal(err)
	}
	for _, extension := range []checkpoint.Extension{
		{PreviousTail: "wrong", NewTail: "fork", PolicyGeneration: 4},
		{PreviousTail: "tail-1", NewTail: "rollback", PolicyGeneration: 2},
		{PreviousTail: "tail-1", NewTail: "", PolicyGeneration: 4},
		{PreviousTail: "tail-1", NewTail: "tail-1", PolicyGeneration: 4},
	} {
		if _, err := signer.Extend(extension); err == nil {
			t.Fatalf("expected rejection for %#v", extension)
		}
	}
}

func TestSignerExposesOnlyVerifiableTimestampedState(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	signer, err := checkpoint.Open(path, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(-time.Second)
	state, err := signer.Extend(checkpoint.Extension{NewTail: "tail-1", PolicyGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if state.SignedAt.Before(before) || state.SignedAt.After(time.Now().UTC().Add(time.Second)) {
		t.Fatalf("signed_at = %s", state.SignedAt)
	}
	if got := signer.State(); got != state {
		t.Fatalf("state = %#v, want %#v", got, state)
	}
	if err := signer.Verify(state); err != nil {
		t.Fatalf("verify valid state: %v", err)
	}
	state.Tail = "replacement-history"
	if err := signer.Verify(state); err == nil {
		t.Fatal("expected forged state rejection")
	}
}
