package gitref_test

import (
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/gitref"
)

func TestBranchNameAcceptsShortAndFullyQualifiedHeadsRefs(t *testing.T) {
	for input, want := range map[string]string{
		"fix/routing":            "fix/routing",
		"refs/heads/fix/routing": "fix/routing",
	} {
		if got := gitref.BranchName(input); got != want {
			t.Fatalf("BranchName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBranchNameRejectsNestedAndNonHeadQualifiedRefs(t *testing.T) {
	for _, input := range []string{
		"",
		"refs/heads/",
		"refs/heads/refs/heads/fix/routing",
		"refs/tags/v1.0.0",
	} {
		if got := gitref.BranchName(input); got != "" {
			t.Fatalf("BranchName(%q) = %q, want rejection", input, got)
		}
	}
}
