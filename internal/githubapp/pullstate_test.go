package githubapp

import "testing"

// The classification is the whole fix in miniature: three GitHub outcomes plus
// an honest "we could not tell", where the old code had one boolean.
func TestClassifyPullDistinguishesAllFourOutcomes(t *testing.T) {
	t.Parallel()
	for name, testCase := range map[string]struct {
		state    string
		merged   bool
		mergeSHA string
		want     PullOutcome
		wantSHA  string
	}{
		"open awaiting a decision":    {state: "open", want: PullOutcomeOpen},
		"merged carries its SHA":      {state: "closed", merged: true, mergeSHA: "abc123", want: PullOutcomeMerged, wantSHA: "abc123"},
		"closed without merging":      {state: "closed", want: PullOutcomeClosedUnmerged},
		"missing state is not closed": {state: "", want: PullOutcomeIndeterminate},
		"unknown state is not closed": {state: "draft-ish", want: PullOutcomeIndeterminate},
		"merged wins over open state": {state: "open", merged: true, mergeSHA: "def456", want: PullOutcomeMerged, wantSHA: "def456"},
	} {
		got := classifyPull(testCase.state, testCase.merged, testCase.mergeSHA)
		if got.Outcome != testCase.want {
			t.Fatalf("%s: outcome = %q, want %q", name, got.Outcome, testCase.want)
		}
		if got.MergeSHA != testCase.wantSHA {
			t.Fatalf("%s: merge sha = %q, want %q", name, got.MergeSHA, testCase.wantSHA)
		}
	}
}

// The hazard this type exists to prevent: a lagging or malformed read must
// never produce a terminal verdict, because terminal verdicts strand a
// genuinely merged pull request forever.
func TestIndeterminateIsNeverTerminalAndNeverMerged(t *testing.T) {
	t.Parallel()
	unknown := classifyPull("", false, "")
	if unknown.Terminal() {
		t.Fatal("an indeterminate read reported a terminal pull request")
	}
	if unknown.Merged() {
		t.Fatal("an indeterminate read reported a merge")
	}
	if !classifyPull("closed", false, "").Terminal() {
		t.Fatal("closed-unmerged must be terminal")
	}
	if !classifyPull("closed", true, "sha").Terminal() {
		t.Fatal("merged must be terminal")
	}
	if classifyPull("open", false, "").Terminal() {
		t.Fatal("an open pull request is not terminal")
	}
}

// Merged() is the narrow bridge for callers that only care about the merge. It
// must not widen: an indeterminate read reading as "merged" would publish a
// completion nobody performed.
func TestMergedIsTrueOnlyForAConfirmedMerge(t *testing.T) {
	t.Parallel()
	for _, outcome := range []PullOutcome{PullOutcomeOpen, PullOutcomeClosedUnmerged, PullOutcomeIndeterminate} {
		if (PullState{Outcome: outcome}).Merged() {
			t.Fatalf("%q reported as merged", outcome)
		}
	}
	if !(PullState{Outcome: PullOutcomeMerged}).Merged() {
		t.Fatal("a confirmed merge did not report as merged")
	}
}
