package githubapp

// PullOutcome is what a pull request's lifecycle actually resolved to.
//
// GitHub encodes three outcomes in two fields (`state` and `merged`), and this
// codebase collapsed them into one boolean — so "closed without merging" was
// indistinguishable from "not merged yet". That collapse is why a sync whose PR
// was closed unmerged sat in public_pr_created forever with a Done button that
// could never succeed.
//
// The fourth value, PullOutcomeIndeterminate, is not a GitHub state. It is the
// honest answer when the read failed or came back without the fields needed to
// decide, and it exists so no caller can mistake a broken instrument for a
// verdict about the world.
type PullOutcome string

const (
	// PullOutcomeOpen: still awaiting a decision. Retryable — come back later.
	PullOutcomeOpen PullOutcome = "open"
	// PullOutcomeMerged: merged, MergeSHA is populated.
	PullOutcomeMerged PullOutcome = "merged"
	// PullOutcomeClosedUnmerged: closed and never merged. Terminal, and only
	// ever asserted on a POSITIVE witness — state=="closed" AND merged==false,
	// both read from the same payload.
	PullOutcomeClosedUnmerged PullOutcome = "closed_unmerged"
	// PullOutcomeIndeterminate: we could not tell. NEVER terminal.
	//
	// The rule this enforces: a verifier's negative read against an
	// eventually-consistent system is a null-prone instrument, and its "absent"
	// must not be terminal. Inferring closed-unmerged from !merged would let a
	// lagging read strand a genuinely MERGED pull request in a terminal state —
	// irreversibly, and worse than the bug being fixed.
	PullOutcomeIndeterminate PullOutcome = "indeterminate"
)

// PullState is one pull request's resolved lifecycle, carried whole so no layer
// beneath the decision has to re-derive it from a boolean.
type PullState struct {
	Outcome  PullOutcome `json:"outcome"`
	MergeSHA string      `json:"merge_sha,omitempty"`
	HTMLURL  string      `json:"html_url,omitempty"`
}

// Merged answers the old boolean question for callers that legitimately only
// care whether the merge happened. It is deliberately narrow: it returns true
// ONLY for a confirmed merge, so an indeterminate read reads as "not merged"
// here and callers that need the difference must ask for the Outcome.
func (s PullState) Merged() bool { return s.Outcome == PullOutcomeMerged }

// Terminal reports whether the pull request can no longer change on its own.
// Indeterminate is deliberately excluded — it describes our read, not the PR.
func (s PullState) Terminal() bool {
	return s.Outcome == PullOutcomeMerged || s.Outcome == PullOutcomeClosedUnmerged
}

// classifyPull turns GitHub's two fields into one outcome, requiring a positive
// witness before returning anything terminal.
//
// `state` is the field this codebase used to fetch and discard: it arrives in
// the same response as `merged`, so distinguishing the three outcomes costs no
// extra API call. An empty state means the payload did not carry the field —
// indeterminate, never closed.
func classifyPull(state string, merged bool, mergeSHA string) PullState {
	switch {
	case merged:
		// A merged PR is merged whatever `state` says; GitHub reports it as
		// closed, but the merge is the stronger signal and needs no corroboration.
		return PullState{Outcome: PullOutcomeMerged, MergeSHA: mergeSHA}
	case state == "open":
		return PullState{Outcome: PullOutcomeOpen}
	case state == "closed":
		return PullState{Outcome: PullOutcomeClosedUnmerged}
	default:
		return PullState{Outcome: PullOutcomeIndeterminate}
	}
}
