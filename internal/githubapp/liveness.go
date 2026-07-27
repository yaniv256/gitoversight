package githubapp

import (
	"fmt"

	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

// PullNotWritableError refuses a mutation whose target pull request cannot
// receive it, and NAMES why.
//
// A bare `pull_request_closed` would repeat the defect this guard exists to
// fix — one opaque token standing for several distinguishable causes, which is
// the most-repeated error shape in this codebase (worker_request_incomplete,
// human_session_rejected, and the merge boolean itself). The caller needs to
// know whether the pull request was closed, merged, or simply unreadable,
// because those have three different recoveries.
type PullNotWritableError struct {
	Repository string
	Number     int64
	Outcome    PullOutcome
	HTMLURL    string
}

func (e *PullNotWritableError) Error() string {
	switch e.Outcome {
	case PullOutcomeMerged:
		return fmt.Sprintf("pull request %s#%d is already merged, so this write cannot reach anyone (%s)",
			e.Repository, e.Number, e.HTMLURL)
	case PullOutcomeClosedUnmerged:
		return fmt.Sprintf("pull request %s#%d is closed without merging, so this write would land where nobody will read it (%s)",
			e.Repository, e.Number, e.HTMLURL)
	default:
		// Indeterminate. The guard FAILS CLOSED: we could not establish the
		// pull request is writable, so we do not write. This is the mirror of
		// the merge-read rule — there an indeterminate read must never produce
		// a terminal verdict; here it must never produce permission. Permit-on-
		// error would silently disable the guard during a GitHub outage and the
		// void-writes would return, invisibly.
		return fmt.Sprintf("could not establish that pull request %s#%d is open; refusing to write on an unverified target",
			e.Repository, e.Number)
	}
}

// Retryable reports whether the caller should try again later. An
// indeterminate read is a statement about our instrument, not about the pull
// request, so it is retryable; closed and merged are facts about the world and
// are not.
func (e *PullNotWritableError) Retryable() bool { return e.Outcome == PullOutcomeIndeterminate }

// pullRequestWriteRule says what liveness means for one operation.
type pullRequestWriteRule int

const (
	// ruleNone: the operation does not target an existing pull request, or
	// guards itself. `merge` is deliberately here — see requirePullRequestIsWritable.
	ruleNone pullRequestWriteRule = iota
	// ruleRequireOpen: refuse unless the pull request is open. The conversation
	// is over on a closed or merged PR, and GitHub will still accept the write.
	ruleRequireOpen
	// ruleRefuseMerged: refuse only when merged. Used by `close`, where
	// closing an already-closed pull request is a correct idempotent no-op.
	ruleRefuseMerged
)

// pullRequestWriteRules is the KTD3 table, in code.
//
// There are FIVE pull-request-targeting operations, not four, and they do not
// all want the same treatment. Enumerating them forces the question the first
// draft never asked: is the rule "refuse when the PR is not open", or "refuse
// when the write cannot achieve its intent"? Those coincide for three
// operations and diverge for two — and `close` is the case that settles it,
// because a blanket open-only rule would break a working idempotent operation.
//
// The rule this codebase adopts is: REFUSE A WRITE THAT CANNOT ACHIEVE ITS
// INTENT.
var pullRequestWriteRules = map[string]pullRequestWriteRule{
	"pull_request.update": ruleRequireOpen,
	"pull_request.review": ruleRequireOpen,
	"pull_request.close":  ruleRefuseMerged,
	// COMMENTS ARE NOT GUARDED. `issue.comment` and `pull_request.reply` are
	// absent deliberately, and the distinction is the whole point of the rule.
	//
	// An update into a closed pull request VANISHES: GitHub accepts it, returns
	// 200, and nobody will ever read it — the author does not learn their work
	// went nowhere. That is a GitHub misfeature this system exists to close.
	//
	// A comment into a closed pull request does the opposite: it is visible,
	// and wanting it is ordinary. A reviewer closes the PR and you still need to
	// discuss it — to explain a mistake, to ask why, to link a replacement. The
	// conversation outliving the merge decision is the NORMAL case, not an edge
	// one, and it is exactly what a closed pre-PR does here already (U8 keeps
	// the discussion thread open precisely so a closed pre-PR stays discussable).
	//
	// The rule was always "refuse a write that cannot achieve its intent". A
	// comment on a closed PR achieves its intent completely. The first version
	// of this table wrote ruleRequireOpen for both comment operations, which
	// applied "refuse when not open" — the rule this file's own comment block
	// argues against. It named `close` as the sole divergent case and missed
	// that comments are the other one.
	// pull_request.merge is ABSENT deliberately, not forgotten. It already
	// fails informatively — GitHub's own message via `github did not merge pull
	// request: %s` — so a pre-flight read would buy a nicer error at the cost of
	// an extra API call plus a TOCTOU window between the read and the PUT that
	// does not exist today. Map its failure; do not guard it.
}

// requirePullRequestIsWritable refuses a mutation whose target pull request
// cannot receive it.
//
// Before this existed, GitHub accepted a PATCH on a closed pull request and
// returned 200; reconciliation then re-read it, saw the title matched, and
// reported `present`. The system CONFIRMED a write that changed nothing anyone
// would ever merge — strictly worse than failing, because a confident-wrong
// success ends the investigation before it starts.
func (c *Client) requirePullRequestIsWritable(request worker.Request, mode TokenMode, subject string) error {
	rule, guarded := pullRequestWriteRules[request.Operation]
	if !guarded || rule == ruleNone {
		return nil
	}
	// PUBLIC repositories only.
	//
	// The harm this guard prevents is a write that lands, unread, on someone
	// else's public pull request while our system reports success — and on a
	// not-owned repo it is visible to a third party and cannot be quietly
	// undone. On a private mirror the same write is cheap to notice and cheap to
	// redo, so charging every private mutation an extra GitHub read to prevent
	// it is the wrong trade.
	//
	// Scoped after the operation check so a visibility lookup is not spent on
	// operations that were never going to be guarded.
	visibility, err := c.visibility(request.Repository)
	if err != nil {
		// Unknown visibility fails CLOSED for the same reason an unknown pull
		// request state does: we cannot establish the write is safe.
		return &PullNotWritableError{Repository: request.Repository, Outcome: PullOutcomeIndeterminate}
	}
	if visibility != "public" {
		return nil
	}
	number, err := requiredNumber(request.Payload)
	if err != nil {
		// No number to check. The operation's own validation will reject an
		// incomplete packet with a better message than this guard could.
		return nil
	}
	state, readErr := c.PullRequestState(request.Repository, int64(number), mode, subject)
	if readErr != nil {
		return &PullNotWritableError{Repository: request.Repository, Number: int64(number), Outcome: PullOutcomeIndeterminate}
	}
	switch rule {
	case ruleRequireOpen:
		if state.Outcome == PullOutcomeOpen {
			return nil
		}
	case ruleRefuseMerged:
		if state.Outcome != PullOutcomeMerged {
			return nil
		}
	}
	return &PullNotWritableError{
		Repository: request.Repository, Number: int64(number),
		Outcome: state.Outcome, HTMLURL: state.HTMLURL,
	}
}
