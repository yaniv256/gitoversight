package ui

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

// approvalView is what a human needs in order to authorize an agent's action on
// a PUBLIC repository: the text that will be published, and a plain statement of
// what happens if they approve.
//
// Every field here was already carried by the operation packet and simply never
// rendered — the approval page showed a 16-character packet hash where the
// comment body was. Asking someone to approve a publication they cannot read is
// not oversight; it is a rubber stamp with extra steps.
type approvalView struct {
	// Effect is one sentence: the verb, the repository, and the target.
	Effect string
	// TargetURL links the public PR or issue the write lands on, so the
	// approver can look at it before deciding. Empty when the packet carries
	// no number.
	TargetURL string
	// TargetLabel is the human name for that link ("PR #42").
	TargetLabel string
	// Published is the exact text that will appear on GitHub. Rendered as
	// text, never as HTML — it is agent-authored.
	Published string
	// PublishedLabel says what Published IS, since a comment body and a
	// replacement PR description need different framing.
	PublishedLabel string
	// ProposedTitle is set for operations that rewrite a PR's title.
	ProposedTitle string
	// Ref is a branch or head SHA when the operation moves refs rather than
	// text.
	Ref string
}

// buildApprovalView derives the view from the stored packet. It reads only —
// nothing here may influence the approve binding, which the broker cross-checks
// field by field.
func buildApprovalView(operation storage.Operation) approvalView {
	view := approvalView{}
	number := payloadNumber(operation.PayloadJSON)
	if number > 0 {
		// A pull URL resolves to the issue view for issue numbers and vice
		// versa, so one form is correct for both comment kinds.
		view.TargetURL = fmt.Sprintf("https://github.com/%s/pull/%d", operation.Repository, number)
		view.TargetLabel = fmt.Sprintf("PR #%d", number)
	}
	target := view.TargetLabel
	if target == "" {
		target = operation.Repository
	}

	switch operation.Kind {
	case "pull_request.reply", "issue.comment":
		view.Effect = fmt.Sprintf("Posts this comment publicly on %s, as the agent.", target)
		view.Published, view.PublishedLabel = operation.Body, "Comment to be posted"
	case "pull_request.review":
		view.Effect = fmt.Sprintf("Submits a public review on %s.", target)
		view.Published, view.PublishedLabel = operation.Body, "Review comment"
	case "pull_request.update":
		view.Effect = fmt.Sprintf("Replaces the title and description of %s.", target)
		view.Published, view.PublishedLabel = operation.Body, "New description"
		view.ProposedTitle = operation.Title
	case "pull_request.create":
		view.Effect = fmt.Sprintf("Opens a new public pull request on %s.", operation.Repository)
		view.Published, view.PublishedLabel = operation.Body, "Pull request description"
		view.ProposedTitle, view.Ref = operation.Title, refSummary(operation)
	case "pull_request.merge":
		view.Effect = fmt.Sprintf("Merges %s into its base branch.", target)
		view.Ref = refSummary(operation)
	case "pull_request.close":
		view.Effect = fmt.Sprintf("Closes %s without merging.", target)
	case "branch.push":
		view.Effect = fmt.Sprintf("Pushes commits to %s.", operation.Repository)
		view.Ref = refSummary(operation)
	case "branch.delete":
		view.Effect = fmt.Sprintf("Deletes a branch from %s.", operation.Repository)
		view.Ref = refSummary(operation)
	case "issue.create":
		view.Effect = fmt.Sprintf("Opens a new public issue on %s.", operation.Repository)
		view.Published, view.PublishedLabel = operation.Body, "Issue body"
		view.ProposedTitle = operation.Title
	default:
		// An unrecognised kind still renders. The generic line says less, but
		// a page that errors on an unknown operation would block approval of
		// an operation the broker is perfectly willing to execute.
		view.Effect = fmt.Sprintf("Runs %s against %s.", operation.Kind, operation.Repository)
		view.Published, view.PublishedLabel = operation.Body, "Body"
		view.ProposedTitle, view.Ref = operation.Title, refSummary(operation)
	}
	view.Published = withoutReconciliationMarker(view.Published)
	if strings.TrimSpace(view.Published) == "" {
		// Blank rather than an empty labelled box: "Comment to be posted"
		// above nothing reads as a rendering fault.
		view.Published, view.PublishedLabel = "", ""
	}
	return view
}

// withoutReconciliationMarker strips the HTML comment the worker embeds so it
// can later find its own comment on GitHub (see hasReconciliationMarker in
// internal/githubapp/operations.go).
//
// The marker is plumbing. It goes to GitHub — where it is invisible, being an
// HTML comment — but on this page it would render as visible text, so a
// reviewer reading "the comment to be posted" would see an internal token
// spliced into their prose. Caught by driving the deployed page, not by a unit
// test: the fixtures were written by hand without markers, so nothing exercised
// the shape a real packet has.
func withoutReconciliationMarker(body string) string {
	for {
		start := strings.Index(body, "<!-- gitoversight-request:")
		if start < 0 {
			break
		}
		end := strings.Index(body[start:], "-->")
		if end < 0 {
			// An unterminated marker is malformed; leave the text alone rather
			// than truncating a reviewer's content on a guess.
			break
		}
		body = body[:start] + body[start+end+len("-->"):]
	}
	return strings.TrimSpace(body)
}

// payloadNumber extracts the PR or issue number the operation targets. A packet
// with no number is normal (branch pushes, repository creates), so absence
// returns 0 rather than an error.
func payloadNumber(payload []byte) int64 {
	if len(payload) == 0 {
		return 0
	}
	var fields struct {
		Number *json.Number `json:"number"`
	}
	if err := json.Unmarshal(payload, &fields); err != nil || fields.Number == nil {
		return 0
	}
	number, err := fields.Number.Int64()
	if err != nil || number <= 0 {
		return 0
	}
	return number
}

// refSummary names the branch and head an operation moves, for the kinds where
// the change is a ref rather than prose.
func refSummary(operation storage.Operation) string {
	switch {
	case operation.Branch != "" && operation.HeadSHA != "":
		return fmt.Sprintf("%s at %.12s", operation.Branch, operation.HeadSHA)
	case operation.Branch != "":
		return operation.Branch
	case operation.HeadSHA != "":
		return fmt.Sprintf("%.12s", operation.HeadSHA)
	}
	return ""
}
