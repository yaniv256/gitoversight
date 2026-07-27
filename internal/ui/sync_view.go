package ui

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/attribution"
	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/prpreview"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

// syncView is everything the pre-PR page renders. It is assembled server-side
// so the template does no computation and no string building: every value here
// is escaped as text by html/template (KTD6 — diff content is authored by an
// agent and must never reach the page as markup).
type syncView struct {
	Files        []prpreview.FileDiff
	Warnings     []string
	TotalAdded   int
	TotalRemoved int
	// Counts per change kind, for the summary bar.
	AddedFiles, ModifiedFiles, DeletedFiles, SubmoduleFiles int
	// AutoExpand opens every file's <details> when the change is small enough
	// to read at once (KTD7).
	AutoExpand bool
	// Unavailable explains why no diff could be rendered. It is a REFUSAL, not
	// an empty state: a page that silently shows no files where files exist
	// would invite authorizing an unseen change.
	Unavailable string
}

// diffLimitForExpand is the file count below which every diff opens by default.
const diffLimitForExpand = 5

// buildSyncView renders the stored pre-PR into reviewable diffs.
//
// base supplies the public repository's content per path. When it is nil the
// view refuses rather than rendering a contentless file list — the previous
// behavior, and the thing this whole feature exists to remove.
func buildSyncView(sync sqlite.SyncRequest, base prpreview.BaseContent, identities []attribution.Identity) syncView {
	if strings.TrimSpace(sync.CommitPacketJSON) == "" {
		return syncView{Unavailable: "This proposal carries no commit packet, so its contents cannot be shown. Do not authorize it."}
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(sync.CommitPacketJSON), &raw); err != nil {
		return syncView{Unavailable: "The stored commit packet could not be read. Do not authorize it."}
	}
	packet, present, err := commitpacket.Decode(raw)
	if err != nil || !present {
		return syncView{Unavailable: "The stored commit packet is not valid. Do not authorize it."}
	}
	if base == nil {
		return syncView{Unavailable: "The public repository could not be read, so this change cannot be shown as a diff. Do not authorize it."}
	}
	preview, err := prpreview.Build(packet, packet.Tree.BaseTree, base, nil, identities)
	if err != nil {
		return syncView{Unavailable: "This change could not be rendered as a diff: " + err.Error() + ". Do not authorize it."}
	}

	view := syncView{
		Files: preview.Files, Warnings: preview.Warnings,
		TotalAdded: preview.TotalAdded, TotalRemoved: preview.TotalRemoved,
		AutoExpand: len(preview.Files) <= diffLimitForExpand,
	}
	for _, file := range preview.Files {
		switch file.Kind {
		case prpreview.ChangeAdd:
			view.AddedFiles++
		case prpreview.ChangeModify:
			view.ModifiedFiles++
		case prpreview.ChangeDelete:
			view.DeletedFiles++
		case prpreview.ChangeSubmodule:
			view.SubmoduleFiles++
		}
	}
	return view
}

// lineClass maps a diff op to its CSS class. Kept here rather than in the
// template so the template stays declarative.
func lineClass(op byte) string {
	switch op {
	case '+':
		return "add"
	case '-':
		return "del"
	default:
		return "ctx"
	}
}

// kindLabel is the human word for a change kind, matching GitHub's vocabulary.
func kindLabel(kind prpreview.ChangeKind) string {
	switch kind {
	case prpreview.ChangeAdd:
		return "added"
	case prpreview.ChangeModify:
		return "modified"
	case prpreview.ChangeDelete:
		return "deleted"
	case prpreview.ChangeSubmodule:
		return "submodule"
	}
	return string(kind)
}

// baseContentFor returns a reader for the public repository's current content,
// or nil when the base cannot be resolved.
//
// Nil is deliberate and is NOT an empty result: buildSyncView turns it into a
// visible refusal. A page that quietly rendered "no files" where files exist
// would invite authorizing an unseen change — the exact failure this feature
// exists to prevent.
func (handler *Handler) baseContentFor(ctx context.Context, sync sqlite.SyncRequest) prpreview.BaseContent {
	if handler.bases == nil || sync.PublicRepository == "" {
		return nil
	}
	base, err := handler.bases.ReadBase(workerrpc.BaseReadRequest{Repository: sync.PublicRepository, Branch: handler.baseBranch})
	if err != nil {
		return nil
	}
	shaByPath := make(map[string]string, len(base.Entries))
	for _, entry := range base.Entries {
		shaByPath[entry.Path] = entry.SHA
	}
	return func(path string) ([]byte, bool, error) {
		sha, present := shaByPath[path]
		if !present {
			return nil, false, nil
		}
		content, err := handler.bases.ReadBlob(sync.PublicRepository, sha)
		if err != nil {
			return nil, false, err
		}
		return content, true, nil
	}
}
