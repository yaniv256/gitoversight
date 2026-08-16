package ui

import (
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
	Files    []prpreview.FileDiff
	Warnings []string
	// Counts per change kind, for the summary bar.
	AddedFiles, ModifiedFiles, DeletedFiles, SubmoduleFiles int
	// Unavailable explains why no diff could be rendered. It is a REFUSAL, not
	// an empty state: a page that silently shows no files where files exist
	// would invite authorizing an unseen change.
	Unavailable string
}

func decodeSyncPacket(sync sqlite.SyncRequest) (commitpacket.Packet, string) {
	if strings.TrimSpace(sync.CommitPacketJSON) == "" {
		return commitpacket.Packet{}, "This proposal carries no commit packet, so its contents cannot be shown. Do not authorize it."
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(sync.CommitPacketJSON), &raw); err != nil {
		return commitpacket.Packet{}, "The stored commit packet could not be read. Do not authorize it."
	}
	packet, present, err := commitpacket.Decode(raw)
	if err != nil || !present {
		return commitpacket.Packet{}, "The stored commit packet is not valid. Do not authorize it."
	}
	return packet, ""
}

// buildSyncView builds a content-light review shell. It resolves the base tree
// once but never reads a base blob or computes a line diff.
func (handler *Handler) buildSyncView(sync sqlite.SyncRequest, identities []attribution.Identity) syncView {
	packet, unavailable := decodeSyncPacket(sync)
	if unavailable != "" {
		return syncView{Unavailable: unavailable}
	}
	if handler.bases == nil || sync.PublicRepository == "" {
		return syncView{Unavailable: "The public repository could not be read, so this change cannot be shown as a diff. Do not authorize it."}
	}
	base, err := handler.bases.ReadBase(workerrpc.BaseReadRequest{Repository: sync.PublicRepository, Branch: handler.baseBranch})
	if err != nil {
		return syncView{Unavailable: "The public repository could not be read, so this change cannot be shown as a diff. Do not authorize it."}
	}
	if packet.Tree.BaseTree != "" && base.TreeSHA != packet.Tree.BaseTree {
		return syncView{Unavailable: "The public base moved after this proposal was created. Do not authorize it."}
	}
	entries := make(map[string]prpreview.BaseEntry, len(base.Entries))
	for _, entry := range base.Entries {
		entries[entry.Path] = prpreview.BaseEntry{SHA: entry.SHA, Mode: entry.Mode, Type: entry.Type}
	}
	preview, err := prpreview.Inspect(packet, entries, identities)
	if err != nil {
		return syncView{Unavailable: "This change could not be rendered as a diff: " + err.Error() + ". Do not authorize it."}
	}

	view := syncView{
		Files: preview.Files, Warnings: preview.Warnings,
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
