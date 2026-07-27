package sqlite

import (
	"context"
	"encoding/json"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

// SyncProvenance is what a reviewer needs when a REVISED pre-PR lands: that it
// is a revision at all, what they asked for, and how many times it has come
// back.
//
// The revision loop already worked end to end — Request changes → the agent is
// notified → it resubmits through /v1/sync/{id}/update, which re-bases against
// the public HEAD exactly like a first proposal. What was missing is memory. The
// page rendered the new proposal with no sign it was a revision, so the reviewer
// re-read it cold, with no record of the change they themselves requested.
//
// Both signals were already persisted and simply never read: the change note as
// a `sync_change_note` authority transition, and each revision as a
// sync_transition carrying `"revised": true`.
type SyncProvenance struct {
	// Revision is how many times the agent has resubmitted. Zero means this is
	// the original proposal and the page shows no provenance at all — the
	// common case must not grow a banner saying "revision 0".
	Revision int
	// ChangeNotes are the reviewer's requests, oldest first. Plural because a
	// proposal can go around more than once, and "what did I ask for last
	// time?" is a different question from "what have I asked for?".
	ChangeNotes []string
}

// LatestChangeNote is the request the current revision was written against.
func (p SyncProvenance) LatestChangeNote() string {
	if len(p.ChangeNotes) == 0 {
		return ""
	}
	return p.ChangeNotes[len(p.ChangeNotes)-1]
}

// SyncProvenanceFor reconstructs the revision history from the receipted audit
// trail rather than from a denormalised counter.
//
// The audit chain is hash-linked and already the system's record of what
// happened, so deriving from it cannot drift from the truth the way a
// maintained-in-parallel column would.
func (db *DB) SyncProvenanceFor(ctx context.Context, tenantID, id string) (SyncProvenance, error) {
	events, err := db.AuthorityAuditEvents(ctx, tenantID, id)
	if err != nil {
		return SyncProvenance{}, err
	}
	provenance := SyncProvenance{}
	for _, event := range events {
		switch event.Kind {
		case "sync_change_note":
			if note := decodedString(event, "note"); note != "" {
				provenance.ChangeNotes = append(provenance.ChangeNotes, note)
			}
		case "sync_transition":
			if decodedBool(event, "revised") {
				provenance.Revision++
			}
		}
	}
	return provenance, nil
}

func decodedString(event storage.AuditEvent, key string) string {
	var payload map[string]any
	if err := json.Unmarshal(event.PayloadJSON, &payload); err != nil {
		return ""
	}
	value, _ := payload[key].(string)
	return value
}

func decodedBool(event storage.AuditEvent, key string) bool {
	var payload map[string]any
	if err := json.Unmarshal(event.PayloadJSON, &payload); err != nil {
		return false
	}
	value, _ := payload[key].(bool)
	return value
}
