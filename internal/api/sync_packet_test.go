package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/api"
	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

// Does the packet the API STORES still satisfy commitpacket.Validate? The
// publish path re-decodes it, so a delta that no longer validates would be
// accepted at propose time and fail at publish — after the human approved.
func TestStoredRebasedPacketStillValidates(t *testing.T) {
	db := syncAPIDB(t)
	base := []githubapp.TreeEntry{{Path: "OLD.md", Mode: "100644", Type: "blob", SHA: "1111111111111111111111111111111111111111"}}
	handler := apiHandlerWith(t, db, fakeBases{entries: base, treeSHA: "2222222222222222222222222222222222222222", commitSHA: "3333333333333333333333333333333333333333"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if response.Code != http.StatusCreated {
		t.Fatalf("propose = %d body=%s", response.Code, response.Body.String())
	}
	item, err := db.GetSyncRequest(context.Background(), "default", "sync-a")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(item.CommitPacketJSON), &raw); err != nil {
		t.Fatal(err)
	}
	packet, present, err := commitpacket.Decode(raw)
	if !present {
		t.Fatal("stored packet has no object_package")
	}
	if err != nil {
		t.Fatalf("stored packet does not validate: %v", err)
	}
	// The rebase must have derived the deletion of the base-only path.
	deleted := false
	for _, entry := range packet.Tree.Entries {
		if entry.Path == "OLD.md" && entry.Delete {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("rebase did not derive the deletion; entries = %+v", packet.Tree.Entries)
	}
	if packet.Tree.BaseTree != "2222222222222222222222222222222222222222" {
		t.Fatalf("base_tree = %q, want the PUBLIC tree sha", packet.Tree.BaseTree)
	}
}

func apiHandlerWith(t *testing.T, db *sqlite.DB, bases fakeBases) http.Handler {
	t.Helper()
	return api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: db, Bases: bases})
}
