package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/api"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

func syncAPIPolicy() policy.Snapshot {
	return policy.Snapshot{
		Generation:   1,
		QueueCurator: "zara",
		Agents: map[string]policy.Agent{
			"zara":  {UID: 1002, FirstName: "Zara"},
			"tomas": {UID: 1005, FirstName: "Tomas"},
		},
		Repositories: map[string]policy.Repository{
			"yaniv256/mirror.dev": {Visibility: "private", Owners: []string{"zara"}, Writers: []string{"zara", "tomas"}, Approvers: []string{"yaniv"}, SyncsTo: "yaniv256/mirror"},
			"yaniv256/mirror":     {Visibility: "public", Owners: []string{"zara"}, Writers: []string{"zara"}, Approvers: []string{"yaniv"}},
		},
	}
}

func syncAPIDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "api.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.EnsureTenant(context.Background(), "default", time.Unix(1_700_000_000, 0).UTC())
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return db
}

func agentRequest(method, path, body, agentID string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	return request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "default", AgentID: agentID, CredentialID: agentID + "-key"}))
}

// shapePacketJSON is a real, self-consistent shape packet: every hash is git's
// own, so commitpacket.Validate's content->blob->tree->commit chain holds. A
// stub would be rejected before the rebase under test ever ran.
const shapePacketJSON = `{\"sha\": \"68d273daa52639af3825a0e4c2d0a5ab82bd40a0\", \"object_package\": {\"blobs\": [{\"sha\": \"50860bb5e14f44f3916a2b1f2976f009c1580b65\", \"content\": \"IyBTa2lsbAo=\", \"encoding\": \"base64\"}], \"tree\": {\"sha\": \"9ff4fc377ca2fdf571913c2f2abeb30655ea91a8\", \"entries\": [{\"path\": \"SKILL.md\", \"mode\": \"100644\", \"type\": \"blob\", \"sha\": \"50860bb5e14f44f3916a2b1f2976f009c1580b65\"}]}, \"commit\": {\"sha\": \"68d273daa52639af3825a0e4c2d0a5ab82bd40a0\", \"message\": \"Release\\n\", \"tree\": \"9ff4fc377ca2fdf571913c2f2abeb30655ea91a8\", \"parents\": [], \"author\": {\"name\": \"Zara\", \"email\": \"zara@example.com\", \"date\": \"2023-11-14T22:13:20Z\"}, \"committer\": {\"name\": \"Zara\", \"email\": \"zara@example.com\", \"date\": \"2023-11-14T22:13:20Z\"}}}}`

var proposeBody = `{"id":"sync-a","repository":"yaniv256/mirror.dev","text":"Release","commit_packet_json":"` + shapePacketJSON + `","packet_head_sha":"68d273daa52639af3825a0e4c2d0a5ab82bd40a0"}`

// fakeBases stands in for the worker's public-repository read. An EMPTY base
// makes the whole shape an addition, which is the common first-sync case.
type fakeBases struct {
	entries   []githubapp.TreeEntry
	treeSHA   string
	commitSHA string
	empty     bool
	err       error
}

func (f fakeBases) ReadBase(workerrpc.BaseReadRequest) (workerrpc.BaseRead, error) {
	if f.err != nil {
		return workerrpc.BaseRead{}, f.err
	}
	if f.empty {
		return workerrpc.BaseRead{Empty: true}, nil
	}
	treeSHA, commitSHA := f.treeSHA, f.commitSHA
	if treeSHA == "" {
		treeSHA = "2222222222222222222222222222222222222222"
	}
	if commitSHA == "" {
		commitSHA = "3333333333333333333333333333333333333333"
	}
	return workerrpc.BaseRead{CommitSHA: commitSHA, TreeSHA: treeSHA, Entries: f.entries}, nil
}

func TestSyncProposeHappyPath(t *testing.T) {
	t.Parallel()
	handler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: syncAPIDB(t), Bases: fakeBases{empty: true}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"public_repository":"yaniv256/mirror"`) {
		t.Fatalf("body = %s", response.Body.String())
	}
}

func TestSyncProposeDeniedWithoutTargetStanding(t *testing.T) {
	t.Parallel()
	handler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: syncAPIDB(t), Bases: fakeBases{empty: true}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "tomas"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestSyncProposeUnauthenticated(t *testing.T) {
	t.Parallel()
	handler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: syncAPIDB(t), Bases: fakeBases{empty: true}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/sync", strings.NewReader(proposeBody)))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestSyncUpdateOnlyFromChangesRequested(t *testing.T) {
	t.Parallel()
	db := syncAPIDB(t)
	handler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: db, Bases: fakeBases{empty: true}})
	create := httptest.NewRecorder()
	handler.ServeHTTP(create, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d", create.Code)
	}
	updateBody := `{"text":"Release v2","commit_packet_json":"` + shapePacketJSON + `","packet_head_sha":"68d273daa52639af3825a0e4c2d0a5ab82bd40a0"}`
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, agentRequest(http.MethodPost, "/v1/sync/sync-a/update", updateBody, "zara"))
	if blocked.Code != http.StatusConflict {
		t.Fatalf("update from proposed = %d, want 409", blocked.Code)
	}
	if err := db.RequestSyncChanges(context.Background(), "default", "sync-a", time.Unix(1_800_000_100, 0)); err != nil {
		t.Fatalf("request changes: %v", err)
	}
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, agentRequest(http.MethodPost, "/v1/sync/sync-a/update", updateBody, "zara"))
	if allowed.Code != http.StatusOK {
		t.Fatalf("update from changes_requested = %d body=%s", allowed.Code, allowed.Body.String())
	}
}

func TestQueueOrderCuratorGateAndValidation(t *testing.T) {
	t.Parallel()
	db := syncAPIDB(t)
	syncHandler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: db, Bases: fakeBases{empty: true}})
	created := httptest.NewRecorder()
	syncHandler.ServeHTTP(created, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if created.Code != http.StatusCreated {
		t.Fatalf("seed sync: %d", created.Code)
	}
	handler := api.NewQueueHandler(api.QueueHandlerConfig{Policy: syncAPIPolicy(), Store: db})

	// non-curator rejected
	forbidden := httptest.NewRecorder()
	handler.ServeHTTP(forbidden, agentRequest(http.MethodPost, "/v1/queue/order", `{"items":[{"item_id":"q1","kind":"sync","ref":"sync-a"}]}`, "tomas"))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("non-curator = %d", forbidden.Code)
	}
	// unknown ref rejected whole
	unknown := httptest.NewRecorder()
	handler.ServeHTTP(unknown, agentRequest(http.MethodPost, "/v1/queue/order", `{"items":[{"item_id":"q1","kind":"sync","ref":"ghost"}]}`, "zara"))
	if unknown.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown ref = %d", unknown.Code)
	}
	// review kind fails closed in v1
	review := httptest.NewRecorder()
	handler.ServeHTTP(review, agentRequest(http.MethodPost, "/v1/queue/order", `{"items":[{"item_id":"q1","kind":"review","ref":"pr-1"}]}`, "zara"))
	if review.Code != http.StatusUnprocessableEntity {
		t.Fatalf("review kind = %d", review.Code)
	}
	// happy path + top read
	ok := httptest.NewRecorder()
	handler.ServeHTTP(ok, agentRequest(http.MethodPost, "/v1/queue/order", `{"items":[{"item_id":"q1","kind":"sync","ref":"sync-a"}]}`, "zara"))
	if ok.Code != http.StatusOK {
		t.Fatalf("set order = %d body=%s", ok.Code, ok.Body.String())
	}
	top := httptest.NewRecorder()
	handler.ServeHTTP(top, agentRequest(http.MethodGet, "/v1/queue/top", "", "zara"))
	if top.Code != http.StatusOK || !strings.Contains(top.Body.String(), `"depth":1`) {
		t.Fatalf("top = %d body=%s", top.Code, top.Body.String())
	}
}

// The manifest a human reviews must be DERIVED from the packet, never accepted
// from the submission. Before this, `files` was a hand-typed CLI flag stored
// verbatim and hashed into the approval, while publication was driven entirely
// by the packet — so a proposal could declare one path and publish twenty.
// The submitted body below DECLARES a file list, because clients built before
// 2026-07-26 still carry a `-files` flag and still send one. Without that field
// in the request this test would assert only the "derives" half and pass no
// matter how the ignored half behaved — the name would promise a guarantee the
// body never exercised.
func TestSyncProposeDerivesManifestAndIgnoresAnyDeclaredFiles(t *testing.T) {
	t.Parallel()
	db := syncAPIDB(t)
	handler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: db, Bases: fakeBases{empty: true}})
	response := httptest.NewRecorder()
	declaringBody := `{"id":"sync-a","repository":"yaniv256/mirror.dev","text":"Release",` +
		`"files":["LICENSE","cmd/main.go","internal/secret.go"],` +
		`"commit_packet_json":"` + shapePacketJSON + `","packet_head_sha":"68d273daa52639af3825a0e4c2d0a5ab82bd40a0"}`
	handler.ServeHTTP(response, agentRequest(http.MethodPost, "/v1/sync", declaringBody, "zara"))
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	item, err := db.GetSyncRequest(context.Background(), "default", "sync-a")
	if err != nil {
		t.Fatal(err)
	}
	// The shape carries exactly one path; the stored manifest must equal it.
	if len(item.FileManifest) != 1 || item.FileManifest[0] != "SKILL.md" {
		t.Fatalf("stored manifest = %v, want [SKILL.md] derived from the packet", item.FileManifest)
	}
	if !strings.Contains(item.CommitPacketJSON, "SKILL.md") {
		t.Fatal("stored packet lost its entry during rebase")
	}
}

// Rebasing the CONTENTS onto the public HEAD is only half the job: the commit
// must also be PARENTED on it. PR #9 shipped with a correct rebased tree but
// kept its private parent, so GitHub computed the merge from a stale merge-base
// and reported conflicts on three files — a pre-PR that promised "this is what
// merging produces" and could not be merged.
//
// Every other test asserted the TREE. None asserted the ANCESTRY, so the two
// notions of "based on the public HEAD" stayed conflated all the way to a
// broken public PR.
func TestSyncProposeParentsTheCommitOnThePublicHead(t *testing.T) {
	t.Parallel()
	db := syncAPIDB(t)
	handler := api.NewSyncHandler(api.SyncHandlerConfig{
		Policy: syncAPIPolicy(), Store: db,
		Bases: fakeBases{commitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", treeSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	item, err := db.GetSyncRequest(context.Background(), "default", "sync-a")
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		ObjectPackage struct {
			Commit struct {
				Parents []string `json:"parents"`
			} `json:"commit"`
		} `json:"object_package"`
	}
	if err := json.Unmarshal([]byte(item.CommitPacketJSON), &stored); err != nil {
		t.Fatal(err)
	}
	parents := stored.ObjectPackage.Commit.Parents
	if len(parents) != 1 || parents[0] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("parents = %v, want exactly the public HEAD; a commit that does not descend from the base cannot merge cleanly", parents)
	}
}

// An empty public repository has no HEAD to descend from — the published commit
// is a root commit, and inventing a parent would reference a nonexistent object.
func TestSyncProposeLeavesTheFirstCommitParentless(t *testing.T) {
	t.Parallel()
	db := syncAPIDB(t)
	handler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: db, Bases: fakeBases{empty: true}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	item, err := db.GetSyncRequest(context.Background(), "default", "sync-a")
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		ObjectPackage struct {
			Commit struct {
				Parents []string `json:"parents"`
			} `json:"commit"`
		} `json:"object_package"`
	}
	if err := json.Unmarshal([]byte(item.CommitPacketJSON), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.ObjectPackage.Commit.Parents) != 0 {
		t.Fatalf("parents = %v, want none against an empty public repository", stored.ObjectPackage.Commit.Parents)
	}
}

// A shape identical to the public base is an empty pre-PR: there is nothing to
// review and publishing it would create an empty commit.
func TestSyncProposeRefusesAShapeMatchingThePublicBase(t *testing.T) {
	t.Parallel()
	identical := []githubapp.TreeEntry{{
		Path: "SKILL.md", Mode: "100644", Type: "blob",
		SHA: "50860bb5e14f44f3916a2b1f2976f009c1580b65",
	}}
	handler := api.NewSyncHandler(api.SyncHandlerConfig{
		Policy: syncAPIPolicy(), Store: syncAPIDB(t), Bases: fakeBases{entries: identical},
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 for a no-op pre-PR", response.Code)
	}
	if !strings.Contains(response.Body.String(), "already matches") {
		t.Fatalf("body = %s, want it to name the cause", response.Body.String())
	}
}

// R8's whole point is that agents review EACH OTHER's pre-PRs, so the
// commenting agent is by design not the sync's creator. That makes this the
// first agent-facing sync mutation where the caller does not own the record —
// and without a registered `sync.comment` policy operation the route would be
// gated on nothing but tenant scope.
func TestAgentCommentRequiresPolicyStandingNotJustAuthentication(t *testing.T) {
	t.Parallel()
	db := syncAPIDB(t)
	handler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: db, Bases: fakeBases{empty: true}})
	proposed := httptest.NewRecorder()
	handler.ServeHTTP(proposed, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if proposed.Code != http.StatusCreated {
		t.Fatalf("seed proposal = %d body=%s", proposed.Code, proposed.Body.String())
	}

	// tomas is a WRITER on the mirror but not its creator — the cross-agent
	// review case, which must be allowed.
	reviewer := httptest.NewRecorder()
	handler.ServeHTTP(reviewer, agentRequest(http.MethodPost, "/v1/sync/sync-a/comment",
		`{"body":"The vendored binary is still in the manifest."}`, "tomas"))
	if reviewer.Code != http.StatusCreated {
		t.Fatalf("a policy-listed reviewing agent was refused: %d body=%s", reviewer.Code, reviewer.Body.String())
	}
	thread, err := db.SyncCommentsFor(context.Background(), "default", sqlite.SyncCommentSubjectSync, "sync-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(thread) != 1 || thread[0].AuthorKind != sqlite.CommentAuthorAgent || thread[0].AuthorID != "tomas" {
		t.Fatalf("agent comment misattributed: %+v", thread)
	}

	// An agent with no standing on the repository is refused — the gate is
	// authorization, not merely authentication.
	stranger := httptest.NewRecorder()
	handler.ServeHTTP(stranger, agentRequest(http.MethodPost, "/v1/sync/sync-a/comment",
		`{"body":"drive-by"}`, "mallory"))
	if stranger.Code != http.StatusForbidden {
		t.Fatalf("an agent with no policy standing commented: %d", stranger.Code)
	}
	after, _ := db.SyncCommentsFor(context.Background(), "default", sqlite.SyncCommentSubjectSync, "sync-a")
	if len(after) != 1 {
		t.Fatalf("a refused comment was stored anyway: %+v", after)
	}
}

// The rule U8 exists for: a CLOSED pre-PR refuses updates because it is
// TERMINAL — not as a side effect of a narrow allowlist that a future state
// could silently widen — while still accepting comments, the way a closed pull
// request on GitHub still takes replies.
func TestClosedPrePRRefusesUpdatesButStillAcceptsComments(t *testing.T) {
	t.Parallel()
	db := syncAPIDB(t)
	handler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: db, Bases: fakeBases{empty: true}})
	proposed := httptest.NewRecorder()
	handler.ServeHTTP(proposed, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if proposed.Code != http.StatusCreated {
		t.Fatalf("seed = %d body=%s", proposed.Code, proposed.Body.String())
	}
	if err := db.CloseSync(context.Background(), "default", "sync-a", "yaniv", "not wanted", time.Unix(1_800_000_500, 0)); err != nil {
		t.Fatal(err)
	}

	updateBody := `{"text":"Release v2","commit_packet_json":"` + shapePacketJSON + `","packet_head_sha":"68d273daa52639af3825a0e4c2d0a5ab82bd40a0"}`
	update := httptest.NewRecorder()
	handler.ServeHTTP(update, agentRequest(http.MethodPost, "/v1/sync/sync-a/update", updateBody, "zara"))
	if update.Code != http.StatusConflict {
		t.Fatalf("update on a closed pre-PR = %d", update.Code)
	}
	// The error must name TERMINALITY. "not revisable" would send the agent
	// hunting for a request-changes it never received, rather than learning the
	// proposal is over.
	if !strings.Contains(update.Body.String(), "sync_is_terminal") {
		t.Fatalf("refused for an ambiguous reason: %s", update.Body.String())
	}

	// Comments stay open — losing "here is why we closed this" the moment it
	// closes would discard the most useful comment on the thread.
	comment := httptest.NewRecorder()
	handler.ServeHTTP(comment, agentRequest(http.MethodPost, "/v1/sync/sync-a/comment",
		`{"body":"Understood — I will fold this into the next proposal."}`, "tomas"))
	if comment.Code != http.StatusCreated {
		t.Fatalf("a closed pre-PR refused a comment: %d body=%s", comment.Code, comment.Body.String())
	}
}

// The stored envelope's `sha` must name the commit the stored package actually
// contains. Rebasing REPARENTS the commit — a reparented commit is a different
// commit — so an envelope that keeps the submitted SHA is describing a commit
// that no longer exists in its own payload.
//
// Nothing on the review path reads `sha`, which is why this survived to the
// worst possible moment: validateExecutableOperation requires
// packet.Commit.SHA == payload["sha"] before persisting a branch.push, so the
// mismatch surfaced only AFTER Yaniv approved publication, and the operation
// was rejected before insertion — making the retry report "durable operation
// not found", an error about the recovery rather than the cause.
//
// Live 2026-07-27: envelope c160200d, package commit c2cd22e1, publication
// refused, nothing written to GitHub.
func TestRebasedEnvelopeSHANamesTheCommitItActuallyCarries(t *testing.T) {
	t.Parallel()
	db := syncAPIDB(t)
	// A NON-EMPTY base is the case that matters: it gives the rebase a public
	// HEAD to reparent onto, which is what rewrites the commit SHA. An empty
	// base produces a root commit whose SHA may coincide with the submitted
	// one, so the divergence never appears and the test cannot fail.
	handler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: db, Bases: fakeBases{}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	item, err := db.GetSyncRequest(context.Background(), "default", "sync-a")
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal([]byte(item.CommitPacketJSON), &stored); err != nil {
		t.Fatal(err)
	}
	envelope, _ := stored["sha"].(string)
	pkg, _ := stored["object_package"].(map[string]any)
	commit, _ := pkg["commit"].(map[string]any)
	actual, _ := commit["sha"].(string)
	if envelope == "" || actual == "" {
		t.Fatalf("stored packet lost its shape: envelope=%q commit=%q", envelope, actual)
	}
	if envelope != actual {
		t.Fatalf("envelope sha %s does not name the stored commit %s — branch.push will be refused after a human approves it", envelope, actual)
	}
}

// PacketHeadSHA is handed to BOTH branch.push and pull_request.create as the
// head commit. After a reparent the submitted value names a commit that will
// never exist on the remote, so a PR created with it points at nothing — the
// same envelope-vs-package divergence as the stored `sha`, one field over.
// Storing it from the rebased packet is what keeps the two consumers honest.
func TestStoredHeadSHAIsTheRebasedCommitNotTheSubmittedOne(t *testing.T) {
	t.Parallel()
	db := syncAPIDB(t)
	handler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: syncAPIPolicy(), Store: db, Bases: fakeBases{}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, agentRequest(http.MethodPost, "/v1/sync", proposeBody, "zara"))
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	item, err := db.GetSyncRequest(context.Background(), "default", "sync-a")
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal([]byte(item.CommitPacketJSON), &stored); err != nil {
		t.Fatal(err)
	}
	pkg, _ := stored["object_package"].(map[string]any)
	commit, _ := pkg["commit"].(map[string]any)
	actual, _ := commit["sha"].(string)
	if item.PacketHeadSHA != actual {
		t.Fatalf("stored head_sha %s is not the rebased commit %s — the PR would be opened against a commit that was never pushed", item.PacketHeadSHA, actual)
	}
}
