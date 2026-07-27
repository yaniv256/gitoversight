package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/prpreview"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type SyncHandlerConfig struct {
	Policy       policy.Snapshot
	Store        *sqlite.DB
	MaxBodyBytes int64
	Now          func() time.Time
	// Bases resolves the public repository's current HEAD — the base half of a
	// pre-PR's cross-repository diff. Nil disables rebasing, which refuses
	// proposals rather than storing an unrebased packet: a packet built against
	// a private parent cannot be reviewed or published correctly.
	Bases BaseReader
	// BaseBranch is the public branch a pre-PR is measured against.
	BaseBranch string
}

// BaseReader is the worker-side public-repository read the propose path needs.
type BaseReader interface {
	ReadBase(workerrpc.BaseReadRequest) (workerrpc.BaseRead, error)
}

type SyncHandler struct {
	policy     policy.Snapshot
	store      *sqlite.DB
	maxBody    int64
	now        func() time.Time
	bases      BaseReader
	baseBranch string
}

func NewSyncHandler(config SyncHandlerConfig) *SyncHandler {
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 1 << 20
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.BaseBranch == "" {
		config.BaseBranch = "main"
	}
	return &SyncHandler{policy: config.Policy, store: config.Store, maxBody: config.MaxBodyBytes, now: config.Now,
		bases: config.Bases, baseBranch: config.BaseBranch}
}

// rebaseAgainstPublicBase turns a submitted shape into the pre-PR that will be
// reviewed and published: the delta from the PUBLIC repository's current HEAD
// to that shape, plus the file manifest DERIVED from it.
//
// Both halves are computed here rather than accepted from the submission. The
// agent cannot name its own base (policy resolves SyncsTo) and cannot declare
// its own file list — anything the human's approval binds is computed by the
// party doing the binding.
func (handler *SyncHandler) rebaseAgainstPublicBase(target, packetJSON string) (string, []string, error) {
	if handler.bases == nil {
		return "", nil, errors.New("public base resolution is unavailable")
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(packetJSON), &raw); err != nil {
		return "", nil, errors.New("commit packet is not JSON")
	}
	packet, present, err := commitpacket.Decode(raw)
	if err != nil || !present {
		return "", nil, errors.New("commit packet is invalid")
	}
	base, err := handler.bases.ReadBase(workerrpc.BaseReadRequest{Repository: target, Branch: handler.baseBranch})
	if err != nil {
		return "", nil, err
	}
	rebased, err := prpreview.Rebase(base.Entries, base.TreeSHA, base.CommitSHA, packet.Tree.Entries, packet.Blobs)
	if err != nil {
		return "", nil, err
	}
	packet.Tree.Entries = rebased.Entries
	packet.Tree.BaseTree = rebased.BaseTreeSHA
	packet.Blobs = rebased.Blobs
	// The published commit must also be PARENTED on the public HEAD, not merely
	// have its contents rebased onto it. These are two different claims and
	// conflating them shipped a broken PR: the reviewed diff was correct
	// against ee92d91, but the commit kept its private parent da9dfab, so
	// GitHub computed the merge from a stale merge-base and reported conflicts
	// on three files (PR #9, 2026-07-26).
	//
	// A pre-PR promises "this is what merging produces". A commit whose ancestry
	// predates the base cannot keep that promise however correct its tree is.
	if rebased.BaseCommitSHA != "" {
		packet.Reparent(rebased.BaseCommitSHA)
	} else {
		// An empty public repository has no HEAD to parent on: the first commit
		// is a root commit.
		packet.Reparent()
	}
	// Re-validate what will actually be STORED. The submitted shape was
	// validated on the way in, but rebasing rewrites entries, blobs, and
	// base_tree — so validity of the input says nothing about validity of the
	// output. Without this, a malformed rebased packet is accepted here,
	// rendered on the review page, APPROVED BY A HUMAN, and only then rejected
	// at publish: the worst possible moment to discover it.
	if err := packet.Validate(); err != nil {
		return "", nil, fmt.Errorf("rebased packet is invalid: %w", err)
	}
	raw["object_package"] = packet
	// The envelope's `sha` must follow the commit it describes. Reparent above
	// rewrites the commit SHA — a reparented commit is a DIFFERENT commit — so
	// leaving the submitted value here strands the envelope one commit behind
	// the package it wraps.
	//
	// Nothing on the review path reads `sha`, so the divergence is invisible
	// right up to the last step: validateExecutableOperation requires
	// packet.Commit.SHA == payload["sha"] before it will persist a branch.push.
	// It fails AFTER the human approves, and because the operation is rejected
	// before insertion, the retry's reconcile finds no row and reports "durable
	// operation not found" — an error describing the recovery attempt rather
	// than the cause. Observed live 2026-07-27: envelope c160200d, commit
	// c2cd22e1, publication refused with nothing written to GitHub.
	raw["sha"] = packet.Commit.SHA
	rebasedJSON, err := json.Marshal(raw)
	if err != nil {
		return "", nil, err
	}
	return string(rebasedJSON), rebased.Manifest, nil
}

// Files is ACCEPTED AND DISCARDED, deliberately. It is a compatibility shim,
// not an input.
//
// A declared file list used to be stored verbatim and hashed into the approval
// while publication was driven entirely by the packet, so a proposal could
// declare one path and publish twenty — the human approved a description rather
// than the thing described. The manifest is now DERIVED by
// rebaseAgainstPublicBase: anything the human's approval binds is computed by
// the party doing the binding.
//
// Deleting the field is the tempting cleanup and it is WRONG. decodeStrict sets
// DisallowUnknownFields, so an absent field turns "silently ignored" into a
// hard 400 for every client built before 2026-07-26 — those still carry a
// `-files` flag and still send it. Keeping the field keeps them working while
// the security property holds regardless of what they send.
//
// TestSyncProposeDerivesManifestAndIgnoresAnyDeclaredFiles submits a body that
// declares files contradicting the packet, so the discard is exercised rather
// than assumed.
type syncProposeInput struct {
	ID               string   `json:"id"`
	Repository       string   `json:"repository"`
	Text             string   `json:"text"`
	Files            []string `json:"files"`
	CommitPacketJSON string   `json:"commit_packet_json"`
	PacketHeadSHA    string   `json:"packet_head_sha"`
}

// Files here is the same accepted-and-discarded shim as syncProposeInput's.
type syncUpdateInput struct {
	Text             string   `json:"text"`
	Files            []string `json:"files"`
	CommitPacketJSON string   `json:"commit_packet_json"`
	PacketHeadSHA    string   `json:"packet_head_sha"`
}

func (handler *SyncHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	if handler.store == nil {
		writeError(response, http.StatusServiceUnavailable, "sync_unavailable")
		return
	}
	path := strings.Trim(request.URL.Path, "/")
	switch {
	case request.Method == http.MethodPost && path == "v1/sync":
		handler.propose(response, request, identity)
	case request.Method == http.MethodPost && strings.HasPrefix(path, "v1/sync/") && strings.HasSuffix(path, "/update"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "v1/sync/"), "/update")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(response, request)
			return
		}
		handler.update(response, request, identity, id)
	case request.Method == http.MethodPost && strings.HasPrefix(path, "v1/sync/") && strings.HasSuffix(path, "/comment"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "v1/sync/"), "/comment")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(response, request)
			return
		}
		handler.comment(response, request, identity, id)
	case request.Method == http.MethodGet && strings.HasPrefix(path, "v1/sync/"):
		id := strings.TrimPrefix(path, "v1/sync/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(response, request)
			return
		}
		item, err := handler.store.GetSyncRequest(request.Context(), identity.TenantID, id)
		if err != nil {
			writeError(response, http.StatusNotFound, "sync_not_found")
			return
		}
		writeJSON(response, http.StatusOK, item)
	default:
		http.NotFound(response, request)
	}
}

func (handler *SyncHandler) propose(response http.ResponseWriter, request *http.Request, identity agentauth.Identity) {
	var input syncProposeInput
	if err := decodeStrict(request, handler.maxBody, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_sync_input")
		return
	}
	decision := policy.Evaluate(handler.policy, policy.Request{Caller: identity.AgentID, Repository: input.Repository, Operation: "sync.propose"})
	if decision.Code != policy.Allowed {
		writeJSON(response, http.StatusForbidden, map[string]any{"error": string(decision.Code), "reason": decision.Reason})
		return
	}
	target := handler.policy.Repositories[input.Repository].SyncsTo
	// The submitted shape is re-expressed as the diff from the PUBLIC repo's
	// current HEAD, and the reviewed file list is derived from that diff. The
	// agent's own `files` field is discarded: it was never checked against the
	// packet, so a proposal could declare one path and publish twenty.
	packetJSON, manifest, err := handler.rebaseAgainstPublicBase(target, input.CommitPacketJSON)
	if err != nil {
		writeJSON(response, http.StatusUnprocessableEntity, map[string]any{"error": "sync_rebase_failed", "reason": err.Error()})
		return
	}
	now := handler.now()
	req := sqlite.SyncRequest{
		TenantID: identity.TenantID, ID: input.ID,
		PrivateRepository: input.Repository, PublicRepository: target,
		ProposalText: input.Text, FileManifest: manifest,
		// PacketHeadSHA names the commit that will be PUBLISHED, which after a
		// reparent is not the one the client submitted. Storing input's value
		// sends a stale head_sha to both branch.push and pull_request.create —
		// a PR opened against a commit that was never pushed.
		CommitPacketJSON: packetJSON, PacketHeadSHA: rebasedHeadSHA(packetJSON, input.PacketHeadSHA),
		CreatedBy: identity.AgentID,
	}
	if err := handler.store.CreateSyncProposal(request.Context(), req, handler.policy.QueueCurator, now); err != nil {
		if sqlite.IsUniqueViolation(err) {
			writeError(response, http.StatusConflict, "sync_exists")
			return
		}
		writeError(response, http.StatusUnprocessableEntity, "sync_rejected")
		return
	}
	hash := sqlite.SyncProposalHash(input.Text, manifest, input.PacketHeadSHA, packetJSON)
	writeJSON(response, http.StatusCreated, map[string]any{"id": input.ID, "state": "proposed", "proposal_hash": hash, "public_repository": target, "files": manifest})
}

func (handler *SyncHandler) update(response http.ResponseWriter, request *http.Request, identity agentauth.Identity, id string) {
	var input syncUpdateInput
	if err := decodeStrict(request, handler.maxBody, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_sync_input")
		return
	}
	existing, err := handler.store.GetSyncRequest(request.Context(), identity.TenantID, id)
	if err != nil {
		writeError(response, http.StatusNotFound, "sync_not_found")
		return
	}
	decision := policy.Evaluate(handler.policy, policy.Request{Caller: identity.AgentID, Repository: existing.PrivateRepository, Operation: "sync.update"})
	if decision.Code != policy.Allowed {
		writeJSON(response, http.StatusForbidden, map[string]any{"error": string(decision.Code), "reason": decision.Reason})
		return
	}
	// The state gate comes BEFORE the rebase. Rebasing first would answer a
	// too-early resubmission with "sync_rebase_failed", sending the agent to
	// debug a packet whose real problem is that nobody requested changes yet —
	// and would spend a GitHub read on a request that can never be accepted.
	// Terminality is stated DIRECTLY, not inferred from the allowlist below.
	//
	// `State != "changes_requested"` already happens to reject a closed pre-PR,
	// but only as a side effect of a narrow allowlist: a future state added to
	// that list would silently reopen the hole. A terminal pre-PR refuses
	// updates BECAUSE it is terminal, and the error says so — an agent told
	// "not revisable" would go looking for a request-changes it never received,
	// rather than learning the proposal is over.
	//
	// Comments are deliberately not gated by this: a closed pre-PR stays
	// discussable, the way a closed pull request on GitHub still takes replies.
	if terminalSyncStates[existing.State] {
		writeJSON(response, http.StatusConflict, map[string]any{
			"error": "sync_is_terminal", "state": existing.State,
			"detail": "This pre-PR is finished and cannot be revised. Propose a new one if the change is still wanted; you can still comment on this thread.",
		})
		return
	}
	if existing.State != "changes_requested" {
		writeError(response, http.StatusConflict, "sync_not_revisable")
		return
	}
	// A revision is re-based exactly like a first proposal. Skipping it here
	// would leave the unverified path in place for the case that matters most:
	// the resubmission a human asked for after clicking "Request changes".
	packetJSON, manifest, err := handler.rebaseAgainstPublicBase(existing.PublicRepository, input.CommitPacketJSON)
	if err != nil {
		writeJSON(response, http.StatusUnprocessableEntity, map[string]any{"error": "sync_rebase_failed", "reason": err.Error()})
		return
	}
	if err := handler.store.ReviseSyncProposal(request.Context(), identity.TenantID, id, input.Text, manifest, packetJSON, rebasedHeadSHA(packetJSON, input.PacketHeadSHA), handler.now()); err != nil {
		writeError(response, http.StatusConflict, "sync_not_revisable")
		return
	}
	hash := sqlite.SyncProposalHash(input.Text, manifest, input.PacketHeadSHA, packetJSON)
	writeJSON(response, http.StatusOK, map[string]any{"id": id, "state": "proposed", "proposal_hash": hash, "files": manifest})
}

func decodeStrict(request *http.Request, maxBody int64, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, request.Body, maxBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing content")
	}
	return nil
}

// comment lets an AGENT post to a pre-PR's thread, so agents can review each
// other's proposals before a human is involved.
//
// Authentication is not authorization. Every other agent write in this file
// evaluates policy first, and the commenting agent is BY DESIGN not the sync's
// creator — so without a registered `sync.comment` operation this route would
// grant cross-agent write access on nothing but tenant scope, the only such
// route in the codebase.
func (handler *SyncHandler) comment(response http.ResponseWriter, request *http.Request, identity agentauth.Identity, id string) {
	var input struct {
		// app.js wraps every typed field as {"note": ...} — one convention for
		// every data-body-id control. Accepting only "body" made this endpoint
		// unreachable from its own button (400 invalid_comment, found live).
		// Both are accepted rather than forcing a second convention on the
		// script, which would just move the drift point.
		Body string `json:"body"`
		Note string `json:"note"`
	}
	if err := decodeStrict(request, handler.maxBody, &input); err != nil {
		// DisallowUnknownFields is load-bearing here: it rejects any attempt to
		// supply author fields, which are taken from the authenticated
		// principal and never from the body.
		writeError(response, http.StatusBadRequest, "invalid_comment")
		return
	}
	existing, err := handler.store.GetSyncRequest(request.Context(), identity.TenantID, id)
	if err != nil {
		writeError(response, http.StatusNotFound, "sync_not_found")
		return
	}
	decision := policy.Evaluate(handler.policy, policy.Request{
		Caller: identity.AgentID, Repository: existing.PrivateRepository, Operation: "sync.comment"})
	if decision.Code != policy.Allowed {
		writeJSON(response, http.StatusForbidden, map[string]any{"error": string(decision.Code), "reason": decision.Reason})
		return
	}
	now := handler.now()
	comment := sqlite.SyncComment{
		ID:          fmt.Sprintf("%s:%s:%d", id, identity.AgentID, now.UnixNano()),
		SubjectKind: sqlite.SyncCommentSubjectSync, SubjectID: id,
		AuthorKind: sqlite.CommentAuthorAgent, AuthorID: identity.AgentID,
		Body: commentBody(input.Body, input.Note),
	}
	if err := handler.store.AppendSyncComment(request.Context(), identity.TenantID, comment, now); err != nil {
		writeJSON(response, http.StatusUnprocessableEntity, map[string]any{"error": "comment_rejected", "reason": err.Error()})
		return
	}
	writeJSON(response, http.StatusCreated, map[string]any{"id": comment.ID, "sync_id": id, "author": identity.AgentID})
}

// terminalSyncStates are the states a pre-PR cannot leave. Naming them here
// makes "refuse because it is terminal" a rule rather than a coincidence of
// whichever states happen to be missing from an allowlist.
//
// This is the one place the plan's INV-R11 concern bites least: a new terminal
// state that forgets this map still refuses updates via the allowlist below —
// it just refuses with the wrong error. Losing the reason is the failure mode,
// not losing the guard.
var terminalSyncStates = map[string]bool{
	"done":      true,
	"abandoned": true,
	"closed":    true,
}

// rebasedHeadSHA reads the commit SHA out of the packet that will actually be
// stored, falling back to the submitted value only if the packet cannot be
// read.
//
// The submitted head SHA describes the commit the agent built locally. Rebasing
// reparents it onto the public HEAD, producing a DIFFERENT commit — so every
// downstream consumer that wants "the commit being published" must read it from
// the rebased packet, never from the submission. Two consumers wanted exactly
// that and both had the stale value: branch.push (refused at validation, after
// the human approved) and pull_request.create (would open a PR against a commit
// that was never pushed).
func rebasedHeadSHA(packetJSON, submitted string) string {
	var raw map[string]any
	if err := json.Unmarshal([]byte(packetJSON), &raw); err != nil {
		return submitted
	}
	packet, present, err := commitpacket.Decode(raw)
	if err != nil || !present || packet.Commit.SHA == "" {
		return submitted
	}
	return packet.Commit.SHA
}
