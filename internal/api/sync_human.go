package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

// SyncBroker and SyncExecutor are the slices of the durable authority the
// authorize chain composes. SyncMergeChecker answers whether the public PR is
// actually merged on GitHub (the Done gate).
type SyncBroker interface {
	Submit(ctx context.Context, identity server.DurableIdentity, request server.DurableOperationRequest) (server.DurableResult, error)
	Approve(ctx context.Context, request server.DurableApprovalRequest) (server.DurableResult, error)
}

type SyncExecutor interface {
	Execute(ctx context.Context, identity server.DurableIdentity, operationID string) (server.DurableResult, error)
}

// SyncPullStateReader answers what the public pull request actually resolved
// to. It replaced a Merged() bool: that boolean could not express "closed
// without merging", so the Done gate treated a dead PR and a pending one
// identically and stranded the sync forever.
type SyncPullStateReader interface {
	PullState(ctx context.Context, tenantID, repository string, number int64) (githubapp.PullState, error)
}

type SyncHumanHandlerConfig struct {
	Policy   policy.Snapshot
	Store    *sqlite.DB
	Broker   SyncBroker
	Executor SyncExecutor
	Merges   SyncPullStateReader
	// Bases re-reads the public repository at authorization so a diff that went
	// stale while the page was open cannot be published as if it were current.
	Bases        BaseReader
	BaseBranch   string
	ApprovalTTL  time.Duration
	MaxBodyBytes int64
	Now          func() time.Time
}

type SyncHumanHandler struct {
	policy      policy.Snapshot
	store       *sqlite.DB
	broker      SyncBroker
	executor    SyncExecutor
	merges      SyncPullStateReader
	bases       BaseReader
	baseBranch  string
	approvalTTL time.Duration
	maxBody     int64
	now         func() time.Time
	// reconcileDelay spaces the reconcile fallback attempts; tests shrink it.
	reconcileDelay time.Duration
}

func NewSyncHumanHandler(config SyncHumanHandlerConfig) *SyncHumanHandler {
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 64 << 10
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.BaseBranch == "" {
		config.BaseBranch = "main"
	}
	if config.ApprovalTTL <= 0 {
		config.ApprovalTTL = 15 * time.Minute
	}
	return &SyncHumanHandler{policy: config.Policy, store: config.Store, broker: config.Broker, executor: config.Executor,
		merges: config.Merges, bases: config.Bases, baseBranch: config.BaseBranch, approvalTTL: config.ApprovalTTL, maxBody: config.MaxBodyBytes, now: config.Now}
}

func (handler *SyncHumanHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	approver, ok := HumanApproverFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "human_authentication_required")
		return
	}
	if handler.store == nil {
		writeError(response, http.StatusServiceUnavailable, "sync_unavailable")
		return
	}
	path := strings.Trim(request.URL.Path, "/")
	if request.Method != http.MethodPost {
		http.NotFound(response, request)
		return
	}
	switch {
	case strings.HasPrefix(path, "v1/human/sync/") && strings.HasSuffix(path, "/authorize"):
		handler.authorize(response, request, approver, strings.TrimSuffix(strings.TrimPrefix(path, "v1/human/sync/"), "/authorize"))
	case strings.HasPrefix(path, "v1/human/sync/") && strings.HasSuffix(path, "/request-changes"):
		handler.requestChanges(response, request, approver, strings.TrimSuffix(strings.TrimPrefix(path, "v1/human/sync/"), "/request-changes"))
	case strings.HasPrefix(path, "v1/human/sync/") && strings.HasSuffix(path, "/done"):
		handler.done(response, request, approver, strings.TrimSuffix(strings.TrimPrefix(path, "v1/human/sync/"), "/done"))
	case strings.HasPrefix(path, "v1/human/sync/") && strings.HasSuffix(path, "/close"):
		handler.close(response, request, approver, strings.TrimSuffix(strings.TrimPrefix(path, "v1/human/sync/"), "/close"))
	case strings.HasPrefix(path, "v1/human/sync/") && strings.HasSuffix(path, "/comment"):
		handler.comment(response, request, approver, strings.TrimSuffix(strings.TrimPrefix(path, "v1/human/sync/"), "/comment"))
	case strings.HasPrefix(path, "v1/human/queue/") && strings.HasSuffix(path, "/defer"):
		handler.deferItem(response, request, approver, strings.TrimSuffix(strings.TrimPrefix(path, "v1/human/queue/"), "/defer"))
	default:
		http.NotFound(response, request)
	}
}

func (handler *SyncHumanHandler) authorize(response http.ResponseWriter, request *http.Request, approver HumanApprover, id string) {
	var input struct {
		PacketHash string `json:"packet_hash"`
	}
	if err := decodeStrict(request, handler.maxBody, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_authorization")
		return
	}
	now := handler.now()
	// The base must still be what the reviewer SAW. A pre-PR is a diff against
	// the public repository's HEAD at review time; if that HEAD moved while the
	// page was open, the change that publishes is not the change that was read,
	// and every guarantee this feature provides is void. Checked BEFORE
	// AuthorizeSync, because once that succeeds the state has already moved.
	if reason, moved := handler.publicBaseMoved(request.Context(), approver.TenantID, id); moved {
		writeJSON(response, http.StatusConflict, map[string]any{
			"error": "base_moved", "reason": reason,
			"detail": "The public repository changed since this pre-PR was prepared. Ask the agent to resubmit so you review the diff that will actually publish.",
		})
		return
	}
	if err := handler.store.AuthorizeSync(request.Context(), approver.TenantID, id, input.PacketHash, now); err != nil {
		writeError(response, http.StatusConflict, "authorization_stale")
		return
	}
	sync, err := handler.store.GetSyncRequest(request.Context(), approver.TenantID, id)
	if err != nil {
		writeError(response, http.StatusNotFound, "sync_not_found")
		return
	}
	identity := server.DurableIdentity{TenantID: approver.TenantID, AgentID: sync.CreatedBy}
	// The proposal id is private orchestration metadata and commonly includes
	// the creating agent's name. Never copy it into a public Git branch. The
	// proposal hash is already bound to the reviewed text, manifest, head, and
	// packet, so it gives this publication a stable public-safe branch identity.
	branch := "sync/" + shortSHA(sync.ProposalHash)

	var packetPayload map[string]any
	if err := json.Unmarshal([]byte(sync.CommitPacketJSON), &packetPayload); err != nil {
		handler.receiptFailure(request.Context(), approver.TenantID, id, "sync_publish_failed", "invalid commit packet", now)
		writeError(response, http.StatusUnprocessableEntity, "invalid_commit_packet")
		return
	}
	pushRequest := server.DurableOperationRequest{
		ID: id + "-push", Repository: sync.PublicRepository, Operation: "branch.push",
		Branch: branch, HeadSHA: sync.PacketHeadSHA, ManifestHash: sync.ProposalHash,
		Payload: packetPayload,
	}
	pushRequest.ID = handler.retryableOperationID(request.Context(), approver.TenantID, pushRequest.ID)
	// SKIP a push that already succeeded — do not re-submit it.
	//
	// Publishing 302 blobs takes long enough that GitHub's read replica lags
	// the write. The immediate reconcile answered "absent", KTD1a correctly
	// refused to call that terminal and parked the operation indeterminate, and
	// the chain treated "I cannot confirm yet" as "this failed" — aborting
	// before the pull request was ever created.
	//
	// Retrying then hit the replay guard, which is right: the operation id had
	// been submitted, and re-submitting an executed public write is exactly
	// what that guard exists to prevent. The bug is not the guard. It is asking
	// to re-run a step whose work is already done. So the chain now CHECKS
	// FIRST and resumes from where it actually is.
	//
	// Live 2026-07-27: branch on GitHub with all 302 files, push reconciled
	// VERIFIED, no pull request, and every retry answered "already submitted".
	// The publication was complete except for its last step and could not
	// proceed by any route available to the reviewer.
	if !handler.alreadyPublished(request.Context(), approver.TenantID, pushRequest.ID) {
		if _, err := handler.runChainOrReconcile(request.Context(), identity, approver, pushRequest); err != nil {
			// Re-check: the chain reports an error for "unconfirmed" as well as
			// for "failed", and only the second should stop publication.
			if !handler.alreadyPublished(request.Context(), approver.TenantID, pushRequest.ID) {
				handler.receiptFailure(request.Context(), approver.TenantID, id, "sync_publish_failed", "branch push: "+err.Error(), handler.now())
				writeJSON(response, http.StatusBadGateway, map[string]any{"error": "sync_publish_failed", "stage": "branch.push", "detail": err.Error(), "state": "authorized"})
				return
			}
		}
	}
	title := strings.SplitN(strings.TrimSpace(sync.AuthorizedText), "\n", 2)[0]
	if title == "" {
		title = "Sync " + id
	}
	prRequest := server.DurableOperationRequest{
		ID: id + "-pr", Repository: sync.PublicRepository, Operation: "pull_request.create",
		Branch: branch, Title: title, Body: sync.AuthorizedText,
		HeadSHA: sync.PacketHeadSHA, ManifestHash: sync.ProposalHash,
		Payload: map[string]any{"base": handler.baseBranch, "head_sha": sync.PacketHeadSHA},
	}
	prRequest.ID = handler.retryableOperationID(request.Context(), approver.TenantID, prRequest.ID)
	// Same resume discipline as the push above: this step can be interrupted
	// between "GitHub created the PR" and "we recorded that it did", and a
	// retry must then continue rather than re-submit into the replay guard.
	prResult, err := handler.runChainOrReconcile(request.Context(), identity, approver, prRequest)
	if err != nil && handler.alreadyPublished(request.Context(), approver.TenantID, prRequest.ID) {
		prResult, err = handler.reconcileOnly(request.Context(), identity, prRequest.ID)
	}
	if err != nil {
		handler.receiptFailure(request.Context(), approver.TenantID, id, "sync_publish_failed", "pull request: "+err.Error(), handler.now())
		writeJSON(response, http.StatusBadGateway, map[string]any{"error": "sync_publish_failed", "stage": "pull_request.create", "detail": err.Error(), "state": "authorized"})
		return
	}
	number := parsePRNumber(prResult.ResourceID)
	if err := handler.store.RecordSyncPublicPR(request.Context(), approver.TenantID, id, number, handler.now()); err != nil {
		writeError(response, http.StatusConflict, "sync_state_conflict")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"id": id, "state": "public_pr_created", "public_pr_number": number, "repository": sync.PublicRepository})
}

// runChainOrReconcile runs the chain and, when it fails, falls back to
// reconciling the operation by id. Two real failure shapes land here
// (agent-kanban-wip-limit, 2026-07-24): a fresh Execute whose immediate
// read-back hit replica lag and parked indeterminate, and a RESUME where the
// operation already exists from a died publish (Submit refuses the replayed
// id) but the mutation actually landed on GitHub. In both, an independent
// reconcile against converged replicas proves the true outcome and lets the
// publish continue instead of stranding the sync at "authorized".
func (handler *SyncHumanHandler) runChainOrReconcile(ctx context.Context, identity server.DurableIdentity, approver HumanApprover, operation server.DurableOperationRequest) (server.DurableResult, error) {
	result, chainErr := handler.runChain(ctx, identity, approver, operation)
	if chainErr == nil {
		return result, nil
	}
	reconciler, ok := handler.executor.(OperationReconciler)
	if !ok {
		return result, chainErr
	}
	delay := handler.reconcileDelay
	if delay <= 0 {
		delay = 2 * time.Second
	}
	lastErr := chainErr
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return result, lastErr
			case <-time.After(delay):
			}
		}
		reconciled, err := reconciler.Reconcile(ctx, identity, operation.ID)
		// Only an independently VERIFIED outcome continues the publish — a
		// nil-error reconcile that found the object absent is a truthful
		// failure, not a success.
		if err == nil && reconciled.State == server.DurableVerified {
			return reconciled, nil
		}
		if err == nil {
			return result, fmt.Errorf("%v (reconcile found %s: %s)", chainErr, reconciled.State, reconciled.Reason)
		}
		lastErr = fmt.Errorf("%v (reconcile attempt %d: %v)", chainErr, attempt+1, err)
	}
	return result, lastErr
}

// runChain performs Submit -> Approve (with the Submit-returned packet hash,
// binding the human approver) -> Execute for one composed operation.
func (handler *SyncHumanHandler) runChain(ctx context.Context, identity server.DurableIdentity, approver HumanApprover, operation server.DurableOperationRequest) (server.DurableResult, error) {
	now := handler.now()
	operation.ApprovalID = operation.ID + "-approval"
	operation.ApprovalNonce = fmt.Sprintf("%s-%d", operation.ID, now.UnixNano())
	operation.ApprovalExpiresAt = now.Add(handler.approvalTTL)
	operation.Approver = approver.ID
	submitted, err := handler.broker.Submit(ctx, identity, operation)
	if err != nil {
		return submitted, fmt.Errorf("submit: %w", err)
	}
	if submitted.State == server.DurableAwaitingApproval {
		approved, err := handler.broker.Approve(ctx, server.DurableApprovalRequest{
			TenantID: identity.TenantID, OperationID: submitted.ID, ApprovalID: operation.ApprovalID,
			PacketHash: submitted.PacketHash, ManifestHash: operation.ManifestHash, HeadSHA: operation.HeadSHA,
			Approver: approver.ID, Nonce: operation.ApprovalNonce, ExpiresAt: operation.ApprovalExpiresAt,
		})
		if err != nil {
			return approved, fmt.Errorf("approve: %w", err)
		}
		submitted = approved
	}
	if submitted.State != server.DurableAuthorized {
		return submitted, fmt.Errorf("operation %s is %s (%s)", submitted.ID, submitted.State, submitted.Reason)
	}
	executed, err := handler.executor.Execute(ctx, identity, submitted.ID)
	if err != nil {
		return executed, fmt.Errorf("execute: %w", err)
	}
	if executed.State != server.DurableVerified {
		return executed, fmt.Errorf("operation %s finished %s (%s)", executed.ID, executed.State, executed.Reason)
	}
	return executed, nil
}

func (handler *SyncHumanHandler) requestChanges(response http.ResponseWriter, request *http.Request, approver HumanApprover, id string) {
	var input struct {
		Note string `json:"note"`
	}
	if err := decodeStrict(request, handler.maxBody, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	sync, err := handler.store.GetSyncRequest(request.Context(), approver.TenantID, id)
	if err != nil {
		writeError(response, http.StatusNotFound, "sync_not_found")
		return
	}
	if err := handler.store.RequestSyncChangesNotify(request.Context(), approver.TenantID, id, sync.CreatedBy, handler.now()); err != nil {
		writeError(response, http.StatusConflict, "sync_state_conflict")
		return
	}
	if input.Note != "" {
		_ = handler.store.AppendSyncEvent(request.Context(), approver.TenantID, id, "sync_change_note", map[string]any{"note": input.Note, "by": approver.ID}, handler.now())
	}
	writeJSON(response, http.StatusOK, map[string]any{"id": id, "state": "changes_requested"})
}

func (handler *SyncHumanHandler) done(response http.ResponseWriter, request *http.Request, approver HumanApprover, id string) {
	sync, err := handler.store.GetSyncRequest(request.Context(), approver.TenantID, id)
	if err != nil {
		writeError(response, http.StatusNotFound, "sync_not_found")
		return
	}
	if sync.State != "public_pr_created" || sync.PublicPRNumber == 0 {
		writeError(response, http.StatusConflict, "sync_not_completable")
		return
	}
	if handler.merges == nil {
		writeError(response, http.StatusServiceUnavailable, "merge_verification_unavailable")
		return
	}
	state, err := handler.merges.PullState(request.Context(), approver.TenantID, sync.PublicRepository, sync.PublicPRNumber)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "merge_verification_unavailable")
		return
	}
	switch state.Outcome {
	case githubapp.PullOutcomeMerged:
		// Fall through to completion below.
	case githubapp.PullOutcomeClosedUnmerged:
		// The PR is dead and this sync will never merge. Before this branch
		// existed the row sat in public_pr_created forever, behind a Done
		// button returning 409 on every tap — a control offered to a human
		// that could never succeed.
		if err := handler.store.AbandonSync(request.Context(), approver.TenantID, id, sync.PublicPRNumber, handler.now()); err != nil {
			writeError(response, http.StatusConflict, "sync_state_conflict")
			return
		}
		_ = handler.store.CompleteQueueItemForRef(request.Context(), approver.TenantID, "sync", id, handler.now())
		writeJSON(response, http.StatusOK, map[string]any{"id": id, "state": "abandoned", "public_pr_number": sync.PublicPRNumber})
		return
	case githubapp.PullOutcomeOpen:
		// Retryable and honest: come back after merging. Distinct from the
		// closed case, which is why this no longer says "not merged".
		writeError(response, http.StatusConflict, "public_pr_still_open")
		return
	default:
		// Indeterminate. NEVER transition on a read we could not trust — a
		// lagging read must not strand a genuinely merged PR (KTD1a).
		writeError(response, http.StatusServiceUnavailable, "merge_verification_unavailable")
		return
	}
	if err := handler.store.CompleteSyncMerged(request.Context(), approver.TenantID, id, state.MergeSHA, handler.policy.QueueCurator, handler.now()); err != nil {
		writeError(response, http.StatusConflict, "sync_state_conflict")
		return
	}
	// The sync is done; its Now-queue entry must not keep resurfacing it.
	// Best-effort: the queue is a view, and the next curator ordering rewrites
	// it wholesale anyway.
	_ = handler.store.CompleteQueueItemForRef(request.Context(), approver.TenantID, "sync", id, handler.now())
	writeJSON(response, http.StatusOK, map[string]any{"id": id, "state": "done", "merge_sha": state.MergeSHA})
}

func (handler *SyncHumanHandler) deferItem(response http.ResponseWriter, request *http.Request, approver HumanApprover, itemID string) {
	var input struct {
		Mode string `json:"mode"`
	}
	if err := decodeStrict(request, handler.maxBody, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_deferral")
		return
	}
	if err := handler.store.DeferQueueItem(request.Context(), approver.TenantID, itemID, input.Mode, handler.now()); err != nil {
		writeError(response, http.StatusConflict, "deferral_rejected")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"item": itemID, "mode": input.Mode})
}

func (handler *SyncHumanHandler) receiptFailure(ctx context.Context, tenantID, id, kind, detail string, now time.Time) {
	_ = handler.store.AppendSyncEvent(ctx, tenantID, id, kind, map[string]any{"detail": detail}, now)
}

func parsePRNumber(resource string) int64 {
	trimmed := resource
	if index := strings.LastIndexAny(resource, "/:"); index >= 0 {
		trimmed = resource[index+1:]
	}
	trimmed = strings.TrimPrefix(trimmed, "#")
	number, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0
	}
	return number
}

// publicBaseMoved reports whether the public repository's tree differs from the
// one this pre-PR was rebased onto.
//
// It fails CLOSED: when the base cannot be read, the answer is "moved", because
// an unreadable base cannot prove the reviewed diff is still current, and
// authorizing on an unproven base is exactly the failure the pre-PR exists to
// prevent. A resubmission is cheap; publishing an unreviewed change is not.
//
// Nil Bases disables the check rather than blocking every approval — a
// deployment without base resolution has no diffs to go stale, because the
// review page refuses to render in the first place.
func (handler *SyncHumanHandler) publicBaseMoved(ctx context.Context, tenantID, id string) (string, bool) {
	if handler.bases == nil {
		return "", false
	}
	sync, err := handler.store.GetSyncRequest(ctx, tenantID, id)
	if err != nil {
		return "the proposal could not be read", true
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(sync.CommitPacketJSON), &raw); err != nil {
		return "the stored packet could not be read", true
	}
	packet, present, err := commitpacket.Decode(raw)
	if err != nil || !present {
		return "the stored packet is not valid", true
	}
	// A pre-PR against an empty public repository has no base tree to compare;
	// its emptiness is checked by the rebase at submission time.
	if packet.Tree.BaseTree == "" {
		return "", false
	}
	base, err := handler.bases.ReadBase(workerrpc.BaseReadRequest{Repository: sync.PublicRepository, Branch: handler.baseBranch})
	if err != nil {
		return "the public repository could not be read", true
	}
	if base.TreeSHA != packet.Tree.BaseTree {
		return fmt.Sprintf("reviewed against tree %s, but %s is now at %s",
			shortSHA(packet.Tree.BaseTree), sync.PublicRepository, shortSHA(base.TreeSHA)), true
	}
	return "", false
}

func shortSHA(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

// comment posts a human's comment to a pre-PR thread.
//
// Added as a case INSIDE this switch, deliberately: the handler is mounted
// behind HumanSessionManager.Protect, so a route registered here inherits the
// session and CSRF check. A separately-wired route would silently bypass the
// standing rule that every mutating route keeps using Authorize/Protect.
//
// Commenting publishes nothing, so it sits on the non-step-up side of the
// router split alongside request-changes and done.
func (handler *SyncHumanHandler) comment(response http.ResponseWriter, request *http.Request, approver HumanApprover, id string) {
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
		writeError(response, http.StatusBadRequest, "invalid_comment")
		return
	}
	if _, err := handler.store.GetSyncRequest(request.Context(), approver.TenantID, id); err != nil {
		writeError(response, http.StatusNotFound, "sync_not_found")
		return
	}
	now := handler.now()
	comment := sqlite.SyncComment{
		ID:          fmt.Sprintf("%s:%s:%d", id, approver.ID, now.UnixNano()),
		SubjectKind: sqlite.SyncCommentSubjectSync, SubjectID: id,
		// Author comes from the AUTHENTICATED PRINCIPAL, never the request
		// body. If it were client-supplied an agent could post a comment
		// attributed to the human approver, and the reviewer would then weigh
		// a publication partly on words nobody wrote.
		AuthorKind: sqlite.CommentAuthorHuman, AuthorID: approver.ID,
		Body: commentBody(input.Body, input.Note),
	}
	if err := handler.store.AppendSyncComment(request.Context(), approver.TenantID, comment, now); err != nil {
		writeJSON(response, http.StatusUnprocessableEntity, map[string]any{"error": "comment_rejected", "reason": err.Error()})
		return
	}
	writeJSON(response, http.StatusCreated, map[string]any{"id": comment.ID, "sync_id": id, "author": approver.ID})
}

// commentBody takes whichever field carried the prose. app.js sends "note" for
// every typed field; a direct API caller may reasonably send "body".
func commentBody(body, note string) string {
	if strings.TrimSpace(body) != "" {
		return body
	}
	return note
}

// close records a human declining a pre-PR outright.
//
// Parity with GitHub: a reviewer can close a pull request they do not want.
// Before this the only options were approve it or leave it in the queue
// forever, which is not a decision — it is an absence of one, and the audit
// trail cannot tell the difference.
//
// Closing publishes nothing, so it sits on the non-step-up side of the router
// split: refusing must never cost more friction than consenting.
func (handler *SyncHumanHandler) close(response http.ResponseWriter, request *http.Request, approver HumanApprover, id string) {
	var input struct {
		Body string `json:"body"`
		Note string `json:"note"`
	}
	if request.ContentLength > 0 {
		if err := decodeStrict(request, handler.maxBody, &input); err != nil {
			writeError(response, http.StatusBadRequest, "invalid_close")
			return
		}
	}
	if err := handler.store.CloseSync(request.Context(), approver.TenantID, id, approver.ID,
		commentBody(input.Body, input.Note), handler.now()); err != nil {
		writeJSON(response, http.StatusConflict, map[string]any{
			"error":  "sync_not_closable",
			"detail": "Only a pre-PR still awaiting your review can be closed. Once publishing has started, closing this record would not retract what is already on GitHub.",
		})
		return
	}
	// The queue must stop resurfacing a decision already made.
	_ = handler.store.CompleteQueueItemForRef(request.Context(), approver.TenantID, "sync", id, handler.now())
	writeJSON(response, http.StatusOK, map[string]any{"id": id, "state": "closed"})
}

// alreadyPublished reports whether an operation reached a POSITIVE terminal
// state despite the chain returning an error.
//
// It exists because "the chain errored" and "the write did not happen" are
// different claims, and conflating them stranded a completed push: the branch
// was on GitHub, the operation later verified, and publication stopped anyway.
// A reconcile that says verified is a positive witness; anything else is not,
// so this fails closed and the caller reports the failure.
func (handler *SyncHumanHandler) alreadyPublished(ctx context.Context, tenantID, operationID string) bool {
	if handler.store == nil {
		return false
	}
	operation, err := handler.store.Operation(ctx, tenantID, operationID)
	if err != nil {
		return false
	}
	return server.DurableState(operation.State) == server.DurableVerified
}

// retryableOperationID preserves replay protection for every operation that
// may have executed, while giving a fresh identity to a terminal negative that
// proves no public mutation occurred. This lets an already-reviewed pre-PR
// recover after an internal policy defect is repaired without asking the human
// to approve byte-identical content again.
func (handler *SyncHumanHandler) retryableOperationID(ctx context.Context, tenantID, baseID string) string {
	if handler.store == nil {
		return baseID
	}
	for attempt := 0; attempt < 100; attempt++ {
		candidate := baseID
		if attempt > 0 {
			candidate = fmt.Sprintf("%s-retry-%d", baseID, attempt)
		}
		operation, err := handler.store.Operation(ctx, tenantID, candidate)
		if err != nil {
			return candidate
		}
		state := server.DurableState(operation.State)
		if state != server.DurableDenied && state != server.DurableAbsent {
			return candidate
		}
	}
	return baseID
}

// reconcileOnly returns the durable result for an operation that already ran,
// without submitting anything. It is how the chain resumes past a step whose
// work is complete: the resource id it carries (a PR number, a ref) is what the
// following steps need, and re-submitting to obtain it would be denied by the
// replay guard — correctly, since the write already happened.
func (handler *SyncHumanHandler) reconcileOnly(ctx context.Context, identity server.DurableIdentity, operationID string) (server.DurableResult, error) {
	reconciler, ok := handler.executor.(OperationReconciler)
	if !ok {
		return server.DurableResult{}, fmt.Errorf("cannot resume %s: no reconciler", operationID)
	}
	return reconciler.Reconcile(ctx, identity, operationID)
}
