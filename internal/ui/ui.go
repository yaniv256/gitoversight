// Package ui serves GitOversight's phone-first human interface. Pages are
// rendered server-side by the broker binary (KTD1): no build chain, no CDN,
// no external origins. The system font stack renders San Francisco on Apple
// devices. GET routes sit behind the cookie-only page gate (KTD7); every
// mutation posts to the /v1/human API with the template-injected CSRF token.
package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/api"
	"github.com/yaniv256/gitoversight.dev/internal/attribution"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/prpreview"
	"github.com/yaniv256/gitoversight.dev/internal/searchembed"
	"github.com/yaniv256/gitoversight.dev/internal/searchstore"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

//go:embed templates/*.html templates/app.js templates/static.css
var templateFS embed.FS

type Config struct {
	Store  *sqlite.DB
	Policy policy.Snapshot
	// Pulls is retained for wiring compatibility only. Since the everything
	// view moved onto the search dataset (U7) no UI page performs live
	// pull_request.list calls; tests pin that invariant.
	Pulls api.PullLister
	// ProposedPolicyPath, when set, names the staged next-generation policy
	// file the promote view offers for human approval.
	ProposedPolicyPath string
	// Bases resolves public-repository content for pre-PR diff review.
	Bases Bases
	// BaseBranch is the public branch a pre-PR is measured against.
	BaseBranch string
	// PrivateIdentities are internal identifiers the review page warns about
	// when they would publish.
	PrivateIdentities []attribution.Identity
	// SearchDBPath locates the searchstore database backing the search page
	// and the everything view. Opened lazily: the file legitimately does not
	// exist until the first sync run completes. Empty means the search
	// dataset feature is off entirely (matching the worker's gate), so the
	// pages render an explicit "not configured" state instead of pretending
	// an index is on its way.
	SearchDBPath string
	// Logf defaults to log.Printf (the same seam internal/searchsync uses).
	Logf func(format string, args ...any)
}

type Handler struct {
	store              *sqlite.DB
	policy             policy.Snapshot
	proposedPolicyPath string
	pages              map[string]*template.Template
	diffPage           *template.Template
	logf               func(format string, args ...any)

	// searchConfigured records whether Config.SearchDBPath was set; when it
	// is false searchReader would only ever fail, so the pages short-circuit.
	searchConfigured bool
	searchReader     *searchstore.LazyReader

	// bases reads a public repository's current content so a pre-PR can be
	// shown as a real diff. Nil makes the page REFUSE rather than render a
	// contentless file list.
	bases Bases
	// privateIdentities are the internal names and addresses that must not
	// cross into public content; the page warns when they would.
	privateIdentities []attribution.Identity
	baseBranch        string
}

// Bases resolves a public repository's base tree for pre-PR review. It is the
// same worker-side read the propose path uses; the UI holds no credentials.
type Bases interface {
	ReadBase(workerrpc.BaseReadRequest) (workerrpc.BaseRead, error)
	ReadBlob(repository, sha string) ([]byte, error)
}

// NewHandler parses each page as its own template set (layout + one content
// template) — every page defines "content", so a single shared set would let
// the last-parsed page silently win for all routes.
func NewHandler(config Config) (*Handler, error) {
	// An unknown state yields order[state]==0, which renders EVERY rail stage as
	// un-started — a blank, apparently-fresh progress rail for a sync that is
	// finished. `abandoned` sits at the merge stage because publication did
	// happen; only the merge did not.
	//
	// `merged_public` is receipt-only: CompleteSyncMerged writes 'done'
	// directly and never persists it, so that entry is unreachable. Left in
	// place rather than cleaned up here — that belongs with the shared state
	// registry (INV-R11), not this change.
	order := map[string]int{"proposed": 1, "changes_requested": 1, "authorized": 2, "public_pr_created": 3, "merged_public": 4, "done": 4, "abandoned": 3, "closed": 1}
	funcs := template.FuncMap{
		"railClass": func(state, stage string) string {
			current, stagePos := order[state], order[stage]
			switch {
			case current > stagePos:
				return "done"
			case current == stagePos:
				return "current"
			default:
				return ""
			}
		},
		"lineClass": lineClass,
		"kindLabel": kindLabel,
	}
	baseBranch := config.BaseBranch
	if baseBranch == "" {
		baseBranch = "main"
	}
	pages := map[string]*template.Template{}
	for _, name := range []string{"now", "everything", "sync", "approval", "promote", "search"} {
		parsed, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		pages[name] = parsed
	}
	diffPage, err := template.New("diff.html").Funcs(funcs).ParseFS(templateFS, "templates/diff.html")
	if err != nil {
		return nil, err
	}
	logf := config.Logf
	if logf == nil {
		logf = log.Printf
	}
	return &Handler{store: config.Store, policy: config.Policy, proposedPolicyPath: config.ProposedPolicyPath,
		searchConfigured: config.SearchDBPath != "", searchReader: searchstore.NewLazyReader(config.SearchDBPath),
		bases: config.Bases, baseBranch: baseBranch, privateIdentities: config.PrivateIdentities,
		logf: logf, pages: pages, diffPage: diffPage}, nil
}

// pageCSP deliberately overwrites the router-wide lockdown CSP (KTD6): the
// HTML views need self-hosted styles while remaining closed to every external
// origin and to framing.
const pageCSP = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

type pageData struct {
	Title, Tab, CSRFToken  string
	Item                   sqlite.QueueItem
	Depth                  int64
	PendingPromotion       bool
	Repos                  []repoView
	Sync                   sqlite.SyncRequest
	View                   syncView
	Provenance             sqlite.SyncProvenance
	Comments               []sqlite.SyncComment
	Op                     storage.Operation
	Approval               approvalView
	ApproveBody            string
	PromoteBody            template.JS
	PromoteSummary         string
	PromoteFrom, PromoteTo uint64
	// Search page + everything view dataset state. Every string below is
	// untrusted (READMEs, descriptions, PR titles) and MUST stay a plain
	// string so html/template escapes it — never template.HTML/template.JS.
	Query         string
	Results       []searchResultView
	NotConfigured bool
	IndexBuilding bool
	SearchError   bool
	LastSync      string
	File          prpreview.FileDiff
}

type repoView struct {
	Name      string
	NotSynced bool
	Pulls     []pullView
}

// searchResultView is one rendered search hit. Plain strings only (see
// pageData); the template escapes them in text and attribute context.
type searchResultView struct {
	Name        string
	Description string
	Snippet     string
	HTMLURL     string
}

type pullView struct {
	Number  int
	Title   string
	Author  string
	HTMLURL string
	Chip    string
	Deny    bool
}

// chipFor maps a PR to its human-facing chip per the plan's vocabulary. A PR
// whose head is a sync branch inherits the sync state's chip; every other
// open PR reads as plainly open. One shared mapping — U8 and U9 both use it.
func chipFor(pull githubapp.PullRequestSummary, syncsByBranch map[string]string) (string, bool) {
	if state, ok := syncsByBranch[pull.HeadRef]; ok {
		switch state {
		case "proposed":
			return "Your review", false
		case "changes_requested":
			return "Agent revising", false
		case "authorized":
			return "Publishing…", false
		case "public_pr_created":
			return "Your merge", false
		case "merged_public":
			return "Confirm done", false
		case "abandoned":
			// Without this arm the chip falls through to "Open" — actively
			// telling the reviewer a dead pull request is still live.
			return "Closed unmerged", false
		case "closed":
			return "Declined", false
		}
	}
	if pull.Draft {
		return "Draft", false
	}
	return "Open", false
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	// Stylesheet and script carry no tenant data and are served BEFORE the
	// session check. They sat after it, so a logged-out browser got a redirect
	// instead of CSS/JS — the assets were coupled to session state for no
	// reason, and any unauthenticated page would render unstyled and scriptless.
	// Found by the post-deploy smoke on its first run (2026-07-26); the existing
	// unit tests missed it because they call this handler with an already
	// authenticated context, entering below the gate the defect lives at.
	path := strings.Trim(request.URL.Path, "/")
	if path == "ui/static/styles.css" || path == "ui/static/app.js" {
		handler.static(response, request, path)
		return
	}
	approver, ok := api.HumanApproverFromContext(request.Context())
	if !ok {
		// Login is an interruption, not the reviewer's destination. Preserve the
		// exact same-site UI route across the OAuth round-trip; otherwise a direct
		// review link silently degrades into the generic queue page.
		returnTo := request.URL.RequestURI()
		if returnTo == "" {
			returnTo = "/ui/now"
		}
		http.Redirect(response, request, "/login/github?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}
	// Every action on these pages needs this token, so rendering without it
	// produces a page whose buttons are dead on arrival: the POST carries an
	// empty X-CSRF-Token, the API answers 403, and the client — which cannot
	// tell that apart from a lapsed step-up — tells the reviewer to sign in
	// again. Signing in does not help, so the reviewer loops.
	//
	// That happened live (2026-07-27) when only the session cookie was Lax:
	// the reviewer arrived from GitHub with a session but no CSRF cookie, and
	// the page rendered an empty token in silence. Both cookies are Lax now,
	// but a page that cannot act must SAY so rather than render a control that
	// cannot work — the failure has to be visible where the action is.
	cookie, err := request.Cookie("gitoversight_csrf")
	if err != nil || cookie.Value == "" {
		http.Redirect(response, request, "/login/github?return_to="+url.QueryEscape("/"+path), http.StatusFound)
		return
	}
	csrf := cookie.Value
	if strings.HasPrefix(path, "ui/approval/") {
		id := strings.TrimPrefix(path, "ui/approval/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(response, request)
			return
		}
		operation, err := handler.store.Operation(request.Context(), approver.TenantID, id)
		if err != nil {
			http.NotFound(response, request)
			return
		}
		// The approve POST must carry exactly the approval binding the
		// submitter attached; the broker cross-checks every field. Rendered
		// server-side into the button, never editable.
		body, err := json.Marshal(map[string]any{
			"tenant_id": operation.TenantID, "approval_id": operation.ApprovalID,
			"packet_hash": operation.PacketHash, "manifest_hash": operation.ManifestHash,
			"head_sha": operation.HeadSHA, "nonce": operation.ApprovalNonce,
			"expires_at": operation.ApprovalExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		})
		if err != nil {
			http.Error(response, "render failed", http.StatusInternalServerError)
			return
		}
		handler.render(response, "approval", pageData{Title: "Approval", Tab: "now", CSRFToken: csrf, Op: operation,
			ApproveBody: string(body), Approval: buildApprovalView(operation)})
		return
	}
	if strings.HasPrefix(path, "ui/sync/") {
		remainder := strings.TrimPrefix(path, "ui/sync/")
		if strings.HasSuffix(remainder, "/diff") {
			id := strings.TrimSuffix(remainder, "/diff")
			if id == "" || strings.Contains(id, "/") {
				http.NotFound(response, request)
				return
			}
			handler.serveSyncDiff(response, request, approver.TenantID, id)
			return
		}
		id := remainder
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(response, request)
			return
		}
		sync, err := handler.store.GetSyncRequest(request.Context(), approver.TenantID, id)
		if err != nil {
			http.NotFound(response, request)
			return
		}
		// The diff is part of the authorization surface, so it is needed only
		// while the proposal is awaiting review. Rebuilding it after the public
		// PR already exists performs hundreds of worker RPC blob reads for data
		// the template does not render; sufficiently large historical syncs can
		// therefore time out before showing the one link the reviewer needs.
		var view syncView
		if sync.State == "proposed" {
			view = handler.buildSyncView(sync, handler.privateIdentities)
		}
		// Provenance is best-effort: a reviewer who cannot see the revision
		// history is worse off than one who can, but not as badly off as one
		// who cannot see the proposal at all. An audit-read failure must not
		// take the page down.
		provenance, provenanceErr := handler.store.SyncProvenanceFor(request.Context(), approver.TenantID, id)
		if provenanceErr != nil {
			handler.logf("sync provenance unavailable for %s: %v", id, provenanceErr)
		}
		comments, commentsErr := handler.store.SyncCommentsFor(request.Context(), approver.TenantID, sqlite.SyncCommentSubjectSync, id)
		if commentsErr != nil {
			handler.logf("sync comments unavailable for %s: %v", id, commentsErr)
		}
		handler.render(response, "sync", pageData{Title: sync.PublicRepository, Tab: "now", CSRFToken: csrf,
			Sync: sync, View: view, Provenance: provenance, Comments: comments})
		return
	}
	switch path {
	case "ui/promote-policy":
		handler.promotePolicy(response, request, approver.TenantID, csrf)
		return
	case "ui/everything":
		handler.everything(response, request, approver.TenantID, csrf)
		return
	case "ui/search":
		handler.search(response, request, csrf)
		return
	case "ui", "ui/now":
		item, depth, err := handler.store.TopQueueItem(request.Context(), approver.TenantID)
		if err != nil {
			handler.render(response, "now", pageData{Title: "Now", Tab: "now", CSRFToken: csrf})
			return
		}
		data := pageData{Title: "Now", Tab: "now", CSRFToken: csrf, Item: item, Depth: depth}
		// A staged policy promotion is human work even though it is not a queue
		// item — surface it instead of an empty state ("Nothing needs you"
		// while a promotion waited was a real miss, 2026-07-22).
		if item.ItemID == "" {
			data.PendingPromotion = handler.promotablePolicy(request.Context(), approver.TenantID)
		}
		handler.render(response, "now", data)
	default:
		http.NotFound(response, request)
	}
}

func (handler *Handler) serveSyncDiff(response http.ResponseWriter, request *http.Request, tenantID, id string) {
	sync, err := handler.store.GetSyncRequest(request.Context(), tenantID, id)
	if err != nil || sync.State != "proposed" || handler.bases == nil {
		http.NotFound(response, request)
		return
	}
	packet, unavailable := decodeSyncPacket(sync)
	if unavailable != "" {
		http.Error(response, unavailable, http.StatusUnprocessableEntity)
		return
	}
	base, err := handler.bases.ReadBase(workerrpc.BaseReadRequest{Repository: sync.PublicRepository, Branch: handler.baseBranch})
	if err != nil {
		http.Error(response, "The public repository could not be read.", http.StatusServiceUnavailable)
		return
	}
	if packet.Tree.BaseTree != "" && base.TreeSHA != packet.Tree.BaseTree {
		http.Error(response, "The public base moved after this proposal was created. Reload the review before authorizing.", http.StatusConflict)
		return
	}
	entries := make(map[string]prpreview.BaseEntry, len(base.Entries))
	for _, entry := range base.Entries {
		entries[entry.Path] = prpreview.BaseEntry{SHA: entry.SHA, Mode: entry.Mode, Type: entry.Type}
	}
	baseContent := func(path string) ([]byte, bool, error) {
		entry, present := entries[path]
		if !present {
			return nil, false, nil
		}
		content, err := handler.bases.ReadBlob(sync.PublicRepository, entry.SHA)
		return content, true, err
	}
	file, err := prpreview.BuildFile(packet, request.URL.Query().Get("path"), baseContent, entries)
	if err != nil {
		http.Error(response, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "private, no-store")
	if err := handler.diffPage.ExecuteTemplate(response, "diff", pageData{File: file}); err != nil {
		http.Error(response, "render failed", http.StatusInternalServerError)
	}
}

func (handler *Handler) render(response http.ResponseWriter, page string, data pageData) {
	set, ok := handler.pages[page]
	if !ok {
		http.Error(response, "render failed", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Security-Policy", pageCSP)
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	if err := set.ExecuteTemplate(response, "layout", data); err != nil {
		http.Error(response, "render failed", http.StatusInternalServerError)
	}
}

const (
	searchResultLimit = 20
	searchMaxQueryLen = 512
)

// search renders the owner-facing search page. Cookie-gated owner view: NO
// policy filtering here — the human sees the whole dataset.
func (handler *Handler) search(response http.ResponseWriter, request *http.Request, csrf string) {
	data := pageData{Title: "Search", Tab: "search", CSRFToken: csrf}
	query := strings.TrimSpace(request.URL.Query().Get("q"))
	if len(query) > searchMaxQueryLen {
		query = query[:searchMaxQueryLen]
	}
	data.Query = query
	if !handler.searchConfigured {
		data.NotConfigured = true
		handler.render(response, "search", data)
		return
	}
	if query == "" {
		handler.render(response, "search", data)
		return
	}
	store, err := handler.searchReader.Open(request.Context())
	if searchstore.IndexNotBuilt(err) {
		data.IndexBuilding = true
		handler.render(response, "search", data)
		return
	}
	if err != nil {
		handler.logf("ui: search dataset open failed: %v", err)
		data.SearchError = true
		handler.render(response, "search", data)
		return
	}
	ranked, err := searchembed.Query(store.EmbedIndex(request.Context()), query, nil, searchResultLimit)
	if err != nil {
		data.SearchError = true
		handler.render(response, "search", data)
		return
	}
	for _, hit := range ranked {
		repo, found, err := store.GetRepo(request.Context(), hit.FullName)
		if err != nil {
			data.SearchError = true
			handler.render(response, "search", data)
			return
		}
		if !found || repo.TombstonedAt != "" {
			continue
		}
		data.Results = append(data.Results, searchResultView{
			Name: repo.FullName, Description: repo.Description,
			Snippet: searchstore.Snippet(repo), HTMLURL: repo.HTMLURL,
		})
	}
	handler.render(response, "search", data)
}

// everything renders every registered repository from the cached search
// dataset in ONE read — zero live GitHub calls (the pre-U7 bounded-concurrency
// pulls.List fan-out is gone). A repo in policy but absent from the dataset
// renders a neutral "not synced yet" row; when the dataset itself is not built
// yet, every repo renders that way under a building notice.
func (handler *Handler) everything(response http.ResponseWriter, request *http.Request, tenantID, csrf string) {
	syncsByBranch := map[string]string{}
	if open, err := handler.store.ListOpenSyncRequests(request.Context(), tenantID); err == nil {
		for _, item := range open {
			syncsByBranch["sync/"+item.ID] = item.State
		}
	}
	names := make([]string, 0, len(handler.policy.Repositories))
	for name := range handler.policy.Repositories {
		names = append(names, name)
	}
	sort.Strings(names)
	data := pageData{Title: "Everything", Tab: "everything", CSRFToken: csrf}
	if !handler.searchConfigured {
		// Feature off: render the explicit not-configured state. The refresh
		// route is only registered when the feature is on, so the template
		// also suppresses the Refresh button in this state.
		data.NotConfigured = true
		for _, name := range names {
			data.Repos = append(data.Repos, repoView{Name: name, NotSynced: true})
		}
		handler.render(response, "everything", data)
		return
	}
	inDataset, pullsByRepo, lastSync, state := handler.loadDataset(request.Context())
	if state != datasetOK {
		if state == datasetBuilding {
			data.IndexBuilding = true
		} else {
			data.SearchError = true
		}
		for _, name := range names {
			data.Repos = append(data.Repos, repoView{Name: name, NotSynced: true})
		}
		handler.render(response, "everything", data)
		return
	}
	data.LastSync = lastSync
	for _, name := range names {
		view := repoView{Name: name}
		if !inDataset[name] {
			view.NotSynced = true
		} else {
			for _, pull := range pullsByRepo[name] {
				// Cached pulls do not record draft state; chipFor's sync-branch
				// mapping is what matters here.
				chip, deny := chipFor(githubapp.PullRequestSummary{HeadRef: pull.HeadRef}, syncsByBranch)
				view.Pulls = append(view.Pulls, pullView{Number: pull.Number, Title: pull.Title, Author: pull.Author, HTMLURL: pull.HTMLURL, Chip: chip, Deny: deny})
			}
		}
		data.Repos = append(data.Repos, view)
	}
	handler.render(response, "everything", data)
}

// datasetState classifies loadDataset's outcome so the everything view can
// tell the benign "index not built yet" state apart from a real failure —
// the same distinction search() draws inline.
type datasetState int

const (
	datasetOK datasetState = iota
	// datasetBuilding: the store is legitimately absent (or its schema is
	// from another build) and the next sync resolves it.
	datasetBuilding
	// datasetFailed: a real error (permissions, bad path, corrupt file) that
	// waiting will not fix; it has been logged.
	datasetFailed
)

// loadDataset reads the everything view's whole input from the searchstore.
// Any state other than datasetOK means the dataset is unavailable and the
// caller should render the degraded zero-call view.
func (handler *Handler) loadDataset(ctx context.Context) (map[string]bool, map[string][]searchstore.Pull, string, datasetState) {
	store, err := handler.searchReader.Open(ctx)
	if searchstore.IndexNotBuilt(err) {
		return nil, nil, "", datasetBuilding
	}
	if err != nil {
		handler.logf("ui: search dataset open failed: %v", err)
		return nil, nil, "", datasetFailed
	}
	repos, err := store.ListRepos(ctx, false)
	if err != nil {
		handler.logf("ui: search dataset repo read failed: %v", err)
		return nil, nil, "", datasetFailed
	}
	pulls, err := store.ListAllPulls(ctx)
	if err != nil {
		handler.logf("ui: search dataset pull read failed: %v", err)
		return nil, nil, "", datasetFailed
	}
	lastSync, _, err := store.GetMeta(ctx, "last_sync")
	if err != nil {
		handler.logf("ui: search dataset meta read failed: %v", err)
		return nil, nil, "", datasetFailed
	}
	inDataset := make(map[string]bool, len(repos))
	for _, repo := range repos {
		inDataset[repo.FullName] = true
	}
	pullsByRepo := make(map[string][]searchstore.Pull, len(pulls))
	for _, pull := range pulls {
		pullsByRepo[pull.FullName] = append(pullsByRepo[pull.FullName], pull)
	}
	return inDataset, pullsByRepo, lastSync, datasetOK
}

func (handler *Handler) static(response http.ResponseWriter, request *http.Request, path string) {
	name, contentType := "templates/static.css", "text/css; charset=utf-8"
	if strings.HasSuffix(path, "app.js") {
		name, contentType = "templates/app.js", "text/javascript; charset=utf-8"
	}
	content, err := templateFS.ReadFile(name)
	if err != nil {
		http.Error(response, "not found", http.StatusNotFound)
		return
	}
	// An ETag over the asset's own bytes. Without it, `max-age` alone meant a
	// browser that had ever loaded the page kept serving the OLD stylesheet from
	// cache after a deploy — a plain reload did not refetch, so a shipped CSS fix
	// was invisible to exactly the returning users it was shipped for.
	//
	// Caught live (2026-07-26) chasing a tabbar occlusion fix that was present in
	// the served bytes and absent from the page's CSSOM: same URL, cached copy
	// 7605 bytes, fresh fetch 8671. The deploy was fine; the browser never asked.
	//
	// The asset is embedded at build time, so its content hash IS its version —
	// no build step or fingerprinted filename needed, and it cannot drift from
	// what is actually served the way a hand-maintained version string would.
	sum := sha256.Sum256(content)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Cache-Control", "public, max-age=300")
	response.Header().Set("ETag", etag)
	if match := request.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = response.Write(content)
}

// promotePolicy renders the staged next-generation policy for one-tap human
// promotion. The body is bound to the ACTIVE generation and hash read from the
// durable store, so a promotion races safely: any drift rejects untouched.
// promotablePolicy reports whether a staged policy could ACTUALLY be promoted
// right now — the same question promotePolicy answers, asked the same way.
//
// The Now page used to test only that the file EXISTS (os.Stat). The promote
// page additionally parses it, validates it, and requires generation ==
// active+1. So a leftover staged file whose generation had already been
// promoted made Now advertise "A policy update is staged for your review" while
// the page behind the button said "No policy update staged" — observed live
// 2026-07-26 with a generation-6 file against active generation 6.
//
// A control that offers an action must use the SAME predicate as the handler
// that performs it. When the advertising check is cheaper than the executing
// check, the gap between them is exactly the set of buttons that cannot
// succeed.
func (handler *Handler) promotablePolicy(ctx context.Context, tenantID string) bool {
	if handler.proposedPolicyPath == "" {
		return false
	}
	raw, err := os.ReadFile(handler.proposedPolicyPath)
	if err != nil {
		return false
	}
	var proposed policy.Snapshot
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proposed); err != nil || proposed.Validate() != nil {
		return false
	}
	active, err := handler.store.LatestPolicyGeneration(ctx, tenantID)
	if err != nil {
		return false
	}
	return proposed.Generation == active.Generation+1
}

func (handler *Handler) promotePolicy(response http.ResponseWriter, request *http.Request, tenantID, csrf string) {
	empty := pageData{Title: "Policy", Tab: "now", CSRFToken: csrf}
	if handler.proposedPolicyPath == "" {
		handler.render(response, "promote", empty)
		return
	}
	raw, err := os.ReadFile(handler.proposedPolicyPath)
	if err != nil {
		handler.render(response, "promote", empty)
		return
	}
	var proposed policy.Snapshot
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proposed); err != nil || proposed.Validate() != nil {
		handler.render(response, "promote", empty)
		return
	}
	active, err := handler.store.LatestPolicyGeneration(request.Context(), tenantID)
	if err != nil || proposed.Generation != active.Generation+1 {
		handler.render(response, "promote", empty)
		return
	}
	body, err := json.Marshal(map[string]any{
		"tenant_id": tenantID, "expected_generation": active.Generation,
		"expected_policy_hash": active.PolicyHash, "snapshot": proposed,
	})
	if err != nil {
		handler.render(response, "promote", empty)
		return
	}
	summary := fmt.Sprintf("%d repositories · curator: %s", len(proposed.Repositories), proposed.QueueCurator)
	handler.render(response, "promote", pageData{Title: "Policy", Tab: "now", CSRFToken: csrf,
		PromoteBody: template.JS(body), PromoteSummary: summary, PromoteFrom: active.Generation, PromoteTo: proposed.Generation})
}
