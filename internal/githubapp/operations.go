package githubapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/gitref"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

type gitReference struct {
	Ref    string `json:"ref"`
	Object struct {
		SHA string `json:"sha"`
	} `json:"object"`
}

type gitObject struct {
	SHA string `json:"sha"`
}

type pullRequestState struct {
	Number         int    `json:"number"`
	HTMLURL        string `json:"html_url"`
	Title          string `json:"title"`
	Body           string `json:"body"`
	State          string `json:"state"`
	Merged         bool   `json:"merged"`
	MergeCommitSHA string `json:"merge_commit_sha"`
	Head           struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

type reviewState struct {
	ID       int64  `json:"id"`
	Body     string `json:"body"`
	CommitID string `json:"commit_id"`
}

type commentState struct {
	ID      int64  `json:"id"`
	HTMLURL string `json:"html_url"`
	Body    string `json:"body"`
}

type issueState struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	Title   string `json:"title"`
	Body    string `json:"body"`
}

type mergeState struct {
	SHA     string `json:"sha"`
	Merged  bool   `json:"merged"`
	Message string `json:"message"`
}

type releaseState struct {
	ID              int64               `json:"id"`
	HTMLURL         string              `json:"html_url"`
	TagName         string              `json:"tag_name"`
	TargetCommitish string              `json:"target_commitish"`
	Name            string              `json:"name"`
	Body            string              `json:"body"`
	Draft           bool                `json:"draft"`
	Prerelease      bool                `json:"prerelease"`
	UploadURL       string              `json:"upload_url"`
	Assets          []releaseAssetState `json:"assets"`
}

type repositoryState struct {
	ID                  int64  `json:"id"`
	FullName            string `json:"full_name"`
	HTMLURL             string `json:"html_url"`
	Visibility          string `json:"visibility"`
	Private             bool   `json:"private"`
	Description         string `json:"description"`
	Homepage            string `json:"homepage"`
	DefaultBranch       string `json:"default_branch"`
	Archived            bool   `json:"archived"`
	HasIssues           bool   `json:"has_issues"`
	HasProjects         bool   `json:"has_projects"`
	HasWiki             bool   `json:"has_wiki"`
	AllowSquashMerge    bool   `json:"allow_squash_merge"`
	AllowMergeCommit    bool   `json:"allow_merge_commit"`
	AllowRebaseMerge    bool   `json:"allow_rebase_merge"`
	AllowAutoMerge      bool   `json:"allow_auto_merge"`
	DeleteBranchOnMerge bool   `json:"delete_branch_on_merge"`
}

func (c *Client) ExecuteMutation(request worker.Request, mode TokenMode, subject string) (string, error) {
	if err := c.requireActor(request, mode, subject); err != nil {
		return "", err
	}
	if err := c.requirePullRequestIsWritable(request, mode, subject); err != nil {
		return "", err
	}
	subject = scopedSubject(mode, subject, request.Repository, request.Operation)
	switch request.Operation {
	case "branch.push":
		branch := gitref.BranchName(request.Branch)
		sha, ok := stringValue(request.Payload, "sha")
		if !ok || sha == "" || branch == "" {
			return "", errors.New("branch push packet is incomplete")
		}
		packet, present, err := commitpacket.Decode(request.Payload)
		if err != nil {
			return "", fmt.Errorf("branch push packet is invalid: %w", err)
		}
		if present && packet.Commit.SHA != sha {
			return "", errors.New("branch push commit hash does not match ref target")
		}
		refPath := referencePath(request.Repository, branch)
		// Empty-repository bootstrap (brand-yaniv, 2026-07-24): GitHub disables
		// the whole git-data API on a commitless repo — object uploads AND ref
		// calls answer 409 "Git Repository is empty". The contents API still
		// works and mints a root commit, which initializes the git database.
		// Sequence: bootstrap root commit → publish the packet's objects →
		// verify the branch still points at OUR bootstrap commit → force-move it
		// onto the packet's history. The precondition makes the force-move safe
		// (the repo was empty moments ago and its only reachable commit is one
		// this process just authored); the bootstrap commit becomes unreachable
		// and its marker file never appears in the final tree.
		bootstrap := func() (string, error) {
			bootstrapSHA, bootErr := c.bootstrapEmptyRepository(request.Repository, mode, subject, branch)
			if bootErr != nil {
				return "", fmt.Errorf("empty repository bootstrap failed: %w", bootErr)
			}
			if err := c.publishCommitObjects(request.Repository, mode, subject, packet); err != nil {
				return "", err
			}
			var current gitReference
			if err := c.call(http.MethodGet, refPath, mode, subject, nil, &current); err != nil {
				return "", err
			}
			if current.Object.SHA != bootstrapSHA {
				return "", errors.New("repository gained history during empty-repository bootstrap; refusing to force-move the branch")
			}
			payload, _ := json.Marshal(map[string]any{"sha": sha, "force": true})
			var moved gitReference
			if err := c.call(http.MethodPatch, refPath, mode, subject, bytes.NewReader(payload), &moved); err != nil {
				return "", err
			}
			return moved.Ref, nil
		}
		if present {
			if err := c.publishCommitObjects(request.Repository, mode, subject, packet); err != nil {
				if errors.Is(err, ErrGitHubRepositoryEmpty) {
					return bootstrap()
				}
				return "", err
			}
		}
		push := func() (string, error) {
			var current gitReference
			readErr := c.call(http.MethodGet, refPath, mode, subject, nil, &current)
			// An unborn branch on a repo WITH history reads as 404; the ref is
			// then created rather than moved. (A commitless repo answers 409
			// "Git Repository is empty" instead — handled by the bootstrap below,
			// because on such a repo the git-data API refuses writes too.)
			if readErr != nil && !errors.Is(readErr, ErrGitHubNotFound) {
				return "", readErr
			}
			var result gitReference
			if errors.Is(readErr, ErrGitHubNotFound) {
				payload, _ := json.Marshal(map[string]any{"ref": "refs/heads/" + branch, "sha": sha})
				if err := c.call(http.MethodPost, "/repos/"+request.Repository+"/git/refs", mode, subject, bytes.NewReader(payload), &result); err != nil {
					return "", err
				}
			} else {
				payload, _ := json.Marshal(map[string]any{"sha": sha, "force": false})
				if err := c.call(http.MethodPatch, refPath, mode, subject, bytes.NewReader(payload), &result); err != nil {
					return "", err
				}
			}
			return result.Ref, nil
		}
		resource, pushErr := push()
		if pushErr != nil && errors.Is(pushErr, ErrGitHubRepositoryEmpty) && present {
			return bootstrap()
		}
		return resource, pushErr
	case "branch.delete":
		branch := gitref.BranchName(request.Branch)
		if branch == "" {
			return "", errors.New("branch delete packet is incomplete")
		}
		// DELETE the ref. GitHub returns 204 No Content on success; if the ref is
		// already gone it returns 404, which we treat as success (idempotent — the
		// intended end state, ref absent, holds either way).
		if err := c.call(http.MethodDelete, referencePath(request.Repository, branch), mode, subject, nil, nil); err != nil && !errors.Is(err, ErrGitHubNotFound) {
			return "", err
		}
		return "refs/heads/" + branch, nil
	case "policy.promote":
		sha, ok := stringValue(request.Payload, "sha")
		if !ok || sha == "" || request.Branch == "" {
			return "", errors.New("policy promotion packet is incomplete")
		}
		payload, _ := json.Marshal(map[string]any{"sha": sha, "force": false})
		var result gitReference
		if err := c.call(http.MethodPatch, referencePath(request.Repository, request.Branch), mode, subject, bytes.NewReader(payload), &result); err != nil {
			return "", err
		}
		return result.Ref, nil
	case "pull_request.update":
		number, err := requiredNumber(request.Payload)
		if err != nil || request.Title == "" {
			return "", errors.New("pull request update packet is incomplete")
		}
		payload, _ := json.Marshal(map[string]string{"title": request.Title, "body": request.Body})
		var result pullRequestState
		if err := c.call(http.MethodPatch, pullPath(request.Repository, number), mode, subject, bytes.NewReader(payload), &result); err != nil {
			return "", err
		}
		return pullResource(result), nil
	case "pull_request.close":
		number, err := requiredNumber(request.Payload)
		if err != nil {
			return "", errors.New("pull request close packet is incomplete")
		}
		payload, _ := json.Marshal(map[string]string{"state": "closed"})
		var result pullRequestState
		if err := c.call(http.MethodPatch, pullPath(request.Repository, number), mode, subject, bytes.NewReader(payload), &result); err != nil {
			return "", err
		}
		return pullResource(result), nil
	case "pull_request.review":
		number, err := requiredNumber(request.Payload)
		event, ok := stringValue(request.Payload, "event")
		if err != nil || !ok || !validReviewEvent(event) || !hasReconciliationMarker(request) {
			return "", errors.New("pull request review packet is incomplete")
		}
		payload := map[string]string{"event": event, "body": request.Body}
		if head, ok := stringValue(request.Payload, "head_sha"); ok && head != "" {
			payload["commit_id"] = head
		}
		encoded, _ := json.Marshal(payload)
		var result reviewState
		if err := c.call(http.MethodPost, pullPath(request.Repository, number)+"/reviews", mode, subject, bytes.NewReader(encoded), &result); err != nil {
			return "", err
		}
		return fmt.Sprintf("review:%d", result.ID), nil
	case "pull_request.reply":
		number, err := requiredNumber(request.Payload)
		if err != nil || !hasReconciliationMarker(request) {
			return "", errors.New("pull request reply packet is incomplete")
		}
		payload, _ := json.Marshal(map[string]string{"body": request.Body})
		var result commentState
		if err := c.call(http.MethodPost, issuePath(request.Repository, number)+"/comments", mode, subject, bytes.NewReader(payload), &result); err != nil {
			return "", err
		}
		if result.HTMLURL != "" {
			return result.HTMLURL, nil
		}
		return fmt.Sprintf("comment:%d", result.ID), nil
	case "pull_request.merge":
		number, err := requiredNumber(request.Payload)
		method, ok := stringValue(request.Payload, "merge_method")
		if err != nil || !ok || (method != "merge" && method != "squash" && method != "rebase") {
			return "", errors.New("pull request merge packet is incomplete")
		}
		payload := map[string]string{"merge_method": method}
		if head, ok := stringValue(request.Payload, "head_sha"); ok && head != "" {
			payload["sha"] = head
		}
		if request.Title != "" {
			payload["commit_title"] = request.Title
		}
		if request.Body != "" {
			payload["commit_message"] = request.Body
		}
		encoded, _ := json.Marshal(payload)
		var result mergeState
		if err := c.call(http.MethodPut, pullPath(request.Repository, number)+"/merge", mode, subject, bytes.NewReader(encoded), &result); err != nil {
			return "", err
		}
		if !result.Merged {
			return "", fmt.Errorf("github did not merge pull request: %s", result.Message)
		}
		return result.SHA, nil
	case "issue.create":
		if request.Title == "" || !hasReconciliationMarker(request) {
			return "", errors.New("issue create packet is incomplete")
		}
		payload, _ := json.Marshal(map[string]string{"title": request.Title, "body": request.Body})
		var result issueState
		if err := c.call(http.MethodPost, "/repos/"+request.Repository+"/issues", mode, subject, bytes.NewReader(payload), &result); err != nil {
			return "", err
		}
		return issueResource(result), nil
	case "issue.comment":
		number, err := requiredNumber(request.Payload)
		if err != nil || !hasReconciliationMarker(request) {
			return "", errors.New("issue comment packet is incomplete")
		}
		payload, _ := json.Marshal(map[string]string{"body": request.Body})
		var result commentState
		if err := c.call(http.MethodPost, issuePath(request.Repository, number)+"/comments", mode, subject, bytes.NewReader(payload), &result); err != nil {
			return "", err
		}
		return commentResource(result), nil
	case "release.publish":
		tag, tagOK := stringValue(request.Payload, "tag_name")
		target, targetOK := stringValue(request.Payload, "target_commitish")
		prerelease, prereleaseOK := boolValue(request.Payload, "prerelease")
		if !tagOK || tag == "" || !targetOK || target == "" || !prereleaseOK || request.Title == "" {
			return "", errors.New("release packet is incomplete")
		}
		payload, _ := json.Marshal(map[string]any{"tag_name": tag, "target_commitish": target, "name": request.Title, "body": request.Body, "draft": false, "prerelease": prerelease})
		var result releaseState
		if err := c.call(http.MethodPost, "/repos/"+request.Repository+"/releases", mode, subject, bytes.NewReader(payload), &result); err != nil {
			return "", err
		}
		return releaseResource(result), nil
	case "release.asset.upload":
		asset, content, err := releaseAssetPacket(request.Payload)
		if err != nil {
			return "", err
		}
		var release releaseState
		if err := c.call(http.MethodGet, "/repos/"+request.Repository+"/releases/tags/"+url.PathEscape(asset.TagName), mode, subject, nil, &release); err != nil {
			return "", err
		}
		uploadURL, err := c.releaseUploadURL(release.UploadURL, asset.Name)
		if err != nil {
			return "", err
		}
		encoded, err := c.callAbsolute(http.MethodPost, uploadURL, mode, subject, asset.ContentType, bytes.NewReader(content), 1<<20)
		if err != nil {
			return "", err
		}
		var result releaseAssetState
		if err := json.Unmarshal(encoded, &result); err != nil || result.ID <= 0 || result.Name != asset.Name || result.Size != asset.Size {
			return "", errors.New("github release asset response did not match approved packet")
		}
		return releaseAssetResource(result), nil
	case "repository.create":
		owner, name, ok := splitRepository(request.Repository)
		visibility, visibilityOK := stringValue(request.Payload, "visibility")
		if !ok || !visibilityOK || (visibility != "private" && visibility != "public") || mode != HumanUser || subject == "" {
			return "", errors.New("repository creation requires its exact human owner")
		}
		// The subject is a governance human id, not a GitHub login. Prove the
		// credential actually belongs to the target namespace by asking GitHub
		// who the token is — string comparison against the subject cannot.
		login, err := c.authenticatedLogin(mode, subject)
		if err != nil {
			return "", err
		}
		if !strings.EqualFold(login, owner) {
			return "", errors.New("human credential does not own the target namespace")
		}
		description, _ := stringValue(request.Payload, "description")
		payload, _ := json.Marshal(map[string]any{"name": name, "description": description, "private": visibility == "private", "auto_init": false})
		var result repositoryState
		if err := c.call(http.MethodPost, "/user/repos", mode, subject, bytes.NewReader(payload), &result); err != nil {
			return "", err
		}
		return repositoryResource(result), nil
	case "repository.settings.update":
		settings, err := repositorySettings(request.Payload)
		if err != nil {
			return "", err
		}
		if visibility, exists := settings["visibility"]; exists && visibility == "public" && mode != HumanUser {
			return "", ErrHumanTokenRequired
		}
		payload, _ := json.Marshal(settings)
		var result repositoryState
		if err := c.call(http.MethodPatch, "/repos/"+request.Repository, mode, subject, bytes.NewReader(payload), &result); err != nil {
			return "", err
		}
		return repositoryResource(result), nil
	case "installation.repository.add":
		if mode != HumanUser || subject == "" {
			return "", ErrHumanTokenRequired
		}
		installationID, err := requiredPositiveInteger(request.Payload, "installation_id")
		if err != nil {
			return "", errors.New("installation repository packet is incomplete")
		}
		var repository repositoryState
		if err := c.call(http.MethodGet, "/repos/"+request.Repository, mode, subject, nil, &repository); err != nil {
			return "", err
		}
		if repository.ID <= 0 || !strings.EqualFold(repository.FullName, request.Repository) {
			return "", errors.New("github repository identity did not match approved packet")
		}
		path := fmt.Sprintf("/user/installations/%d/repositories/%d", installationID, repository.ID)
		if err := c.call(http.MethodPut, path, mode, subject, nil, nil); err != nil {
			return "", err
		}
		return fmt.Sprintf("installation:%d/repository:%d", installationID, repository.ID), nil
	default:
		return "", errors.New("operation has no privileged executor")
	}
}

// bootstrapEmptyRepository mints a root commit on a commitless repository via
// the contents API (the only write surface GitHub allows before the first
// commit), returning the bootstrap commit's sha. This initializes the git
// database so the normal object-upload + ref flow can run.
func (c *Client) bootstrapEmptyRepository(repository string, mode TokenMode, subject, branch string) (string, error) {
	// The bootstrap file is a plain .gitignore: on the happy path this commit
	// becomes unreachable, and on any failure path the residue is a file every
	// repository should carry anyway rather than visible plumbing (Yaniv,
	// 2026-07-24).
	payload, _ := json.Marshal(map[string]string{
		"message": "Initialize repository",
		"content": base64.StdEncoding.EncodeToString([]byte("# Ignore rules for this repository.\n")),
		"branch":  branch,
	})
	var result struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := c.call(http.MethodPut, "/repos/"+repository+"/contents/.gitignore", mode, subject, bytes.NewReader(payload), &result); err != nil {
		return "", err
	}
	if result.Commit.SHA == "" {
		return "", errors.New("empty repository bootstrap returned no commit hash")
	}
	return result.Commit.SHA, nil
}

// secondaryRateLimited reports whether an error is GitHub's secondary rate
// limit — the anti-burst control, distinct from the hourly quota. It is a 403
// with a specific body rather than a 429, so status alone cannot identify it.
func secondaryRateLimited(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "secondary rate limit") || strings.Contains(text, "abuse detection")
}

// blobUploadAttempts bounds the retry. GitHub asks for "a few minutes"; the
// backoff below reaches ~4 minutes of total waiting, after which the failure is
// real and the operation should reconcile absent rather than retry forever.
const blobUploadAttempts = 5

func (c *Client) publishCommitObjects(repository string, mode TokenMode, subject string, packet commitpacket.Packet) error {
	// Blobs upload one request at a time, so a large publication is a burst:
	// 302 files in the first public sync of this repository tripped GitHub's
	// secondary rate limit partway through (2026-07-27). The loop had no
	// backoff at all, so the whole publication failed on one throttled request
	// and the human who had just approved it saw only an unresponsive button.
	//
	// Secondary limits are anti-burst, not quota — they clear in minutes and
	// the documented remedy is to wait and retry the SAME request. Failing the
	// entire publication instead turns a transient condition into a dead
	// approval.
	for _, blob := range packet.Blobs {
		payload, _ := json.Marshal(map[string]string{"content": blob.Content, "encoding": blob.Encoding})
		var result gitObject
		var err error
		for attempt := 0; attempt < blobUploadAttempts; attempt++ {
			err = c.call(http.MethodPost, "/repos/"+repository+"/git/blobs", mode, subject, bytes.NewReader(payload), &result)
			if !secondaryRateLimited(err) {
				break
			}
			// Exponential: 5s, 15s, 45s, 135s. Uploading a blob twice is
			// harmless — content addressing makes it the same object — so a
			// retry cannot double-write.
			c.sleep(time.Duration(5*pow3(attempt)) * time.Second)
		}
		if err != nil {
			return err
		}
		if result.SHA != blob.SHA {
			return errors.New("GitHub returned an unexpected blob hash")
		}
	}
	treeEntries := make([]map[string]any, 0, len(packet.Tree.Entries))
	for _, entry := range packet.Tree.Entries {
		encoded := map[string]any{"path": entry.Path, "mode": entry.Mode, "type": entry.Type, "sha": entry.SHA}
		if entry.Delete {
			encoded["sha"] = nil
		}
		treeEntries = append(treeEntries, encoded)
	}
	treePayload := map[string]any{"tree": treeEntries}
	if packet.Tree.BaseTree != "" {
		treePayload["base_tree"] = packet.Tree.BaseTree
	}
	encodedTree, _ := json.Marshal(treePayload)
	var tree gitObject
	if err := c.call(http.MethodPost, "/repos/"+repository+"/git/trees", mode, subject, bytes.NewReader(encodedTree), &tree); err != nil {
		return err
	}
	if tree.SHA != packet.Tree.SHA {
		return errors.New("GitHub returned an unexpected tree hash")
	}
	commitPayload := map[string]any{
		"message": packet.Commit.Message,
		"tree":    packet.Commit.Tree,
		// GitHub requires parents to be an array; a root commit built by a
		// packet builder that left the slice nil would otherwise serialize as
		// JSON null and draw a 422 (brand-yaniv-push, 2026-07-24).
		"parents":   nonNilParents(packet.Commit.Parents),
		"author":    packet.Commit.Author,
		"committer": packet.Commit.Committer,
	}
	encodedCommit, _ := json.Marshal(commitPayload)
	var commit gitObject
	if err := c.call(http.MethodPost, "/repos/"+repository+"/git/commits", mode, subject, bytes.NewReader(encodedCommit), &commit); err != nil {
		return err
	}
	if commit.SHA != packet.Commit.SHA {
		return errors.New("GitHub returned an unexpected commit hash")
	}
	return nil
}

func (c *Client) ReconcileMutation(request worker.Request, mode TokenMode, subject string) (worker.Reconciliation, error) {
	if err := c.requireActor(request, mode, subject); err != nil {
		return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
	}
	// A write the guard REFUSED must never reconcile as present (R5).
	//
	// This matters most for pull_request.update, whose reconciler compares the
	// stored title and body against the live pull request. On a closed PR those
	// match — the update was refused, but the values were never different — so
	// without this the operation is blocked and then recorded as successful.
	// That is the original defect wearing a different hat.
	//
	// An INDETERMINATE liveness read reconciles Unknown (retryable), not Absent
	// (terminal): a transient GitHub blip must not permanently mark a live
	// operation as never-happened.
	if err := c.requirePullRequestIsWritable(request, mode, subject); err != nil {
		var notWritable *PullNotWritableError
		if errors.As(err, &notWritable) && notWritable.Retryable() {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
	}
	subject = scopedSubject(mode, subject, request.Repository, request.Operation)
	switch request.Operation {
	case "branch.push":
		branch := gitref.BranchName(request.Branch)
		sha, ok := stringValue(request.Payload, "sha")
		if !ok || sha == "" || branch == "" {
			return unknown("branch push reconciliation packet is incomplete")
		}
		var result gitReference
		if err := c.call(http.MethodGet, referencePath(request.Repository, branch), mode, subject, nil, &result); err != nil {
			if errors.Is(err, ErrGitHubNotFound) {
				return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
			}
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		return presence(result.Object.SHA == sha, result.Ref), nil
	case "branch.delete":
		branch := gitref.BranchName(request.Branch)
		if branch == "" {
			return unknown("branch delete reconciliation packet is incomplete")
		}
		// For a delete the intended end state is ref ABSENT. So NotFound is the
		// SUCCESS/committed outcome; a ref that still resolves means the delete did
		// not take (absent, i.e. the mutation didn't land). This inverts branch.push.
		var result gitReference
		if err := c.call(http.MethodGet, referencePath(request.Repository, branch), mode, subject, nil, &result); err != nil {
			if errors.Is(err, ErrGitHubNotFound) {
				return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: "refs/heads/" + branch}, nil
			}
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
	case "policy.promote":
		sha, ok := stringValue(request.Payload, "sha")
		if !ok || sha == "" || request.Branch == "" {
			return unknown("policy promotion reconciliation packet is incomplete")
		}
		var result gitReference
		if err := c.call(http.MethodGet, referencePath(request.Repository, request.Branch), mode, subject, nil, &result); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		return presence(result.Object.SHA == sha, result.Ref), nil
	case "pull_request.update":
		number, err := requiredNumber(request.Payload)
		if err != nil || request.Title == "" {
			return unknown("pull request update reconciliation packet is incomplete")
		}
		var result pullRequestState
		if err := c.call(http.MethodGet, pullPath(request.Repository, number), mode, subject, nil, &result); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		return presence(result.Title == request.Title && result.Body == request.Body, pullResource(result)), nil
	case "pull_request.close":
		number, err := requiredNumber(request.Payload)
		if err != nil {
			return unknown("pull request close reconciliation packet is incomplete")
		}
		var result pullRequestState
		if err := c.call(http.MethodGet, pullPath(request.Repository, number), mode, subject, nil, &result); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		return presence(result.State == "closed", pullResource(result)), nil
	case "pull_request.review":
		number, err := requiredNumber(request.Payload)
		head, ok := stringValue(request.Payload, "head_sha")
		if err != nil || !ok || head == "" || !hasReconciliationMarker(request) {
			return unknown("pull request review reconciliation packet is incomplete")
		}
		var results []reviewState
		if err := c.call(http.MethodGet, pullPath(request.Repository, number)+"/reviews?per_page=100", mode, subject, nil, &results); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		for _, result := range results {
			if result.Body == request.Body && result.CommitID == head {
				return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: fmt.Sprintf("review:%d", result.ID)}, nil
			}
		}
		return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
	case "pull_request.reply":
		number, err := requiredNumber(request.Payload)
		if err != nil || !hasReconciliationMarker(request) {
			return unknown("pull request reply reconciliation packet is incomplete")
		}
		var results []commentState
		if err := c.call(http.MethodGet, issuePath(request.Repository, number)+"/comments?per_page=100", mode, subject, nil, &results); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		for _, result := range results {
			if result.Body == request.Body {
				resource := result.HTMLURL
				if resource == "" {
					resource = fmt.Sprintf("comment:%d", result.ID)
				}
				return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: resource}, nil
			}
		}
		return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
	case "pull_request.merge":
		number, err := requiredNumber(request.Payload)
		if err != nil {
			return unknown("pull request merge reconciliation packet is incomplete")
		}
		var result pullRequestState
		if err := c.call(http.MethodGet, pullPath(request.Repository, number), mode, subject, nil, &result); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		return presence(result.Merged, result.MergeCommitSHA), nil
	case "issue.create":
		if request.Title == "" || !hasReconciliationMarker(request) {
			return unknown("issue create reconciliation packet is incomplete")
		}
		var results []issueState
		if err := c.call(http.MethodGet, "/repos/"+request.Repository+"/issues?state=all&per_page=100", mode, subject, nil, &results); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		for _, result := range results {
			if result.Title == request.Title && result.Body == request.Body {
				return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: issueResource(result)}, nil
			}
		}
		return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
	case "issue.comment":
		number, err := requiredNumber(request.Payload)
		if err != nil || !hasReconciliationMarker(request) {
			return unknown("issue comment reconciliation packet is incomplete")
		}
		var results []commentState
		if err := c.call(http.MethodGet, issuePath(request.Repository, number)+"/comments?per_page=100", mode, subject, nil, &results); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		for _, result := range results {
			if result.Body == request.Body {
				return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: commentResource(result)}, nil
			}
		}
		return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
	case "release.publish":
		tag, tagOK := stringValue(request.Payload, "tag_name")
		target, targetOK := stringValue(request.Payload, "target_commitish")
		prerelease, prereleaseOK := boolValue(request.Payload, "prerelease")
		if !tagOK || tag == "" || !targetOK || target == "" || !prereleaseOK || request.Title == "" {
			return unknown("release reconciliation packet is incomplete")
		}
		var result releaseState
		if err := c.call(http.MethodGet, "/repos/"+request.Repository+"/releases/tags/"+url.PathEscape(tag), mode, subject, nil, &result); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		matches := !result.Draft && result.Prerelease == prerelease && result.TagName == tag && result.TargetCommitish == target && result.Name == request.Title && result.Body == request.Body
		return presence(matches, releaseResource(result)), nil
	case "release.asset.upload":
		asset, _, err := releaseAssetPacket(request.Payload)
		if err != nil {
			return unknown(err.Error())
		}
		var release releaseState
		if err := c.call(http.MethodGet, "/repos/"+request.Repository+"/releases/tags/"+url.PathEscape(asset.TagName), mode, subject, nil, &release); err != nil {
			if errors.Is(err, ErrGitHubNotFound) {
				return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
			}
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		for _, candidate := range release.Assets {
			if candidate.Name != asset.Name || candidate.Size != asset.Size {
				continue
			}
			downloadURL, err := c.releaseAssetURL(candidate.URL)
			if err != nil {
				return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
			}
			content, err := c.callAbsolute(http.MethodGet, downloadURL, mode, subject, "", nil, maxReleaseAssetBytes)
			if err != nil {
				return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
			}
			digest := fmt.Sprintf("%x", sha256.Sum256(content))
			if int64(len(content)) == asset.Size && digest == asset.SHA256 {
				return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: releaseAssetResource(candidate)}, nil
			}
			return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
		}
		return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
	case "repository.create":
		_, _, ok := splitRepository(request.Repository)
		visibility, visibilityOK := stringValue(request.Payload, "visibility")
		if !ok || !visibilityOK || mode != HumanUser || subject == "" {
			return unknown("repository creation reconciliation packet is incomplete")
		}
		var result repositoryState
		if err := c.call(http.MethodGet, "/repos/"+request.Repository, mode, subject, nil, &result); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		matches := strings.EqualFold(result.FullName, request.Repository) && result.Private == (visibility == "private")
		return presence(matches, repositoryResource(result)), nil
	case "repository.settings.update":
		settings, err := repositorySettings(request.Payload)
		if err != nil {
			return unknown(err.Error())
		}
		if visibility, exists := settings["visibility"]; exists && visibility == "public" && mode != HumanUser {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, ErrHumanTokenRequired
		}
		var result repositoryState
		if err := c.call(http.MethodGet, "/repos/"+request.Repository, mode, subject, nil, &result); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		return presence(repositorySettingsMatch(result, settings), repositoryResource(result)), nil
	case "installation.repository.add":
		if mode != HumanUser || subject == "" {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, ErrHumanTokenRequired
		}
		installationID, err := requiredPositiveInteger(request.Payload, "installation_id")
		if err != nil {
			return unknown("installation repository reconciliation packet is incomplete")
		}
		var result struct {
			Repositories []repositoryState `json:"repositories"`
		}
		path := fmt.Sprintf("/user/installations/%d/repositories?per_page=100", installationID)
		if err := c.call(http.MethodGet, path, mode, subject, nil, &result); err != nil {
			return worker.Reconciliation{State: worker.ReconciliationUnknown}, err
		}
		for _, repository := range result.Repositories {
			if strings.EqualFold(repository.FullName, request.Repository) {
				return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: fmt.Sprintf("installation:%d/repository:%d", installationID, repository.ID)}, nil
			}
		}
		return worker.Reconciliation{State: worker.ReconciliationAbsent}, nil
	default:
		return unknown("operation has no reconciliation adapter")
	}
}

// authenticatedLogin asks GitHub which login the resolved credential belongs
// to. Used to bind a human credential to a namespace by identity, not by
// comparing governance ids to logins.
func (c *Client) authenticatedLogin(mode TokenMode, subject string) (string, error) {
	var user struct {
		Login string `json:"login"`
	}
	if err := c.call(http.MethodGet, "/user", mode, subject, nil, &user); err != nil {
		return "", err
	}
	if user.Login == "" {
		return "", errors.New("github credential identity unavailable")
	}
	return user.Login, nil
}

func (c *Client) requireActor(request worker.Request, mode TokenMode, subject string) error {
	var visibility string
	if request.Operation == "repository.create" {
		// The target repository does not exist yet, so no resolver can know it.
		// The approved packet itself declares the visibility being created.
		value, ok := stringValue(request.Payload, "visibility")
		if !ok || (value != "public" && value != "private") {
			return errors.New("repository visibility unavailable")
		}
		visibility = value
	} else {
		value, err := c.visibility(request.Repository)
		if err != nil || (value != "public" && value != "private") {
			return errors.New("repository visibility unavailable")
		}
		visibility = value
	}
	if visibility == "public" && (mode != HumanUser || subject == "") {
		return ErrHumanTokenRequired
	}
	return nil
}

func requiredNumber(payload map[string]any) (int, error) {
	return requiredPositiveInteger(payload, "number")
}

func requiredPositiveInteger(payload map[string]any, key string) (int, error) {
	value, ok := payload[key]
	if !ok {
		return 0, errors.New("number is required")
	}
	switch number := value.(type) {
	case float64:
		if number <= 0 || number != float64(int(number)) {
			return 0, errors.New("number is invalid")
		}
		return int(number), nil
	case int:
		if number <= 0 {
			return 0, errors.New("number is invalid")
		}
		return number, nil
	case json.Number:
		parsed, err := strconv.Atoi(string(number))
		if err != nil || parsed <= 0 {
			return 0, errors.New("number is invalid")
		}
		return parsed, nil
	default:
		return 0, errors.New("number is invalid")
	}
}

func boolValue(payload map[string]any, key string) (bool, bool) {
	value, exists := payload[key]
	result, ok := value.(bool)
	return result, exists && ok
}

func splitRepository(repository string) (string, string, bool) {
	owner, name, ok := strings.Cut(repository, "/")
	return owner, name, ok && owner != "" && name != "" && !strings.Contains(name, "/")
}

func repositorySettings(payload map[string]any) (map[string]any, error) {
	raw, ok := payload["settings"].(map[string]any)
	if !ok || len(raw) == 0 {
		return nil, errors.New("repository settings packet is incomplete")
	}
	allowed := map[string]string{
		"description": "string", "homepage": "string", "visibility": "visibility", "default_branch": "string",
		"archived": "bool", "has_issues": "bool", "has_projects": "bool", "has_wiki": "bool",
		"allow_squash_merge": "bool", "allow_merge_commit": "bool", "allow_rebase_merge": "bool",
		"allow_auto_merge": "bool", "delete_branch_on_merge": "bool",
	}
	result := make(map[string]any, len(raw))
	for key, value := range raw {
		kind, exists := allowed[key]
		if !exists {
			return nil, fmt.Errorf("repository setting %q is not allowed", key)
		}
		switch kind {
		case "string":
			if _, ok := value.(string); !ok {
				return nil, fmt.Errorf("repository setting %q is invalid", key)
			}
		case "bool":
			if _, ok := value.(bool); !ok {
				return nil, fmt.Errorf("repository setting %q is invalid", key)
			}
		case "visibility":
			if value != "private" && value != "public" {
				return nil, errors.New("repository visibility is invalid")
			}
		}
		result[key] = value
	}
	return result, nil
}

func repositorySettingsMatch(repository repositoryState, settings map[string]any) bool {
	actual := map[string]any{
		"description": repository.Description, "homepage": repository.Homepage, "visibility": repository.Visibility,
		"default_branch": repository.DefaultBranch, "archived": repository.Archived, "has_issues": repository.HasIssues,
		"has_projects": repository.HasProjects, "has_wiki": repository.HasWiki, "allow_squash_merge": repository.AllowSquashMerge,
		"allow_merge_commit": repository.AllowMergeCommit, "allow_rebase_merge": repository.AllowRebaseMerge,
		"allow_auto_merge": repository.AllowAutoMerge, "delete_branch_on_merge": repository.DeleteBranchOnMerge,
	}
	for key, expected := range settings {
		if actual[key] != expected {
			return false
		}
	}
	return true
}

func validReviewEvent(value string) bool {
	switch strings.ToUpper(value) {
	case "APPROVE", "REQUEST_CHANGES", "COMMENT":
		return value == strings.ToUpper(value)
	default:
		return false
	}
}

func hasReconciliationMarker(request worker.Request) bool {
	if request.RequestID == "" {
		return false
	}
	return strings.Contains(request.Body, "<!-- gitoversight-request:"+request.RequestID+" -->")
}

func referencePath(repository, branch string) string {
	return "/repos/" + repository + "/git/refs/heads/" + url.PathEscape(branch)
}

func pullPath(repository string, number int) string {
	return "/repos/" + repository + "/pulls/" + strconv.Itoa(number)
}

func issuePath(repository string, number int) string {
	return "/repos/" + repository + "/issues/" + strconv.Itoa(number)
}

func pullResource(result pullRequestState) string {
	if result.HTMLURL != "" {
		return result.HTMLURL
	}
	return fmt.Sprintf("pull_request:%d", result.Number)
}

func issueResource(result issueState) string {
	if result.HTMLURL != "" {
		return result.HTMLURL
	}
	return fmt.Sprintf("issue:%d", result.Number)
}

func commentResource(result commentState) string {
	if result.HTMLURL != "" {
		return result.HTMLURL
	}
	return fmt.Sprintf("comment:%d", result.ID)
}

func releaseResource(result releaseState) string {
	if result.HTMLURL != "" {
		return result.HTMLURL
	}
	return fmt.Sprintf("release:%d", result.ID)
}

func repositoryResource(result repositoryState) string {
	if result.HTMLURL != "" {
		return result.HTMLURL
	}
	return result.FullName
}

func presence(committed bool, resource string) worker.Reconciliation {
	if committed {
		return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: resource}
	}
	return worker.Reconciliation{State: worker.ReconciliationAbsent}
}

func unknown(message string) (worker.Reconciliation, error) {
	return worker.Reconciliation{State: worker.ReconciliationUnknown}, errors.New(message)
}

func nonNilParents(parents []string) []string {
	if parents == nil {
		return []string{}
	}
	return parents
}

func releaseAssetPacket(payload map[string]any) (releaseAssetPacketState, []byte, error) {
	tag, tagOK := stringValue(payload, "tag_name")
	name, nameOK := stringValue(payload, "name")
	contentType, typeOK := stringValue(payload, "content_type")
	wantSHA, shaOK := stringValue(payload, "sha256")
	encoded, contentOK := stringValue(payload, "content_base64")
	size, sizeErr := requiredPositiveInteger(payload, "size")
	asset := releaseAssetPacketState{TagName: tag, Name: name, ContentType: contentType, SHA256: strings.ToLower(wantSHA), Size: int64(size)}
	if !tagOK || tag == "" || !nameOK || name == "" || filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") || !typeOK || contentType == "" || !shaOK || len(wantSHA) != 64 || !contentOK || sizeErr != nil || size > maxReleaseAssetBytes {
		return releaseAssetPacketState{}, nil, errors.New("release asset packet is incomplete")
	}
	for _, character := range strings.ToLower(wantSHA) {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return releaseAssetPacketState{}, nil, errors.New("release asset packet is incomplete")
		}
	}
	content, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(content) != size {
		return releaseAssetPacketState{}, nil, errors.New("release asset content does not match approved size")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	if digest != asset.SHA256 {
		return releaseAssetPacketState{}, nil, errors.New("release asset content does not match approved checksum")
	}
	return asset, content, nil
}

func (c *Client) releaseUploadURL(template, name string) (string, error) {
	base := strings.Split(template, "{")[0]
	parsed, err := c.validReleaseURL(base, true)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("name", name)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func releaseAssetResource(result releaseAssetState) string {
	if result.BrowserDownloadURL != "" {
		return result.BrowserDownloadURL
	}
	if result.URL != "" {
		return result.URL
	}
	return fmt.Sprintf("release-asset:%d", result.ID)
}

func (c *Client) releaseAssetURL(rawURL string) (string, error) {
	parsed, err := c.validReleaseURL(rawURL, false)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

type releaseAssetState struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	URL                string `json:"url"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type releaseAssetPacketState struct {
	TagName     string
	Name        string
	ContentType string
	SHA256      string
	Size        int64
}

func (c *Client) validReleaseURL(rawURL string, upload bool) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	base, baseErr := url.Parse(c.baseURL)
	if err != nil || baseErr != nil || parsed.Scheme != base.Scheme || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" {
		return nil, errors.New("github release URL is invalid")
	}
	allowed := strings.EqualFold(parsed.Host, base.Host)
	if upload && strings.EqualFold(base.Host, "api.github.com") && strings.EqualFold(parsed.Host, "uploads.github.com") {
		allowed = true
	}
	if !allowed {
		return nil, errors.New("github release URL host is not trusted")
	}
	return parsed, nil
}

const maxReleaseAssetBytes = 700 << 10
