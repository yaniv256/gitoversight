package githubapp_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

func TestBranchPushAmbiguousObjectCreationNeverUpdatesRefAndReconcilesAbsent(t *testing.T) {
	const treeSHA = "1111111111111111111111111111111111111111"
	const commitSHA = "5557dfea0c12ec2afea282dfcef4447aef1c38ee"
	const blobSHA = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
	request := worker.Request{Repository: "yaniv256/private", Operation: "branch.push", Branch: "agent/zara/novel", Payload: map[string]any{
		"sha": commitSHA,
		"object_package": map[string]any{
			"blobs":  []any{map[string]any{"sha": blobSHA, "content": "", "encoding": "base64"}},
			"tree":   map[string]any{"sha": treeSHA, "entries": []any{map[string]any{"path": "empty.txt", "mode": "100644", "type": "blob", "sha": blobSHA}}},
			"commit": map[string]any{"sha": commitSHA, "message": "novel", "tree": treeSHA, "parents": []any{}, "author": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}, "committer": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}},
		},
	}}
	var refUpdates int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		switch got.URL.EscapedPath() {
		case "/repos/yaniv256/private/git/blobs":
			io.WriteString(response, `{"sha":"`+blobSHA+`"}`)
		case "/repos/yaniv256/private/git/trees":
			io.WriteString(response, `{"sha":"`+treeSHA+`"}`)
		case "/repos/yaniv256/private/git/commits":
			hijacker := response.(http.Hijacker)
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = connection.Close()
		case "/repos/yaniv256/private/git/refs/heads/agent%2Fzara%2Fnovel":
			if got.Method == http.MethodPatch {
				refUpdates++
				t.Fatal("ref updated after ambiguous object creation")
			}
			io.WriteString(response, `{"ref":"refs/heads/agent/zara/novel","object":{"sha":"0000000000000000000000000000000000000000"}}`)
		default:
			t.Fatalf("unexpected request: %s %s", got.Method, got.URL.EscapedPath())
		}
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err == nil {
		t.Fatal("ambiguous commit creation was reported successful")
	}
	result, err := client.ReconcileMutation(request, githubapp.AppInstallation, "")
	if err != nil || result.State != worker.ReconciliationAbsent || refUpdates != 0 {
		t.Fatalf("result = %#v, ref updates = %d, err = %v", result, refUpdates, err)
	}
}

func TestBranchPushPublishesImmutableGitObjectsBeforeUpdatingRef(t *testing.T) {
	const treeSHA = "1111111111111111111111111111111111111111"
	const commitSHA = "a48bcfdf10f8fd18cac0b6664cf2c662e333e4bd"
	const parentSHA = "3333333333333333333333333333333333333333"
	const blobSHA = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
	request := worker.Request{Repository: "yaniv256/private", Operation: "branch.push", Branch: "agent/zara/new", Payload: map[string]any{
		"sha": commitSHA,
		"object_package": map[string]any{
			"blobs":  []any{map[string]any{"sha": blobSHA, "content": "", "encoding": "base64"}},
			"tree":   map[string]any{"sha": treeSHA, "base_tree": "2222222222222222222222222222222222222222", "entries": []any{map[string]any{"path": "empty.txt", "mode": "100644", "type": "blob", "sha": blobSHA}, map[string]any{"path": "removed.txt", "mode": "100644", "type": "blob", "delete": true}}},
			"commit": map[string]any{"sha": commitSHA, "message": "novel commit", "tree": treeSHA, "parents": []any{parentSHA}, "author": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}, "committer": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}},
		},
	}}
	want := []struct{ method, path, sha string }{
		{http.MethodPost, "/repos/yaniv256/private/git/blobs", blobSHA},
		{http.MethodPost, "/repos/yaniv256/private/git/trees", treeSHA},
		{http.MethodPost, "/repos/yaniv256/private/git/commits", commitSHA},
		{http.MethodGet, "/repos/yaniv256/private/git/refs/heads/agent%2Fzara%2Fnew", commitSHA},
		{http.MethodPatch, "/repos/yaniv256/private/git/refs/heads/agent%2Fzara%2Fnew", ""},
	}
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		if calls >= len(want) || got.Method != want[calls].method || got.URL.EscapedPath() != want[calls].path {
			t.Fatalf("call %d = %s %s", calls, got.Method, got.URL.EscapedPath())
		}
		var body map[string]any
		if got.Method != http.MethodGet {
			if err := json.NewDecoder(got.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
		}
		switch calls {
		case 0:
			if body["content"] != "" || body["encoding"] != "base64" {
				t.Fatalf("blob body = %#v", body)
			}
		case 1:
			entries, ok := body["tree"].([]any)
			if !ok || body["base_tree"] != "2222222222222222222222222222222222222222" || len(entries) != 2 || entries[0].(map[string]any)["path"] != "empty.txt" || entries[1].(map[string]any)["path"] != "removed.txt" || entries[1].(map[string]any)["sha"] != nil {
				t.Fatalf("tree body = %#v", body)
			}
		case 2:
			parents, ok := body["parents"].([]any)
			if !ok || len(parents) != 1 || parents[0] != parentSHA || body["tree"] != treeSHA {
				t.Fatalf("commit body = %#v", body)
			}
		case 3:
			io.WriteString(response, `{"ref":"refs/heads/agent/zara/new","object":{"sha":"`+commitSHA+`"}}`)
			calls++
			return
		case 4:
			if body["sha"] != commitSHA || body["force"] != false {
				t.Fatalf("ref body = %#v", body)
			}
		}
		if want[calls].sha == "" {
			io.WriteString(response, `{"ref":"refs/heads/agent/zara/new","object":{"sha":"`+commitSHA+`"}}`)
		} else {
			_ = json.NewEncoder(response).Encode(map[string]string{"sha": want[calls].sha})
		}
		calls++
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	resource, err := client.ExecuteMutation(request, githubapp.AppInstallation, "")
	if err != nil || resource != "refs/heads/agent/zara/new" || calls != len(want) {
		t.Fatalf("resource = %q, calls = %d, err = %v", resource, calls, err)
	}
}

func TestBranchPushCreatesMissingReferenceAfterIndependentAbsentRead(t *testing.T) {
	request := worker.Request{
		Repository: "yaniv256/private",
		Operation:  "branch.push",
		Branch:     "refs/heads/agent/tomas/new",
		Payload:    map[string]any{"sha": "abc123"},
	}
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		calls++
		switch calls {
		case 1, 2:
			if got.Method != http.MethodGet || got.URL.EscapedPath() != "/repos/yaniv256/private/git/refs/heads/agent%2Ftomas%2Fnew" {
				t.Fatalf("reference read = %s %s", got.Method, got.URL.EscapedPath())
			}
			http.NotFound(response, got)
		case 3:
			if got.Method != http.MethodPost || got.URL.EscapedPath() != "/repos/yaniv256/private/git/refs" {
				t.Fatalf("reference create = %s %s", got.Method, got.URL.EscapedPath())
			}
			var body map[string]any
			if err := json.NewDecoder(got.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["ref"] != "refs/heads/agent/tomas/new" || body["sha"] != "abc123" {
				t.Fatalf("reference body = %#v", body)
			}
			io.WriteString(response, `{"ref":"refs/heads/agent/tomas/new","object":{"sha":"abc123"}}`)
		default:
			t.Fatalf("unexpected call %d", calls)
		}
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	result, err := client.ReconcileMutation(request, githubapp.AppInstallation, "")
	if err != nil || result.State != worker.ReconciliationAbsent {
		t.Fatalf("absent result = %#v, err = %v", result, err)
	}
	resource, err := client.ExecuteMutation(request, githubapp.AppInstallation, "")
	if err != nil || resource != "refs/heads/agent/tomas/new" || calls != 3 {
		t.Fatalf("resource = %q, calls = %d, err = %v", resource, calls, err)
	}
}

// emptyRepoPushRequest builds a full-packet branch.push request reusing the
// valid object fixture from the immutable-objects test.
func emptyRepoPushRequest() worker.Request {
	const treeSHA = "1111111111111111111111111111111111111111"
	const commitSHA = "a48bcfdf10f8fd18cac0b6664cf2c662e333e4bd"
	const parentSHA = "3333333333333333333333333333333333333333"
	const blobSHA = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
	return worker.Request{Repository: "yaniv256/brand-new", Operation: "branch.push", Branch: "main", Payload: map[string]any{
		"sha": commitSHA,
		"object_package": map[string]any{
			"blobs":  []any{map[string]any{"sha": blobSHA, "content": "", "encoding": "base64"}},
			"tree":   map[string]any{"sha": treeSHA, "base_tree": "2222222222222222222222222222222222222222", "entries": []any{map[string]any{"path": "empty.txt", "mode": "100644", "type": "blob", "sha": blobSHA}}},
			"commit": map[string]any{"sha": commitSHA, "message": "novel commit", "tree": treeSHA, "parents": []any{parentSHA}, "author": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}, "committer": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}},
		},
	}}
}

func emptyRepo409(response http.ResponseWriter) {
	response.WriteHeader(http.StatusConflict)
	io.WriteString(response, `{"message":"Git Repository is empty.","documentation_url":"https://docs.github.com"}`)
}

// TestBranchPushBootstrapsEmptyRepositoryViaContentsAPI guards the empty-repo
// bootstrap (brand-yaniv, 2026-07-24): GitHub disables the whole git-data API
// on a commitless repo (object POSTs included, all 409 "Git Repository is
// empty"), so the first push must mint a root commit via the contents API,
// re-publish the packet's objects, verify the branch still points at the
// bootstrap commit, and force-move it onto the packet's history.
func TestBranchPushBootstrapsEmptyRepositoryViaContentsAPI(t *testing.T) {
	const commitSHA = "a48bcfdf10f8fd18cac0b6664cf2c662e333e4bd"
	const bootSHA = "b007b007b007b007b007b007b007b007b007b007"
	request := emptyRepoPushRequest()
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		calls++
		path := got.URL.EscapedPath()
		switch calls {
		case 1: // first blob upload hits the disabled git-data API
			if got.Method != http.MethodPost || path != "/repos/yaniv256/brand-new/git/blobs" {
				t.Fatalf("call 1 = %s %s", got.Method, path)
			}
			emptyRepo409(response)
		case 2: // contents-API bootstrap
			if got.Method != http.MethodPut || path != "/repos/yaniv256/brand-new/contents/.gitignore" {
				t.Fatalf("call 2 = %s %s", got.Method, path)
			}
			var body map[string]any
			if err := json.NewDecoder(got.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["branch"] != "main" || body["message"] == "" || body["content"] == "" {
				t.Fatalf("bootstrap body = %#v", body)
			}
			io.WriteString(response, `{"content":{},"commit":{"sha":"`+bootSHA+`"}}`)
		case 3:
			if path != "/repos/yaniv256/brand-new/git/blobs" {
				t.Fatalf("call 3 = %s %s", got.Method, path)
			}
			io.WriteString(response, `{"sha":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"}`)
		case 4:
			if path != "/repos/yaniv256/brand-new/git/trees" {
				t.Fatalf("call 4 = %s %s", got.Method, path)
			}
			io.WriteString(response, `{"sha":"1111111111111111111111111111111111111111"}`)
		case 5:
			if path != "/repos/yaniv256/brand-new/git/commits" {
				t.Fatalf("call 5 = %s %s", got.Method, path)
			}
			io.WriteString(response, `{"sha":"`+commitSHA+`"}`)
		case 6: // precondition read: branch must still be at the bootstrap commit
			if got.Method != http.MethodGet || path != "/repos/yaniv256/brand-new/git/refs/heads/main" {
				t.Fatalf("call 6 = %s %s", got.Method, path)
			}
			io.WriteString(response, `{"ref":"refs/heads/main","object":{"sha":"`+bootSHA+`"}}`)
		case 7: // force-move onto the packet's history
			if got.Method != http.MethodPatch || path != "/repos/yaniv256/brand-new/git/refs/heads/main" {
				t.Fatalf("call 7 = %s %s", got.Method, path)
			}
			var body map[string]any
			if err := json.NewDecoder(got.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["sha"] != commitSHA || body["force"] != true {
				t.Fatalf("force-move body = %#v", body)
			}
			io.WriteString(response, `{"ref":"refs/heads/main","object":{"sha":"`+commitSHA+`"}}`)
		default:
			t.Fatalf("unexpected call %d: %s %s", calls, got.Method, path)
		}
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	resource, err := client.ExecuteMutation(request, githubapp.AppInstallation, "")
	if err != nil || resource != "refs/heads/main" || calls != 7 {
		t.Fatalf("resource = %q, calls = %d, err = %v", resource, calls, err)
	}
}

// If the branch moved off the bootstrap commit before the force-move, someone
// else pushed — the bootstrap must refuse rather than clobber their history.
func TestBranchPushBootstrapRefusesForceMoveWhenBranchMoved(t *testing.T) {
	request := emptyRepoPushRequest()
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		calls++
		path := got.URL.EscapedPath()
		switch {
		case calls == 1:
			emptyRepo409(response)
		case calls == 2:
			io.WriteString(response, `{"content":{},"commit":{"sha":"b007b007b007b007b007b007b007b007b007b007"}}`)
		case path == "/repos/yaniv256/brand-new/git/blobs":
			io.WriteString(response, `{"sha":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"}`)
		case path == "/repos/yaniv256/brand-new/git/trees":
			io.WriteString(response, `{"sha":"1111111111111111111111111111111111111111"}`)
		case path == "/repos/yaniv256/brand-new/git/commits":
			io.WriteString(response, `{"sha":"a48bcfdf10f8fd18cac0b6664cf2c662e333e4bd"}`)
		case got.Method == http.MethodGet && path == "/repos/yaniv256/brand-new/git/refs/heads/main":
			io.WriteString(response, `{"ref":"refs/heads/main","object":{"sha":"someoneelse00000000000000000000000000000"}}`)
		default:
			t.Fatalf("unexpected call %d: %s %s (force-move must not run)", calls, got.Method, path)
		}
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err == nil || !strings.Contains(err.Error(), "refusing to force-move") {
		t.Fatalf("err = %v, want force-move refusal", err)
	}
}

// A ref-only push (no object package) against an empty repository has nothing
// to bootstrap from and must fail rather than invent content.
func TestBranchPushWithoutPacketOnEmptyRepositoryFails(t *testing.T) {
	request := worker.Request{
		Repository: "yaniv256/brand-new",
		Operation:  "branch.push",
		Branch:     "main",
		Payload:    map[string]any{"sha": "abc123"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		emptyRepo409(response)
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err == nil {
		t.Fatal("expected packetless push on empty repository to fail")
	}
}

// A 409 that is NOT the empty-repository answer must stay a hard error — the
// sentinel must not swallow real conflicts.
func TestBranchPushOtherConflictOnRefReadStaysFatal(t *testing.T) {
	request := worker.Request{
		Repository: "yaniv256/brand-new",
		Operation:  "branch.push",
		Branch:     "main",
		Payload:    map[string]any{"sha": "abc123"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		response.WriteHeader(http.StatusConflict)
		io.WriteString(response, `{"message":"merge conflict"}`)
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err == nil {
		t.Fatal("expected a non-empty-repo 409 to stay fatal")
	}
}

func TestBranchPushRejectsAmbiguousQualifiedRefBeforeGitHubCall(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	request := worker.Request{
		Repository: "yaniv256/private",
		Operation:  "branch.push",
		Branch:     "refs/heads/refs/heads/main",
		Payload:    map[string]any{"sha": "abc123"},
	}
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err == nil {
		t.Fatal("ambiguous qualified ref was accepted")
	}
	if calls != 0 {
		t.Fatalf("ambiguous qualified ref made %d GitHub calls", calls)
	}
}

func TestApprovedPrivateOperationAdaptersUseExactGitHubEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		request    worker.Request
		method     string
		path       string
		response   string
		resourceID string
	}{
		{"branch push", worker.Request{Repository: "yaniv256/private", Operation: "branch.push", Branch: "agent/zara/change", Payload: map[string]any{"sha": "abc123"}}, http.MethodPatch, "/repos/yaniv256/private/git/refs/heads/agent%2Fzara%2Fchange", `{"ref":"refs/heads/agent/zara/change","object":{"sha":"abc123"}}`, "refs/heads/agent/zara/change"},
		{"policy promote", worker.Request{Repository: "yaniv256/private", Operation: "policy.promote", Branch: "main", Payload: map[string]any{"sha": "abc123"}}, http.MethodPatch, "/repos/yaniv256/private/git/refs/heads/main", `{"ref":"refs/heads/main","object":{"sha":"abc123"}}`, "refs/heads/main"},
		{"pull request update", worker.Request{Repository: "yaniv256/private", Operation: "pull_request.update", Title: "Updated", Body: "Body", Payload: map[string]any{"number": float64(7)}}, http.MethodPatch, "/repos/yaniv256/private/pulls/7", `{"number":7,"html_url":"https://github.test/pull/7","title":"Updated","body":"Body"}`, "https://github.test/pull/7"},
		{"pull request review", worker.Request{RequestID: "review-1", Repository: "yaniv256/private", Operation: "pull_request.review", Body: "Review\n\n<!-- gitoversight-request:review-1 -->\n\n— Zara", Payload: map[string]any{"number": float64(7), "event": "APPROVE", "head_sha": "abc123"}}, http.MethodPost, "/repos/yaniv256/private/pulls/7/reviews", `{"id":81,"body":"Review\n\n<!-- gitoversight-request:review-1 -->\n\n— Zara","commit_id":"abc123"}`, "review:81"},
		{"pull request reply", worker.Request{RequestID: "reply-1", Repository: "yaniv256/private", Operation: "pull_request.reply", Body: "Reply\n\n<!-- gitoversight-request:reply-1 -->\n\n— Zara", Payload: map[string]any{"number": float64(7)}}, http.MethodPost, "/repos/yaniv256/private/issues/7/comments", `{"id":91,"html_url":"https://github.test/comment/91","body":"Reply\n\n<!-- gitoversight-request:reply-1 -->\n\n— Zara"}`, "https://github.test/comment/91"},
		{"pull request merge", worker.Request{Repository: "yaniv256/private", Operation: "pull_request.merge", Title: "Squashed", Body: "Message", Payload: map[string]any{"number": float64(7), "merge_method": "squash", "head_sha": "abc123"}}, http.MethodPut, "/repos/yaniv256/private/pulls/7/merge", `{"sha":"merge123","merged":true,"message":"merged"}`, "merge123"},
		{"issue create", worker.Request{RequestID: "issue-1", Repository: "yaniv256/private", Operation: "issue.create", Title: "Issue", Body: "Body\n<!-- gitoversight-request:issue-1 -->"}, http.MethodPost, "/repos/yaniv256/private/issues", `{"number":12,"html_url":"https://github.test/issues/12","title":"Issue","body":"Body\n<!-- gitoversight-request:issue-1 -->"}`, "https://github.test/issues/12"},
		{"issue comment", worker.Request{RequestID: "comment-1", Repository: "yaniv256/private", Operation: "issue.comment", Body: "Body\n<!-- gitoversight-request:comment-1 -->\n\n— Zara", Payload: map[string]any{"number": float64(12)}}, http.MethodPost, "/repos/yaniv256/private/issues/12/comments", `{"id":92,"html_url":"https://github.test/comment/92","body":"Body\n<!-- gitoversight-request:comment-1 -->\n\n— Zara"}`, "https://github.test/comment/92"},
		{"release publish", worker.Request{Repository: "yaniv256/private", Operation: "release.publish", Title: "Version 1", Body: "Notes", Payload: map[string]any{"tag_name": "v1.0.0", "target_commitish": "abc123", "prerelease": false}}, http.MethodPost, "/repos/yaniv256/private/releases", `{"id":5,"html_url":"https://github.test/releases/v1.0.0","tag_name":"v1.0.0","target_commitish":"abc123","name":"Version 1","body":"Notes","draft":false,"prerelease":false}`, "https://github.test/releases/v1.0.0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if test.name == "branch push" && request.Method == http.MethodGet && request.URL.EscapedPath() == test.path {
					io.WriteString(response, test.response)
					return
				}
				if request.Method != test.method || request.URL.EscapedPath() != test.path {
					t.Fatalf("request = %s %s", request.Method, request.URL.EscapedPath())
				}
				if request.Header.Get("Authorization") != "Bearer installation-token" {
					t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
				}
				io.WriteString(response, test.response)
			}))
			defer server.Close()
			client := operationClient(t, server, "private")
			resourceID, err := client.ExecuteMutation(test.request, githubapp.AppInstallation, "")
			if err != nil || resourceID != test.resourceID {
				t.Fatalf("resource = %q, err = %v", resourceID, err)
			}
		})
	}
}

func TestApprovedOperationAdaptersReconcileThroughIndependentReads(t *testing.T) {
	tests := []struct {
		name     string
		request  worker.Request
		path     string
		response string
	}{
		{"branch push", worker.Request{Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature", Payload: map[string]any{"sha": "abc123"}}, "/repos/yaniv256/private/git/refs/heads/feature", `{"ref":"refs/heads/feature","object":{"sha":"abc123"}}`},
		{"policy promote", worker.Request{Repository: "yaniv256/private", Operation: "policy.promote", Branch: "main", Payload: map[string]any{"sha": "abc123"}}, "/repos/yaniv256/private/git/refs/heads/main", `{"ref":"refs/heads/main","object":{"sha":"abc123"}}`},
		{"pull request update", worker.Request{Repository: "yaniv256/private", Operation: "pull_request.update", Title: "Updated", Body: "Body", Payload: map[string]any{"number": float64(7)}}, "/repos/yaniv256/private/pulls/7", `{"number":7,"title":"Updated","body":"Body"}`},
		{"pull request review", worker.Request{RequestID: "review-1", Repository: "yaniv256/private", Operation: "pull_request.review", Body: "Review\n\n<!-- gitoversight-request:review-1 -->\n\n— Zara", Payload: map[string]any{"number": float64(7), "head_sha": "abc123"}}, "/repos/yaniv256/private/pulls/7/reviews?per_page=100", `[{"id":81,"body":"Review\n\n<!-- gitoversight-request:review-1 -->\n\n— Zara","commit_id":"abc123"}]`},
		{"pull request reply", worker.Request{RequestID: "reply-1", Repository: "yaniv256/private", Operation: "pull_request.reply", Body: "Reply\n\n<!-- gitoversight-request:reply-1 -->\n\n— Zara", Payload: map[string]any{"number": float64(7)}}, "/repos/yaniv256/private/issues/7/comments?per_page=100", `[{"id":91,"body":"Reply\n\n<!-- gitoversight-request:reply-1 -->\n\n— Zara"}]`},
		{"pull request merge", worker.Request{Repository: "yaniv256/private", Operation: "pull_request.merge", Payload: map[string]any{"number": float64(7)}}, "/repos/yaniv256/private/pulls/7", `{"number":7,"merged":true,"merge_commit_sha":"merge123"}`},
		{"issue create", worker.Request{RequestID: "issue-1", Repository: "yaniv256/private", Operation: "issue.create", Title: "Issue", Body: "Body\n<!-- gitoversight-request:issue-1 -->"}, "/repos/yaniv256/private/issues?state=all&per_page=100", `[{"number":12,"title":"Issue","body":"Body\n<!-- gitoversight-request:issue-1 -->"}]`},
		{"issue comment", worker.Request{RequestID: "comment-1", Repository: "yaniv256/private", Operation: "issue.comment", Body: "Body\n<!-- gitoversight-request:comment-1 -->\n\n— Zara", Payload: map[string]any{"number": float64(12)}}, "/repos/yaniv256/private/issues/12/comments?per_page=100", `[{"id":92,"body":"Body\n<!-- gitoversight-request:comment-1 -->\n\n— Zara"}]`},
		{"release publish", worker.Request{Repository: "yaniv256/private", Operation: "release.publish", Title: "Version 1", Body: "Notes", Payload: map[string]any{"tag_name": "v1.0.0", "target_commitish": "abc123", "prerelease": false}}, "/repos/yaniv256/private/releases/tags/v1.0.0", `{"id":5,"tag_name":"v1.0.0","target_commitish":"abc123","name":"Version 1","body":"Notes","draft":false,"prerelease":false}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				path := request.URL.EscapedPath()
				if request.URL.RawQuery != "" {
					path += "?" + request.URL.RawQuery
				}
				if request.Method != http.MethodGet || path != test.path {
					t.Fatalf("request = %s %s", request.Method, path)
				}
				io.WriteString(response, test.response)
			}))
			defer server.Close()
			client := operationClient(t, server, "private")
			result, err := client.ReconcileMutation(test.request, githubapp.AppInstallation, "")
			if err != nil || result.State != worker.ReconciliationCommitted {
				t.Fatalf("result = %#v, err = %v", result, err)
			}
		})
	}
}

func TestEveryOperationAdapterReconcilesAbsentAndIndeterminate(t *testing.T) {
	tests := []struct {
		name     string
		request  worker.Request
		path     string
		response string
		mode     githubapp.TokenMode
		subject  string
	}{
		{"branch push", worker.Request{Repository: "yaniv256/private", Operation: "branch.push", Branch: "feature", Payload: map[string]any{"sha": "abc123"}}, "/repos/yaniv256/private/git/refs/heads/feature", `{"ref":"refs/heads/feature","object":{"sha":"different"}}`, githubapp.AppInstallation, ""},
		{"policy promote", worker.Request{Repository: "yaniv256/private", Operation: "policy.promote", Branch: "main", Payload: map[string]any{"sha": "abc123"}}, "/repos/yaniv256/private/git/refs/heads/main", `{"ref":"refs/heads/main","object":{"sha":"different"}}`, githubapp.AppInstallation, ""},
		{"pull request update", worker.Request{Repository: "yaniv256/private", Operation: "pull_request.update", Title: "Updated", Body: "Body", Payload: map[string]any{"number": float64(7)}}, "/repos/yaniv256/private/pulls/7", `{"number":7,"title":"Old","body":"Body"}`, githubapp.AppInstallation, ""},
		{"pull request review", worker.Request{RequestID: "review-1", Repository: "yaniv256/private", Operation: "pull_request.review", Body: "Review\n\n<!-- gitoversight-request:review-1 -->\n\n— Zara", Payload: map[string]any{"number": float64(7), "head_sha": "abc123"}}, "/repos/yaniv256/private/pulls/7/reviews?per_page=100", `[]`, githubapp.AppInstallation, ""},
		{"pull request reply", worker.Request{RequestID: "reply-1", Repository: "yaniv256/private", Operation: "pull_request.reply", Body: "Reply\n\n<!-- gitoversight-request:reply-1 -->\n\n— Zara", Payload: map[string]any{"number": float64(7)}}, "/repos/yaniv256/private/issues/7/comments?per_page=100", `[]`, githubapp.AppInstallation, ""},
		{"pull request merge", worker.Request{Repository: "yaniv256/private", Operation: "pull_request.merge", Payload: map[string]any{"number": float64(7)}}, "/repos/yaniv256/private/pulls/7", `{"number":7,"merged":false}`, githubapp.AppInstallation, ""},
		{"issue create", worker.Request{RequestID: "issue-1", Repository: "yaniv256/private", Operation: "issue.create", Title: "Issue", Body: "Body\n<!-- gitoversight-request:issue-1 -->"}, "/repos/yaniv256/private/issues?state=all&per_page=100", `[]`, githubapp.AppInstallation, ""},
		{"issue comment", worker.Request{RequestID: "comment-1", Repository: "yaniv256/private", Operation: "issue.comment", Body: "Body\n<!-- gitoversight-request:comment-1 -->\n\n— Zara", Payload: map[string]any{"number": float64(12)}}, "/repos/yaniv256/private/issues/12/comments?per_page=100", `[]`, githubapp.AppInstallation, ""},
		{"release publish", worker.Request{Repository: "yaniv256/private", Operation: "release.publish", Title: "Version 1", Body: "Notes", Payload: map[string]any{"tag_name": "v1.0.0", "target_commitish": "abc123", "prerelease": false}}, "/repos/yaniv256/private/releases/tags/v1.0.0", `{"id":5,"tag_name":"v1.0.0","target_commitish":"different","name":"Version 1","body":"Notes","draft":false,"prerelease":false}`, githubapp.AppInstallation, ""},
		{"repository create", worker.Request{Repository: "yaniv256/new-private", Operation: "repository.create", Payload: map[string]any{"visibility": "private"}}, "/repos/yaniv256/new-private", `{"full_name":"yaniv256/new-private","private":false,"visibility":"public"}`, githubapp.HumanUser, "yaniv256"},
		{"repository settings", worker.Request{Repository: "yaniv256/private", Operation: "repository.settings.update", Payload: map[string]any{"settings": map[string]any{"allow_squash_merge": true}}}, "/repos/yaniv256/private", `{"full_name":"yaniv256/private","visibility":"private","allow_squash_merge":false}`, githubapp.AppInstallation, ""},
	}

	for _, test := range tests {
		t.Run(test.name+" absent", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				path := request.URL.EscapedPath()
				if request.URL.RawQuery != "" {
					path += "?" + request.URL.RawQuery
				}
				if request.Method != http.MethodGet || path != test.path {
					t.Fatalf("request = %s %s", request.Method, path)
				}
				io.WriteString(response, test.response)
			}))
			defer server.Close()
			client := operationClient(t, server, "private")
			result, err := client.ReconcileMutation(test.request, test.mode, test.subject)
			if err != nil || result.State != worker.ReconciliationAbsent {
				t.Fatalf("result = %#v, err = %v", result, err)
			}
		})

		t.Run(test.name+" indeterminate", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				http.Error(response, "read unavailable", http.StatusServiceUnavailable)
			}))
			defer server.Close()
			client := operationClient(t, server, "private")
			result, err := client.ReconcileMutation(test.request, test.mode, test.subject)
			if err == nil || result.State != worker.ReconciliationUnknown {
				t.Fatalf("result = %#v, err = %v", result, err)
			}
		})
	}
}

func TestEveryPublicOperationAdapterRequiresHumanSubject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("public mutation reached GitHub without human authority")
	}))
	defer server.Close()
	client := operationClient(t, server, "public")
	requests := []worker.Request{
		{Repository: "yaniv256/public", Operation: "branch.push", Branch: "export", Payload: map[string]any{"sha": "abc123"}},
		{Repository: "yaniv256/public", Operation: "pull_request.update", Title: "Title", Payload: map[string]any{"number": float64(1)}},
		{RequestID: "review-1", Repository: "yaniv256/public", Operation: "pull_request.review", Body: "Body\n<!-- gitoversight-request:review-1 -->", Payload: map[string]any{"number": float64(1), "event": "APPROVE"}},
		{RequestID: "reply-1", Repository: "yaniv256/public", Operation: "pull_request.reply", Body: "Body\n<!-- gitoversight-request:reply-1 -->", Payload: map[string]any{"number": float64(1)}},
		{Repository: "yaniv256/public", Operation: "pull_request.merge", Payload: map[string]any{"number": float64(1), "merge_method": "squash"}},
		{RequestID: "issue-1", Repository: "yaniv256/public", Operation: "issue.create", Title: "Issue", Body: "Body\n<!-- gitoversight-request:issue-1 -->"},
		{RequestID: "comment-1", Repository: "yaniv256/public", Operation: "issue.comment", Body: "Body\n<!-- gitoversight-request:comment-1 -->", Payload: map[string]any{"number": float64(1)}},
		{Repository: "yaniv256/public", Operation: "release.publish", Title: "Version 1", Payload: map[string]any{"tag_name": "v1.0.0", "target_commitish": "abc123", "prerelease": false}},
	}
	for _, request := range requests {
		if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); !errors.Is(err, githubapp.ErrHumanTokenRequired) {
			t.Fatalf("%s error = %v", request.Operation, err)
		}
	}
}

func TestRepeatableDiscussionOperationsRequireUniqueReconciliationMarker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unreconcilable discussion reached GitHub")
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	for _, request := range []worker.Request{
		{RequestID: "review-1", Repository: "yaniv256/private", Operation: "pull_request.review", Body: "No marker\n\n— Zara", Payload: map[string]any{"number": float64(1), "event": "APPROVE", "head_sha": "abc123"}},
		{RequestID: "reply-1", Repository: "yaniv256/private", Operation: "pull_request.reply", Body: "No marker\n\n— Zara", Payload: map[string]any{"number": float64(1)}},
		{RequestID: "issue-1", Repository: "yaniv256/private", Operation: "issue.create", Title: "Issue", Body: "No marker"},
		{RequestID: "comment-1", Repository: "yaniv256/private", Operation: "issue.comment", Body: "No marker\n\n— Zara", Payload: map[string]any{"number": float64(1)}},
	} {
		if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err == nil {
			t.Fatalf("%s accepted without marker", request.Operation)
		}
	}
}

func TestRepositoryCreationRequiresExactHumanOwnerAndReconciles(t *testing.T) {
	// The subject is a governance human id ("yaniv"); the namespace binding is
	// proven by asking GitHub who the credential is (login yaniv256), never by
	// comparing the subject string to the namespace.
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		switch calls {
		case 1:
			if request.Method != http.MethodGet || request.URL.Path != "/user" {
				t.Fatalf("identity request = %s %s", request.Method, request.URL.Path)
			}
			io.WriteString(response, `{"login":"yaniv256"}`)
		case 2:
			if request.Method != http.MethodPost || request.URL.Path != "/user/repos" {
				t.Fatalf("create request = %s %s", request.Method, request.URL.Path)
			}
			io.WriteString(response, `{"full_name":"yaniv256/new-private","html_url":"https://github.test/yaniv256/new-private","private":true,"visibility":"private"}`)
		case 3:
			if request.Method != http.MethodGet || request.URL.Path != "/repos/yaniv256/new-private" {
				t.Fatalf("read request = %s %s", request.Method, request.URL.Path)
			}
			io.WriteString(response, `{"full_name":"yaniv256/new-private","private":true,"visibility":"private"}`)
		}
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	request := worker.Request{Repository: "yaniv256/new-private", Operation: "repository.create", Payload: map[string]any{"visibility": "private", "description": "Review twin"}}
	if _, err := client.ExecuteMutation(request, githubapp.HumanUser, "yaniv"); err != nil {
		t.Fatal(err)
	}
	result, err := client.ReconcileMutation(request, githubapp.HumanUser, "yaniv")
	if err != nil || result.State != worker.ReconciliationCommitted {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err == nil {
		t.Fatal("installation token created a personal repository")
	}
}

func TestRepositoryCreationRejectsCredentialThatDoesNotOwnNamespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/user" {
			t.Fatalf("unexpected write reached GitHub: %s %s", request.Method, request.URL.Path)
		}
		io.WriteString(response, `{"login":"somebody-else"}`)
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	request := worker.Request{Repository: "yaniv256/new-private", Operation: "repository.create", Payload: map[string]any{"visibility": "private"}}
	if _, err := client.ExecuteMutation(request, githubapp.HumanUser, "yaniv"); err == nil || !strings.Contains(err.Error(), "does not own the target namespace") {
		t.Fatalf("mismatched credential accepted: %v", err)
	}
}

func TestRepositoryCreateDerivesVisibilityFromPayloadNotResolver(t *testing.T) {
	// The target repository does not exist yet, so no resolver can know it. A
	// failing resolver must not block the create; every other operation still
	// requires the resolver to answer.
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		if request.URL.Path == "/user" {
			io.WriteString(response, `{"login":"yaniv256"}`)
			return
		}
		io.WriteString(response, `{"full_name":"yaniv256/unknown-to-resolver","private":true,"visibility":"private"}`)
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	client, err := githubapp.New(server.URL, httpClient, func(githubapp.TokenMode, string) (string, error) {
		return "user-token", nil
	}, func(string) (string, error) {
		return "", errors.New("repository visibility unavailable")
	})
	if err != nil {
		t.Fatal(err)
	}
	request := worker.Request{Repository: "yaniv256/unknown-to-resolver", Operation: "repository.create", Payload: map[string]any{"visibility": "private"}}
	if _, err := client.ExecuteMutation(request, githubapp.HumanUser, "yaniv"); err != nil {
		t.Fatalf("resolver failure blocked repository.create: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d (want identity read + create)", calls)
	}
	push := worker.Request{Repository: "yaniv256/unknown-to-resolver", Operation: "branch.push", Branch: "main", Payload: map[string]any{"sha": "abc123"}}
	if _, err := client.ExecuteMutation(push, githubapp.HumanUser, "yaniv"); err == nil || err.Error() != "repository visibility unavailable" {
		t.Fatalf("non-create op bypassed the resolver: %v", err)
	}
	missing := worker.Request{Repository: "yaniv256/unknown-to-resolver", Operation: "repository.create", Payload: map[string]any{}}
	if _, err := client.ExecuteMutation(missing, githubapp.HumanUser, "yaniv"); err == nil || err.Error() != "repository visibility unavailable" {
		t.Fatalf("create without declared visibility accepted: %v", err)
	}
}

func TestRepositorySettingsUseStrictAllowlistAndHumanGateForPublicVisibility(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPatch || request.URL.Path != "/repos/yaniv256/private" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		io.WriteString(response, `{"full_name":"yaniv256/private","visibility":"private","allow_squash_merge":true,"delete_branch_on_merge":true}`)
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	request := worker.Request{Repository: "yaniv256/private", Operation: "repository.settings.update", Payload: map[string]any{"settings": map[string]any{"allow_squash_merge": true, "delete_branch_on_merge": true}}}
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err != nil {
		t.Fatal(err)
	}
	request.Payload = map[string]any{"settings": map[string]any{"visibility": "public"}}
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); !errors.Is(err, githubapp.ErrHumanTokenRequired) {
		t.Fatalf("visibility error = %v", err)
	}
	request.Payload = map[string]any{"settings": map[string]any{"delete_branch_on_merge": "yes"}}
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err == nil {
		t.Fatal("invalid setting type accepted")
	}
}

func TestInstallationRepositoryAddUsesExactHumanInstallationAndReconciles(t *testing.T) {
	request := worker.Request{
		Repository: "yaniv256/private",
		Operation:  "installation.repository.add",
		Payload:    map[string]any{"installation_id": float64(42)},
	}
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		calls++
		if got.Header.Get("Authorization") != "Bearer human-token" {
			t.Fatalf("authorization = %q", got.Header.Get("Authorization"))
		}
		switch calls {
		case 1:
			if got.Method != http.MethodGet || got.URL.EscapedPath() != "/repos/yaniv256/private" {
				t.Fatalf("repository identity request = %s %s", got.Method, got.URL.EscapedPath())
			}
			io.WriteString(response, `{"id":99,"full_name":"yaniv256/private","private":true}`)
		case 2:
			if got.Method != http.MethodPut || got.URL.EscapedPath() != "/user/installations/42/repositories/99" {
				t.Fatalf("installation add request = %s %s", got.Method, got.URL.EscapedPath())
			}
			response.WriteHeader(http.StatusNoContent)
		case 3:
			if got.Method != http.MethodGet || got.URL.RequestURI() != "/user/installations/42/repositories?per_page=100" {
				t.Fatalf("installation reconciliation request = %s %s", got.Method, got.URL.RequestURI())
			}
			io.WriteString(response, `{"repositories":[{"id":99,"full_name":"yaniv256/private","private":true}]}`)
		default:
			t.Fatalf("unexpected call %d", calls)
		}
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	client, err := githubapp.New(server.URL, httpClient, func(mode githubapp.TokenMode, subject string) (string, error) {
		if mode != githubapp.HumanUser || subject != "yaniv256" {
			t.Fatalf("actor = %s %q", mode, subject)
		}
		return "human-token", nil
	}, func(string) (string, error) { return "private", nil })
	if err != nil {
		t.Fatal(err)
	}
	resource, err := client.ExecuteMutation(request, githubapp.HumanUser, "yaniv256")
	if err != nil || resource != "installation:42/repository:99" {
		t.Fatalf("resource = %q, err = %v", resource, err)
	}
	result, err := client.ReconcileMutation(request, githubapp.HumanUser, "yaniv256")
	if err != nil || result.State != worker.ReconciliationCommitted || result.ResourceID != resource || calls != 3 {
		t.Fatalf("result = %#v, calls = %d, err = %v", result, calls, err)
	}
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); !errors.Is(err, githubapp.ErrHumanTokenRequired) {
		t.Fatalf("installation actor error = %v", err)
	}
}

func operationClient(t *testing.T, server *httptest.Server, visibility string) *githubapp.Client {
	t.Helper()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	client, err := githubapp.New(server.URL, httpClient, func(githubapp.TokenMode, string) (string, error) {
		return "installation-token", nil
	}, func(string) (string, error) {
		return visibility, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// A root commit whose packet left parents nil must reach GitHub as [] — JSON
// null draws a 422 'properties/parents, nil is not an array'.
func TestPublishCommitObjectsSerializesNilParentsAsEmptyArray(t *testing.T) {
	const treeSHA = "1111111111111111111111111111111111111111"
	const commitSHA = "5557dfea0c12ec2afea282dfcef4447aef1c38ee"
	const blobSHA = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
	request := worker.Request{Repository: "yaniv256/private", Operation: "branch.push", Branch: "agent/zara/root", Payload: map[string]any{
		"sha": commitSHA,
		"object_package": map[string]any{
			"blobs":  []any{map[string]any{"sha": blobSHA, "content": "", "encoding": "base64"}},
			"tree":   map[string]any{"sha": treeSHA, "entries": []any{map[string]any{"path": "empty.txt", "mode": "100644", "type": "blob", "sha": blobSHA}}},
			"commit": map[string]any{"sha": commitSHA, "message": "novel", "tree": treeSHA, "author": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}, "committer": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}},
		},
	}}
	var sawParents any = "unset"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		switch got.URL.EscapedPath() {
		case "/repos/yaniv256/private/git/blobs":
			io.WriteString(response, "{\"sha\":\""+blobSHA+"\"}")
		case "/repos/yaniv256/private/git/trees":
			io.WriteString(response, "{\"sha\":\""+treeSHA+"\"}")
		case "/repos/yaniv256/private/git/commits":
			var body map[string]any
			if err := json.NewDecoder(got.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			sawParents = body["parents"]
			io.WriteString(response, "{\"sha\":\""+commitSHA+"\"}")
		case "/repos/yaniv256/private/git/refs/heads/agent%2Fzara%2Froot":
			io.WriteString(response, "{\"ref\":\"refs/heads/agent/zara/root\",\"object\":{\"sha\":\""+commitSHA+"\"}}")
		default:
			t.Fatalf("unexpected request: %s %s", got.Method, got.URL.EscapedPath())
		}
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err != nil {
		t.Fatalf("execute: %v", err)
	}
	arr, ok := sawParents.([]any)
	if !ok || len(arr) != 0 {
		t.Fatalf("parents reached GitHub as %#v, want empty array", sawParents)
	}
}
func TestReleaseAssetUploadExecutesAndReconcilesExactBytes(t *testing.T) {
	content := []byte("immutable release bytes")
	digest := sha256.Sum256(content)
	request := worker.Request{Repository: "yaniv256/private", Operation: "release.asset.upload", Payload: map[string]any{
		"tag_name": "v1.0.0", "name": "runtime.zip", "content_type": "application/zip",
		"content_base64": base64.StdEncoding.EncodeToString(content), "sha256": fmt.Sprintf("%x", digest), "size": float64(len(content)),
	}}
	var server *httptest.Server
	var uploaded bool
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		switch {
		case got.Method == http.MethodGet && got.URL.EscapedPath() == "/repos/yaniv256/private/releases/tags/v1.0.0":
			assets := "[]"
			if uploaded {
				assets = fmt.Sprintf(`[{"id":7,"name":"runtime.zip","size":%d,"url":%q,"browser_download_url":"https://github.test/runtime.zip"}]`, len(content), server.URL+"/assets/7")
			}
			fmt.Fprintf(response, `{"id":5,"upload_url":%q,"assets":%s}`, server.URL+"/uploads{?name,label}", assets)
		case got.Method == http.MethodPost && got.URL.EscapedPath() == "/uploads":
			if got.URL.Query().Get("name") != "runtime.zip" || got.Header.Get("Content-Type") != "application/zip" {
				t.Fatalf("upload metadata = %s %q", got.URL.RawQuery, got.Header.Get("Content-Type"))
			}
			body, _ := io.ReadAll(got.Body)
			if string(body) != string(content) {
				t.Fatalf("upload body = %q", body)
			}
			uploaded = true
			fmt.Fprintf(response, `{"id":7,"name":"runtime.zip","size":%d,"url":%q,"browser_download_url":"https://github.test/runtime.zip"}`, len(content), server.URL+"/assets/7")
		case got.Method == http.MethodGet && got.URL.EscapedPath() == "/assets/7":
			if got.Header.Get("Accept") != "application/octet-stream" {
				t.Fatalf("asset accept = %q", got.Header.Get("Accept"))
			}
			response.Write(content)
		default:
			t.Fatalf("unexpected request: %s %s", got.Method, got.URL.String())
		}
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	resource, err := client.ExecuteMutation(request, githubapp.AppInstallation, "")
	if err != nil || resource != "https://github.test/runtime.zip" {
		t.Fatalf("resource = %q, err = %v", resource, err)
	}
	result, err := client.ReconcileMutation(request, githubapp.AppInstallation, "")
	if err != nil || result.State != worker.ReconciliationCommitted || result.ResourceID != "https://github.test/runtime.zip" {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
}
func TestReleaseAssetUploadRejectsTamperedBytesAndUntrustedUploadHost(t *testing.T) {
	tampered := worker.Request{Repository: "yaniv256/private", Operation: "release.asset.upload", Payload: map[string]any{
		"tag_name": "v1", "name": "asset.zip", "content_type": "application/zip", "content_base64": "dGFtcGVyZWQ=",
		"sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "size": float64(8),
	}}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		io.WriteString(response, `{"id":5,"upload_url":"http://attacker.invalid/uploads{?name,label}"}`)
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	if _, err := client.ExecuteMutation(tampered, githubapp.AppInstallation, ""); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tampered packet error = %v", err)
	}
	content := []byte("hello")
	digest := sha256.Sum256(content)
	tampered.Payload["content_base64"] = base64.StdEncoding.EncodeToString(content)
	tampered.Payload["size"] = float64(len(content))
	tampered.Payload["sha256"] = fmt.Sprintf("%x", digest)
	if _, err := client.ExecuteMutation(tampered, githubapp.AppInstallation, ""); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("untrusted upload URL error = %v", err)
	}
}

// GitHub's SECONDARY rate limit is an anti-burst control, not the hourly quota.
// It arrives as a 403 with a distinctive body — not a 429 — so status alone
// cannot identify it, and it clears in minutes. Publishing uploads one blob per
// request, so any sizeable tree is a burst: the first public sync of this
// repository (302 files) tripped it partway through on 2026-07-27.
//
// Before this, the loop had no backoff, so one throttled request failed the
// whole publication. Yaniv had already approved; from his side the button
// simply stopped responding while nginx logged a 499. A transient condition
// became a dead approval.
//
// Retrying a blob upload is safe: git objects are content-addressed, so
// uploading the same blob twice yields the same object.
func TestBlobUploadRetriesThroughGitHubSecondaryRateLimit(t *testing.T) {
	const treeSHA = "1111111111111111111111111111111111111111"
	const commitSHA = "a48bcfdf10f8fd18cac0b6664cf2c662e333e4bd"
	const parentSHA = "3333333333333333333333333333333333333333"
	const blobSHA = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
	request := worker.Request{Repository: "yaniv256/private", Operation: "branch.push", Branch: "agent/zara/new", Payload: map[string]any{
		"sha": commitSHA,
		"object_package": map[string]any{
			"blobs":  []any{map[string]any{"sha": blobSHA, "content": "", "encoding": "base64"}},
			"tree":   map[string]any{"sha": treeSHA, "base_tree": "2222222222222222222222222222222222222222", "entries": []any{map[string]any{"path": "empty.txt", "mode": "100644", "type": "blob", "sha": blobSHA}, map[string]any{"path": "removed.txt", "mode": "100644", "type": "blob", "delete": true}}},
			"commit": map[string]any{"sha": commitSHA, "message": "novel commit", "tree": treeSHA, "parents": []any{parentSHA}, "author": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}, "committer": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}},
		},
	}}
	var blobAttempts int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
		switch got.URL.EscapedPath() {
		case "/repos/yaniv256/private/git/blobs":
			blobAttempts++
			// Throttle the first two attempts exactly as GitHub does.
			if blobAttempts <= 2 {
				response.WriteHeader(http.StatusForbidden)
				io.WriteString(response, `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`)
				return
			}
			io.WriteString(response, `{"sha":"`+blobSHA+`"}`)
		case "/repos/yaniv256/private/git/trees":
			io.WriteString(response, `{"sha":"`+treeSHA+`"}`)
		case "/repos/yaniv256/private/git/commits":
			io.WriteString(response, `{"sha":"`+commitSHA+`"}`)
		case "/repos/yaniv256/private/git/refs/heads/agent%2Fzara%2Fnew":
			io.WriteString(response, `{"ref":"refs/heads/agent/zara/new","object":{"sha":"`+parentSHA+`"}}`)
		default:
			io.WriteString(response, `{}`)
		}
	}))
	defer server.Close()
	client := operationClient(t, server, "private")
	// Do not actually wait out the backoff; the point under test is that a
	// retry happens, not how long it sleeps.
	client.SetSleepForTest(func(time.Duration) {})
	if _, err := client.ExecuteMutation(request, githubapp.AppInstallation, ""); err != nil {
		t.Fatalf("publication failed on a transient secondary rate limit: %v", err)
	}
	if blobAttempts != 3 {
		t.Fatalf("blob attempts = %d, want 3 (two throttled, one accepted)", blobAttempts)
	}
}
