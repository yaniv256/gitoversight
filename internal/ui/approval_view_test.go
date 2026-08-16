package ui

import (
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

func TestReleaseAssetApprovalViewShowsEveryGovernedDescriptorField(t *testing.T) {
	operation := storage.Operation{
		Repository: "yaniv256/actions.json.dev",
		Kind:       "release.asset.upload",
		PayloadJSON: []byte(`{
			"tag_name":"v0.1.259",
			"name":"actions-json-bridge-linux-amd64",
			"content_type":"application/octet-stream",
			"asset":{
				"stage_id":"0123456789abcdef0123456789abcdef",
				"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"size":15728640
			}
		}`),
	}
	view := buildApprovalView(operation)
	for _, exact := range []string{
		operation.Repository, "v0.1.259", "actions-json-bridge-linux-amd64",
		"application/octet-stream", "15728640 bytes",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"0123456789abcdef0123456789abcdef",
	} {
		if !strings.Contains(view.Effect+"\n"+view.Published, exact) {
			t.Fatalf("approval view omits %q: %+v", exact, view)
		}
	}
}

func TestReleaseAssetBundleApprovalViewShowsEveryAssetInOneReview(t *testing.T) {
	operation := storage.Operation{
		Repository: "yaniv256/actions.json",
		Kind:       "release.assets.upload",
		PayloadJSON: []byte(`{"assets":[
			{"tag_name":"v1","name":"linux.tar.gz","content_type":"application/gzip","asset":{"stage_id":"11111111111111111111111111111111","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":42}},
			{"tag_name":"v1","name":"mac.tar.gz","content_type":"application/gzip","asset":{"stage_id":"22222222222222222222222222222222","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":84}}
		]}`),
	}
	view := buildApprovalView(operation)
	for _, exact := range []string{
		operation.Repository, "Asset 1 of 2", "Asset 2 of 2", "linux.tar.gz", "mac.tar.gz",
		"42 bytes", "84 bytes", strings.Repeat("a", 64), strings.Repeat("b", 64),
	} {
		if !strings.Contains(view.Effect+"\n"+view.Published, exact) {
			t.Fatalf("bundle approval view omits %q: %+v", exact, view)
		}
	}
}

func TestReleasePublishApprovalViewShowsExactPublicEffect(t *testing.T) {
	operation := storage.Operation{
		Repository: "ActionsJson/actions.json",
		Kind:       "release.publish",
		Title:      "Actions JSON 0.1.264",
		Body:       "Exact consumer-facing release notes.",
		PayloadJSON: []byte(`{
			"tag_name":"extension-v0.1.264",
			"target_commitish":"9e9f14fa60018614ea9d08d489c881a6f77ccbfb",
			"prerelease":false
		}`),
	}
	view := buildApprovalView(operation)
	for _, exact := range []string{
		operation.Repository, "extension-v0.1.264",
		"9e9f14fa60018614ea9d08d489c881a6f77ccbfb", "final",
		operation.Title, operation.Body, "Release notes",
	} {
		if !strings.Contains(view.Effect+"\n"+view.Ref+"\n"+view.ProposedTitle+"\n"+view.Published+"\n"+view.PublishedLabel, exact) {
			t.Fatalf("release approval view omits %q: %+v", exact, view)
		}
	}
}

func TestReleasePublishApprovalViewLabelsPrerelease(t *testing.T) {
	operation := storage.Operation{
		Repository:  "ActionsJson/actions.json",
		Kind:        "release.publish",
		PayloadJSON: []byte(`{"tag_name":"v1.0.0-rc.1","target_commitish":"abc123","prerelease":true}`),
	}
	view := buildApprovalView(operation)
	if !strings.Contains(view.Effect+"\n"+view.Ref, "prerelease") {
		t.Fatalf("release approval view does not identify prerelease: %+v", view)
	}
}
