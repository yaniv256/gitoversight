package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

func TestExecutableOperationValidationRejectsMalformedPacketsBeforeGrant(t *testing.T) {
	tests := []struct {
		kind, branch, title, body string
		payload                   map[string]any
	}{
		{"branch.push", "feat/a", "", "", map[string]any{"sha": "abc"}},
		{"policy.promote", "main", "", "", map[string]any{"sha": "abc"}},
		{"pull_request.create", "feat/a", "Title", "Body", map[string]any{"base": "main", "head_sha": "abc"}},
		{"pull_request.update", "", "Title", "Body", map[string]any{"number": float64(1)}},
		{"pull_request.review", "", "", "review\n<!-- gitoversight-request:op-1 -->", map[string]any{"number": float64(1), "head_sha": "abc", "event": "APPROVE"}},
		{"pull_request.reply", "", "", "reply\n<!-- gitoversight-request:op-1 -->", map[string]any{"number": float64(1)}},
		{"pull_request.merge", "", "", "", map[string]any{"number": float64(1), "merge_method": "squash"}},
		{"issue.create", "", "Title", "Body\n<!-- gitoversight-request:op-1 -->", nil},
		{"issue.comment", "", "", "Body\n<!-- gitoversight-request:op-1 -->", map[string]any{"number": float64(1)}},
		{"release.publish", "", "Release", "Body", map[string]any{"tag_name": "v1", "target_commitish": "abc", "prerelease": false}},
		{"repository.create", "", "", "", map[string]any{"visibility": "private"}},
		{"repository.settings.update", "", "", "", map[string]any{"settings": map[string]any{"has_issues": true}}},
		{"installation.repository.add", "", "", "", map[string]any{"installation_id": float64(42)}},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			payload, err := json.Marshal(test.payload)
			if err != nil {
				t.Fatal(err)
			}
			operation := storage.Operation{ID: "op-1", Repository: "yaniv256/private", Kind: test.kind, Branch: test.branch, Title: test.title, Body: test.body, PayloadJSON: payload}
			if err := validateExecutableOperation(operation); err != nil {
				t.Fatalf("valid packet rejected: %v", err)
			}
			operation.PayloadJSON = []byte(`{}`)
			operation.Branch, operation.Title, operation.Body = "", "", ""
			if err := validateExecutableOperation(operation); !errors.Is(err, ErrDurableInvalid) {
				t.Fatalf("malformed packet error = %v", err)
			}
		})
	}
}

func TestBranchPushRejectsTamperedObjectPackageBeforeGrant(t *testing.T) {
	payload := map[string]any{
		"sha": "2222222222222222222222222222222222222222",
		"object_package": map[string]any{
			"blobs":  []any{map[string]any{"sha": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", "content": "dGFtcGVyZWQ=", "encoding": "base64"}},
			"tree":   map[string]any{"sha": "1111111111111111111111111111111111111111", "entries": []any{map[string]any{"path": "file", "mode": "100644", "type": "blob", "sha": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"}}},
			"commit": map[string]any{"sha": "2222222222222222222222222222222222222222", "message": "test", "tree": "1111111111111111111111111111111111111111", "parents": []any{}, "author": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}, "committer": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}},
		},
	}
	encoded, _ := json.Marshal(payload)
	operation := storage.Operation{ID: "op-1", Repository: "yaniv256/private", Kind: "branch.push", Branch: "feat/a", PayloadJSON: encoded}
	if err := validateExecutableOperation(operation); !errors.Is(err, ErrDurableInvalid) {
		t.Fatalf("tampered packet error = %v", err)
	}
}

func TestReleaseAssetValidationAcceptsMetadataDescriptorOnly(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"tag_name":     "v1",
		"name":         "actions-json-mcp-linux-x64.tar.gz",
		"content_type": "application/gzip",
		"asset": map[string]any{
			"stage_id": "0123456789abcdef0123456789abcdef",
			"sha256":   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"size":     float64(15 << 20),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	operation := storage.Operation{
		ID: "asset-1", Repository: "yaniv256/private", Kind: "release.asset.upload", PayloadJSON: payload,
	}
	if err := validateExecutableOperation(operation); err != nil {
		t.Fatalf("descriptor packet rejected: %v", err)
	}
}

func TestReleaseAssetValidationRejectsNewInlinePayload(t *testing.T) {
	err := rejectNewInlineReleaseAsset(map[string]any{
		"tag_name": "v1", "name": "bridge.zip", "content_type": "application/zip",
		"content_base64": "YWJj", "sha256": "abc", "size": float64(3),
	})
	if !errors.Is(err, ErrStreamedAssetRequired) {
		t.Fatalf("inline error = %v, want ErrStreamedAssetRequired", err)
	}
}

func TestReleaseAssetBundleValidationAcceptsExactDescriptorsAndRejectsDuplicates(t *testing.T) {
	descriptor := func(name, stage, digest string) map[string]any {
		return map[string]any{
			"tag_name": "v1", "name": name, "content_type": "application/gzip",
			"asset": map[string]any{"stage_id": stage, "sha256": digest, "size": float64(42)},
		}
	}
	payload := map[string]any{"assets": []any{
		descriptor("linux.tar.gz", "0123456789abcdef0123456789abcdef", strings.Repeat("a", 64)),
		descriptor("mac.tar.gz", "fedcba9876543210fedcba9876543210", strings.Repeat("b", 64)),
	}}
	encoded, _ := json.Marshal(payload)
	operation := storage.Operation{ID: "assets-1", Repository: "yaniv256/private", Kind: "release.assets.upload", PayloadJSON: encoded}
	if err := validateExecutableOperation(operation); err != nil {
		t.Fatalf("bundle packet rejected: %v", err)
	}
	payload["assets"].([]any)[1].(map[string]any)["name"] = "linux.tar.gz"
	encoded, _ = json.Marshal(payload)
	operation.PayloadJSON = encoded
	if err := validateExecutableOperation(operation); !errors.Is(err, ErrDurableInvalid) {
		t.Fatalf("duplicate bundle error = %v", err)
	}
}
