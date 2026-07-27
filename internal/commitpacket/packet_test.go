package commitpacket

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestDecodeValidatesImmutableObjectPackage(t *testing.T) {
	payload := validPayload()
	packet, present, err := Decode(payload)
	if err != nil || !present || packet.Commit.SHA == "" {
		t.Fatalf("packet = %#v, present = %v, err = %v", packet, present, err)
	}

	payload["object_package"].(map[string]any)["blobs"].([]any)[0].(map[string]any)["content"] = "dGFtcGVyZWQ="
	if _, _, err := Decode(payload); err == nil {
		t.Fatal("tampered blob content was accepted")
	}
}

func TestDecodeRejectsDuplicateBlobObjects(t *testing.T) {
	payload := validPayload()
	objectPackage := payload["object_package"].(map[string]any)
	blob := objectPackage["blobs"].([]any)[0]
	objectPackage["blobs"] = append(objectPackage["blobs"].([]any), blob)
	if _, _, err := Decode(payload); err == nil {
		t.Fatal("duplicate blob object was accepted")
	}
}

func TestDecodeAcceptsDeltaTreeDeletionWithoutRepublishingDeletedBlob(t *testing.T) {
	payload := validPayload()
	objectPackage := payload["object_package"].(map[string]any)
	tree := objectPackage["tree"].(map[string]any)
	tree["base_tree"] = "2222222222222222222222222222222222222222"
	tree["entries"] = append(tree["entries"].([]any), map[string]any{"path": "removed.txt", "mode": "100644", "type": "blob", "delete": true})
	if _, _, err := Decode(payload); err != nil {
		t.Fatalf("valid delta deletion rejected: %v", err)
	}
}

func TestDecodeAcceptsSubmoduleGitlinkEntry(t *testing.T) {
	// A submodule pointer is a type:"commit" mode:"160000" entry with a valid
	// commit SHA and NO bundled blob — GitHub resolves it by SHA. (Card 334.)
	payload := validPayload()
	tree := payload["object_package"].(map[string]any)["tree"].(map[string]any)
	tree["base_tree"] = "2222222222222222222222222222222222222222"
	tree["entries"] = append(tree["entries"].([]any), map[string]any{
		"path": "examples/vendored", "mode": "160000", "type": "commit",
		"sha": "bdae3d1d6dd83decfdecc50dde88323ed156eb1a",
	})
	if _, _, err := Decode(payload); err != nil {
		t.Fatalf("valid submodule gitlink entry rejected: %v", err)
	}
}

func TestDecodeRejectsSubmoduleEntryWithInvalidSHA(t *testing.T) {
	payload := validPayload()
	tree := payload["object_package"].(map[string]any)["tree"].(map[string]any)
	tree["base_tree"] = "2222222222222222222222222222222222222222"
	tree["entries"] = append(tree["entries"].([]any), map[string]any{
		"path": "examples/vendored", "mode": "160000", "type": "commit", "sha": "not-a-sha",
	})
	if _, _, err := Decode(payload); err == nil {
		t.Fatal("submodule entry with an invalid SHA was accepted")
	}
}

func TestDecodeRejectsDeletionWithoutBaseTree(t *testing.T) {
	payload := validPayload()
	tree := payload["object_package"].(map[string]any)["tree"].(map[string]any)
	tree["entries"] = append(tree["entries"].([]any), map[string]any{"path": "removed.txt", "mode": "100644", "type": "blob", "delete": true})
	if _, _, err := Decode(payload); err == nil {
		t.Fatal("deletion without a base tree was accepted")
	}
}

func TestDecodeRejectsOversizedTreePath(t *testing.T) {
	payload := validPayload()
	entry := payload["object_package"].(map[string]any)["tree"].(map[string]any)["entries"].([]any)[0].(map[string]any)
	entry["path"] = string(make([]byte, MaxPathBytes+1))
	if _, _, err := Decode(payload); err == nil {
		t.Fatal("oversized tree path was accepted")
	}
}

func TestDecodeRejectsAggregateTreePathsAboveEnvelope(t *testing.T) {
	payload := validPayload()
	objectPackage := payload["object_package"].(map[string]any)
	tree := objectPackage["tree"].(map[string]any)
	entries := make([]any, 0, MaxTreePathBytes/MaxPathBytes+1)
	for index := 0; index <= MaxTreePathBytes/MaxPathBytes; index++ {
		path := fmt.Sprintf("%04d-%s", index, strings.Repeat("x", MaxPathBytes-5))
		entries = append(entries, map[string]any{"path": path, "mode": "100644", "type": "blob", "sha": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"})
	}
	tree["entries"] = entries
	if _, _, err := Decode(payload); err == nil || !strings.Contains(err.Error(), "tree paths exceed") {
		t.Fatalf("aggregate tree paths error = %v", err)
	}
}

func TestSerializedEnvelopeFitsPublishedTransportLimits(t *testing.T) {
	encodedBlobs := base64.StdEncoding.EncodedLen(MaxTotalBytes)
	conservativeJSONOverhead := MaxTreePathBytes + MaxBlobs*128 + MaxTreeEntries*128 + 1<<20
	if encodedBlobs+conservativeJSONOverhead > MaxPayloadBytes {
		t.Fatal("valid immutable package can exceed payload-file limit")
	}
	if MaxPayloadBytes+(4<<20) > MaxRequestBodyBytes {
		t.Fatal("payload-file can exceed signed API request envelope")
	}
}

func validPayload() map[string]any {
	return map[string]any{"object_package": map[string]any{
		"blobs":  []any{map[string]any{"sha": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", "content": "", "encoding": "base64"}},
		"tree":   map[string]any{"sha": "1111111111111111111111111111111111111111", "entries": []any{map[string]any{"path": "empty.txt", "mode": "100644", "type": "blob", "sha": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"}}},
		"commit": map[string]any{"sha": "91297194f73354e9cc369a608380d0a863a6e105", "message": "test", "tree": "1111111111111111111111111111111111111111", "parents": []any{"3333333333333333333333333333333333333333"}, "author": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}, "committer": map[string]any{"name": "Zara", "email": "zara@example.com", "date": "2026-07-20T00:00:00Z"}},
	}}
}
