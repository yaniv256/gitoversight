package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

var (
	releaseAssetStageIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	releaseAssetSHA256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type releaseAssetDescriptor struct {
	StageID     string
	SHA256      string
	Size        int64
	TagName     string
	Name        string
	ContentType string
}

// validateExecutableOperation rejects packets that cannot be both executed and
// independently reconciled. It runs before a single-use grant is issued.
func validateExecutableOperation(operation storage.Operation) error {
	var payload map[string]any
	if len(operation.PayloadJSON) != 0 {
		if err := json.Unmarshal(operation.PayloadJSON, &payload); err != nil {
			return fmt.Errorf("%w: payload is not valid JSON", ErrDurableInvalid)
		}
	}
	requireString := func(key string) bool {
		value, ok := payload[key].(string)
		return ok && strings.TrimSpace(value) != ""
	}
	requireNumber := func(key string) bool {
		value, ok := payload[key]
		if !ok {
			return false
		}
		switch number := value.(type) {
		case float64:
			return number > 0 && number == float64(int(number))
		case json.Number:
			parsed, err := number.Int64()
			return err == nil && parsed > 0
		default:
			return false
		}
	}
	marker := strings.Contains(operation.Body, "<!-- gitoversight-request:"+operation.ID+" -->")
	valid := false
	switch operation.Kind {
	case "branch.push":
		valid = operation.Branch != "" && requireString("sha")
		if valid {
			packet, present, err := commitpacket.Decode(payload)
			valid = err == nil && (!present || packet.Commit.SHA == payload["sha"])
		}
	case "branch.delete":
		valid = operation.Branch != ""
	case "policy.promote":
		valid = operation.Branch != "" && requireString("sha")
	case "pull_request.create":
		valid = operation.Branch != "" && operation.Title != "" && requireString("base") && requireString("head_sha")
	case "pull_request.close":
		valid = requireNumber("number")
	case "pull_request.update":
		valid = operation.Title != "" && requireNumber("number")
	case "pull_request.review":
		event, _ := payload["event"].(string)
		valid = requireNumber("number") && requireString("head_sha") && marker && (event == "APPROVE" || event == "REQUEST_CHANGES" || event == "COMMENT")
	case "pull_request.reply", "issue.comment":
		valid = requireNumber("number") && marker
	case "pull_request.merge":
		method, _ := payload["merge_method"].(string)
		valid = requireNumber("number") && (method == "merge" || method == "squash" || method == "rebase")
	case "issue.create":
		valid = operation.Title != "" && marker
	case "release.publish":
		_, prerelease := payload["prerelease"].(bool)
		valid = operation.Title != "" && requireString("tag_name") && requireString("target_commitish") && prerelease
	case "release.asset.upload":
		_, descriptorErr := parseReleaseAssetDescriptor(payload)
		valid = descriptorErr == nil || validLegacyInlineReleaseAsset(payload)
	case "release.assets.upload":
		_, descriptorErr := parseReleaseAssetDescriptors(payload)
		valid = descriptorErr == nil
	case "repository.create":
		visibility, _ := payload["visibility"].(string)
		owner, name, found := strings.Cut(operation.Repository, "/")
		valid = found && owner != "" && name != "" && !strings.Contains(name, "/") && (visibility == "private" || visibility == "public")
	case "repository.settings.update":
		valid = validRepositorySettings(payload["settings"])
	case "installation.repository.add":
		valid = requireNumber("installation_id")
	}
	if !valid {
		return fmt.Errorf("%w: %s packet cannot be executed and independently reconciled", ErrDurableInvalid, operation.Kind)
	}
	return nil
}

func parseReleaseAssetDescriptors(payload map[string]any) ([]releaseAssetDescriptor, error) {
	if len(payload) != 1 {
		return nil, fmt.Errorf("%w: release asset bundle has unexpected fields", ErrDurableInvalid)
	}
	raw, ok := payload["assets"].([]any)
	if !ok || len(raw) == 0 || len(raw) > 64 {
		return nil, fmt.Errorf("%w: release asset bundle is incomplete", ErrDurableInvalid)
	}
	result := make([]releaseAssetDescriptor, 0, len(raw))
	names, stages := map[string]struct{}{}, map[string]struct{}{}
	for _, item := range raw {
		descriptorPayload, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: release asset bundle contains an invalid descriptor", ErrDurableInvalid)
		}
		descriptor, err := parseReleaseAssetDescriptor(descriptorPayload)
		if err != nil {
			return nil, err
		}
		if _, duplicate := names[descriptor.Name]; duplicate {
			return nil, fmt.Errorf("%w: release asset bundle contains duplicate names", ErrDurableInvalid)
		}
		if _, duplicate := stages[descriptor.StageID]; duplicate {
			return nil, fmt.Errorf("%w: release asset bundle contains duplicate stages", ErrDurableInvalid)
		}
		names[descriptor.Name], stages[descriptor.StageID] = struct{}{}, struct{}{}
		result = append(result, descriptor)
	}
	return result, nil
}

// validLegacyInlineReleaseAsset is execution-only compatibility for packets
// that were durable before streamed staging existed. Submit rejects this shape
// before it can create a new operation.
func validLegacyInlineReleaseAsset(payload map[string]any) bool {
	name, _ := payload["name"].(string)
	content, contentOK := payload["content_base64"].(string)
	wantSHA, _ := payload["sha256"].(string)
	size, sizeOK := payload["size"].(float64)
	if !contentOK || len(content) > base64.StdEncoding.EncodedLen(int(releaseasset.MaxBytes)) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return false
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(decoded))
	tag, tagOK := payload["tag_name"].(string)
	contentType, typeOK := payload["content_type"].(string)
	return tagOK && strings.TrimSpace(tag) != "" && name != "" && filepath.Base(name) == name &&
		name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00") &&
		typeOK && strings.TrimSpace(contentType) != "" && sizeOK && size > 0 &&
		size <= float64(releaseasset.MaxBytes) && size == float64(len(decoded)) &&
		len(wantSHA) == 64 && strings.EqualFold(wantSHA, digest)
}

func rejectNewInlineReleaseAsset(payload map[string]any) error {
	if _, present := payload["content_base64"]; present {
		return fmt.Errorf("%w: stage the file and submit an asset descriptor", ErrStreamedAssetRequired)
	}
	return nil
}

func parseReleaseAssetDescriptor(payload map[string]any) (releaseAssetDescriptor, error) {
	if len(payload) != 4 {
		return releaseAssetDescriptor{}, fmt.Errorf("%w: release asset descriptor has unexpected fields", ErrDurableInvalid)
	}
	tagName, tagOK := payload["tag_name"].(string)
	name, nameOK := payload["name"].(string)
	contentType, typeOK := payload["content_type"].(string)
	asset, assetOK := payload["asset"].(map[string]any)
	if !assetOK || len(asset) != 3 {
		return releaseAssetDescriptor{}, fmt.Errorf("%w: release asset descriptor is incomplete", ErrDurableInvalid)
	}
	stageID, stageOK := asset["stage_id"].(string)
	digest, digestOK := asset["sha256"].(string)
	sizeValue, sizeOK := asset["size"].(float64)
	size := int64(sizeValue)
	if !tagOK || strings.TrimSpace(tagName) == "" || !nameOK || name == "" ||
		filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") ||
		!typeOK || strings.TrimSpace(contentType) == "" || !stageOK ||
		!releaseAssetStageIDPattern.MatchString(stageID) || !digestOK ||
		!releaseAssetSHA256Pattern.MatchString(digest) || !sizeOK || sizeValue < 0 ||
		sizeValue != float64(size) {
		return releaseAssetDescriptor{}, fmt.Errorf("%w: release asset descriptor is invalid", ErrDurableInvalid)
	}
	return releaseAssetDescriptor{
		StageID: stageID, SHA256: digest, Size: size, TagName: tagName,
		Name: name, ContentType: contentType,
	}, nil
}

func validRepositorySettings(value any) bool {
	settings, ok := value.(map[string]any)
	if !ok || len(settings) == 0 {
		return false
	}
	allowed := map[string]string{
		"description": "string", "homepage": "string", "visibility": "visibility", "default_branch": "string",
		"archived": "bool", "has_issues": "bool", "has_projects": "bool", "has_wiki": "bool",
		"allow_squash_merge": "bool", "allow_merge_commit": "bool", "allow_rebase_merge": "bool",
		"allow_auto_merge": "bool", "delete_branch_on_merge": "bool",
	}
	for key, value := range settings {
		switch allowed[key] {
		case "string":
			if _, ok := value.(string); !ok {
				return false
			}
		case "bool":
			if _, ok := value.(bool); !ok {
				return false
			}
		case "visibility":
			if value != "private" && value != "public" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
