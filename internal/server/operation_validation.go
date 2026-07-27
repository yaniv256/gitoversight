package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

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
		name, _ := payload["name"].(string)
		content, contentOK := payload["content_base64"].(string)
		wantSHA, _ := payload["sha256"].(string)
		size, sizeOK := payload["size"].(float64)
		decoded, decodeErr := base64.StdEncoding.DecodeString(content)
		digest := fmt.Sprintf("%x", sha256.Sum256(decoded))
		valid = requireString("tag_name") && name != "" && filepath.Base(name) == name && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00") && requireString("content_type") && contentOK && decodeErr == nil && sizeOK && size > 0 && size <= 700<<10 && size == float64(len(decoded)) && len(wantSHA) == 64 && strings.EqualFold(wantSHA, digest)
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
