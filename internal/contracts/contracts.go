package contracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

type Kind string

const (
	Policy   Kind = "policy"
	Request  Kind = "request"
	Approval Kind = "approval"
	Receipt  Kind = "receipt"
)

var knownOperations = map[string]struct{}{
	"branch.push": {}, "branch.delete": {}, "pull_request.create": {}, "pull_request.update": {},
	"pull_request.review": {}, "pull_request.reply": {}, "pull_request.merge": {}, "pull_request.close": {},
	"repository.read": {}, "repository.create": {}, "repository.settings.update": {}, "installation.repository.add": {}, "policy.promote": {},
	"sync.propose": {}, "sync.update": {}, "queue.set_order": {},
	"release.publish": {}, "release.asset.upload": {}, "release.assets.upload": {}, "issue.create": {}, "issue.comment": {},
}

type requestDocument struct {
	SchemaVersion int    `json:"schema_version"`
	RequestID     string `json:"request_id"`
	Repository    string `json:"repository"`
	Operation     string `json:"operation"`
	Branch        string `json:"branch,omitempty"`
}

type approvalMetadata struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type approvalDocument struct {
	SchemaVersion         int              `json:"schema_version"`
	ApprovalID            string           `json:"approval_id"`
	SourceRepository      string           `json:"source_repository"`
	DestinationRepository string           `json:"destination_repository"`
	SourceCommit          string           `json:"source_commit"`
	ExportTree            string           `json:"export_tree"`
	Paths                 []string         `json:"paths"`
	Metadata              approvalMetadata `json:"metadata"`
	Operations            []string         `json:"operations"`
	Approver              string           `json:"approver"`
	ExpiresAt             string           `json:"expires_at"`
	Nonce                 string           `json:"nonce"`
}

type receiptDocument struct {
	SchemaVersion int    `json:"schema_version"`
	RequestID     string `json:"request_id"`
	State         string `json:"state"`
	Event         string `json:"event"`
	PreviousHash  string `json:"previous_hash"`
	RecordedAt    string `json:"recorded_at"`
}

func Validate(kind Kind, payload []byte) error {
	switch kind {
	case Policy:
		var doc policy.Document
		if err := decodeStrict(payload, &doc); err != nil {
			return err
		}
		if doc.SchemaVersion != 1 || doc.Generation == 0 || len(doc.Repositories) == 0 {
			return errors.New("policy requires schema_version 1, positive generation, and repositories")
		}
		for _, repo := range doc.Repositories {
			if invalidRepository(repo.Name) || len(repo.Owners) == 0 && doc.FallbackOwner == "" {
				return fmt.Errorf("repository %q requires an exact name and owner", repo.Name)
			}
			if repo.Visibility != "private" && repo.Visibility != "public" {
				return fmt.Errorf("repository %q has invalid visibility", repo.Name)
			}
		}
		return nil
	case Request:
		var doc requestDocument
		if err := decodeStrict(payload, &doc); err != nil {
			return err
		}
		if doc.SchemaVersion != 1 || doc.RequestID == "" || invalidRepository(doc.Repository) {
			return errors.New("request requires schema_version 1, request_id, and exact repository")
		}
		if _, ok := knownOperations[doc.Operation]; !ok {
			return fmt.Errorf("unknown operation %q", doc.Operation)
		}
		return nil
	case Approval:
		var doc approvalDocument
		if err := decodeStrict(payload, &doc); err != nil {
			return err
		}
		if doc.SchemaVersion != 1 || doc.ApprovalID == "" || invalidRepository(doc.SourceRepository) || invalidRepository(doc.DestinationRepository) || len(doc.SourceCommit) < 7 || len(doc.ExportTree) < 7 || len(doc.Paths) == 0 || len(doc.Operations) == 0 || doc.Approver == "" || len(doc.Nonce) < 16 || doc.Metadata.Title == "" {
			return errors.New("approval packet is incomplete")
		}
		for _, operation := range doc.Operations {
			if _, ok := knownOperations[operation]; !ok {
				return fmt.Errorf("unknown operation %q", operation)
			}
		}
		if expires, err := time.Parse(time.RFC3339, doc.ExpiresAt); err != nil || expires.IsZero() {
			return errors.New("approval requires RFC3339 expiration")
		}
		return nil
	case Receipt:
		var doc receiptDocument
		if err := decodeStrict(payload, &doc); err != nil {
			return err
		}
		if doc.SchemaVersion != 1 || doc.RequestID == "" || doc.State == "" || doc.Event == "" || doc.RecordedAt == "" {
			return errors.New("receipt is incomplete")
		}
		if _, err := time.Parse(time.RFC3339Nano, doc.RecordedAt); err != nil {
			return errors.New("receipt recorded_at must be RFC3339")
		}
		return nil
	default:
		return fmt.Errorf("unknown contract kind %q", kind)
	}
}

func CanonicalHash(kind Kind, payload []byte) (string, error) {
	if err := Validate(kind, payload); err != nil {
		return "", err
	}
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func decodeStrict(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func invalidRepository(value string) bool {
	return value == "" || strings.ContainsAny(value, "*?[") || strings.Count(value, "/") != 1
}
