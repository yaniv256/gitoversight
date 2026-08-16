package releaseasset

import (
	"errors"
	"regexp"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

type Stage = storage.StagedAsset
type State = storage.StagedAssetState

const (
	// ProtocolVersion is the minimum API/worker agreement required before a
	// descriptor-only release operation may be accepted.
	ProtocolVersion = 1

	StateCreated   = storage.StagedAssetCreated
	StateUploading = storage.StagedAssetUploading
	StateReady     = storage.StagedAssetReady
	StatePinned    = storage.StagedAssetPinned
	StateAbandoned = storage.StagedAssetAbandoned
	StateExpired   = storage.StagedAssetExpired
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidateStage(stage Stage) error {
	if strings.TrimSpace(stage.TenantID) == "" || strings.TrimSpace(stage.ID) == "" ||
		strings.TrimSpace(stage.AgentID) == "" || strings.TrimSpace(stage.CredentialID) == "" ||
		strings.TrimSpace(stage.Repository) == "" || strings.TrimSpace(stage.Name) == "" ||
		strings.TrimSpace(stage.ContentType) == "" {
		return errors.New("staged asset binding is incomplete")
	}
	if !sha256Pattern.MatchString(stage.ExpectedSHA256) || stage.ExpectedSize < 0 {
		return errors.New("staged asset integrity binding is invalid")
	}
	if stage.ReservedSize != stage.ExpectedSize || stage.CreatedAt.IsZero() ||
		stage.UpdatedAt.IsZero() || stage.ExpiresAt.IsZero() {
		return errors.New("staged asset reservation or lifecycle is invalid")
	}
	if stage.State != StateCreated || stage.CapabilityHash == "" ||
		stage.CapabilityExpiresAt.IsZero() {
		return errors.New("new staged asset capability is incomplete")
	}
	return nil
}
