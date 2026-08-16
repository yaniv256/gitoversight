package releaseasset

import (
	"context"
	"time"
)

// MetadataTransaction is the narrow mutation boundary used by ingress and
// governed-operation orchestration. Callers must execute it inside the
// broker's checkpoint-aware durable transaction; this package intentionally
// does not expose an autocommit path.
type MetadataTransaction interface {
	PutStagedAsset(context.Context, Stage) error
	BeginStagedAssetUpload(context.Context, string, string, string, time.Time) error
	MarkStagedAssetReady(context.Context, string, string, string, time.Time) error
	PinStagedAsset(context.Context, Stage, string, time.Time) error
	AbandonStagedAsset(context.Context, string, string, time.Time) error
	ExpireStagedAsset(context.Context, string, string, time.Time) error
}

// MetadataReader has no mutation methods and returns opaque not-found results
// when an ownership binding does not match.
type MetadataReader interface {
	StagedAssetForOwner(context.Context, string, string, string, string, string) (Stage, error)
}
