package mcpapp

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
)

// ChangeDrafts is the narrow application seam used by the MCP adapter. The
// concrete brokerapp service owns base reads, deterministic construction,
// persistence, expiry, and tamper detection; this adapter owns only wire
// decoding, repository scope, and compact result shaping.
type ChangeDrafts interface {
	Create(context.Context, brokerapp.Identity, brokerapp.CreateChangeDraftRequest) (brokerapp.ChangeDraftReceipt, error)
	Resolve(context.Context, brokerapp.Identity, brokerapp.ChangeDraftBinding) (changedraft.StoredDraft, error)
}

type ChangeDraftPublisher interface {
	Publish(context.Context, brokerapp.Identity, brokerapp.PublishChangeDraftRequest) (brokerapp.SubmitResult, error)
}

type createDraftArguments struct {
	Repository string                `json:"repository"`
	BaseCommit changedraft.ObjectID  `json:"base_commit"`
	Changes    []draftChangeArgument `json:"changes"`
}

type draftChangeArgument struct {
	Operation     changedraft.Operation `json:"operation"`
	Path          string                `json:"path"`
	Mode          changedraft.Mode      `json:"mode,omitempty"`
	ContentBase64 string                `json:"content_base64,omitempty"`
}

func (arguments createDraftArguments) request() (brokerapp.CreateChangeDraftRequest, error) {
	if arguments.Repository == "" || arguments.BaseCommit == "" || len(arguments.Changes) == 0 {
		return brokerapp.CreateChangeDraftRequest{}, errInvalidArguments
	}
	changes := make([]changedraft.Change, len(arguments.Changes))
	for index, input := range arguments.Changes {
		if input.Operation == "" || input.Path == "" {
			return brokerapp.CreateChangeDraftRequest{}, errInvalidArguments
		}
		content, err := base64.StdEncoding.DecodeString(input.ContentBase64)
		if err != nil {
			return brokerapp.CreateChangeDraftRequest{}, errInvalidArguments
		}
		changes[index] = changedraft.Change{
			Operation: input.Operation,
			Path:      input.Path,
			Mode:      input.Mode,
			Content:   content,
		}
	}
	return brokerapp.CreateChangeDraftRequest{
		Repository: arguments.Repository,
		BaseCommit: arguments.BaseCommit,
		Changes:    changes,
	}, nil
}

type inspectDraftArguments struct {
	DraftID     string               `json:"draft_id"`
	Repository  string               `json:"repository"`
	BaseCommit  changedraft.ObjectID `json:"base_commit"`
	PreviewHash string               `json:"preview_hash"`
}

type publishDraftArguments struct {
	inspectDraftArguments
	OperationID string `json:"operation_id"`
	Branch      string `json:"branch"`
	Message     string `json:"message"`
}

func (arguments publishDraftArguments) request() (brokerapp.PublishChangeDraftRequest, error) {
	binding, err := arguments.binding()
	if err != nil || arguments.OperationID == "" || arguments.Branch == "" || arguments.Message == "" {
		return brokerapp.PublishChangeDraftRequest{}, errInvalidArguments
	}
	return brokerapp.PublishChangeDraftRequest{Binding: binding, OperationID: arguments.OperationID, Branch: arguments.Branch, Message: arguments.Message}, nil
}

func (arguments inspectDraftArguments) binding() (brokerapp.ChangeDraftBinding, error) {
	if arguments.DraftID == "" || arguments.Repository == "" || arguments.BaseCommit == "" || arguments.PreviewHash == "" {
		return brokerapp.ChangeDraftBinding{}, errInvalidArguments
	}
	return brokerapp.ChangeDraftBinding{
		ID: arguments.DraftID, Repository: arguments.Repository,
		BaseCommit: arguments.BaseCommit, PreviewHash: arguments.PreviewHash,
	}, nil
}

type draftPreviewEnvelope struct {
	DraftID     string                      `json:"draft_id"`
	Repository  string                      `json:"repository"`
	BaseCommit  changedraft.ObjectID        `json:"base_commit"`
	ResultTree  changedraft.ObjectID        `json:"result_tree"`
	PreviewHash string                      `json:"preview_hash"`
	ExpiresAt   time.Time                   `json:"expires_at"`
	Changes     []changedraft.ChangeSummary `json:"changes"`
}

func receiptEnvelope(receipt brokerapp.ChangeDraftReceipt) draftPreviewEnvelope {
	return draftPreviewEnvelope{
		DraftID: receipt.ID, Repository: receipt.Preview.Repository,
		BaseCommit: receipt.Preview.BaseCommit, ResultTree: receipt.Preview.ResultTree,
		PreviewHash: receipt.Preview.Hash, ExpiresAt: receipt.ExpiresAt,
		Changes: append([]changedraft.ChangeSummary(nil), receipt.Preview.Changes...),
	}
}

func storedDraftEnvelope(draft changedraft.StoredDraft) draftPreviewEnvelope {
	return draftPreviewEnvelope{
		DraftID: draft.ID, Repository: draft.Preview.Repository,
		BaseCommit: draft.Preview.BaseCommit, ResultTree: draft.Preview.ResultTree,
		PreviewHash: draft.Preview.Hash, ExpiresAt: draft.ExpiresAt,
		Changes: append([]changedraft.ChangeSummary(nil), draft.Preview.Changes...),
	}
}

func changeDraftToolErrorCode(err error) string {
	switch {
	case errors.Is(err, brokerapp.ErrChangeDraftInvalid):
		return "change_draft_invalid"
	case errors.Is(err, brokerapp.ErrChangeDraftNotFound):
		return "change_draft_not_found"
	case errors.Is(err, brokerapp.ErrChangeDraftStaleBase):
		return "change_draft_stale_base"
	case errors.Is(err, brokerapp.ErrChangeDraftBinding):
		return "change_draft_binding_mismatch"
	case errors.Is(err, brokerapp.ErrChangeDraftExpired):
		return "change_draft_expired"
	case errors.Is(err, brokerapp.ErrChangeDraftTampered):
		return "change_draft_tampered"
	case errors.Is(err, brokerapp.ErrChangeDraftRepository):
		return "change_draft_repository_unavailable"
	case errors.Is(err, brokerapp.ErrChangeDraftPublicationInvalid):
		return "change_draft_publication_invalid"
	default:
		return "change_draft_failed"
	}
}
