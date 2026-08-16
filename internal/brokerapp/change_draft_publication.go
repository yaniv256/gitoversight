package brokerapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/gitref"
	"github.com/yaniv256/gitoversight.dev/internal/server"
)

var ErrChangeDraftPublicationInvalid = errors.New("change draft publication is invalid")

type PublishChangeDraftRequest struct {
	Binding     ChangeDraftBinding
	OperationID string
	Branch      string
	Message     string
}

type ChangeDraftPublisher struct {
	drafts     *ChangeDraftService
	store      ChangeDraftPublicationStore
	operations *OperationService
	now        func() time.Time
}

type ChangeDraftPublicationStore interface {
	PutChangeDraftPublication(context.Context, changedraft.PublicationBinding) error
	ChangeDraftPublication(context.Context, string, string, string) (changedraft.PublicationBinding, error)
}

func NewChangeDraftPublisher(drafts *ChangeDraftService, store ChangeDraftPublicationStore, operations *OperationService, now func() time.Time) *ChangeDraftPublisher {
	if now == nil {
		now = time.Now
	}
	return &ChangeDraftPublisher{drafts: drafts, store: store, operations: operations, now: now}
}

func (service *ChangeDraftPublisher) Publish(ctx context.Context, identity Identity, request PublishChangeDraftRequest) (SubmitResult, error) {
	if service == nil || service.drafts == nil || service.store == nil || service.operations == nil || strings.TrimSpace(request.OperationID) == "" ||
		strings.TrimSpace(request.Branch) == "" || strings.TrimSpace(request.Message) == "" {
		return SubmitResult{}, ErrChangeDraftPublicationInvalid
	}
	request.Branch = gitref.BranchName(request.Branch)
	if request.Branch == "" {
		return SubmitResult{}, ErrChangeDraftPublicationInvalid
	}
	requestHash, err := changeDraftPublicationRequestHash(request)
	if err != nil {
		return SubmitResult{}, ErrChangeDraftPublicationInvalid
	}
	// Preserve operation idempotency after a successful push moves the base and
	// makes this draft stale. An existing durable receipt wins over rebuilding
	// or resubmitting any bytes.
	binding, bindingErr := service.store.ChangeDraftPublication(ctx, identity.TenantID, identity.AgentID, request.OperationID)
	if bindingErr == nil {
		if binding.RequestHash != requestHash {
			return SubmitResult{}, fmt.Errorf("%w: operation id is bound to a different publication", ErrChangeDraftPublicationInvalid)
		}
		if existing, statusErr := service.operations.Status(ctx, identity, request.OperationID); statusErr == nil {
			if existing.Repository != request.Binding.Repository || existing.Operation != "branch.push" ||
				existing.Branch != request.Branch || existing.Title != request.Message || existing.ManifestHash != request.Binding.PreviewHash || existing.HeadSHA != binding.HeadSHA {
				return SubmitResult{}, fmt.Errorf("%w: durable operation does not match its publication binding", ErrChangeDraftPublicationInvalid)
			}
			return SubmitResult{Result: existing}, nil
		} else if !errors.Is(statusErr, server.ErrDurableNotFound) {
			return SubmitResult{}, statusErr
		}
	} else if !errors.Is(bindingErr, changedraft.ErrStoredPublicationNotFound) {
		return SubmitResult{}, bindingErr
	}
	draft, err := service.drafts.Resolve(ctx, identity, request.Binding)
	if err != nil {
		return SubmitResult{}, err
	}
	packet, err := draftCommitPacket(draft, identity, request.Message, draft.CreatedAt.UTC())
	if err != nil {
		return SubmitResult{}, fmt.Errorf("%w: %v", ErrChangeDraftPublicationInvalid, err)
	}
	if bindingErr == nil {
		if binding.HeadSHA != packet.Commit.SHA {
			return SubmitResult{}, fmt.Errorf("%w: stored publication head does not match rebuilt draft", ErrChangeDraftPublicationInvalid)
		}
	} else {
		binding = changedraft.PublicationBinding{TenantID: identity.TenantID, AgentID: identity.AgentID, OperationID: request.OperationID, RequestHash: requestHash, HeadSHA: packet.Commit.SHA, CreatedAt: service.now().UTC()}
		if err := service.store.PutChangeDraftPublication(ctx, binding); err != nil {
			existing, lookupErr := service.store.ChangeDraftPublication(ctx, identity.TenantID, identity.AgentID, request.OperationID)
			if lookupErr != nil || existing.RequestHash != binding.RequestHash || existing.HeadSHA != binding.HeadSHA {
				return SubmitResult{}, fmt.Errorf("%w: publication binding conflict", ErrChangeDraftPublicationInvalid)
			}
		}
	}
	payload := map[string]any{"sha": packet.Commit.SHA, "object_package": packet}
	return service.operations.Submit(ctx, identity, OperationRequest{
		ID: request.OperationID, Repository: request.Binding.Repository, Operation: "branch.push",
		Branch: request.Branch, HeadSHA: packet.Commit.SHA, ManifestHash: draft.Preview.Hash,
		Title: request.Message, Payload: payload,
	})
}

func changeDraftPublicationRequestHash(request PublishChangeDraftRequest) (string, error) {
	payload, err := json.Marshal(struct{ DraftID, Repository, BaseCommit, PreviewHash, Branch, Message string }{
		request.Binding.ID, request.Binding.Repository, string(request.Binding.BaseCommit), request.Binding.PreviewHash, request.Branch, request.Message,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func draftCommitPacket(draft changedraft.StoredDraft, identity Identity, message string, now time.Time) (commitpacket.Packet, error) {
	entries := make([]commitpacket.TreeEntry, 0, len(draft.Changes))
	blobs := make([]commitpacket.Blob, 0, len(draft.Changes))
	seenBlobs := make(map[string]struct{})
	for _, change := range draft.Changes {
		switch change.Operation {
		case changedraft.Add, changedraft.Replace:
			blob := commitpacket.BlobFromBytes(change.Content)
			mode := change.Mode
			if change.Operation == changedraft.Replace {
				for _, result := range draft.Preview.Result {
					if result.Path == change.Path {
						mode = result.Mode
						break
					}
				}
			}
			entries = append(entries, commitpacket.TreeEntry{Path: change.Path, Mode: string(mode), Type: "blob", SHA: blob.SHA})
			if _, exists := seenBlobs[blob.SHA]; !exists {
				blobs = append(blobs, blob)
				seenBlobs[blob.SHA] = struct{}{}
			}
		case changedraft.Delete:
			var mode changedraft.Mode
			for _, summary := range draft.Preview.Changes {
				if summary.Path == change.Path {
					mode = summary.Mode
					break
				}
			}
			entries = append(entries, commitpacket.TreeEntry{Path: change.Path, Mode: string(mode), Type: "blob", Delete: true})
		case changedraft.ChangeMode:
			var object changedraft.ObjectID
			for _, result := range draft.Preview.Result {
				if result.Path == change.Path {
					object = result.Object
					break
				}
			}
			entries = append(entries, commitpacket.TreeEntry{Path: change.Path, Mode: string(change.Mode), Type: "blob", SHA: string(object)})
		default:
			return commitpacket.Packet{}, errors.New("unsupported stored change")
		}
	}
	name := identity.AgentID
	if name == "" {
		return commitpacket.Packet{}, errors.New("missing agent identity")
	}
	signature := commitpacket.Signature{Name: name, Email: name + "@gitoversight.invalid", Date: now.Format(time.RFC3339)}
	return commitpacket.NewDelta(string(draft.Preview.BaseCommit), string(draft.Preview.BaseTree), string(draft.Preview.ResultTree), message, signature, entries, blobs)
}
