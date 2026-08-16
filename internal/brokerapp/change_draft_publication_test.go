package brokerapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/server"
)

type draftPublicationAuthority struct {
	request   server.DurableOperationRequest
	status    server.DurableResult
	statusErr error
}

type draftPublicationStore struct {
	bindings map[string]changedraft.PublicationBinding
}

func newDraftPublicationStore() *draftPublicationStore {
	return &draftPublicationStore{bindings: map[string]changedraft.PublicationBinding{}}
}
func (store *draftPublicationStore) PutChangeDraftPublication(_ context.Context, binding changedraft.PublicationBinding) error {
	key := binding.TenantID + "\x00" + binding.AgentID + "\x00" + binding.OperationID
	if _, exists := store.bindings[key]; exists {
		return errors.New("duplicate")
	}
	store.bindings[key] = binding
	return nil
}
func (store *draftPublicationStore) ChangeDraftPublication(_ context.Context, tenantID, agentID, operationID string) (changedraft.PublicationBinding, error) {
	binding, exists := store.bindings[tenantID+"\x00"+agentID+"\x00"+operationID]
	if !exists {
		return changedraft.PublicationBinding{}, changedraft.ErrStoredPublicationNotFound
	}
	return binding, nil
}

func (authority *draftPublicationAuthority) Submit(_ context.Context, _ server.DurableIdentity, request server.DurableOperationRequest) (server.DurableResult, error) {
	authority.request = request
	return server.DurableResult{ID: request.ID, State: server.DurableDenied}, nil
}
func (authority *draftPublicationAuthority) Status(context.Context, server.DurableIdentity, string) (server.DurableResult, error) {
	if authority.statusErr != nil {
		return server.DurableResult{}, authority.statusErr
	}
	if authority.status.ID != "" {
		return authority.status, nil
	}
	return server.DurableResult{}, server.ErrDurableNotFound
}

func TestChangeDraftPublisherReturnsExistingReceiptBeforeResolvingStaleDraft(t *testing.T) {
	authority := &draftPublicationAuthority{status: server.DurableResult{ID: "push-1", Repository: "yaniv256/example", Operation: "branch.push", Branch: "feat/work", Title: "feat: already submitted", HeadSHA: "head", ManifestHash: "hash", State: server.DurableVerified}}
	store := newDraftPublicationStore()
	request := PublishChangeDraftRequest{
		Binding:     ChangeDraftBinding{ID: "expired", Repository: "yaniv256/example", BaseCommit: changedraft.ObjectID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), PreviewHash: "hash"},
		OperationID: "push-1", Branch: "feat/work", Message: "feat: already submitted",
	}
	requestHash, _ := changeDraftPublicationRequestHash(request)
	store.bindings["tenant-a\x00work-agent\x00push-1"] = changedraft.PublicationBinding{TenantID: "tenant-a", AgentID: "work-agent", OperationID: "push-1", RequestHash: requestHash, HeadSHA: "head"}
	publisher := NewChangeDraftPublisher(&ChangeDraftService{}, store, NewOperationService(authority, nil), nil)
	request.Branch = "refs/heads/feat/work"
	result, err := publisher.Publish(context.Background(), Identity{TenantID: "tenant-a", AgentID: "work-agent"}, request)
	if err != nil || result.Result.State != server.DurableVerified {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestChangeDraftPublisherRejectsOperationIDBoundToDifferentPublication(t *testing.T) {
	authority := &draftPublicationAuthority{status: server.DurableResult{ID: "push-1", Repository: "yaniv256/other", Operation: "branch.push", Branch: "feat/other", Title: "other", ManifestHash: "other-hash", State: server.DurableVerified}}
	store := newDraftPublicationStore()
	store.bindings["tenant-a\x00work-agent\x00push-1"] = changedraft.PublicationBinding{TenantID: "tenant-a", AgentID: "work-agent", OperationID: "push-1", RequestHash: "different", HeadSHA: "head"}
	publisher := NewChangeDraftPublisher(&ChangeDraftService{}, store, NewOperationService(authority, nil), nil)
	_, err := publisher.Publish(context.Background(), Identity{TenantID: "tenant-a", AgentID: "work-agent"}, PublishChangeDraftRequest{
		Binding:     ChangeDraftBinding{ID: "draft", Repository: "yaniv256/example", BaseCommit: changedraft.ObjectID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), PreviewHash: "hash"},
		OperationID: "push-1", Branch: "feat/work", Message: "feat: requested publication",
	})
	if !errors.Is(err, ErrChangeDraftPublicationInvalid) {
		t.Fatalf("conflicting operation ID error=%v", err)
	}
}

func TestChangeDraftPublisherBuildsGovernedDeltaWithoutCallerPacket(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	repository := &draftRepositoryFake{snapshot: draftBaseFixture()}
	drafts := NewChangeDraftService(repository, newDraftStoreFake(), ChangeDraftConfig{Now: func() time.Time { return now }, NewID: func() (string, error) { return "draft-1", nil }})
	identity := Identity{TenantID: "tenant-a", AgentID: "work-agent", CredentialID: "family-1"}
	receipt, err := drafts.Create(context.Background(), identity, CreateChangeDraftRequest{
		Repository: repository.snapshot.Repository, BaseCommit: repository.snapshot.Commit,
		Changes: []changedraft.Change{{Operation: changedraft.Replace, Path: "README.md", Content: []byte("safe replacement\n")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	authority := &draftPublicationAuthority{}
	publisher := NewChangeDraftPublisher(drafts, newDraftPublicationStore(), NewOperationService(authority, nil), func() time.Time { return now })
	result, err := publisher.Publish(context.Background(), identity, PublishChangeDraftRequest{
		Binding:     ChangeDraftBinding{ID: receipt.ID, Repository: receipt.Preview.Repository, BaseCommit: receipt.Preview.BaseCommit, PreviewHash: receipt.Preview.Hash},
		OperationID: "work-push-1", Branch: "feat/work", Message: "feat: safe replacement",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Result.ID != "work-push-1" || authority.request.Operation != "branch.push" || authority.request.ManifestHash != receipt.Preview.Hash {
		t.Fatalf("unexpected submission: result=%+v request=%+v", result, authority.request)
	}
	packet, present, err := commitpacket.Decode(authority.request.Payload)
	if err != nil || !present {
		t.Fatalf("packet=%+v present=%v error=%v", packet, present, err)
	}
	if packet.Tree.BaseTree != string(receipt.Preview.BaseTree) || packet.Tree.SHA != string(receipt.Preview.ResultTree) || packet.Commit.Parents[0] != string(receipt.Preview.BaseCommit) {
		t.Fatalf("packet is not bound to preview: %+v", packet)
	}
	if packet.Commit.Author.Name != identity.AgentID || packet.Commit.Author.Email != "work-agent@gitoversight.invalid" {
		t.Fatalf("unexpected transparent attribution: %+v", packet.Commit.Author)
	}
}
