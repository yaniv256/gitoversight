package mcpapp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
)

type changeDraftsStub struct {
	mu              sync.Mutex
	createCalls     int
	createIdentity  brokerapp.Identity
	createRequest   brokerapp.CreateChangeDraftRequest
	createReceipt   brokerapp.ChangeDraftReceipt
	createErr       error
	resolveCalls    int
	resolveIdentity brokerapp.Identity
	resolveBinding  brokerapp.ChangeDraftBinding
	resolveDraft    changedraft.StoredDraft
	resolveErr      error
}

type changeDraftPublisherStub struct {
	calls    int
	identity brokerapp.Identity
	request  brokerapp.PublishChangeDraftRequest
}

func (stub *changeDraftPublisherStub) Publish(_ context.Context, identity brokerapp.Identity, request brokerapp.PublishChangeDraftRequest) (brokerapp.SubmitResult, error) {
	stub.calls++
	stub.identity, stub.request = identity, request
	return brokerapp.SubmitResult{}, nil
}

func (stub *changeDraftsStub) Create(_ context.Context, identity brokerapp.Identity, request brokerapp.CreateChangeDraftRequest) (brokerapp.ChangeDraftReceipt, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.createCalls++
	stub.createIdentity = identity
	stub.createRequest = request
	return stub.createReceipt, stub.createErr
}

func (stub *changeDraftsStub) Resolve(_ context.Context, identity brokerapp.Identity, binding brokerapp.ChangeDraftBinding) (changedraft.StoredDraft, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.resolveCalls++
	stub.resolveIdentity = identity
	stub.resolveBinding = binding
	return stub.resolveDraft, stub.resolveErr
}

func TestCreateDraftArgumentsDecodeOnlyBoundedPathOperations(t *testing.T) {
	arguments := createDraftArguments{
		Repository: "yaniv256/example",
		BaseCommit: changedraft.ObjectID(strings.Repeat("a", 40)),
		Changes: []draftChangeArgument{
			{Operation: changedraft.Add, Path: "empty.txt", Mode: changedraft.ModeFile},
			{Operation: changedraft.Replace, Path: "README.md", ContentBase64: "aGVsbG8K"},
		},
	}
	request, err := arguments.request()
	if err != nil {
		t.Fatal(err)
	}
	if request.Repository != arguments.Repository || request.BaseCommit != arguments.BaseCommit || len(request.Changes) != 2 {
		t.Fatalf("request=%#v", request)
	}
	if len(request.Changes[0].Content) != 0 || string(request.Changes[1].Content) != "hello\n" {
		t.Fatalf("decoded changes=%#v", request.Changes)
	}
	arguments.Changes[1].ContentBase64 = "not base64!"
	if _, err := arguments.request(); err == nil {
		t.Fatal("invalid base64 accepted")
	}
}

func TestDraftPreviewEnvelopeNeverReturnsSnapshotOrChangedContent(t *testing.T) {
	expires := time.Date(2026, 8, 16, 12, 15, 0, 0, time.UTC)
	preview := changedraft.Preview{
		Repository: "yaniv256/example",
		BaseCommit: changedraft.ObjectID(strings.Repeat("a", 40)),
		ResultTree: changedraft.ObjectID(strings.Repeat("b", 40)),
		Hash:       strings.Repeat("c", 64),
		Result: []changedraft.Entry{{
			Path: "private.txt", Mode: changedraft.ModeFile, Object: changedraft.ObjectID(strings.Repeat("d", 40)),
		}},
		Changes: []changedraft.ChangeSummary{{Operation: changedraft.Replace, Path: "private.txt", Bytes: 18}},
	}
	receipt := receiptEnvelope(brokerapp.ChangeDraftReceipt{ID: "draft-1", Preview: preview, ExpiresAt: expires})
	stored := storedDraftEnvelope(changedraft.StoredDraft{
		ID: "draft-1", Preview: preview, ExpiresAt: expires,
		Changes: []changedraft.Change{{Operation: changedraft.Replace, Path: "private.txt", Content: []byte("private full bytes")}},
	})
	for _, value := range []draftPreviewEnvelope{receipt, stored} {
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(payload), "private full bytes") || strings.Contains(string(payload), `"result"`) || strings.Contains(string(payload), `"content"`) {
			t.Fatalf("compact envelope leaked snapshot/content: %s", payload)
		}
		if !strings.Contains(string(payload), `"preview_hash"`) || !strings.Contains(string(payload), `"changes"`) {
			t.Fatalf("compact envelope missing binding/summary: %s", payload)
		}
	}
}

func TestChangeDraftToolsAuthorizeScopeBeforeServiceAndReturnCompactBindings(t *testing.T) {
	base := changedraft.ObjectID(strings.Repeat("a", 40))
	resultTree := changedraft.ObjectID(strings.Repeat("b", 40))
	previewHash := strings.Repeat("c", 64)
	expires := time.Date(2026, 8, 16, 12, 15, 0, 0, time.UTC)
	preview := changedraft.Preview{
		Repository: "yaniv256/allowed", BaseCommit: base, ResultTree: resultTree, Hash: previewHash,
		Result:  []changedraft.Entry{{Path: "unrelated-private.txt", Mode: changedraft.ModeFile, Object: changedraft.ObjectID(strings.Repeat("d", 40))}},
		Changes: []changedraft.ChangeSummary{{Operation: changedraft.Replace, Path: "README.md", Bytes: 6}},
	}
	drafts := &changeDraftsStub{
		createReceipt: brokerapp.ChangeDraftReceipt{ID: "draft-1", Preview: preview, ExpiresAt: expires},
		resolveDraft: changedraft.StoredDraft{ID: "draft-1", Preview: preview, ExpiresAt: expires,
			Changes: []changedraft.Change{{Operation: changedraft.Replace, Path: "README.md", Content: []byte("secret")}}},
	}
	publisher := &changeDraftPublisherStub{}
	handler := newTestHandler(t, func(config *Config) {
		config.ChangeDrafts = drafts
		config.ChangeDraftPublisher = publisher
		config.Scope = scopeStub{denied: map[string]bool{"yaniv256/denied": true}}
	})
	session := initializeSession(t, handler, "token-a", "client-a")
	markInitialized(t, handler, "token-a", session)

	denied := callTool(t, handler, "token-a", session, 2, "change_draft.create", map[string]any{
		"repository": "yaniv256/denied", "base_commit": string(base),
		"changes": []map[string]any{{"operation": "replace", "path": "README.md", "content_base64": "c2VjcmV0"}},
	})
	if !strings.Contains(denied.Body.String(), `"code":"repository_denied"`) || drafts.createCalls != 0 {
		t.Fatalf("denied=%s calls=%d", denied.Body.String(), drafts.createCalls)
	}

	created := callTool(t, handler, "token-a", session, 3, "change_draft.create", map[string]any{
		"repository": "yaniv256/allowed", "base_commit": string(base),
		"changes": []map[string]any{{"operation": "replace", "path": "README.md", "content_base64": "c2VjcmV0"}},
	})
	if created.Code != http.StatusOK || strings.Contains(created.Body.String(), `"isError":true`) {
		t.Fatalf("created=%d %s", created.Code, created.Body.String())
	}
	if drafts.createCalls != 1 || drafts.createIdentity.AgentID != "zara" || drafts.createRequest.Repository != "yaniv256/allowed" || string(drafts.createRequest.Changes[0].Content) != "secret" {
		t.Fatalf("create identity=%+v request=%+v calls=%d", drafts.createIdentity, drafts.createRequest, drafts.createCalls)
	}
	if strings.Contains(created.Body.String(), "unrelated-private.txt") || strings.Contains(created.Body.String(), "c2VjcmV0") || strings.Contains(created.Body.String(), "secret") {
		t.Fatalf("create leaked snapshot/content: %s", created.Body.String())
	}
	for _, expected := range []string{"draft-1", string(base), string(resultTree), previewHash, "README.md"} {
		if !strings.Contains(created.Body.String(), expected) {
			t.Fatalf("create missing %q: %s", expected, created.Body.String())
		}
	}

	inspected := callTool(t, handler, "token-a", session, 4, "change_draft.inspect", map[string]any{
		"draft_id": "draft-1", "repository": "yaniv256/allowed", "base_commit": string(base), "preview_hash": previewHash,
	})
	if inspected.Code != http.StatusOK || strings.Contains(inspected.Body.String(), `"isError":true`) || strings.Contains(inspected.Body.String(), "secret") || strings.Contains(inspected.Body.String(), "unrelated-private.txt") {
		t.Fatalf("inspect=%d %s", inspected.Code, inspected.Body.String())
	}
	if drafts.resolveCalls != 1 || drafts.resolveIdentity.AgentID != "zara" || drafts.resolveBinding.PreviewHash != previewHash {
		t.Fatalf("resolve identity=%+v binding=%+v calls=%d", drafts.resolveIdentity, drafts.resolveBinding, drafts.resolveCalls)
	}

	published := callTool(t, handler, "token-a", session, 5, "change_draft.publish", map[string]any{
		"draft_id": "draft-1", "repository": "yaniv256/allowed", "base_commit": string(base), "preview_hash": previewHash,
		"operation_id": "push-1", "branch": "feat/work", "message": "feat: publish draft",
	})
	if published.Code != http.StatusOK || strings.Contains(published.Body.String(), `"isError":true`) {
		t.Fatalf("publish=%d %s", published.Code, published.Body.String())
	}
	if publisher.calls != 1 || publisher.identity.AgentID != "zara" || publisher.request.OperationID != "push-1" || publisher.request.Binding.PreviewHash != previewHash {
		t.Fatalf("publisher identity=%+v request=%+v calls=%d", publisher.identity, publisher.request, publisher.calls)
	}
}

func TestChangeDraftToolsReturnStableErrorsWithoutCallingOnInvalidInput(t *testing.T) {
	drafts := &changeDraftsStub{createErr: brokerapp.ErrChangeDraftStaleBase}
	handler := newTestHandler(t, func(config *Config) { config.ChangeDrafts = drafts })
	session := initializeSession(t, handler, "token-a", "client-a")
	markInitialized(t, handler, "token-a", session)
	base := strings.Repeat("a", 40)

	invalid := callTool(t, handler, "token-a", session, 2, "change_draft.create", map[string]any{
		"repository": "yaniv256/allowed", "base_commit": base,
		"changes": []map[string]any{{"operation": "replace", "path": "README.md", "content_base64": "not base64"}},
	})
	if !strings.Contains(invalid.Body.String(), `"code":"invalid_arguments"`) || drafts.createCalls != 0 {
		t.Fatalf("invalid=%s calls=%d", invalid.Body.String(), drafts.createCalls)
	}
	stale := callTool(t, handler, "token-a", session, 3, "change_draft.create", map[string]any{
		"repository": "yaniv256/allowed", "base_commit": base,
		"changes": []map[string]any{{"operation": "replace", "path": "README.md", "content_base64": ""}},
	})
	if !strings.Contains(stale.Body.String(), `"code":"change_draft_stale_base"`) || drafts.createCalls != 1 {
		t.Fatalf("stale=%s calls=%d", stale.Body.String(), drafts.createCalls)
	}
	if !errors.Is(drafts.createErr, brokerapp.ErrChangeDraftStaleBase) {
		t.Fatal("stub setup lost stable error")
	}
}

func TestToolCatalogStaysWithinRemoteAgentTokenBudget(t *testing.T) {
	payload, err := json.Marshal(toolCatalog(true, true, true, true))
	if err != nil {
		t.Fatal(err)
	}
	const maxCatalogBytes = 12 << 10
	const maxApproxTokens = 3072
	approxTokens := (len(payload) + 3) / 4
	if len(payload) > maxCatalogBytes || approxTokens > maxApproxTokens {
		t.Fatalf("catalog bytes=%d approx_tokens=%d, limits=%d/%d", len(payload), approxTokens, maxCatalogBytes, maxApproxTokens)
	}
	t.Logf("catalog bytes=%d approximate tokens=%d", len(payload), approxTokens)
}
