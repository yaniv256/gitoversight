package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type staticUploadAuthenticator struct {
	identity agentauth.Identity
	err      error
}

type testReleaseAssetAuthority struct {
	store storage.Store
}

func (authority testReleaseAssetAuthority) CreateStagedAsset(ctx context.Context, stage releaseasset.Stage) error {
	return authority.store.WithTx(ctx, func(tx storage.Transaction) error { return tx.PutStagedAsset(ctx, stage) })
}
func (authority testReleaseAssetAuthority) BeginStagedAssetUpload(ctx context.Context, stage releaseasset.Stage, attemptID, nonce string, nonceExpiresAt, at time.Time) error {
	return authority.store.WithTx(ctx, func(tx storage.Transaction) error {
		if err := tx.ConsumeNonce(ctx, stage.TenantID, stage.CredentialID, nonce, nonceExpiresAt); err != nil {
			return err
		}
		return tx.BeginStagedAssetUpload(ctx, stage.TenantID, stage.ID, attemptID, at)
	})
}
func (authority testReleaseAssetAuthority) MarkStagedAssetReady(ctx context.Context, stage releaseasset.Stage, objectKey string, at time.Time) error {
	return authority.store.WithTx(ctx, func(tx storage.Transaction) error {
		return tx.MarkStagedAssetReady(ctx, stage.TenantID, stage.ID, objectKey, at)
	})
}
func (authority testReleaseAssetAuthority) AbandonStagedAsset(ctx context.Context, stage releaseasset.Stage, at time.Time) error {
	return authority.store.WithTx(ctx, func(tx storage.Transaction) error {
		return tx.AbandonStagedAsset(ctx, stage.TenantID, stage.ID, at)
	})
}

func (auth staticUploadAuthenticator) Verify(*http.Request) (agentauth.Identity, string, time.Time, error) {
	return auth.identity, "test-nonce", time.Now().Add(time.Minute), auth.err
}

type countingBody struct {
	reader io.Reader
	reads  int
}

func (body *countingBody) Read(payload []byte) (int, error) {
	body.reads++
	return body.reader.Read(payload)
}
func (*countingBody) Close() error { return nil }

type deadlineResponseWriter struct {
	*httptest.ResponseRecorder
	readDeadline  time.Time
	writeDeadline time.Time
}

func (writer *deadlineResponseWriter) SetReadDeadline(deadline time.Time) error {
	writer.readDeadline = deadline
	return nil
}

func (writer *deadlineResponseWriter) SetWriteDeadline(deadline time.Time) error {
	writer.writeDeadline = deadline
	return nil
}

func TestReleaseAssetUploadExtendsSharedServerDeadline(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	timeout := 30 * time.Minute
	handler := &ReleaseAssetHandler{config: ReleaseAssetHandlerConfig{
		UploadTimeout: timeout,
		Now:           func() time.Time { return now },
		MaxAssetBytes: 2 << 30,
	}}
	response := &deadlineResponseWriter{ResponseRecorder: httptest.NewRecorder()}

	if err := handler.configureUploadDeadline(response); err != nil {
		t.Fatal(err)
	}

	want := now.Add(timeout)
	if !response.readDeadline.Equal(want) || !response.writeDeadline.Equal(want) {
		t.Fatalf("stream deadlines = read %v write %v, want %v", response.readDeadline, response.writeDeadline, want)
	}
}

func TestReleaseAssetIssueAndRawUpload(t *testing.T) {
	ctx := context.Background()
	db := openReleaseAssetTestDB(t)
	files, err := releaseasset.NewFileStore(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_780_000_000, 0).UTC()
	identity := agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-1"}
	handler, err := NewReleaseAssetHandler(ReleaseAssetHandlerConfig{
		Authority: testReleaseAssetAuthority{store: db.Store()}, Reader: db, Files: files,
		UploadAuth:       staticUploadAuthenticator{identity: identity},
		MaxMetadataBytes: 4096, MaxAssetBytes: 2 << 30, CapabilityTTL: 10 * time.Minute,
		StageTTL: time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("stream-me-"), 256*1024)
	digest := sha256.Sum256(payload)
	issue := httptest.NewRequest(http.MethodPost, "/v1/release-assets", strings.NewReader(`{
		"repository":"yaniv256/private",
		"name":"gitoversightctl-linux-amd64",
		"content_type":"application/octet-stream",
		"size":`+jsonInt64(int64(len(payload)))+`,
		"sha256":"`+hex.EncodeToString(digest[:])+`"
	}`))
	issue = issue.WithContext(agentauth.WithIdentityForTrustedBoundary(issue.Context(), identity))
	issue.Header.Set("Content-Type", "application/json")
	issueResponse := httptest.NewRecorder()
	handler.ServeHTTP(issueResponse, issue)
	if issueResponse.Code != http.StatusCreated {
		t.Fatalf("issue = %d: %s", issueResponse.Code, issueResponse.Body.String())
	}
	var issued struct {
		StageID    string `json:"stage_id"`
		Capability string `json:"upload_capability"`
	}
	if err := json.Unmarshal(issueResponse.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.StageID == "" || issued.Capability == "" {
		t.Fatalf("issued = %+v", issued)
	}

	upload := httptest.NewRequest(http.MethodPut, "/v1/release-assets/"+issued.StageID+"/content", bytes.NewReader(payload))
	upload.ContentLength = int64(len(payload))
	upload.Header.Set("Content-Length", jsonInt64(int64(len(payload))))
	upload.Header.Set("Content-Type", "application/octet-stream")
	upload.Header.Set(agentauth.HeaderRepository, "yaniv256/private")
	upload.Header.Set(agentauth.HeaderAssetSize, jsonInt64(int64(len(payload))))
	upload.Header.Set(agentauth.HeaderAssetSHA256, hex.EncodeToString(digest[:]))
	upload.Header.Set("Authorization", "Bearer "+issued.Capability)
	uploadResponse := httptest.NewRecorder()
	handler.ServeHTTP(uploadResponse, upload)
	if uploadResponse.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", uploadResponse.Code, uploadResponse.Body.String())
	}
	stage, err := db.StagedAssetForOwner(ctx, "tenant-a", issued.StageID, "zara", "zara-1", "yaniv256/private")
	if err != nil {
		t.Fatal(err)
	}
	if stage.State != storage.StagedAssetReady || stage.ObjectKey == "" || stage.ReservedSize != 0 {
		t.Fatalf("stage = %+v", stage)
	}
	object, err := files.Open(ctx, "tenant-a", issued.StageID, int64(len(payload)), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	got, err := io.ReadAll(object)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("object mismatch: err=%v size=%d", err, len(got))
	}
}

func TestReleaseAssetUploadFailureCategoryDoesNotExposeRawErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "integrity", err: releaseasset.ErrIntegrity, want: "integrity"},
		{name: "wrapped integrity", err: fmt.Errorf("secret path: %w", releaseasset.ErrIntegrity), want: "integrity"},
		{name: "object exists", err: releaseasset.ErrObjectExists, want: "object_exists"},
		{name: "unsafe object", err: releaseasset.ErrUnsafeObject, want: "unsafe_object"},
		{name: "canceled", err: context.Canceled, want: "context_canceled"},
		{name: "deadline", err: context.DeadlineExceeded, want: "context_deadline"},
		{name: "path permission", err: &os.PathError{Op: "open", Path: "/private/path/secret", Err: os.ErrPermission}, want: "storage_open_permission"},
		{name: "unknown path details", err: &os.PathError{Op: "rename-secret", Path: "/private/path/secret", Err: errors.New("secret errno")}, want: "storage_other_other"},
		{name: "opaque storage error", err: errors.New("/private/path/secret"), want: "storage"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := releaseAssetUploadFailureCategory(test.err); got != test.want {
				t.Fatalf("category = %q, want %q", got, test.want)
			}
		})
	}
}

func TestReleaseAssetIssueUsesGitHubBoundaryWithoutLowerProductLimit(t *testing.T) {
	const githubLimit = int64(2 << 30)
	db := openReleaseAssetTestDB(t)
	files, err := releaseasset.NewFileStore(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	identity := agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-1"}
	handler, err := NewReleaseAssetHandler(ReleaseAssetHandlerConfig{
		Authority: testReleaseAssetAuthority{store: db.Store()}, Reader: db, Files: files,
		UploadAuth: staticUploadAuthenticator{identity: identity}, MaxMetadataBytes: 4096,
		MaxAssetBytes: githubLimit, CapabilityTTL: time.Minute, StageTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	if stageID, _ := issueReleaseAsset(t, handler, identity, githubLimit-1, digest); stageID == "" {
		t.Fatal("GitHub's largest accepted asset size was rejected")
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/release-assets", strings.NewReader(`{
		"repository":"yaniv256/private","name":"too-large.bin","content_type":"application/octet-stream",
		"size":`+jsonInt64(githubLimit)+`,"sha256":"`+digest+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), identity))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("GitHub limit status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestReleaseAssetStatusAndAbandonAreOwnerScopedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	db := openReleaseAssetTestDB(t)
	files, err := releaseasset.NewFileStore(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_780_000_000, 0).UTC()
	identity := agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-1"}
	handler, err := NewReleaseAssetHandler(ReleaseAssetHandlerConfig{
		Authority: testReleaseAssetAuthority{store: db.Store()}, Reader: db, Files: files,
		UploadAuth: staticUploadAuthenticator{identity: identity}, MaxMetadataBytes: 4096,
		MaxAssetBytes: 2 << 30, CapabilityTTL: 10 * time.Minute, StageTTL: time.Hour,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	stage := releaseasset.Stage{
		TenantID: identity.TenantID, ID: "0123456789abcdef0123456789abcdef",
		AgentID: identity.AgentID, CredentialID: identity.CredentialID,
		Repository: "yaniv256/private", Name: "bridge.zip", ContentType: "application/zip",
		ExpectedSHA256: strings.Repeat("a", 64), ExpectedSize: 42, ReservedSize: 42,
		State: releaseasset.StateCreated, CapabilityHash: strings.Repeat("b", 64),
		CapabilityExpiresAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := (testReleaseAssetAuthority{store: db.Store()}).CreateStagedAsset(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := db.Store().WithTx(ctx, func(tx storage.Transaction) error {
		if err := tx.BeginStagedAssetUpload(ctx, stage.TenantID, stage.ID, "attempt", now.Add(time.Second)); err != nil {
			return err
		}
		return tx.MarkStagedAssetReady(ctx, stage.TenantID, stage.ID, "object-key", now.Add(2*time.Second))
	}); err != nil {
		t.Fatal(err)
	}
	call := func(method string, who agentauth.Identity, repository string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "/v1/release-assets/"+stage.ID+"?repository="+repository, nil)
		request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), who))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := call(http.MethodGet, identity, stage.Repository); response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"state":"ready"`) ||
		strings.Contains(response.Body.String(), "capability") {
		t.Fatalf("status = %d %s", response.Code, response.Body.String())
	}
	foreign := identity
	foreign.AgentID = "other"
	if response := call(http.MethodGet, foreign, stage.Repository); response.Code != http.StatusNotFound {
		t.Fatalf("foreign status = %d %s", response.Code, response.Body.String())
	}
	for attempt := 0; attempt < 2; attempt++ {
		if response := call(http.MethodDelete, identity, stage.Repository); response.Code != http.StatusOK ||
			!strings.Contains(response.Body.String(), `"state":"abandoned"`) {
			t.Fatalf("abandon %d = %d %s", attempt, response.Code, response.Body.String())
		}
	}
}

func TestReleaseAssetRejectsBeforeReadingBodyAndCapabilityIsOneAttempt(t *testing.T) {
	db := openReleaseAssetTestDB(t)
	files, err := releaseasset.NewFileStore(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	identity := agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-1"}
	handler, err := NewReleaseAssetHandler(ReleaseAssetHandlerConfig{
		Authority: testReleaseAssetAuthority{store: db.Store()}, Reader: db, Files: files,
		UploadAuth:       staticUploadAuthenticator{identity: identity},
		MaxMetadataBytes: 4096, MaxAssetBytes: 1024, CapabilityTTL: time.Minute, StageTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello")
	digest := sha256.Sum256(payload)
	stageID, capability := issueReleaseAsset(t, handler, identity, int64(len(payload)), hex.EncodeToString(digest[:]))

	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "wrong capability", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }},
		{name: "transfer encoding", mutate: func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
		{name: "content encoding", mutate: func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{name: "wrong length", mutate: func(r *http.Request) { r.ContentLength = 4; r.Header.Set("Content-Length", "4") }},
		{name: "unexpected expect", mutate: func(r *http.Request) { r.Header.Set("Expect", "something-else") }},
		{name: "duplicate content length", mutate: func(r *http.Request) {
			r.Header["Content-Length"] = []string{jsonInt64(int64(len(payload))), jsonInt64(int64(len(payload)))}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &countingBody{reader: bytes.NewReader(payload)}
			request := httptest.NewRequest(http.MethodPut, "/v1/release-assets/"+stageID+"/content", nil)
			request.Body = body
			request.ContentLength = int64(len(payload))
			request.Header.Set("Content-Length", jsonInt64(int64(len(payload))))
			request.Header.Set("Content-Type", "application/octet-stream")
			request.Header.Set(agentauth.HeaderRepository, "yaniv256/private")
			request.Header.Set(agentauth.HeaderAssetSize, jsonInt64(int64(len(payload))))
			request.Header.Set(agentauth.HeaderAssetSHA256, hex.EncodeToString(digest[:]))
			request.Header.Set("Authorization", "Bearer "+capability)
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code < 400 {
				t.Fatalf("status = %d", response.Code)
			}
			if body.reads != 0 {
				t.Fatalf("body reads = %d, want zero", body.reads)
			}
		})
	}

	success := httptest.NewRequest(http.MethodPut, "/v1/release-assets/"+stageID+"/content", bytes.NewReader(payload))
	setReleaseAssetUploadHeaders(success, capability, int64(len(payload)), hex.EncodeToString(digest[:]))
	successResponse := httptest.NewRecorder()
	handler.ServeHTTP(successResponse, success)
	if successResponse.Code != http.StatusCreated {
		t.Fatalf("first attempt = %d: %s", successResponse.Code, successResponse.Body.String())
	}
	replayBody := &countingBody{reader: bytes.NewReader(payload)}
	replay := httptest.NewRequest(http.MethodPut, "/v1/release-assets/"+stageID+"/content", nil)
	replay.Body = replayBody
	setReleaseAssetUploadHeaders(replay, capability, int64(len(payload)), hex.EncodeToString(digest[:]))
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, replay)
	if replayResponse.Code < 400 || replayBody.reads != 0 {
		t.Fatalf("replay status=%d body_reads=%d", replayResponse.Code, replayBody.reads)
	}
}

func TestReleaseAssetIssueRejectsNonCanonicalDisplayMetadata(t *testing.T) {
	db := openReleaseAssetTestDB(t)
	files, err := releaseasset.NewFileStore(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	identity := agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-1"}
	handler, err := NewReleaseAssetHandler(ReleaseAssetHandlerConfig{
		Authority: testReleaseAssetAuthority{store: db.Store()}, Reader: db, Files: files,
		UploadAuth:       staticUploadAuthenticator{identity: identity},
		MaxMetadataBytes: 4096, MaxAssetBytes: 1024, CapabilityTTL: time.Minute, StageTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		`{"repository":"yaniv256/private","name":"../asset.bin","content_type":"application/octet-stream","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}`,
		`{"repository":"yaniv256/private","name":"asset\u202Ebin","content_type":"application/octet-stream","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}`,
		`{"repository":"yaniv256/private","name":"asset.bin","content_type":"application/octet-stream; charset=utf-8","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}`,
		`{"repository":"yaniv256/private","name":"asset.bin","content_type":"Application/Octet-Stream","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/release-assets", strings.NewReader(input))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), identity))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("input %q status = %d", input, response.Code)
		}
	}
}

func TestNetHTTPRejectsConflictingContentLengthBeforeRawUploadHandler(t *testing.T) {
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, err = io.WriteString(connection,
		"PUT /v1/release-assets/0123456789abcdef0123456789abcdef/content HTTP/1.1\r\n"+
			"Host: "+address+"\r\nContent-Length: 5\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello!")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodPut})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || called.Load() {
		t.Fatalf("status=%d handler_called=%t", response.StatusCode, called.Load())
	}
}

func openReleaseAssetTestDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "broker.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		if err := tx.EnsureTenant(context.Background(), "tenant-a", time.Now().UTC()); err != nil {
			return err
		}
		return tx.PutAgentCredential(context.Background(), storage.AgentCredential{
			TenantID: "tenant-a", AgentID: "zara", ID: "zara-1", PublicKey: bytes.Repeat([]byte{1}, 32),
			CreatedAt: time.Now().UTC(), ApprovedAt: time.Now().UTC(), ApprovedBy: "yaniv",
		})
	}); err != nil {
		t.Fatal(err)
	}
	return db
}

func issueReleaseAsset(t *testing.T, handler http.Handler, identity agentauth.Identity, size int64, digest string) (string, string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/release-assets", strings.NewReader(`{
		"repository":"yaniv256/private","name":"asset.bin","content_type":"application/octet-stream",
		"size":`+jsonInt64(size)+`,"sha256":"`+digest+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), identity))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("issue = %d: %s", response.Code, response.Body.String())
	}
	var result struct {
		StageID    string `json:"stage_id"`
		Capability string `json:"upload_capability"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.StageID, result.Capability
}

func setReleaseAssetUploadHeaders(request *http.Request, capability string, size int64, digest string) {
	request.ContentLength = size
	request.Header.Set("Content-Length", jsonInt64(size))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set(agentauth.HeaderRepository, "yaniv256/private")
	request.Header.Set(agentauth.HeaderAssetSize, jsonInt64(size))
	request.Header.Set(agentauth.HeaderAssetSHA256, digest)
	request.Header.Set("Authorization", "Bearer "+capability)
}

func jsonInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}
