package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
)

const releaseAssetPrefix = "/v1/release-assets/"

var (
	releaseAssetNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	repositoryPattern       = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	stageIDPattern          = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type ReleaseAssetUploadAuthenticator interface {
	Verify(*http.Request) (agentauth.Identity, string, time.Time, error)
}

type ReleaseAssetAuthority interface {
	CreateStagedAsset(context.Context, releaseasset.Stage) error
	BeginStagedAssetUpload(context.Context, releaseasset.Stage, string, string, time.Time, time.Time) error
	MarkStagedAssetReady(context.Context, releaseasset.Stage, string, time.Time) error
	AbandonStagedAsset(context.Context, releaseasset.Stage, time.Time) error
}

type ReleaseAssetHandlerConfig struct {
	Authority        ReleaseAssetAuthority
	Reader           releaseasset.MetadataReader
	Files            *releaseasset.FileStore
	UploadAuth       ReleaseAssetUploadAuthenticator
	MaxMetadataBytes int64
	MaxAssetBytes    int64
	CapabilityTTL    time.Duration
	StageTTL         time.Duration
	// UploadTimeout is the route-specific streaming deadline. It overrides the
	// shared API server's shorter ordinary-request deadline for raw asset bytes.
	UploadTimeout time.Duration
	Now           func() time.Time
}

type ReleaseAssetHandler struct {
	config ReleaseAssetHandlerConfig
}

type releaseAssetIssueRequest struct {
	Repository  string `json:"repository"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

func NewReleaseAssetHandler(config ReleaseAssetHandlerConfig) (*ReleaseAssetHandler, error) {
	if config.Authority == nil || config.Reader == nil || config.Files == nil || config.UploadAuth == nil {
		return nil, errors.New("release asset storage and authentication are required")
	}
	if config.MaxMetadataBytes <= 0 || config.MaxAssetBytes <= 0 {
		return nil, errors.New("positive release asset limits are required")
	}
	if config.CapabilityTTL <= 0 || config.StageTTL <= config.CapabilityTTL {
		return nil, errors.New("release asset lifecycle is invalid")
	}
	if config.UploadTimeout <= 0 {
		config.UploadTimeout = 30 * time.Minute
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &ReleaseAssetHandler{config: config}, nil
}

func (handler *ReleaseAssetHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch {
	case request.URL.Path == "/v1/release-assets" && request.Method == http.MethodPost:
		handler.issue(response, request)
	case request.Method == http.MethodGet:
		handler.status(response, request)
	case request.Method == http.MethodDelete:
		handler.abandon(response, request)
	case strings.HasPrefix(request.URL.Path, releaseAssetPrefix) &&
		strings.HasSuffix(request.URL.Path, "/content") && request.Method == http.MethodPut:
		handler.upload(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (handler *ReleaseAssetHandler) status(response http.ResponseWriter, request *http.Request) {
	stage, ok := handler.ownerStage(response, request)
	if !ok {
		return
	}
	writeReleaseAssetJSON(response, http.StatusOK, safeStage(stage))
}

func (handler *ReleaseAssetHandler) abandon(response http.ResponseWriter, request *http.Request) {
	stage, ok := handler.ownerStage(response, request)
	if !ok {
		return
	}
	if stage.State == releaseasset.StatePinned {
		writeReleaseAssetError(response, http.StatusConflict, "release asset stage is pinned by an operation")
		return
	}
	if stage.State != releaseasset.StateAbandoned {
		if err := handler.config.Authority.AbandonStagedAsset(request.Context(), stage, handler.config.Now().UTC()); err != nil {
			writeReleaseAssetError(response, http.StatusConflict, "release asset stage cannot be abandoned")
			return
		}
		stage.State = releaseasset.StateAbandoned
		stage.UpdatedAt = handler.config.Now().UTC()
	}
	writeReleaseAssetJSON(response, http.StatusOK, safeStage(stage))
}

func (handler *ReleaseAssetHandler) ownerStage(response http.ResponseWriter, request *http.Request) (releaseasset.Stage, bool) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeReleaseAssetError(response, http.StatusUnauthorized, "unauthorized")
		return releaseasset.Stage{}, false
	}
	stageID := strings.TrimPrefix(request.URL.Path, releaseAssetPrefix)
	repository := request.URL.Query().Get("repository")
	if !stageIDPattern.MatchString(stageID) || !repositoryPattern.MatchString(repository) {
		writeReleaseAssetError(response, http.StatusNotFound, "release asset stage not found")
		return releaseasset.Stage{}, false
	}
	stage, err := handler.config.Reader.StagedAssetForOwner(
		request.Context(), identity.TenantID, stageID, identity.AgentID, identity.CredentialID, repository,
	)
	if err != nil {
		writeReleaseAssetError(response, http.StatusNotFound, "release asset stage not found")
		return releaseasset.Stage{}, false
	}
	return stage, true
}

func safeStage(stage releaseasset.Stage) map[string]any {
	result := map[string]any{
		"stage_id": stage.ID, "state": stage.State, "repository": stage.Repository,
		"name": stage.Name, "content_type": stage.ContentType, "size": stage.ExpectedSize,
		"sha256": stage.ExpectedSHA256, "expires_at": stage.ExpiresAt,
	}
	if stage.OperationID != "" {
		result["operation_id"] = stage.OperationID
	}
	return result
}

func (handler *ReleaseAssetHandler) issue(response http.ResponseWriter, request *http.Request) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeReleaseAssetError(response, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input releaseAssetIssueRequest
	body := http.MaxBytesReader(response, request.Body, handler.config.MaxMetadataBytes)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeReleaseAssetError(response, http.StatusBadRequest, "invalid release asset metadata")
		return
	}
	if err := requireJSONEnd(decoder); err != nil {
		writeReleaseAssetError(response, http.StatusBadRequest, "invalid release asset metadata")
		return
	}
	name, contentType, err := canonicalReleaseAssetMetadata(input.Name, input.ContentType)
	if err != nil || !repositoryPattern.MatchString(input.Repository) ||
		input.Size < 0 || input.Size >= handler.config.MaxAssetBytes ||
		input.SHA256 != strings.ToLower(input.SHA256) || !isSHA256(input.SHA256) {
		writeReleaseAssetError(response, http.StatusBadRequest, "invalid release asset metadata")
		return
	}
	stageID, err := randomOpaque(16)
	if err != nil {
		writeReleaseAssetError(response, http.StatusServiceUnavailable, "release asset staging unavailable")
		return
	}
	capability, err := randomCapability()
	if err != nil {
		writeReleaseAssetError(response, http.StatusServiceUnavailable, "release asset staging unavailable")
		return
	}
	capabilityDigest := sha256.Sum256([]byte(capability))
	now := handler.config.Now().UTC()
	stage := releaseasset.Stage{
		TenantID: identity.TenantID, ID: stageID, AgentID: identity.AgentID, CredentialID: identity.CredentialID,
		Repository: input.Repository, Name: name, ContentType: contentType,
		ExpectedSHA256: input.SHA256, ExpectedSize: input.Size, ReservedSize: input.Size,
		State: releaseasset.StateCreated, CapabilityHash: hex.EncodeToString(capabilityDigest[:]),
		CapabilityExpiresAt: now.Add(handler.config.CapabilityTTL),
		CreatedAt:           now, UpdatedAt: now, ExpiresAt: now.Add(handler.config.StageTTL),
	}
	if err := releaseasset.ValidateStage(stage); err != nil {
		writeReleaseAssetError(response, http.StatusBadRequest, "invalid release asset metadata")
		return
	}
	if err := handler.config.Authority.CreateStagedAsset(request.Context(), stage); err != nil {
		writeReleaseAssetError(response, http.StatusServiceUnavailable, "release asset staging unavailable")
		return
	}
	writeReleaseAssetJSON(response, http.StatusCreated, map[string]any{
		"stage_id": stage.ID, "upload_capability": capability,
		"capability_expires_at": stage.CapabilityExpiresAt,
		"upload_path":           releaseAssetPrefix + stage.ID + "/content",
	})
}

func (handler *ReleaseAssetHandler) upload(response http.ResponseWriter, request *http.Request) {
	stageID, ok := uploadStageID(request.URL.Path)
	if !ok || !validRawUploadFraming(request, handler.config.MaxAssetBytes) {
		writeReleaseAssetError(response, http.StatusBadRequest, "invalid upload request")
		return
	}
	identity, nonce, nonceExpiresAt, err := handler.config.UploadAuth.Verify(request)
	if err != nil {
		writeReleaseAssetError(response, http.StatusUnauthorized, "unauthorized")
		return
	}
	repository := request.Header.Get(agentauth.HeaderRepository)
	stage, err := handler.config.Reader.StagedAssetForOwner(
		request.Context(), identity.TenantID, stageID, identity.AgentID, identity.CredentialID, repository,
	)
	if err != nil {
		writeReleaseAssetError(response, http.StatusNotFound, "release asset stage not found")
		return
	}
	capability, ok := bearerCapability(request.Header.Get("Authorization"))
	if !ok || !capabilityMatches(capability, stage.CapabilityHash) ||
		stage.State != releaseasset.StateCreated || !handler.config.Now().UTC().Before(stage.CapabilityExpiresAt) ||
		request.ContentLength != stage.ExpectedSize ||
		request.Header.Get(agentauth.HeaderAssetSize) != strconv.FormatInt(stage.ExpectedSize, 10) ||
		request.Header.Get(agentauth.HeaderAssetSHA256) != stage.ExpectedSHA256 ||
		request.Header.Get("Content-Type") != stage.ContentType {
		writeReleaseAssetError(response, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := handler.configureUploadDeadline(response); err != nil {
		writeReleaseAssetError(response, http.StatusServiceUnavailable, "release asset upload unavailable")
		return
	}
	attemptID, err := randomOpaque(16)
	if err != nil {
		writeReleaseAssetError(response, http.StatusServiceUnavailable, "release asset staging unavailable")
		return
	}
	now := handler.config.Now().UTC()
	if err := handler.config.Authority.BeginStagedAssetUpload(request.Context(), stage, attemptID, nonce, nonceExpiresAt, now); err != nil {
		writeReleaseAssetError(response, http.StatusConflict, "release asset capability already used")
		return
	}
	object, publishErr := handler.config.Files.Publish(
		request.Context(), stage.TenantID, stage.ID, stage.ExpectedSize, stage.ExpectedSHA256,
		http.MaxBytesReader(response, request.Body, stage.ExpectedSize),
	)
	if publishErr != nil {
		log.Printf(
			"release asset upload failed stage=%s repository=%s category=%s",
			stage.ID,
			stage.Repository,
			releaseAssetUploadFailureCategory(publishErr),
		)
		handler.abandonAfterUploadFailure(stage)
		writeReleaseAssetError(response, http.StatusUnprocessableEntity, "release asset upload failed")
		return
	}
	if err := handler.config.Authority.MarkStagedAssetReady(request.Context(), stage, object.Key, handler.config.Now().UTC()); err != nil {
		handler.abandonAfterUploadFailure(stage)
		writeReleaseAssetError(response, http.StatusServiceUnavailable, "release asset staging unavailable")
		return
	}
	writeReleaseAssetJSON(response, http.StatusCreated, map[string]any{
		"stage_id": stage.ID, "state": releaseasset.StateReady,
		"size": object.Size, "sha256": object.SHA256,
	})
}

func (handler *ReleaseAssetHandler) configureUploadDeadline(response http.ResponseWriter) error {
	deadline := handler.config.Now().UTC().Add(handler.config.UploadTimeout)
	controller := http.NewResponseController(response)
	if err := controller.SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	if err := controller.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}

// releaseAssetUploadFailureCategory keeps operator-visible diagnostics useful
// without logging asset names, paths, capabilities, hashes, or raw errors.
func releaseAssetUploadFailureCategory(err error) string {
	switch {
	case errors.Is(err, releaseasset.ErrIntegrity):
		return "integrity"
	case errors.Is(err, releaseasset.ErrObjectExists):
		return "object_exists"
	case errors.Is(err, releaseasset.ErrUnsafeObject):
		return "unsafe_object"
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "context_deadline"
	default:
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			return "storage_" + safeReleaseAssetStorageOperation(pathErr.Op) + "_" + safeReleaseAssetStorageErrno(pathErr.Err)
		}
		return "storage"
	}
}

func safeReleaseAssetStorageOperation(operation string) string {
	switch operation {
	case "open", "link", "remove", "chmod", "mkdir", "sync":
		return operation
	default:
		return "other"
	}
}

func safeReleaseAssetStorageErrno(err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, os.ErrExist):
		return "exists"
	case errors.Is(err, os.ErrNotExist):
		return "not_exist"
	default:
		return "other"
	}

}

func (handler *ReleaseAssetHandler) abandonAfterUploadFailure(stage releaseasset.Stage) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = handler.config.Authority.AbandonStagedAsset(ctx, stage, handler.config.Now().UTC())
}

func canonicalReleaseAssetMetadata(name, contentType string) (string, string, error) {
	if name != strings.TrimSpace(name) || !releaseAssetNamePattern.MatchString(name) ||
		name == "." || name == ".." || path.Base(name) != name {
		return "", "", errors.New("invalid filename")
	}
	parsed, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || len(parameters) != 0 || parsed != contentType || parsed != strings.ToLower(parsed) ||
		!strings.Contains(parsed, "/") || len(parsed) > 127 {
		return "", "", errors.New("invalid content type")
	}
	return name, parsed, nil
}

func validRawUploadFraming(request *http.Request, maxBytes int64) bool {
	if request.URL == nil || request.URL.IsAbs() || request.RequestURI == "" ||
		strings.HasPrefix(request.RequestURI, "http://") || strings.HasPrefix(request.RequestURI, "https://") ||
		request.ContentLength < 0 || request.ContentLength >= maxBytes ||
		len(request.TransferEncoding) != 0 ||
		len(request.Trailer) != 0 || len(request.Header.Values("Trailer")) != 0 ||
		len(request.Header.Values("Content-Encoding")) != 0 ||
		strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "multipart/") {
		return false
	}
	expectValues := request.Header.Values("Expect")
	if len(expectValues) > 1 || (len(expectValues) == 1 && !strings.EqualFold(strings.TrimSpace(expectValues[0]), "100-continue")) {
		return false
	}
	contentLengthValues := request.Header.Values("Content-Length")
	if len(contentLengthValues) > 1 ||
		(len(contentLengthValues) == 1 && contentLengthValues[0] != strconv.FormatInt(request.ContentLength, 10)) {
		return false
	}
	sizeValues := request.Header.Values(agentauth.HeaderAssetSize)
	return len(sizeValues) == 1 && sizeValues[0] == strconv.FormatInt(request.ContentLength, 10)
}

func uploadStageID(requestPath string) (string, bool) {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(requestPath, releaseAssetPrefix), "/content")
	return trimmed, stageIDPattern.MatchString(trimmed)
}

func bearerCapability(value string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) || strings.Contains(strings.TrimPrefix(value, prefix), " ") {
		return "", false
	}
	token := strings.TrimPrefix(value, prefix)
	return token, token != ""
}

func capabilityMatches(capability, encodedHash string) bool {
	actual := sha256.Sum256([]byte(capability))
	expected, err := hex.DecodeString(encodedHash)
	return err == nil && len(expected) == sha256.Size &&
		subtle.ConstantTimeCompare(actual[:], expected) == 1
}

func isSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func randomOpaque(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func randomCapability() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func requireJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func writeReleaseAssetJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeReleaseAssetError(response http.ResponseWriter, status int, message string) {
	writeReleaseAssetJSON(response, status, map[string]string{"error": message})
}
