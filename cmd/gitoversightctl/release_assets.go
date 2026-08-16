package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
)

const releaseAssetUploadPathPrefix = "/v1/release-assets/"

type releaseAssetMetadata struct {
	Repository  string `json:"repository"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

type releaseAssetIssueResponse struct {
	StageID             string    `json:"stage_id"`
	UploadCapability    string    `json:"upload_capability"`
	CapabilityExpiresAt time.Time `json:"capability_expires_at"`
	UploadPath          string    `json:"upload_path"`
}

type releaseAssetStateFile struct {
	Version             int                  `json:"version"`
	Remote              remoteConfig         `json:"remote"`
	Metadata            releaseAssetMetadata `json:"metadata"`
	StageID             string               `json:"stage_id"`
	UploadCapability    string               `json:"upload_capability"`
	CapabilityExpiresAt time.Time            `json:"capability_expires_at"`
	UploadPath          string               `json:"upload_path"`
}

type releaseAssetSafeOutput struct {
	StageID             string    `json:"stage_id"`
	State               string    `json:"state"`
	Repository          string    `json:"repository"`
	Name                string    `json:"name"`
	ContentType         string    `json:"content_type"`
	Size                int64     `json:"size"`
	SHA256              string    `json:"sha256"`
	CapabilityExpiresAt time.Time `json:"capability_expires_at,omitempty"`
	StateFile           string    `json:"state_file,omitempty"`
	Recovery            string    `json:"recovery"`
}

func runReleaseAssetIssue(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("release-asset-issue", stderr)
	remote := addRemoteFlags(set)
	repository := set.String("repository", "", "exact owner/repository")
	filePath := set.String("file", "", "replayable local regular file (stdin is not supported)")
	name := set.String("name", "", "release asset filename (defaults to local basename)")
	contentType := set.String("content-type", "application/octet-stream", "canonical media type")
	stateFile := set.String("state-file", "", "new owner-only file used by release-asset-upload")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if *stateFile == "" {
		return 0, errors.New("state-file is required")
	}
	if err := validateNewReleaseAssetStatePath(*stateFile); err != nil {
		return 0, err
	}
	metadata, err := inspectReleaseAsset(*filePath, *repository, *name, *contentType)
	if err != nil {
		return 0, err
	}
	fmt.Fprintln(stderr, "requesting a one-use release asset upload capability")
	status, issued, err := issueReleaseAsset(client, *remote, metadata)
	if err != nil || status < 200 || status >= 300 {
		return status, err
	}
	state := releaseAssetStateFile{
		Version: 1, Remote: *remote, Metadata: metadata,
		StageID: issued.StageID, UploadCapability: issued.UploadCapability,
		CapabilityExpiresAt: issued.CapabilityExpiresAt, UploadPath: issued.UploadPath,
	}
	if err := writeReleaseAssetState(*stateFile, state); err != nil {
		return 0, err
	}
	return status, json.NewEncoder(stdout).Encode(releaseAssetSafeOutput{
		StageID: issued.StageID, State: "created", Repository: metadata.Repository,
		Name: metadata.Name, ContentType: metadata.ContentType, Size: metadata.Size, SHA256: metadata.SHA256,
		CapabilityExpiresAt: issued.CapabilityExpiresAt, StateFile: *stateFile,
		Recovery: "run release-asset-upload with this state file and the unchanged local file before the capability expires",
	})
}

func runReleaseAssetUpload(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("release-asset-upload", stderr)
	remote := addRemoteFlags(set)
	filePath := set.String("file", "", "same replayable local regular file used at issue time")
	stateFile := set.String("state-file", "", "owner-only state file from release-asset-issue")
	timeout := set.Duration("upload-timeout", 30*time.Minute, "raw upload deadline")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if *stateFile == "" {
		return 0, errors.New("state-file is required")
	}
	if *timeout <= 0 {
		return 0, errors.New("upload-timeout must be positive")
	}
	state, err := readReleaseAssetState(*stateFile)
	if err != nil {
		return 0, err
	}
	if state.Remote != *remote {
		return 0, errors.New("state-file signing identity or broker does not match command flags")
	}
	observed, err := inspectReleaseAsset(*filePath, state.Metadata.Repository, state.Metadata.Name, state.Metadata.ContentType)
	if err != nil {
		return 0, err
	}
	if observed.Size != state.Metadata.Size || observed.SHA256 != state.Metadata.SHA256 {
		return 0, errors.New("local release asset changed after capability issuance")
	}
	fmt.Fprintf(stderr, "streaming %d bytes to release asset stage %s\n", state.Metadata.Size, state.StageID)
	status, output, attempted, err := uploadReleaseAsset(client, *remote, state.Metadata, releaseAssetIssueResponse{
		StageID: state.StageID, UploadCapability: state.UploadCapability,
		CapabilityExpiresAt: state.CapabilityExpiresAt, UploadPath: state.UploadPath,
	}, *filePath, *timeout)
	if attempted {
		if removeErr := os.Remove(*stateFile); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && err == nil {
			err = fmt.Errorf("remove consumed state-file: %w", removeErr)
		}
	}
	if err != nil || status < 200 || status >= 300 {
		if err == nil {
			err = errors.New("release asset upload failed; restart from zero with release-asset-stage")
		}
		return status, err
	}
	return status, writeReleaseAssetReady(stdout, state.Metadata, output)
}

func runReleaseAssetStage(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("release-asset-stage", stderr)
	remote := addRemoteFlags(set)
	repository := set.String("repository", "", "exact owner/repository")
	filePath := set.String("file", "", "replayable local regular file (stdin is not supported)")
	name := set.String("name", "", "release asset filename (defaults to local basename)")
	contentType := set.String("content-type", "application/octet-stream", "canonical media type")
	timeout := set.Duration("upload-timeout", 30*time.Minute, "raw upload deadline")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if *timeout <= 0 {
		return 0, errors.New("upload-timeout must be positive")
	}
	metadata, err := inspectReleaseAsset(*filePath, *repository, *name, *contentType)
	if err != nil {
		return 0, err
	}
	fmt.Fprintln(stderr, "requesting a one-use release asset upload capability")
	status, issued, err := issueReleaseAsset(client, *remote, metadata)
	if err != nil || status < 200 || status >= 300 {
		return status, err
	}
	fmt.Fprintf(stderr, "streaming %d bytes to release asset stage %s\n", metadata.Size, issued.StageID)
	status, output, _, err := uploadReleaseAsset(client, *remote, metadata, issued, *filePath, *timeout)
	if err != nil || status < 200 || status >= 300 {
		if err == nil {
			err = errors.New("release asset upload failed; restart this command from zero")
		}
		return status, err
	}
	return status, writeReleaseAssetReady(stdout, metadata, output)
}

func runReleaseAssetLifecycle(method string, arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	command := "release-asset-status"
	if method == http.MethodDelete {
		command = "release-asset-abandon"
	}
	set := newFlags(command, stderr)
	remote := addRemoteFlags(set)
	repository := set.String("repository", "", "exact owner/repository")
	stageID := set.String("stage-id", "", "opaque staged asset id")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if strings.Count(*repository, "/") != 1 || !isOpaqueStageID(*stageID) {
		return 0, errors.New("repository and valid stage-id are required")
	}
	requestPath := releaseAssetUploadPathPrefix + *stageID + "?repository=" + url.QueryEscape(*repository)
	return signedJSON(client, *remote, method, requestPath, nil, stdout)
}

func isOpaqueStageID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && value == strings.ToLower(value)
}

func inspectReleaseAsset(filePath, repository, name, contentType string) (releaseAssetMetadata, error) {
	if filePath == "" || filePath == "-" {
		return releaseAssetMetadata{}, errors.New("file must name a replayable local file; stdin is not supported")
	}
	if strings.Count(repository, "/") != 1 || strings.ContainsAny(repository, "*?[]") {
		return releaseAssetMetadata{}, errors.New("repository must be exact owner/repository")
	}
	if name == "" {
		name = filepath.Base(filePath)
	}
	file, err := os.Open(filePath)
	if err != nil {
		return releaseAssetMetadata{}, fmt.Errorf("open release asset: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return releaseAssetMetadata{}, fmt.Errorf("stat release asset: %w", err)
	}
	if !info.Mode().IsRegular() {
		return releaseAssetMetadata{}, errors.New("release asset must be a regular file")
	}
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, file, make([]byte, 256<<10)); err != nil {
		return releaseAssetMetadata{}, fmt.Errorf("hash release asset: %w", err)
	}
	return releaseAssetMetadata{
		Repository: repository, Name: name, ContentType: contentType,
		Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

func issueReleaseAsset(client *http.Client, remote remoteConfig, metadata releaseAssetMetadata) (int, releaseAssetIssueResponse, error) {
	var response bytes.Buffer
	status, err := signedJSON(client, remote, http.MethodPost, "/v1/release-assets", metadata, &response)
	if err != nil {
		return status, releaseAssetIssueResponse{}, err
	}
	if status < 200 || status >= 300 {
		return status, releaseAssetIssueResponse{}, errors.New("release asset capability request failed")
	}
	var issued releaseAssetIssueResponse
	decoder := json.NewDecoder(&response)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&issued); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return 0, releaseAssetIssueResponse{}, errors.New("broker returned an invalid release asset capability")
	}
	if issued.StageID == "" || issued.UploadCapability == "" || issued.CapabilityExpiresAt.IsZero() ||
		issued.UploadPath != releaseAssetUploadPathPrefix+issued.StageID+"/content" {
		return 0, releaseAssetIssueResponse{}, errors.New("broker returned an invalid release asset capability")
	}
	return status, issued, nil
}

func uploadReleaseAsset(client *http.Client, remote remoteConfig, metadata releaseAssetMetadata, issued releaseAssetIssueResponse, filePath string, timeout time.Duration) (int, map[string]any, bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, nil, false, fmt.Errorf("reopen release asset: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, nil, false, fmt.Errorf("restat release asset: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != metadata.Size {
		return 0, nil, false, errors.New("local release asset changed before upload")
	}
	requestURL := strings.TrimRight(remote.BaseURL, "/") + issued.UploadPath
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, requestURL, file)
	if err != nil {
		return 0, nil, false, errors.New("create release asset upload request")
	}
	request.ContentLength = metadata.Size
	request.Header.Set("Authorization", "Bearer "+issued.UploadCapability)
	request.Header.Set("Content-Type", metadata.ContentType)
	request.Header.Set(agentauth.HeaderRepository, metadata.Repository)
	request.Header.Set(agentauth.HeaderAssetSize, strconv.FormatInt(metadata.Size, 10))
	request.Header.Set(agentauth.HeaderAssetSHA256, metadata.SHA256)
	privateKey, err := loadIdentity(remote.IdentityPath)
	if err != nil {
		return 0, nil, false, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return 0, nil, false, err
	}
	identity := agentauth.Identity{TenantID: remote.TenantID, AgentID: remote.AgentID, CredentialID: remote.CredentialID}
	if err := agentauth.SignUploadRequest(request, privateKey, identity, nonce, 90*time.Second); err != nil {
		return 0, nil, false, err
	}
	streamClient := *client
	streamClient.Timeout = 0
	response, err := streamClient.Do(request)
	if err != nil {
		return 0, nil, true, errors.New("release asset upload transport failed; restart from zero")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, nil, true, errors.New("broker release asset response failed")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, nil, true, errors.New("release asset upload failed; restart from zero")
	}
	var output map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&output); err != nil || output == nil || decoder.Decode(&struct{}{}) != io.EOF {
		return 0, nil, true, errors.New("broker returned an invalid release asset result")
	}
	if output["stage_id"] != issued.StageID || output["state"] != "ready" ||
		output["sha256"] != metadata.SHA256 || !jsonNumberEqualsInt64(output["size"], metadata.Size) {
		return 0, nil, true, errors.New("broker returned an inconsistent release asset result")
	}
	return response.StatusCode, output, true, nil
}

func jsonNumberEqualsInt64(value any, expected int64) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	observed, err := number.Int64()
	return err == nil && observed == expected
}

func writeReleaseAssetReady(stdout io.Writer, metadata releaseAssetMetadata, result map[string]any) error {
	return json.NewEncoder(stdout).Encode(releaseAssetSafeOutput{
		StageID: result["stage_id"].(string), State: "ready", Repository: metadata.Repository,
		Name: metadata.Name, ContentType: metadata.ContentType, Size: metadata.Size, SHA256: metadata.SHA256,
		Recovery: "use this stage_id, sha256, size, name, and content_type in the governed release operation",
	})
}

func writeReleaseAssetState(path string, state releaseAssetStateFile) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create state-file directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create state-file: %w", err)
	}
	encoderErr := json.NewEncoder(file).Encode(state)
	syncErr := file.Sync()
	closeErr := file.Close()
	if encoderErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		if encoderErr != nil {
			return fmt.Errorf("write state-file: %w", encoderErr)
		}
		if syncErr != nil {
			return fmt.Errorf("sync state-file: %w", syncErr)
		}
		return fmt.Errorf("close state-file: %w", closeErr)
	}
	return nil
}

func validateNewReleaseAssetStatePath(path string) error {
	if path == "" || path == "-" {
		return errors.New("state-file must name a new local file")
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("state-file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect state-file: %w", err)
	}
	return nil
}

func readReleaseAssetState(path string) (releaseAssetStateFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return releaseAssetStateFile{}, fmt.Errorf("stat state-file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return releaseAssetStateFile{}, errors.New("state-file must be a regular owner-only file (0600)")
	}
	file, err := os.Open(path)
	if err != nil {
		return releaseAssetStateFile{}, fmt.Errorf("open state-file: %w", err)
	}
	defer file.Close()
	var state releaseAssetStateFile
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		state.Version != 1 || state.StageID == "" || state.UploadCapability == "" ||
		state.UploadPath != releaseAssetUploadPathPrefix+state.StageID+"/content" {
		return releaseAssetStateFile{}, errors.New("state-file is invalid")
	}
	return state, nil
}
