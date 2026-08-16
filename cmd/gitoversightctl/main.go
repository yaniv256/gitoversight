package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

type remoteConfig struct {
	BaseURL      string
	IdentityPath string
	TenantID     string
	AgentID      string
	CredentialID string
}

type operationInput struct {
	ID                string         `json:"id"`
	Repository        string         `json:"repository"`
	Operation         string         `json:"operation"`
	Branch            string         `json:"branch,omitempty"`
	Title             string         `json:"title,omitempty"`
	Body              string         `json:"body,omitempty"`
	HeadSHA           string         `json:"head_sha,omitempty"`
	ManifestHash      string         `json:"manifest_hash"`
	ApprovalID        string         `json:"approval_id,omitempty"`
	ApprovalNonce     string         `json:"approval_nonce,omitempty"`
	ApprovalExpiresAt time.Time      `json:"approval_expires_at,omitempty"`
	Approver          string         `json:"approver,omitempty"`
	Payload           map[string]any `json:"payload,omitempty"`
}

func main() {
	// 15s was too tight for multi-MB commit-packet submits (a merge that pulls in
	// a large base tree, or a big-asset push) — the upload intermittently timed out
	// with an opaque "broker request failed". 120s covers the largest packets under
	// the 42 MiB request cap without hanging a genuinely dead connection forever.
	client := &http.Client{Timeout: 120 * time.Second}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, client))
}

func run(arguments []string, stdout, stderr io.Writer, client *http.Client) int {
	if len(arguments) == 0 {
		fmt.Fprintln(stderr, "command is required: identity-create, commit-packet, enroll, clone, request, release-asset-issue, release-asset-upload, release-asset-stage, release-asset-status, release-asset-abandon, execute, reconcile, status, receipt, revoke, pull-list, policy-promote, policy-promote-private-owners, sync-propose, sync-update, sync-status, queue-order, or queue-top")
		return 1
	}
	var err error
	var status int
	switch arguments[0] {
	case "identity-create":
		err = runIdentityCreate(arguments[1:], stdout, stderr)
	case "commit-packet":
		err = runCommitPacket(arguments[1:], stdout, stderr)
	case "enroll":
		status, err = runEnroll(arguments[1:], stdout, stderr, client)
	case "clone":
		status, err = runClone(arguments[1:], stdout, stderr, client)
	case "request":
		status, err = runRequest(arguments[1:], stdout, stderr, client)
	case "release-asset-issue":
		status, err = runReleaseAssetIssue(arguments[1:], stdout, stderr, client)
	case "release-asset-upload":
		status, err = runReleaseAssetUpload(arguments[1:], stdout, stderr, client)
	case "release-asset-stage":
		status, err = runReleaseAssetStage(arguments[1:], stdout, stderr, client)
	case "release-asset-status":
		status, err = runReleaseAssetLifecycle(http.MethodGet, arguments[1:], stdout, stderr, client)
	case "release-asset-abandon":
		status, err = runReleaseAssetLifecycle(http.MethodDelete, arguments[1:], stdout, stderr, client)
	case "pull-list":
		status, err = runPullList(arguments[1:], stdout, stderr, client)
	case "policy-promote-private-owners":
		status, err = runPolicyPromotePrivateOwners(arguments[1:], stdout, stderr, client)
	case "policy-promote":
		status, err = runPolicyPromote(arguments[1:], stdout, stderr, client)
	case "sync-propose":
		status, err = runSyncPropose(arguments[1:], stdout, stderr, client)
	case "sync-update":
		status, err = runSyncUpdate(arguments[1:], stdout, stderr, client)
	case "sync-status":
		status, err = runSyncStatus(arguments[1:], stdout, stderr, client)
	case "queue-order":
		status, err = runQueueOrder(arguments[1:], stdout, stderr, client)
	case "queue-top":
		status, err = runQueueTop(arguments[1:], stdout, stderr, client)
	case "execute", "reconcile", "status", "receipt", "revoke":
		status, err = runOperationAction(arguments[0], arguments[1:], stdout, stderr, client)
	default:
		err = fmt.Errorf("unknown command %q", arguments[0])
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if status < 200 || status >= 300 {
		return 2
	}
	return 0
}

func runPolicyPromotePrivateOwners(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	return runPolicyPromoteAt("policy-promote-private-owners", "/v1/policy/private-owner-additions", arguments, stdout, stderr, client)
}

func runPolicyPromote(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	return runPolicyPromoteAt("policy-promote", "/v1/policy/orchestrator", arguments, stdout, stderr, client)
}

func runPolicyPromoteAt(commandName, endpoint string, arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags(commandName, stderr)
	remote := addRemoteFlags(set)
	snapshotFile := set.String("snapshot-file", "", "validated next policy snapshot JSON")
	expectedGeneration := set.Uint64("expected-generation", 0, "active predecessor generation")
	expectedPolicyHash := set.String("expected-policy-hash", "", "active predecessor policy hash")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if *snapshotFile == "" || *expectedGeneration == 0 || *expectedPolicyHash == "" {
		return 0, errors.New("snapshot-file, expected-generation, and expected-policy-hash are required")
	}
	payload, err := os.ReadFile(*snapshotFile)
	if err != nil {
		return 0, err
	}
	var snapshot policy.Snapshot
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return 0, fmt.Errorf("decode snapshot: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return 0, fmt.Errorf("validate snapshot: %w", err)
	}
	input := map[string]any{
		"tenant_id": remote.TenantID, "expected_generation": *expectedGeneration,
		"expected_policy_hash": *expectedPolicyHash, "snapshot": snapshot,
	}
	return signedJSON(client, *remote, http.MethodPost, endpoint, input, stdout)
}

func runClone(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("clone", stderr)
	remote := addRemoteFlags(set)
	repository := set.String("repository", "", "exact owner/repository")
	destination := set.String("destination", "", "local clone destination")
	gitBinary := set.String("git", "git", "git executable")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if strings.Count(*repository, "/") != 1 || strings.ContainsAny(*repository, "*?[]") {
		return 0, errors.New("repository must be exact owner/repository")
	}
	var session bytes.Buffer
	status, err := signedJSON(client, *remote, http.MethodPost, "/v1/read-sessions", map[string]string{"repository": *repository}, &session)
	if err != nil || status < 200 || status >= 300 {
		_, _ = io.Copy(stdout, &session)
		return status, err
	}
	var value struct {
		Token    string `json:"token"`
		CloneURL string `json:"clone_url"`
	}
	if err := json.Unmarshal(session.Bytes(), &value); err != nil || value.Token == "" || value.CloneURL == "" {
		return 0, errors.New("broker returned an invalid read session")
	}
	args := []string{"-c", "credential.helper=", "clone", value.CloneURL}
	if *destination != "" {
		args = append(args, *destination)
	}
	command := exec.Command(*gitBinary, args...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, stdout, stderr
	command.Env = append(withoutGitConfig(os.Environ()),
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Bearer "+value.Token,
	)
	if err := command.Run(); err != nil {
		return 0, fmt.Errorf("git clone failed: %w", err)
	}
	return http.StatusOK, nil
}

func withoutGitConfig(environment []string) []string {
	result := make([]string, 0, len(environment))
	for _, item := range environment {
		name, _, _ := strings.Cut(item, "=")
		if name == "GIT_CONFIG_COUNT" || strings.HasPrefix(name, "GIT_CONFIG_KEY_") || strings.HasPrefix(name, "GIT_CONFIG_VALUE_") {
			continue
		}
		result = append(result, item)
	}
	return result
}

func runCommitPacket(arguments []string, stdout, stderr io.Writer) error {
	set := newFlags("commit-packet", stderr)
	repository := set.String("repository-path", ".", "local Git repository path")
	revision := set.String("revision", "HEAD", "local commit revision")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	payload, err := buildCommitPacket(*repository, *revision)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(payload)
}

func runIdentityCreate(arguments []string, stdout, stderr io.Writer) error {
	set := newFlags("identity-create", stderr)
	path := set.String("identity", env("GITOVERSIGHT_IDENTITY", ""), "owner-only Ed25519 private key path")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	publicKey, err := generateIdentity(*path)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]string{"public_key": base64.RawURLEncoding.EncodeToString(publicKey)})
}

func runEnroll(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("enroll", stderr)
	remote := addRemoteFlags(set)
	supersedes := set.String("supersedes", "", "credential id replaced after approval")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	privateKey, err := loadIdentity(remote.IdentityPath)
	if err != nil {
		return 0, err
	}
	challengePayload := map[string]string{
		"tenant_id": remote.TenantID, "agent_id": remote.AgentID, "credential_id": remote.CredentialID,
		"public_key": base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
	}
	if *supersedes != "" {
		challengePayload["supersedes_credential_id"] = *supersedes
	}
	response, body, err := doJSON(client, http.MethodPost, remote.BaseURL+"/v1/enrollments/challenge", challengePayload, nil)
	if err != nil {
		return 0, err
	}
	if response.StatusCode != http.StatusCreated {
		_, _ = stdout.Write(body)
		return response.StatusCode, nil
	}
	var challenge struct {
		ID           string `json:"id"`
		ProofMessage string `json:"proof_message"`
	}
	if err := json.Unmarshal(body, &challenge); err != nil {
		return 0, errors.New("broker returned an invalid enrollment challenge")
	}
	proofMessage, err := base64.RawURLEncoding.DecodeString(challenge.ProofMessage)
	if err != nil || challenge.ID == "" {
		return 0, errors.New("broker returned an invalid enrollment challenge")
	}
	proof := ed25519.Sign(privateKey, proofMessage)
	response, body, err = doJSON(client, http.MethodPost, remote.BaseURL+"/v1/enrollments/"+url.PathEscape(challenge.ID)+"/proof", map[string]string{
		"tenant_id": remote.TenantID, "proof": base64.RawURLEncoding.EncodeToString(proof),
	}, nil)
	if err != nil {
		return 0, err
	}
	if response.StatusCode == http.StatusNoContent {
		return response.StatusCode, json.NewEncoder(stdout).Encode(map[string]string{"enrollment_id": challenge.ID, "state": "awaiting_human_approval"})
	}
	_, _ = stdout.Write(body)
	return response.StatusCode, nil
}

func runRequest(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("request", stderr)
	remote := addRemoteFlags(set)
	input := operationInput{}
	set.StringVar(&input.ID, "request-id", "", "single-use request id")
	set.StringVar(&input.Repository, "repository", "", "exact owner/repository")
	set.StringVar(&input.Operation, "operation", "", "governed operation")
	set.StringVar(&input.Branch, "branch", "", "exact branch")
	set.StringVar(&input.Title, "title", "", "exact title")
	set.StringVar(&input.Body, "body", "", "exact body")
	set.StringVar(&input.HeadSHA, "head-sha", "", "exact reviewed head")
	set.StringVar(&input.ManifestHash, "manifest-hash", "", "canonical manifest hash")
	set.StringVar(&input.ApprovalID, "approval-id", "", "exact approval id")
	set.StringVar(&input.ApprovalNonce, "approval-nonce", "", "exact approval nonce")
	set.StringVar(&input.Approver, "approver", "", "exact human approver")
	expires := set.String("approval-expires-at", "", "RFC3339 approval expiry")
	payloadJSON := set.String("payload-json", "", "operation-specific JSON object")
	payloadFile := set.String("payload-file", "", "path to an operation-specific JSON object")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if input.ID == "" || input.Repository == "" || input.Operation == "" {
		return 0, errors.New("request-id, repository, and operation are required")
	}
	var err error
	input.Payload, err = decodePayloadInput(*payloadJSON, *payloadFile)
	if err != nil {
		return 0, err
	}
	if *expires != "" {
		input.ApprovalExpiresAt, err = time.Parse(time.RFC3339, *expires)
		if err != nil {
			return 0, errors.New("approval-expires-at must be RFC3339")
		}
	}
	var responseBody bytes.Buffer
	status, err := signedJSON(client, *remote, http.MethodPost, "/v1/operations", input, &responseBody)
	_, _ = io.Copy(stdout, &responseBody)
	if err == nil && status == http.StatusAccepted {
		// Awaiting approval is a valid broker state, but not a completed mutation.
		// Keep automation fail-closed until the caller explicitly resumes execution.
		return http.StatusConflict, nil
	}
	return status, err
}

func runPullList(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("pull-list", stderr)
	remote := addRemoteFlags(set)
	repository := set.String("repository", "", "exact owner/repository")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if strings.Count(*repository, "/") != 1 || strings.ContainsAny(*repository, "*?[]") {
		return 0, errors.New("repository must be exact owner/repository")
	}
	path := "/v1/pulls?" + url.Values{"repository": []string{*repository}}.Encode()
	return signedJSON(client, *remote, http.MethodGet, path, nil, stdout)
}

func runOperationAction(action string, arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags(action, stderr)
	remote := addRemoteFlags(set)
	requestID := set.String("request-id", "", "owned request id")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if *requestID == "" {
		return 0, errors.New("request-id is required")
	}
	method, path := http.MethodGet, "/v1/operations/"+url.PathEscape(*requestID)
	if action == "receipt" {
		path += "/receipt"
	}
	if action == "revoke" {
		method, path = http.MethodPost, path+"/revoke"
	}
	if action == "execute" {
		method, path = http.MethodPost, path+"/execute"
	}
	if action == "reconcile" {
		method, path = http.MethodPost, path+"/reconcile"
	}
	return signedJSON(client, *remote, method, path, nil, stdout)
}

func signedJSON(client *http.Client, remote remoteConfig, method, path string, value any, stdout io.Writer) (int, error) {
	privateKey, err := loadIdentity(remote.IdentityPath)
	if err != nil {
		return 0, err
	}
	headers := make(http.Header)
	requestURL := strings.TrimRight(remote.BaseURL, "/") + path
	request, err := newJSONRequest(method, requestURL, value)
	if err != nil {
		return 0, err
	}
	request.Header = headers
	if value != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	nonce, err := randomNonce()
	if err != nil {
		return 0, err
	}
	identity := agentauth.Identity{TenantID: remote.TenantID, AgentID: remote.AgentID, CredentialID: remote.CredentialID}
	if err := signAgentRequest(request, privateKey, identity, nonce, 90*time.Second); err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, errors.New("broker request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, errors.New("broker response failed")
	}
	if len(body) != 0 {
		_, _ = stdout.Write(body)
	}
	return response.StatusCode, nil
}

func doJSON(client *http.Client, method, requestURL string, value any, headers http.Header) (*http.Response, []byte, error) {
	request, err := newJSONRequest(method, requestURL, value)
	if err != nil {
		return nil, nil, err
	}
	if headers != nil {
		request.Header = headers
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, errors.New("broker request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, nil, errors.New("broker response failed")
	}
	return response, body, nil
}

func newJSONRequest(method, requestURL string, value any) (*http.Request, error) {
	var body io.Reader
	if value != nil {
		payload, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequest(method, requestURL, body)
	if err != nil {
		return nil, err
	}
	if value != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func addRemoteFlags(set *flag.FlagSet) *remoteConfig {
	remote := &remoteConfig{}
	set.StringVar(&remote.BaseURL, "url", env("GITOVERSIGHT_URL", ""), "broker HTTPS origin")
	set.StringVar(&remote.IdentityPath, "identity", env("GITOVERSIGHT_IDENTITY", ""), "owner-only Ed25519 private key path")
	set.StringVar(&remote.TenantID, "tenant", env("GITOVERSIGHT_TENANT", ""), "tenant id")
	set.StringVar(&remote.AgentID, "agent", env("GITOVERSIGHT_AGENT", ""), "agent id")
	set.StringVar(&remote.CredentialID, "credential", env("GITOVERSIGHT_CREDENTIAL", ""), "credential id")
	return remote
}

func (remote remoteConfig) validate() error {
	parsed, err := url.Parse(remote.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("url must be an HTTPS origin without path, query, or fragment")
	}
	if remote.IdentityPath == "" || remote.TenantID == "" || remote.AgentID == "" || remote.CredentialID == "" {
		return errors.New("identity, tenant, agent, and credential are required")
	}
	return nil
}

func decodePayload(raw string) (map[string]any, error) {
	if raw == "" {
		return nil, nil
	}
	var payload map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil || payload == nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("payload-json must contain one JSON object")
	}
	return payload, nil
}

func decodePayloadInput(raw, path string) (map[string]any, error) {
	if raw != "" && path != "" {
		return nil, errors.New("payload-json and payload-file are mutually exclusive")
	}
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open payload-file: %w", err)
		}
		defer file.Close()
		contents, err := io.ReadAll(io.LimitReader(file, commitpacket.MaxPayloadBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read payload-file: %w", err)
		}
		if len(contents) > commitpacket.MaxPayloadBytes {
			return nil, fmt.Errorf("payload-file exceeds %d MiB", commitpacket.MaxPayloadBytes>>20)
		}
		raw = string(contents)
	}
	return decodePayload(raw)
}

func randomNonce() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(stderr)
	return set
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
