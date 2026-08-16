package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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
)

func TestReleaseAssetStageStreamsFileAndPrintsMetadataOnly(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.key")
	if _, err := generateIdentity(identityPath); err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(t.TempDir(), "bridge.bin")
	const marker = "binary-marker-that-must-not-reach-output"
	body := bytes.Repeat([]byte(marker), (5<<20)/len(marker)+1)
	body = body[:5<<20]
	if err := os.WriteFile(assetPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	digestHex := hex.EncodeToString(digest[:])
	var sawIssue, sawUpload atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/release-assets":
			sawIssue.Store(true)
			for _, header := range []string{"Signature", "Signature-Input", "Content-Digest", agentauth.HeaderTenant, agentauth.HeaderCredential} {
				if request.Header.Get(header) == "" {
					t.Errorf("issue missing %s", header)
				}
			}
			var metadata releaseAssetMetadata
			if err := json.NewDecoder(request.Body).Decode(&metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.Size != int64(len(body)) || metadata.SHA256 != digestHex || metadata.Name != "bridge-linux-amd64" {
				t.Errorf("metadata = %#v", metadata)
			}
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"stage_id":"0123456789abcdef0123456789abcdef","upload_capability":"one-use-secret","capability_expires_at":"2026-07-30T22:00:00Z","upload_path":"/v1/release-assets/0123456789abcdef0123456789abcdef/content"}`))
		case request.Method == http.MethodPut && request.URL.Path == "/v1/release-assets/0123456789abcdef0123456789abcdef/content":
			sawUpload.Store(true)
			if request.Header.Get("Authorization") != "Bearer one-use-secret" ||
				request.Header.Get(agentauth.HeaderRepository) != "yaniv256/actions.json.dev" ||
				request.Header.Get(agentauth.HeaderAssetSHA256) != digestHex ||
				request.Header.Get(agentauth.HeaderAssetSize) != strconv.Itoa(len(body)) ||
				request.ContentLength != int64(len(body)) {
				t.Errorf("upload framing is incomplete: headers=%v length=%d", request.Header, request.ContentLength)
			}
			if request.Header.Get("Signature") == "" || request.Header.Get("Signature-Input") == "" {
				t.Error("raw upload is not signed")
			}
			if request.Header.Get("Content-Digest") != "" {
				t.Error("raw upload unexpectedly buffered into a content digest")
			}
			uploaded, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(uploaded, body) {
				t.Error("uploaded bytes differ")
			}
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"stage_id":"0123456789abcdef0123456789abcdef","state":"ready","size":5242880,"sha256":"` + digestHex + `"}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	arguments := append([]string{"release-asset-stage"}, releaseAssetRemoteArguments(server.URL, identityPath)...)
	arguments = append(arguments,
		"--repository", "yaniv256/actions.json.dev",
		"--file", assetPath,
		"--name", "bridge-linux-amd64",
		"--content-type", "application/octet-stream",
	)
	var stdout, stderr bytes.Buffer
	if code := run(arguments, &stdout, &stderr, server.Client()); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if !sawIssue.Load() || !sawUpload.Load() {
		t.Fatalf("saw issue=%v upload=%v", sawIssue.Load(), sawUpload.Load())
	}
	for _, output := range []string{stdout.String(), stderr.String()} {
		if strings.Contains(output, marker) || strings.Contains(output, "one-use-secret") {
			t.Fatalf("secret or asset bytes escaped output: %q", output)
		}
	}
	var result releaseAssetSafeOutput
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.StageID != "0123456789abcdef0123456789abcdef" || result.State != "ready" ||
		result.Size != int64(len(body)) || result.SHA256 != digestHex {
		t.Fatalf("result = %#v", result)
	}
}

func TestReleaseAssetIssueAndUploadUseOwnerOnlyStateFile(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.key")
	if _, err := generateIdentity(identityPath); err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(t.TempDir(), "bridge.bin")
	body := []byte("safe test payload")
	if err := os.WriteFile(assetPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	digestHex := hex.EncodeToString(digest[:])
	server := releaseAssetTestServer(t, digestHex, int64(len(body)))
	defer server.Close()
	statePath := filepath.Join(t.TempDir(), "stage.json")

	issue := append([]string{"release-asset-issue"}, releaseAssetRemoteArguments(server.URL, identityPath)...)
	issue = append(issue, "--repository", "yaniv256/private", "--file", assetPath, "--state-file", statePath)
	var stdout, stderr bytes.Buffer
	if code := run(issue, &stdout, &stderr, server.Client()); code != 0 {
		t.Fatalf("issue code=%d stderr=%q", code, stderr.String())
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}
	if strings.Contains(stdout.String(), "one-use-secret") {
		t.Fatal("capability escaped issue stdout")
	}

	upload := append([]string{"release-asset-upload"}, releaseAssetRemoteArguments(server.URL, identityPath)...)
	upload = append(upload, "--file", assetPath, "--state-file", statePath)
	stdout.Reset()
	stderr.Reset()
	if code := run(upload, &stdout, &stderr, server.Client()); code != 0 {
		t.Fatalf("upload code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("consumed state-file still exists: %v", err)
	}
}

func TestReleaseAssetStageLetsServerDetectSameSizeMutation(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.key")
	if _, err := generateIdentity(identityPath); err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(t.TempDir(), "mutable.bin")
	if err := os.WriteFile(assetPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	var uploadCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			if err := os.WriteFile(assetPath, []byte("mutated!"), 0o600); err != nil {
				t.Fatal(err)
			}
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"stage_id":"0123456789abcdef0123456789abcdef","upload_capability":"one-use-secret","capability_expires_at":"2026-07-30T22:00:00Z","upload_path":"/v1/release-assets/0123456789abcdef0123456789abcdef/content"}`))
			return
		}
		uploadCalls.Add(1)
		_, _ = io.Copy(io.Discard, request.Body)
		response.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = response.Write([]byte(`{"error":"release asset upload failed"}`))
	}))
	defer server.Close()
	arguments := append([]string{"release-asset-stage"}, releaseAssetRemoteArguments(server.URL, identityPath)...)
	arguments = append(arguments, "--repository", "yaniv256/private", "--file", assetPath)
	var stdout, stderr bytes.Buffer
	if code := run(arguments, &stdout, &stderr, server.Client()); code != 1 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if uploadCalls.Load() != 1 {
		t.Fatalf("upload calls = %d", uploadCalls.Load())
	}
	if strings.Contains(stdout.String()+stderr.String(), "mutated!") ||
		!strings.Contains(stderr.String(), "restart from zero") {
		t.Fatalf("unsafe or unhelpful output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestReleaseAssetCommandsRejectStdin(t *testing.T) {
	arguments := []string{
		"release-asset-stage", "--url", "https://gitoversight.test", "--identity", "/tmp/key",
		"--tenant", "default", "--agent", "zara", "--credential", "zara-3",
		"--repository", "yaniv256/private", "--file", "-",
	}
	var stdout, stderr bytes.Buffer
	if code := run(arguments, &stdout, &stderr, &http.Client{}); code != 1 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), "stdin is not supported") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestReleaseAssetLifecycleCommandsUseSignedMetadataRoutes(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.key")
	if _, err := generateIdentity(identityPath); err != nil {
		t.Fatal(err)
	}
	var methods []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		methods = append(methods, request.Method+" "+request.URL.RequestURI())
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"stage_id":"0123456789abcdef0123456789abcdef","state":"ready"}`))
	}))
	defer server.Close()
	args := []string{
		"-url", server.URL, "-tenant", "tenant-a", "-agent", "zara",
		"-credential", "zara-1", "-identity", identityPath,
		"-repository", "yaniv256/private", "-stage-id", "0123456789abcdef0123456789abcdef",
	}
	for _, test := range []struct {
		method string
		run    func([]string, io.Writer, io.Writer, *http.Client) (int, error)
	}{
		{http.MethodGet, func(a []string, o, e io.Writer, c *http.Client) (int, error) {
			return runReleaseAssetLifecycle(http.MethodGet, a, o, e, c)
		}},
		{http.MethodDelete, func(a []string, o, e io.Writer, c *http.Client) (int, error) {
			return runReleaseAssetLifecycle(http.MethodDelete, a, o, e, c)
		}},
	} {
		var stdout, stderr bytes.Buffer
		status, err := test.run(args, &stdout, &stderr, server.Client())
		if err != nil || status != http.StatusOK {
			t.Fatalf("%s status=%d err=%v stderr=%s", test.method, status, err, stderr.String())
		}
	}
	if len(methods) != 2 || !strings.HasPrefix(methods[0], "GET /v1/release-assets/") ||
		!strings.HasPrefix(methods[1], "DELETE /v1/release-assets/") {
		t.Fatalf("requests = %v", methods)
	}
}

func releaseAssetRemoteArguments(serverURL, identityPath string) []string {
	return []string{
		"--url", serverURL, "--identity", identityPath,
		"--tenant", "tenant-a", "--agent", "zara", "--credential", "zara-key-1",
	}
}

func releaseAssetTestServer(t *testing.T, digest string, size int64) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodPost:
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"stage_id":"0123456789abcdef0123456789abcdef","upload_capability":"one-use-secret","capability_expires_at":"` +
				time.Now().Add(time.Hour).UTC().Format(time.RFC3339) +
				`","upload_path":"/v1/release-assets/0123456789abcdef0123456789abcdef/content"}`))
		case http.MethodPut:
			_, _ = io.Copy(io.Discard, request.Body)
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"stage_id":"0123456789abcdef0123456789abcdef","state":"ready","size":` +
				strconv.FormatInt(size, 10) + `,"sha256":"` + digest + `"}`))
		default:
			http.NotFound(response, request)
		}
	}))
}
