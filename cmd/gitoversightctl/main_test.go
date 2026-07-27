package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
)

func TestBuildCommitPacketReproducesLocalObjectIdentities(t *testing.T) {
	repository := t.TempDir()
	commands := [][]string{
		{"init", "-q"},
		{"config", "user.name", "Zara"},
		{"config", "user.email", "zara@example.com"},
	}
	for _, arguments := range commands {
		command := exec.Command("git", arguments...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(repository, "hello.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{{"add", "hello.txt"}, {"commit", "-q", "-m", "novel commit"}} {
		command := exec.Command("git", arguments...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}
	payload, err := buildCommitPacket(repository, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	sha := payload["sha"].(string)
	want, err := gitOutput(repository, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if sha != want {
		t.Fatalf("sha = %q, want %q", sha, want)
	}
	packet := payload["object_package"]
	encoded, _ := json.Marshal(packet)
	if !bytes.Contains(encoded, []byte(`"hello.txt"`)) || !bytes.Contains(encoded, []byte(`"encoding":"base64"`)) {
		t.Fatalf("packet = %s", encoded)
	}
}

func TestBuildCommitPacketDescribesCompleteShapeWithoutABase(t *testing.T) {
	repository := t.TempDir()
	for _, arguments := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Zara"},
		{"config", "user.email", "zara@example.com"},
	} {
		command := exec.Command("git", arguments...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}
	largePath := filepath.Join(repository, "existing-large-production-asset.bin")
	largeFile, err := os.OpenFile(largePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := largeFile.Truncate(6 << 20); err != nil {
		_ = largeFile.Close()
		t.Fatal(err)
	}
	if err := largeFile.Close(); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{{"add", "existing-large-production-asset.bin"}, {"commit", "-q", "-m", "large base"}} {
		command := exec.Command("git", arguments...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(repository, "small-change.txt"), []byte("small\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{{"add", "small-change.txt"}, {"commit", "-q", "-m", "small delta"}} {
		command := exec.Command("git", arguments...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}

	payload, err := buildCommitPacket(repository, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(payload["object_package"])
	// A SHAPE packet describes the complete proposed tree — both paths appear,
	// and there is no base_tree because the base is the PUBLIC repository's HEAD,
	// which this process cannot see. The broker drops unchanged blobs when it
	// rebases (see internal/prpreview.Rebase); the CLI must not pre-empt that
	// with a private-parent delta, because a path absent from a delta is
	// indistinguishable from a deletion.
	if bytes.Contains(encoded, []byte(`"base_tree"`)) {
		t.Fatalf("a shape packet must carry no base_tree: %s", encoded)
	}
	if !bytes.Contains(encoded, []byte(`"small-change.txt"`)) || !bytes.Contains(encoded, []byte(`"existing-large-production-asset.bin"`)) {
		t.Fatalf("shape packet must describe the complete tree: %s", encoded)
	}
	assertPacketTreeIdentity(t, repository, payload["object_package"].(commitpacket.Packet))
}

func TestBuildCommitPacketOmitsDeletedPathsFromTheShape(t *testing.T) {
	repository := t.TempDir()
	for _, arguments := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Zara"},
		{"config", "user.email", "zara@example.com"},
	} {
		command := exec.Command("git", arguments...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(repository, "removed.txt"), []byte("remove me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{{"add", "removed.txt"}, {"commit", "-q", "-m", "base"}, {"rm", "-q", "removed.txt"}, {"commit", "-q", "-m", "delete path"}} {
		command := exec.Command("git", arguments...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}

	payload, err := buildCommitPacket(repository, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(payload["object_package"])
	// A shape carries no deletions: it is the complete proposed tree, so a
	// removed path is simply ABSENT. The broker derives the deletion by
	// comparing this shape against the public base — which is the only way a
	// path deleted several private commits ago is still expressed correctly.
	if bytes.Contains(encoded, []byte(`"removed.txt"`)) {
		t.Fatalf("a deleted path must be absent from the shape, not marked: %s", encoded)
	}
	if bytes.Contains(encoded, []byte(`"delete":true`)) {
		t.Fatalf("a shape packet must contain no deletion entries: %s", encoded)
	}
	assertPacketTreeIdentity(t, repository, payload["object_package"].(commitpacket.Packet))
}

func TestBuildCommitPacketPreservesPathTypeTransitions(t *testing.T) {
	for _, test := range []struct {
		name     string
		basePath string
		baseBody string
		nextPath string
		nextBody string
	}{
		{name: "file to directory", basePath: "node", baseBody: "file\n", nextPath: "node/child.txt", nextBody: "child\n"},
		{name: "directory to file", basePath: "node/child.txt", baseBody: "child\n", nextPath: "node", nextBody: "file\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := t.TempDir()
			for _, arguments := range [][]string{{"init", "-q"}, {"config", "user.name", "Zara"}, {"config", "user.email", "zara@example.com"}} {
				runGitTestCommand(t, repository, arguments...)
			}
			baseFile := filepath.Join(repository, filepath.FromSlash(test.basePath))
			if err := os.MkdirAll(filepath.Dir(baseFile), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(baseFile, []byte(test.baseBody), 0o600); err != nil {
				t.Fatal(err)
			}
			runGitTestCommand(t, repository, "add", "-A")
			runGitTestCommand(t, repository, "commit", "-q", "-m", "base")
			if err := os.RemoveAll(filepath.Join(repository, "node")); err != nil {
				t.Fatal(err)
			}
			nextFile := filepath.Join(repository, filepath.FromSlash(test.nextPath))
			if err := os.MkdirAll(filepath.Dir(nextFile), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(nextFile, []byte(test.nextBody), 0o600); err != nil {
				t.Fatal(err)
			}
			runGitTestCommand(t, repository, "add", "-A")
			runGitTestCommand(t, repository, "commit", "-q", "-m", "transition")

			payload, err := buildCommitPacket(repository, "HEAD")
			if err != nil {
				t.Fatal(err)
			}
			assertPacketTreeIdentity(t, repository, payload["object_package"].(commitpacket.Packet))
		})
	}
}

func TestBuildCommitPacketCarriesModeOnlyChangeInTheShape(t *testing.T) {
	repository := t.TempDir()
	for _, arguments := range [][]string{{"init", "-q"}, {"config", "user.name", "Zara"}, {"config", "user.email", "zara@example.com"}} {
		runGitTestCommand(t, repository, arguments...)
	}
	path := filepath.Join(repository, "large-tool")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(6 << 20); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	runGitTestCommand(t, repository, "add", "large-tool")
	runGitTestCommand(t, repository, "commit", "-q", "-m", "base")
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	runGitTestCommand(t, repository, "add", "large-tool")
	runGitTestCommand(t, repository, "commit", "-q", "-m", "mode only")

	payload, err := buildCommitPacket(repository, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	packet := payload["object_package"].(commitpacket.Packet)
	// A shape carries content for every path, because the CLI cannot know which
	// objects the PUBLIC repository already holds. The broker drops the blob
	// during rebase when the base already has that exact object — see
	// prpreview.Rebase's mode-change case, which keeps the entry and no blob.
	if len(packet.Tree.Entries) != 1 || packet.Tree.Entries[0].Mode != "100755" {
		t.Fatalf("entries = %d, first mode = %q, want 1 entry at 100755",
			len(packet.Tree.Entries), packet.Tree.Entries[0].Mode)
	}
	if len(packet.Blobs) != 1 {
		t.Fatalf("blobs = %d, want 1 — a shape carries its content", len(packet.Blobs))
	}
	assertPacketTreeIdentity(t, repository, packet)
}

func assertPacketTreeIdentity(t *testing.T, repository string, packet commitpacket.Packet) {
	t.Helper()
	indexPath := filepath.Join(t.TempDir(), "index")
	// A shape packet describes the COMPLETE tree, so the index starts empty. A
	// delta packet (produced by the broker after rebasing) seeds from its base.
	if packet.Tree.BaseTree != "" {
		runGitTestCommandWithEnv(t, repository, []string{"GIT_INDEX_FILE=" + indexPath}, "read-tree", packet.Tree.BaseTree)
	}
	for _, entry := range packet.Tree.Entries {
		if entry.Delete {
			runGitTestCommandWithEnv(t, repository, []string{"GIT_INDEX_FILE=" + indexPath}, "update-index", "--force-remove", "--", entry.Path)
			continue
		}
		runGitTestCommandWithEnv(t, repository, []string{"GIT_INDEX_FILE=" + indexPath}, "update-index", "--add", "--cacheinfo", entry.Mode, entry.SHA, entry.Path)
	}
	command := exec.Command("git", "write-tree")
	command.Dir = repository
	command.Env = append(os.Environ(), "GIT_INDEX_FILE="+indexPath)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git write-tree: %v: %s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != packet.Tree.SHA {
		t.Fatalf("reconstructed tree = %s, want %s", got, packet.Tree.SHA)
	}
}

func runGitTestCommand(t *testing.T, repository string, arguments ...string) {
	t.Helper()
	runGitTestCommandWithEnv(t, repository, nil, arguments...)
}

func runGitTestCommandWithEnv(t *testing.T, repository string, environment []string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = repository
	command.Env = append(os.Environ(), environment...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}

func TestDecodePayloadInputSupportsBoundedFileAndRejectsAmbiguity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(path, []byte(`{"sha":"abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := decodePayloadInput("", path)
	if err != nil || payload["sha"] != "abc" {
		t.Fatalf("payload = %#v, err = %v", payload, err)
	}
	if _, err := decodePayloadInput(`{"sha":"abc"}`, path); err == nil {
		t.Fatal("inline and file payload were both accepted")
	}
}

func TestRequestUsesSignedHTTPSAPI(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.key")
	if _, err := generateIdentity(identityPath); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/operations" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		for _, header := range []string{"Signature", "Signature-Input", "Content-Digest", "X-Governance-Tenant", "X-Governance-Credential"} {
			if request.Header.Get(header) == "" {
				t.Errorf("missing %s", header)
			}
		}
		var input operationInput
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		if input.ID != "request-1" || input.Repository != "yaniv256/private" || input.Operation != "branch.push" {
			t.Fatalf("input = %#v", input)
		}
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{"state":"authorized"}`))
	}))
	defer server.Close()

	common := []string{"--url", server.URL, "--identity", identityPath, "--tenant", "tenant-a", "--agent", "zara", "--credential", "zara-key-1"}
	arguments := append([]string{"request"}, common...)
	arguments = append(arguments, "--request-id", "request-1", "--repository", "yaniv256/private", "--operation", "branch.push", "--branch", "feat/test")
	var stdout, stderr bytes.Buffer
	if code := run(arguments, &stdout, &stderr, server.Client()); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"authorized"`)) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestCloneUsesShortLivedReadSessionWithoutTokenInArguments(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.key")
	if _, err := generateIdentity(identityPath); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/read-sessions" || request.Header.Get("Signature") == "" {
			t.Fatalf("request = %s %s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{"token":"short-lived-secret","clone_url":"https://gitoversight.test/git/ActionsJson/actions.json.dev.git"}`))
	}))
	defer server.Close()
	directory := t.TempDir()
	capture := filepath.Join(directory, "capture")
	fakeGit := filepath.Join(directory, "git")
	script := "#!/bin/sh\nprintf '%s\\n%s\\n' \"$*\" \"$GIT_CONFIG_VALUE_0\" > \"$CAPTURE\"\n"
	if err := os.WriteFile(fakeGit, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPTURE", capture)
	t.Setenv("GIT_CONFIG_COUNT", "99")
	t.Setenv("GIT_CONFIG_KEY_98", "hostile")
	arguments := []string{
		"clone", "--url", server.URL, "--identity", identityPath, "--tenant", "tenant-a", "--agent", "dakota", "--credential", "dakota-key-1",
		"--repository", "ActionsJson/actions.json.dev", "--destination", filepath.Join(directory, "checkout"), "--git", fakeGit,
	}
	var stdout, stderr bytes.Buffer
	if code := run(arguments, &stdout, &stderr, server.Client()); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	observed, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(observed)), "\n")
	if len(lines) != 2 || strings.Contains(lines[0], "short-lived-secret") || lines[1] != "Authorization: Bearer short-lived-secret" {
		t.Fatalf("captured = %q", observed)
	}
	if strings.Contains(string(observed), "hostile") {
		t.Fatalf("inherited git config escaped scrubbing: %q", observed)
	}
}

func TestRequestAwaitingApprovalIsNotReportedAsCompleted(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.key")
	if _, err := generateIdentity(identityPath); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusAccepted)
		_, _ = response.Write([]byte(`{"state":"awaiting_approval"}`))
	}))
	defer server.Close()

	arguments := []string{
		"request", "--url", server.URL, "--identity", identityPath,
		"--tenant", "tenant-a", "--agent", "zara", "--credential", "zara-key-1",
		"--request-id", "request-1", "--repository", "yaniv256/public", "--operation", "pull_request.create",
	}
	var stdout, stderr bytes.Buffer
	if code := run(arguments, &stdout, &stderr, server.Client()); code == 0 {
		t.Fatalf("awaiting approval returned success; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestStatusUsesOwnedSignedRoute(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.key")
	if _, err := generateIdentity(identityPath); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/operations/request-1" || request.Header.Get("Signature") == "" {
			t.Fatalf("request = %s %s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		_, _ = response.Write([]byte(`{"state":"verified"}`))
	}))
	defer server.Close()
	arguments := []string{"status", "--url", server.URL, "--identity", identityPath, "--tenant", "tenant-a", "--agent", "zara", "--credential", "zara-key-1", "--request-id", "request-1"}
	if code := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}, server.Client()); code != 0 {
		t.Fatalf("code = %d", code)
	}
}

func TestReconcileUsesOwnedSignedReadOnlyRecoveryRoute(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.key")
	if _, err := generateIdentity(identityPath); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/operations/request-1/reconcile" || request.Header.Get("Signature") == "" {
			t.Fatalf("request = %s %s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		_, _ = response.Write([]byte(`{"state":"verified"}`))
	}))
	defer server.Close()
	arguments := []string{"reconcile", "--url", server.URL, "--identity", identityPath, "--tenant", "tenant-a", "--agent", "zara", "--credential", "zara-key-1", "--request-id", "request-1"}
	if code := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}, server.Client()); code != 0 {
		t.Fatalf("code = %d", code)
	}
}

func TestRemoteClientRejectsNonHTTPSOrigin(t *testing.T) {
	remote := remoteConfig{BaseURL: "http://gitoversight.test", IdentityPath: "key", TenantID: "tenant", AgentID: "zara", CredentialID: "key-1"}
	if remote.validate() == nil {
		t.Fatal("accepted non-HTTPS broker origin")
	}
}
