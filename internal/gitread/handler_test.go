package gitread_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/gitread"
)

type tokenMinter struct{ repository string }

func (m *tokenMinter) Token(repository string) (string, error) {
	m.repository = repository
	return "installation-token", nil
}

func TestHandlerProxiesUploadPackWithWorkerHeldInstallationToken(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:installation-token"))
		if request.Method != http.MethodGet || request.URL.Path != "/ActionsJson/actions.json.dev.git/info/refs" || request.URL.Query().Get("service") != "git-upload-pack" || request.Header.Get("Authorization") != want {
			t.Fatalf("upstream request = %s %s auth=%q", request.Method, request.URL.String(), request.Header.Get("Authorization"))
		}
		response.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = io.WriteString(response, "001e# service=git-upload-pack\n0000")
	}))
	defer upstream.Close()
	minter := &tokenMinter{}
	handler, err := gitread.NewHandler(upstream.URL, upstream.Client(), minter)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/ActionsJson/actions.json.dev.git/info/refs?service=git-upload-pack", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || minter.repository != "ActionsJson/actions.json.dev\x00repository.read" || !strings.Contains(response.Body.String(), "git-upload-pack") {
		t.Fatalf("response=%d repository=%q body=%q", response.Code, minter.repository, response.Body.String())
	}
}

func TestHandlerPreservesCompressedUploadPackEncoding(t *testing.T) {
	t.Parallel()
	const compressedBody = "compressed-upload-pack-request"
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if request.Method != http.MethodPost || request.URL.Path != "/yaniv256/seethegalaxy.git/git-upload-pack" || request.Header.Get("Content-Encoding") != "gzip" || string(body) != compressedBody {
			t.Fatalf("upstream request = %s %s encoding=%q body=%q", request.Method, request.URL.String(), request.Header.Get("Content-Encoding"), body)
		}
		response.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		_, _ = io.WriteString(response, "0000")
	}))
	defer upstream.Close()

	handler, err := gitread.NewHandler(upstream.URL, upstream.Client(), &tokenMinter{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/yaniv256/seethegalaxy.git/git-upload-pack", strings.NewReader(compressedBody))
	request.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	request.Header.Set("Content-Encoding", "gzip")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "0000" {
		t.Fatalf("response=%d body=%q", response.Code, response.Body.String())
	}
}

func TestHandlerRejectsReceivePackAndMalformedRepositoryPaths(t *testing.T) {
	t.Parallel()
	minter := &tokenMinter{}
	handler, err := gitread.NewHandler("https://github.example", http.DefaultClient, minter)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"/ActionsJson/actions.json.dev.git/info/refs?service=git-receive-pack",
		"/ActionsJson/actions.json.dev.git/git-receive-pack",
		"/one-segment.git/info/refs?service=git-upload-pack",
		"/ActionsJson/actions.json.dev/extra.git/info/refs?service=git-upload-pack",
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s = %d", target, response.Code)
		}
	}
	if minter.repository != "" {
		t.Fatalf("minter reached for rejected request: %q", minter.repository)
	}
}
