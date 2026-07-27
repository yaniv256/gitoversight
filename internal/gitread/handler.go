package gitread

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxUploadPackRequestBytes = 8 << 20
	maxReadStreamTime         = 15 * time.Minute
)

type TokenMinter interface {
	Token(repository string) (string, error)
}

type Handler struct {
	base   *url.URL
	client *http.Client
	minter TokenMinter
}

func NewHandler(baseURL string, client *http.Client, minter TokenMinter) (*Handler, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" || client == nil || minter == nil {
		return nil, errors.New("git read handler configuration is incomplete")
	}
	return &Handler{base: base, client: client, minter: minter}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	repository, suffix, ok := parsePath(request.URL.Path)
	if !ok || !uploadPackRequest(request, suffix) {
		http.NotFound(response, request)
		return
	}
	// Upload-pack responses need a generous stream window, but never an
	// unbounded one: a stalled downstream must eventually release capacity.
	_ = http.NewResponseController(response).SetWriteDeadline(time.Now().Add(maxReadStreamTime))
	token, err := handler.minter.Token(repository + "\x00repository.read")
	if err != nil || token == "" {
		http.Error(response, "repository read unavailable", http.StatusServiceUnavailable)
		return
	}
	upstreamURL := *handler.base
	upstreamURL.Path = strings.TrimRight(handler.base.Path, "/") + "/" + repository + ".git" + suffix
	upstreamURL.RawQuery = request.URL.RawQuery
	body := io.Reader(request.Body)
	if request.Body != nil {
		body = io.LimitReader(request.Body, maxUploadPackRequestBytes+1)
	}
	upstream, err := http.NewRequestWithContext(request.Context(), request.Method, upstreamURL.String(), body)
	if err != nil {
		http.Error(response, "repository read unavailable", http.StatusServiceUnavailable)
		return
	}
	copyRequestHeaders(upstream.Header, request.Header)
	upstream.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token)))
	result, err := handler.client.Do(upstream)
	if err != nil {
		http.Error(response, "repository read unavailable", http.StatusBadGateway)
		return
	}
	defer result.Body.Close()
	copyResponseHeaders(response.Header(), result.Header)
	response.WriteHeader(result.StatusCode)
	_, _ = io.Copy(response, result.Body)
}

func parsePath(path string) (string, string, bool) {
	marker := strings.Index(path, ".git/")
	if marker <= 1 {
		return "", "", false
	}
	repository := strings.TrimPrefix(path[:marker], "/")
	suffix := path[marker+4:]
	if strings.Count(repository, "/") != 1 || strings.ContainsAny(repository, "*?[]") || strings.Contains(repository, "..") {
		return "", "", false
	}
	return repository, suffix, true
}

func uploadPackRequest(request *http.Request, suffix string) bool {
	switch {
	case request.Method == http.MethodGet && suffix == "/info/refs":
		return request.URL.Query().Get("service") == "git-upload-pack"
	case request.Method == http.MethodPost && suffix == "/git-upload-pack":
		return request.URL.RawQuery == ""
	default:
		return false
	}
}

func copyRequestHeaders(target, source http.Header) {
	for _, name := range []string{"Accept", "Content-Encoding", "Content-Type", "Git-Protocol", "User-Agent"} {
		for _, value := range source.Values(name) {
			target.Add(name, value)
		}
	}
}

func copyResponseHeaders(target, source http.Header) {
	for name, values := range source {
		if hopByHop(name) {
			continue
		}
		for _, value := range values {
			target.Add(name, value)
		}
	}
}

func hopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}
