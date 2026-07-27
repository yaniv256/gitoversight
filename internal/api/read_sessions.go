package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

const (
	readSessionBodyLimit = 4096
	readRepositoryHeader = "X-GitOversight-Repository"
	readAgentHeader      = "X-GitOversight-Agent"
	maxReadSessions      = 4096
	maxAgentReadSessions = 32
	maxReadStreamTime    = 15 * time.Minute
)

type ReadHandlerConfig struct {
	Policy     policy.Snapshot
	SessionTTL time.Duration
	GitBaseURL string
	GitProxy   http.Handler
	Random     io.Reader
	Now        func() time.Time
}

type readSession struct {
	Repository string
	Agent      string
	ExpiresAt  time.Time
}

type ReadHandler struct {
	policy     policy.Snapshot
	ttl        time.Duration
	gitBaseURL string
	gitProxy   http.Handler
	random     io.Reader
	now        func() time.Time
	mu         sync.Mutex
	sessions   map[[sha256.Size]byte]readSession
}

func NewReadHandler(config ReadHandlerConfig) (*ReadHandler, error) {
	if config.SessionTTL <= 0 || config.SessionTTL > time.Hour || strings.TrimSpace(config.GitBaseURL) == "" || config.GitProxy == nil {
		return nil, errors.New("read handler configuration is incomplete")
	}
	if err := config.Policy.Validate(); err != nil {
		return nil, err
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &ReadHandler{
		policy: config.Policy, ttl: config.SessionTTL, gitBaseURL: strings.TrimRight(config.GitBaseURL, "/"),
		gitProxy: config.GitProxy, random: config.Random, now: config.Now, sessions: make(map[[sha256.Size]byte]readSession),
	}, nil
}

func (handler *ReadHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/read-sessions":
		handler.create(response, request)
	case strings.HasPrefix(request.URL.Path, "/git/"):
		handler.read(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (handler *ReadHandler) create(response http.ResponseWriter, request *http.Request) {
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok || identity.AgentID == "" {
		http.Error(response, "agent authentication required", http.StatusUnauthorized)
		return
	}
	var input struct {
		Repository string `json:"repository"`
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, readSessionBodyLimit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF || strings.Count(input.Repository, "/") != 1 || strings.ContainsAny(input.Repository, "*?[]") {
		http.Error(response, "invalid read-session request", http.StatusBadRequest)
		return
	}
	decision := policy.Evaluate(handler.policy, policy.Request{Caller: identity.AgentID, Repository: input.Repository, Operation: "repository.read"})
	if decision.Code != policy.AllowedRead {
		http.Error(response, "repository read denied", http.StatusForbidden)
		return
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(handler.random, secret); err != nil {
		http.Error(response, "read session unavailable", http.StatusServiceUnavailable)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	for index := range secret {
		secret[index] = 0
	}
	expiresAt := handler.now().UTC().Add(handler.ttl)
	handler.mu.Lock()
	now := handler.now().UTC()
	agentSessions := 0
	for digest, session := range handler.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(handler.sessions, digest)
			continue
		}
		if session.Agent == identity.AgentID {
			agentSessions++
		}
	}
	if len(handler.sessions) >= maxReadSessions || agentSessions >= maxAgentReadSessions {
		handler.mu.Unlock()
		http.Error(response, "too many active read sessions", http.StatusTooManyRequests)
		return
	}
	handler.sessions[sha256.Sum256([]byte(token))] = readSession{Repository: input.Repository, Agent: identity.AgentID, ExpiresAt: expiresAt}
	handler.mu.Unlock()
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(response).Encode(map[string]any{
		"token": token, "clone_url": handler.gitBaseURL + "/" + input.Repository + ".git", "expires_at": expiresAt,
	})
}

func (handler *ReadHandler) read(response http.ResponseWriter, request *http.Request) {
	repository, ok := repositoryFromGitPath(request.URL.Path)
	if !ok {
		http.NotFound(response, request)
		return
	}
	value := strings.TrimSpace(request.Header.Get("Authorization"))
	if !strings.HasPrefix(value, "Bearer ") || len(value) <= len("Bearer ") {
		http.Error(response, "read session required", http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
	digest := sha256.Sum256([]byte(token))
	now := handler.now().UTC()
	handler.mu.Lock()
	session, found := handler.sessions[digest]
	if found && !now.Before(session.ExpiresAt) {
		delete(handler.sessions, digest)
		found = false
	}
	handler.mu.Unlock()
	if !found || session.Repository != repository {
		http.Error(response, "read session invalid", http.StatusUnauthorized)
		return
	}
	request.Header.Del("Authorization")
	request.Header.Set(readRepositoryHeader, repository)
	request.Header.Set(readAgentHeader, session.Agent)
	proxied := request.Clone(request.Context())
	proxied.URL.Path = strings.TrimPrefix(request.URL.Path, "/git")
	// Git pack responses can legitimately stream for minutes, but keep a
	// finite ceiling so a slow reader cannot occupy an API slot forever.
	_ = http.NewResponseController(response).SetWriteDeadline(handler.now().Add(maxReadStreamTime))
	handler.gitProxy.ServeHTTP(response, proxied)
}

func repositoryFromGitPath(path string) (string, bool) {
	value := strings.TrimPrefix(path, "/git/")
	marker := strings.Index(value, ".git/")
	if marker <= 0 {
		return "", false
	}
	repository := value[:marker]
	if strings.Count(repository, "/") != 1 || strings.ContainsAny(repository, "*?[]") {
		return "", false
	}
	return repository, true
}
