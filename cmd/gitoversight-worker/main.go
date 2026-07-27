package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/authorityrpc"
	"github.com/yaniv256/gitoversight.dev/internal/credentialfile"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/githubauth"
	"github.com/yaniv256/gitoversight.dev/internal/gitread"
	"github.com/yaniv256/gitoversight.dev/internal/oauthflow"
	"github.com/yaniv256/gitoversight.dev/internal/searchstore"
	"github.com/yaniv256/gitoversight.dev/internal/searchsync"
	"github.com/yaniv256/gitoversight.dev/internal/tokenvault"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type config struct {
	WorkerID            string            `json:"worker_id"`
	Socket              string            `json:"socket"`
	GitReadSocket       string            `json:"git_read_socket"`
	GitHubGitBaseURL    string            `json:"github_git_base_url"`
	AuthoritySocket     string            `json:"authority_socket"`
	BrokerUID           uint32            `json:"broker_uid"`
	GitHubBaseURL       string            `json:"github_base_url"`
	GitHubOAuthBaseURL  string            `json:"github_oauth_base_url"`
	GitHubOAuthRedirect string            `json:"github_oauth_redirect_uri"`
	GitHubAppClientID   string            `json:"github_app_client_id"`
	GitHubAppSecretFile string            `json:"github_app_client_secret_file"`
	GitHubAppKeyFile    string            `json:"github_app_private_key_file"`
	Installations       map[string]int64  `json:"installations"`
	HumanInstallations  map[string]int64  `json:"human_installations"`
	HTTPTimeout         string            `json:"http_timeout"`
	VaultPath           string            `json:"vault_path"`
	VaultKeyFile        string            `json:"vault_key_file"`
	Repositories        map[string]string `json:"repositories"`
	OAuthMaxConcurrent  int               `json:"oauth_max_concurrent"`
	// SearchDBPath enables the repo-search sync loop. Empty means disabled, so
	// deployments without the new config keys keep working unchanged.
	SearchDBPath       string `json:"search_db_path"`
	SearchSyncInterval string `json:"search_sync_interval"`
}

type repositoryOAuthBeginner struct {
	coordinator        oauthCoordinator
	installations      map[string]int64
	humanInstallations map[string]int64
}

type pullListRunner struct {
	*worker.Worker
	executor *githubapp.Executor
}

func (r *pullListRunner) List(request worker.Request) ([]githubapp.PullRequestSummary, error) {
	return r.executor.ListPullRequests(request)
}

func (r *pullListRunner) PullState(request worker.Request, number int64) (githubapp.PullState, error) {
	return r.executor.PullRequestState(request, number)
}

type oauthCoordinator interface {
	Begin(oauthflow.BeginRequest) (string, error)
	Complete(string, string) (oauthflow.Completion, error)
}

func (b *repositoryOAuthBeginner) CompleteOAuth(request workerrpc.OAuthCallbackRequest) (workerrpc.OAuthCompletion, error) {
	completion, err := b.coordinator.Complete(request.State, request.Code)
	return workerrpc.OAuthCompletion{Purpose: completion.Purpose, Session: completion.Session, Subject: completion.Subject}, err
}

func (b *repositoryOAuthBeginner) BeginOAuth(request workerrpc.OAuthBeginRequest) (string, error) {
	var installation int64
	var ok bool
	switch request.Purpose {
	case "human_login":
		installation, ok = b.humanInstallations[request.GitHubLogin]
	case "public_actor":
		installation, ok = githubauth.ResolveInstallation(b.installations, request.Repository)
	default:
		return "", errors.New("oauth purpose unavailable")
	}
	if !ok || installation <= 0 {
		return "", errors.New("repository installation unavailable")
	}
	return b.coordinator.Begin(oauthflow.BeginRequest{
		Purpose: request.Purpose, Session: request.Session, Subject: request.Subject,
		GitHubLogin: request.GitHubLogin, Installation: installation, ExpiresAt: request.ExpiresAt,
	})
}

func main() {
	configPath := flag.String("config", "", "path to root-owned worker configuration")
	flag.Parse()
	if *configPath == "" {
		fatal("-config is required")
	}
	payload, err := os.ReadFile(*configPath)
	if err != nil {
		fatal("read config: %v", err)
	}
	var cfg config
	if err := json.Unmarshal(payload, &cfg); err != nil {
		fatal("decode config: %v", err)
	}
	if cfg.WorkerID == "" || cfg.Socket == "" || cfg.GitReadSocket == "" || cfg.GitHubGitBaseURL == "" || cfg.AuthoritySocket == "" || cfg.GitHubBaseURL == "" || cfg.GitHubOAuthBaseURL == "" || cfg.GitHubOAuthRedirect == "" || cfg.GitHubAppClientID == "" || cfg.GitHubAppSecretFile == "" || cfg.GitHubAppKeyFile == "" || len(cfg.Installations) == 0 || len(cfg.HumanInstallations) == 0 || cfg.VaultPath == "" || cfg.VaultKeyFile == "" || cfg.OAuthMaxConcurrent <= 0 {
		fatal("worker configuration is incomplete")
	}
	timeout, err := time.ParseDuration(cfg.HTTPTimeout)
	if err != nil || timeout <= 0 || timeout > time.Minute {
		fatal("http_timeout must be between 1ns and 1m")
	}
	key, err := loadKey(cfg.VaultKeyFile)
	if err != nil {
		fatal("load vault key: %v", err)
	}
	vault, err := tokenvault.Open(cfg.VaultPath, key)
	if err != nil {
		fatal("open vault: %v", err)
	}
	httpClient := &http.Client{Timeout: timeout}
	gitHTTPClient := &http.Client{Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          16,
	}}
	privateKey, err := loadSecretFile(cfg.GitHubAppKeyFile, 256)
	if err != nil {
		fatal("load GitHub App private key: %v", err)
	}
	minter, err := githubauth.NewInstallationMinter(cfg.GitHubBaseURL, cfg.GitHubAppClientID, privateKey, httpClient, cfg.Installations)
	if err != nil {
		fatal("create installation token minter: %v", err)
	}
	gitReadHandler, err := gitread.NewHandler(cfg.GitHubGitBaseURL, gitHTTPClient, minter)
	if err != nil {
		fatal("create repository read proxy: %v", err)
	}
	gitReadListener, err := gitread.ListenUnix(cfg.GitReadSocket, cfg.BrokerUID)
	if err != nil {
		fatal("listen repository read proxy: %v", err)
	}
	defer gitReadListener.Close()
	gitReadServer := &http.Server{Handler: gitReadHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 15 * time.Minute, IdleTimeout: 30 * time.Second}
	go func() {
		if serveErr := gitReadServer.Serve(gitReadListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			fatal("repository read proxy: %v", serveErr)
		}
	}()
	clientSecret, err := loadSecretFile(cfg.GitHubAppSecretFile, 16)
	if err != nil {
		fatal("load GitHub App client secret: %v", err)
	}
	clientSecret = bytes.TrimSpace(clientSecret)
	userTokens, err := githubauth.NewUserTokenProvider(cfg.GitHubOAuthBaseURL, cfg.GitHubAppClientID, string(clientSecret), httpClient, vault)
	if err != nil {
		fatal("create human token provider: %v", err)
	}
	oauthCoordinator, err := oauthflow.New(oauthflow.Config{OAuthBaseURL: cfg.GitHubOAuthBaseURL, APIBaseURL: cfg.GitHubBaseURL, ClientID: cfg.GitHubAppClientID, ClientSecret: string(clientSecret), RedirectURI: cfg.GitHubOAuthRedirect, MaxConcurrent: cfg.OAuthMaxConcurrent}, httpClient, vault)
	if err != nil {
		fatal("create OAuth coordinator: %v", err)
	}
	redirect, err := url.Parse(cfg.GitHubOAuthRedirect)
	if err != nil || redirect.Path == "" || redirect.Path == "/webhooks/github" {
		fatal("parse OAuth redirect URI")
	}
	tokens := func(mode githubapp.TokenMode, subject string) (string, error) {
		switch mode {
		case githubapp.AppInstallation:
			return minter.Token(subject)
		case githubapp.HumanUser:
			return userTokens.Token(subject)
		case githubapp.InstallationWide:
			installationID, err := strconv.ParseInt(subject, 10, 64)
			if err != nil || installationID <= 0 {
				return "", errors.New("installation-wide subject is invalid")
			}
			return minter.InstallationToken(installationID)
		default:
			return "", errors.New("token mode is invalid")
		}
	}
	visibility := func(repository string) (string, error) {
		value, ok := cfg.Repositories[repository]
		if !ok || (value != "private" && value != "public") {
			return "", errors.New("repository visibility unavailable")
		}
		return value, nil
	}
	client, err := githubapp.New(cfg.GitHubBaseURL, httpClient, tokens, visibility)
	if err != nil {
		fatal("create GitHub client: %v", err)
	}
	executor := githubapp.NewExecutor(client)
	runner := &pullListRunner{Worker: worker.New(authorityrpc.NewClient(cfg.AuthoritySocket), executor), executor: executor}
	oauthService := &repositoryOAuthBeginner{coordinator: oauthCoordinator, installations: cfg.Installations, humanInstallations: cfg.HumanInstallations}
	serviceOptions := []workerrpc.Option{workerrpc.WithRunner(runner), workerrpc.WithOAuthBeginner(oauthService), workerrpc.WithOAuthCompleter(oauthService)}
	// Pre-PR base resolution: the API asks the worker what a public repository
	// currently looks like, because credentials live here and not there.
	if baseIDs := installationIDs(cfg.Installations); len(baseIDs) > 0 {
		baseReader, err := githubapp.NewReader(client, githubapp.ReaderConfig{})
		if err != nil {
			fatal("create base reader: %v", err)
		}
		resolver, err := newBaseResolver(baseReader, baseIDs[0], visibility)
		if err != nil {
			fatal("create base resolver: %v", err)
		}
		serviceOptions = append(serviceOptions, workerrpc.WithBaseReader(resolver))
	}
	if cfg.SearchDBPath != "" {
		searchInterval := time.Hour
		if cfg.SearchSyncInterval != "" {
			searchInterval, err = time.ParseDuration(cfg.SearchSyncInterval)
			if err != nil || searchInterval <= 0 {
				fatal("search_sync_interval must be a positive duration")
			}
		}
		searchIDs := installationIDs(cfg.Installations)
		if len(searchIDs) == 0 {
			fatal("search sync requires at least one enabled installation")
		}
		// searchstore.Open creates the directory group-accessible (0o750): the
		// API binary's OS user reads the database cross-process via WAL.
		// An open failure disables search sync instead of killing the process:
		// the dataset is a rebuildable cache, and governance must not die for it.
		if searchStore := openSearchStore(context.Background(), cfg.SearchDBPath, stderrLogf); searchStore != nil {
			searchReader, err := githubapp.NewReader(client, githubapp.ReaderConfig{})
			if err != nil {
				fatal("create search reader: %v", err)
			}
			syncer, err := searchsync.New(searchsync.Options{
				Store:  searchStore,
				Reader: searchReader,
				Pulls: func(repository string) ([]searchstore.Pull, error) {
					summaries, err := client.ListPullRequests(repository, githubapp.AppInstallation, repository+"\x00"+"pull_request.list")
					if err != nil {
						return nil, err
					}
					return storePulls(summaries), nil
				},
				Interval:            searchInterval,
				InstallationIDs:     searchIDs,
				ConfiguredRepoCount: len(cfg.Repositories),
			})
			if err != nil {
				fatal("create search syncer: %v", err)
			}
			go syncer.Run(context.Background())
			serviceOptions = append(serviceOptions, workerrpc.WithSearchSyncTrigger(syncer.Trigger))
		}
	}
	// The failure reporter is appended to the options main already assembled,
	// rather than replacing them: search-sync wiring and failure reporting are
	// independent additions to the same constructor.
	serviceOptions = append(serviceOptions, workerrpc.WithFailureReporter(func(failure workerrpc.Failure) {
		log.Printf("worker failure action=%q request_id=%q repository=%q operation=%q error=%q", failure.Action, failure.RequestID, failure.Repository, failure.Operation, failure.Err)
	}))
	service := workerrpc.NewServer(cfg.Socket, cfg.BrokerUID, serviceOptions...)
	listener, err := service.Listen()
	if err != nil {
		fatal("listen: %v", err)
	}
	if err := service.Serve(listener); err != nil {
		fatal("serve: %v", err)
	}
}

// openSearchStore opens the search dataset database. On failure it logs
// loudly and returns nil so the caller starts the governance worker with
// search sync disabled (no Syncer goroutine, no RPC trigger wiring) — the
// search dataset is a rebuildable cache and must never take governance down.
func openSearchStore(ctx context.Context, path string, logf func(format string, args ...any)) *searchstore.Store {
	store, err := searchstore.Open(ctx, path)
	if err != nil {
		logf("SEARCH SYNC DISABLED: open search store %q: %v — the governance worker continues without search sync; fix the path/permissions and restart to re-enable", path, err)
		return nil
	}
	return store
}

func stderrLogf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// installationIDs returns the sorted, deduplicated installation IDs from the
// worker's installations map, skipping disabled (non-positive) entries.
func installationIDs(installations map[string]int64) []int64 {
	seen := make(map[int64]bool, len(installations))
	ids := make([]int64, 0, len(installations))
	for _, id := range installations {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// storePulls converts pull_request.list summaries into searchstore rows.
func storePulls(summaries []githubapp.PullRequestSummary) []searchstore.Pull {
	pulls := make([]searchstore.Pull, 0, len(summaries))
	for _, summary := range summaries {
		pulls = append(pulls, searchstore.Pull{
			Number:  summary.Number,
			Title:   summary.Title,
			Author:  summary.Author,
			HTMLURL: summary.HTMLURL,
			HeadRef: summary.HeadRef,
		})
	}
	return pulls
}

func loadKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !credentialfile.PermissionsSafe(path, info.Mode(), os.Getenv("CREDENTIALS_DIRECTORY")) {
		return nil, errors.New("vault key file permissions are unsafe")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(value) == 33 && value[32] == '\n' {
		value = value[:32]
	}
	if len(value) != 32 {
		return nil, errors.New("vault key file must contain exactly 32 bytes")
	}
	return value, nil
}

func loadSecret(path string) ([]byte, error) {
	return loadSecretFile(path, 32)
}

func loadSecretFile(path string, minimumBytes int) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !credentialfile.PermissionsSafe(path, info.Mode(), os.Getenv("CREDENTIALS_DIRECTORY")) {
		return nil, errors.New("secret file permissions are unsafe")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(value) < minimumBytes {
		return nil, errors.New("secret file is too short")
	}
	return value, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
