package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/api"
	"github.com/yaniv256/gitoversight.dev/internal/appauth"
	"github.com/yaniv256/gitoversight.dev/internal/attribution"
	"github.com/yaniv256/gitoversight.dev/internal/auditanchor"
	"github.com/yaniv256/gitoversight.dev/internal/authorityrpc"
	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
	"github.com/yaniv256/gitoversight.dev/internal/checkpoint"
	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/credentialfile"
	"github.com/yaniv256/gitoversight.dev/internal/gitread"
	"github.com/yaniv256/gitoversight.dev/internal/httpapi"
	"github.com/yaniv256/gitoversight.dev/internal/mcpapp"
	"github.com/yaniv256/gitoversight.dev/internal/notificationrpc"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/snapshotdownload"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/ui"
	"github.com/yaniv256/gitoversight.dev/internal/workerread"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type config struct {
	Listen                      string            `json:"listen"`
	DatabasePath                string            `json:"database_path"`
	TenantID                    string            `json:"tenant_id"`
	PolicyFile                  string            `json:"policy_file"`
	WorkerSocket                string            `json:"worker_socket"`
	GitReadSocket               string            `json:"git_read_socket"`
	GitReadBaseURL              string            `json:"git_read_base_url"`
	ReadSessionTTL              string            `json:"read_session_ttl"`
	AuthoritySocket             string            `json:"authority_socket"`
	WorkerUID                   uint32            `json:"worker_uid"`
	AuthoritySocketGID          int               `json:"authority_socket_gid"`
	NotificationSocket          string            `json:"notification_socket"`
	NotificationUID             uint32            `json:"notification_uid"`
	NotificationSocketGID       int               `json:"notification_socket_gid"`
	CheckpointSocket            string            `json:"checkpoint_socket"`
	WebhookSecretFile           string            `json:"webhook_secret_file"`
	EnrollmentChallengeTTL      string            `json:"enrollment_challenge_ttl"`
	HumanSessionTTL             string            `json:"human_session_ttl"`
	SignatureTTL                string            `json:"signature_ttl"`
	SignatureClockSkew          string            `json:"signature_clock_skew"`
	CheckpointTimeout           string            `json:"checkpoint_timeout"`
	ExecutionGrantTTL           string            `json:"execution_grant_ttl"`
	WorkerID                    string            `json:"worker_id"`
	RateLimitWindow             string            `json:"rate_limit_window"`
	RateLimitRequests           int               `json:"rate_limit_requests"`
	SearchDBPath                string            `json:"search_db_path"`
	MaxBodyBytes                int64             `json:"max_body_bytes"`
	ReleaseAssetRoot            string            `json:"release_asset_root"`
	ReleaseAssetCapabilityTTL   string            `json:"release_asset_capability_ttl"`
	ReleaseAssetStageTTL        string            `json:"release_asset_stage_ttl"`
	ReleaseAssetCleanupInterval string            `json:"release_asset_cleanup_interval"`
	ReleaseAssetTerminalGrace   string            `json:"release_asset_terminal_grace"`
	ReleaseAssetClaimTimeout    string            `json:"release_asset_claim_timeout"`
	ReleaseAssetUploadTimeout   string            `json:"release_asset_upload_timeout"`
	ReleaseAssetOrphanGrace     string            `json:"release_asset_orphan_grace"`
	MaxConcurrent               int               `json:"max_concurrent"`
	MinimumFreeBytes            uint64            `json:"minimum_free_bytes"`
	AllowedNotificationAdapters []string          `json:"allowed_notification_adapters"`
	HumanApprovers              map[string]string `json:"human_approvers"`
	PolicyOrchestrators         []string          `json:"policy_orchestrators"`
	WorkOAuthIssuer             string            `json:"work_oauth_issuer"`
	WorkOAuthAudience           string            `json:"work_oauth_audience"`
	WorkOAuthClientID           string            `json:"work_oauth_client_id"`
	WorkOAuthClientName         string            `json:"work_oauth_client_name"`
	WorkOAuthRedirectURIs       []string          `json:"work_oauth_redirect_uris"`
	WorkOAuthAllowedOrigins     []string          `json:"work_oauth_allowed_origins"`
	WorkOAuthCodeTTL            string            `json:"work_oauth_code_ttl"`
	WorkOAuthAccessTTL          string            `json:"work_oauth_access_ttl"`
	WorkOAuthRefreshTTL         string            `json:"work_oauth_refresh_ttl"`
	WorkMCPSessionTTL           string            `json:"work_mcp_session_ttl"`
}

func validateReleaseAssetProtocol(rootID string, status workerrpc.ReleaseAssetReadiness) error {
	if status.ProtocolVersion != releaseasset.ProtocolVersion {
		return fmt.Errorf("release asset protocol mismatch: api=%d worker=%d", releaseasset.ProtocolVersion, status.ProtocolVersion)
	}
	if rootID == "" || status.RootID != rootID {
		return errors.New("release asset root mismatch")
	}
	if !status.Readable {
		return errors.New("release asset root is not readable by worker")
	}
	return nil
}

func main() {
	configPath := flag.String("config", "", "path to API configuration")
	listenOverride := flag.String("listen", "", "override loopback listen address")
	flag.Parse()
	if *configPath == "" {
		fatal("-config is required")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal("configuration: %v", err)
	}
	if *listenOverride != "" {
		cfg.Listen = *listenOverride
	}
	if err := requireLoopback(cfg.Listen); err != nil {
		fatal("listen: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: cfg.DatabasePath})
	if err != nil {
		fatal("database: %v", err)
	}
	defer db.Close()
	// Payload retention: terminal packets keep every authorization-relevant
	// field, but their payload_json commit packets embed whole repository
	// trees and dominated database size in production (279MB of 283MB,
	// 2026-07-22). Prune hourly, keeping a 7-day debugging window.
	go func() {
		const payloadRetention = 7 * 24 * time.Hour
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			if deleted, err := db.DeleteExpiredChangeDrafts(ctx, time.Now().UTC()); err != nil {
				fmt.Fprintf(os.Stderr, "expired change-draft cleanup failed: %v\n", err)
			} else if deleted > 0 {
				fmt.Fprintf(os.Stderr, "deleted %d expired change drafts\n", deleted)
			}
			pruned, err := db.PruneTerminalPacketPayloads(ctx, time.Now().Add(-payloadRetention))
			if err != nil {
				fmt.Fprintf(os.Stderr, "packet payload prune failed: %v\n", err)
			} else if pruned > 0 {
				fmt.Fprintf(os.Stderr, "pruned payloads from %d terminal operation packets\n", pruned)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	snapshot, err := readPolicy(cfg.PolicyFile)
	if err != nil {
		fatal("policy: %v", err)
	}
	checkpointTimeout := duration(cfg.CheckpointTimeout, "checkpoint_timeout")
	checkpointClient, err := checkpoint.NewClient(cfg.CheckpointSocket, checkpointTimeout)
	if err != nil {
		fatal("checkpoint: %v", err)
	}
	authorityAnchor, err := auditanchor.New(db, cfg.TenantID, checkpointClient, checkpointTimeout)
	if err != nil {
		fatal("audit anchor: %v", err)
	}
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(authorityAnchor)
	broker.SetHumanLogins(cfg.HumanApprovers)
	if _, err := broker.RecoverInterruptedExecutions(ctx, cfg.TenantID); err != nil {
		fatal("recover interrupted executions: %v", err)
	}
	snapshot, err = ensurePolicy(ctx, broker, cfg.TenantID, snapshot)
	if err != nil {
		fatal("install policy: %v", err)
	}

	challengeTTL := duration(cfg.EnrollmentChallengeTTL, "enrollment_challenge_ttl")
	sessionTTL := duration(cfg.HumanSessionTTL, "human_session_ttl")
	signatureTTL := duration(cfg.SignatureTTL, "signature_ttl")
	clockSkew := duration(cfg.SignatureClockSkew, "signature_clock_skew")
	executionGrantTTL := duration(cfg.ExecutionGrantTTL, "execution_grant_ttl")
	rateWindow := duration(cfg.RateLimitWindow, "rate_limit_window")

	credentials := agentauth.NewCredentialService(db, agentauth.CredentialServiceConfig{ChallengeTTL: challengeTTL, WriteGate: authorityAnchor})
	limiter, err := agentauth.NewFixedWindowLimiter(cfg.RateLimitRequests, rateWindow, nil)
	if err != nil {
		fatal("rate limiter: %v", err)
	}
	agentMiddleware, err := agentauth.NewMiddleware(credentials, agentauth.MiddlewareConfig{
		MaxBodyBytes: cfg.MaxBodyBytes, SignatureTTL: signatureTTL, ClockSkew: clockSkew, SourceLimiter: limiter,
	})
	if err != nil {
		fatal("agent authentication: %v", err)
	}
	releaseAssetRoot := strings.TrimSpace(cfg.ReleaseAssetRoot)
	if releaseAssetRoot == "" {
		releaseAssetRoot = filepath.Join(filepath.Dir(cfg.DatabasePath), "release-assets")
	}
	releaseAssetFiles, err := releaseasset.NewFileStore(releaseAssetRoot)
	if err != nil {
		fatal("release asset store: %v", err)
	}
	releaseAssetCapabilityTTL := optionalDuration(cfg.ReleaseAssetCapabilityTTL, 10*time.Minute)
	releaseAssetStageTTL := optionalDuration(cfg.ReleaseAssetStageTTL, 24*time.Hour)
	releaseAssetHandler, err := api.NewReleaseAssetHandler(api.ReleaseAssetHandlerConfig{
		Authority: broker, Reader: db, Files: releaseAssetFiles,
		UploadAuth:       agentMiddleware.UploadAuthenticator(),
		MaxMetadataBytes: cfg.MaxBodyBytes,
		// GitHub accepts release assets strictly smaller than 2 GiB. Keep this
		// as the upstream boundary rather than inventing a lower product cap.
		MaxAssetBytes: 2 << 30, CapabilityTTL: releaseAssetCapabilityTTL, StageTTL: releaseAssetStageTTL,
		UploadTimeout: optionalDuration(cfg.ReleaseAssetUploadTimeout, 30*time.Minute),
	})
	if err != nil {
		fatal("release asset ingress: %v", err)
	}
	releaseAssetMaintenance, err := api.NewReleaseAssetMaintenance(db, releaseAssetFiles, api.ReleaseAssetMaintenanceConfig{
		TerminalGrace: optionalDuration(cfg.ReleaseAssetTerminalGrace, 24*time.Hour),
		ClaimTimeout:  optionalDuration(cfg.ReleaseAssetClaimTimeout, 15*time.Minute),
		UploadTimeout: optionalDuration(cfg.ReleaseAssetUploadTimeout, 30*time.Minute),
		OrphanGrace:   optionalDuration(cfg.ReleaseAssetOrphanGrace, 24*time.Hour),
		MaxDeletes:    100,
	})
	if err != nil {
		fatal("release asset maintenance: %v", err)
	}
	cleanupInterval := optionalDuration(cfg.ReleaseAssetCleanupInterval, 5*time.Minute)
	go func() {
		run := func() {
			if maintenanceErr := releaseAssetMaintenance.RunOnce(ctx, time.Now().UTC()); maintenanceErr != nil {
				fmt.Fprintf(os.Stderr, "release asset maintenance: %v\n", maintenanceErr)
			}
		}
		run()
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
	humanSessions, err := api.NewHumanSessionManager(db, api.HumanSessionConfig{SessionTTL: sessionTTL})
	if err != nil {
		fatal("human sessions: %v", err)
	}
	authorityService := authorityrpc.NewServer(cfg.AuthoritySocket, broker, cfg.WorkerUID, cfg.WorkerID, cfg.TenantID, cfg.AuthoritySocketGID)
	authorityListener, err := authorityService.Listen()
	if err != nil {
		fatal("authority RPC: %v", err)
	}
	defer authorityListener.Close()
	serviceErrors := make(chan error, 2)
	go func() {
		if err := authorityService.Serve(authorityListener); err != nil {
			serviceErrors <- fmt.Errorf("authority RPC stopped: %w", err)
		}
	}()
	if cfg.NotificationSocket != "" {
		notificationService := notificationrpc.NewServer(cfg.NotificationSocket, db, cfg.NotificationUID, cfg.NotificationSocketGID)
		notificationListener, listenErr := notificationService.Listen()
		if listenErr != nil {
			fatal("notification RPC: %v", listenErr)
		}
		defer notificationListener.Close()
		go func() {
			if serveErr := notificationService.Serve(notificationListener); serveErr != nil {
				serviceErrors <- fmt.Errorf("notification RPC stopped: %w", serveErr)
			}
		}()
	}
	workerClient := workerrpc.NewClient(cfg.WorkerSocket)
	syncProposals := api.NewSyncProposalApplication(snapshot, db, workerClient, "main", nil, broker)
	executionCoordinator := api.NewExecutionCoordinator(broker, workerClient, api.ExecutionCoordinatorConfig{
		WorkerID: cfg.WorkerID, GrantTTL: executionGrantTTL, ActivityStore: db,
	})
	var workOAuthHandler http.Handler
	var workMCPHandler http.Handler
	var repositorySnapshotHandler http.Handler
	if cfg.WorkOAuthIssuer != "" {
		client := appauth.Client{Issuer: strings.TrimRight(cfg.WorkOAuthIssuer, "/"), Audience: cfg.WorkOAuthAudience, ID: cfg.WorkOAuthClientID, Name: cfg.WorkOAuthClientName, RedirectURIs: cfg.WorkOAuthRedirectURIs}
		authService := appauth.NewService(db)
		if err := authService.RegisterClient(ctx, client); err != nil {
			fatal("work oauth client: %v", err)
		}
		workOAuthHandler, err = api.NewWorkOAuthHandler(authService, broker, api.WorkOAuthConfig{
			Client: client, CodeLifetime: optionalDuration(cfg.WorkOAuthCodeTTL, 5*time.Minute),
			AccessLifetime: optionalDuration(cfg.WorkOAuthAccessTTL, time.Hour), RefreshLifetime: optionalDuration(cfg.WorkOAuthRefreshTTL, 30*24*time.Hour),
			MaxBodyBytes: cfg.MaxBodyBytes,
		})
		if err != nil {
			fatal("work oauth handler: %v", err)
		}
		accessAdapter, err := mcpapp.NewOAuthAccessAdapter(authService, broker, client.Issuer, client.Audience)
		if err != nil {
			fatal("work oauth access adapter: %v", err)
		}
		operations := brokerapp.NewOperationService(broker, executionCoordinator)
		draftRepository, err := workerread.NewChangeDraftRepository(workerClient, "refs/heads/main", changedraft.DefaultLimits())
		if err != nil {
			fatal("work change-draft repository: %v", err)
		}
		changeDrafts := brokerapp.NewChangeDraftService(draftRepository, db, brokerapp.ChangeDraftConfig{})
		changeDraftPublisher := brokerapp.NewChangeDraftPublisher(changeDrafts, db, operations, nil)
		downloads, err := snapshotdownload.New(client.Issuer, 5*time.Minute, nil)
		if err != nil {
			fatal("work snapshot downloads: %v", err)
		}
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					downloads.DeleteExpired()
				}
			}
		}()
		policyRepositories, err := workerread.NewPolicyRepositoryAdapter(broker)
		if err != nil {
			fatal("work repository policy adapter: %v", err)
		}
		limits := changedraft.DefaultLimits()
		repositoryBackend, err := workerread.NewRepositoryBackend(policyRepositories, workerClient, downloads, "refs/heads/main", limits.MaxResultFiles, limits.MaxFileBytes, limits.MaxTotalBytes)
		if err != nil {
			fatal("work repository backend: %v", err)
		}
		repositoryReads := brokerapp.NewRepositoryReadService(policyRepositories, repositoryBackend, brokerapp.RepositoryReadConfig{})
		repositorySnapshotHandler, err = api.NewRepositorySnapshotDownloadHandler(downloads)
		if err != nil {
			fatal("work snapshot handler: %v", err)
		}
		workMCPHandler, err = mcpapp.NewHandler(mcpapp.Config{
			AllowedOrigins: cfg.WorkOAuthAllowedOrigins, AllowMissingOrigin: true,
			Resolver: accessAdapter, Scope: accessAdapter, Operations: operations, ChangeDrafts: changeDrafts, ChangeDraftPublisher: changeDraftPublisher,
			RepositoryReads: repositoryReads, SyncProposals: syncProposals,
			SessionTTL: optionalDuration(cfg.WorkMCPSessionTTL, 15*time.Minute), MaxBodyBytes: cfg.MaxBodyBytes,
		})
		if err != nil {
			fatal("work mcp handler: %v", err)
		}
	}
	webhookSecret, err := loadSecret(cfg.WebhookSecretFile)
	if err != nil {
		fatal("webhook secret: %v", err)
	}
	defer zero(webhookSecret)

	readiness := httpapi.NewCachedReadiness([]httpapi.Check{
		httpapi.CheckFunc{CheckName: "sqlite", Run: func(ctx context.Context) error {
			_, err := db.Readiness(ctx)
			if err != nil {
				// Instrumentation for the recurring readiness flap (2026-07-22):
				// the error detail distinguishes a timeout/busy episode from a
				// genuinely bad pragma value.
				fmt.Fprintf(os.Stderr, "sqlite readiness check failed: %v\n", err)
			}
			return err
		}},
		httpapi.CheckFunc{CheckName: "policy", Run: func(ctx context.Context) error { return policyReady(ctx, broker, cfg.TenantID, snapshot) }},
		httpapi.CheckFunc{CheckName: "checkpoint", Run: func(context.Context) error { return authorityAnchor.Verify() }},
		httpapi.CheckFunc{CheckName: "release_asset_store", Run: func(context.Context) error {
			return releaseAssetFiles.WriterReadiness(cfg.MinimumFreeBytes)
		}},
		httpapi.CheckFunc{CheckName: "worker", Run: func(context.Context) error {
			status, err := workerClient.PingStatus()
			if err != nil {
				return err
			}
			return validateReleaseAssetProtocol(releaseAssetFiles.RootID(), status)
		}},
		httpapi.CheckFunc{CheckName: "disk", Run: func(context.Context) error {
			return freeSpaceReady(filepath.Dir(cfg.DatabasePath), cfg.MinimumFreeBytes)
		}},
	}, 2*time.Second)
	authorityHandler := api.NewAuthorityHandler(broker, api.AuthorityHandlerConfig{
		MaxBodyBytes: cfg.MaxBodyBytes, Executor: executionCoordinator, Queue: db,
		PolicyOrchestrators: cfg.PolicyOrchestrators,
	})
	enrollmentHandler := api.NewEnrollmentHandler(credentials, api.EnrollmentHandlerConfig{MaxBodyBytes: cfg.MaxBodyBytes})
	oauthHandler := api.NewGitHubOAuthHandler(workerClient, api.GitHubOAuthConfig{
		MaxBodyBytes: cfg.MaxBodyBytes, TenantID: cfg.TenantID,
		HumanApprovers: cfg.HumanApprovers, HumanSessions: humanSessions,
	})
	webhookHandler := api.NewGitHubWebhookHandler(db, api.GitHubWebhookConfig{
		TenantID: cfg.TenantID, Secret: webhookSecret, MaxBodyBytes: cfg.MaxBodyBytes, MaxConcurrent: cfg.MaxConcurrent,
	})
	subscriptionHandler := api.NewSubscriptionHandler(db, api.SubscriptionHandlerConfig{
		MaxBodyBytes: cfg.MaxBodyBytes, AllowedAdapters: cfg.AllowedNotificationAdapters,
	})
	readHandler, err := api.NewReadHandler(api.ReadHandlerConfig{
		Policy: snapshot, PolicyResolver: func(resolveCtx context.Context) (policy.Snapshot, error) {
			return broker.PolicySnapshot(resolveCtx, cfg.TenantID)
		}, SessionTTL: duration(cfg.ReadSessionTTL, "read_session_ttl"),
		GitBaseURL: cfg.GitReadBaseURL, GitProxy: gitread.NewUnixProxy(cfg.GitReadSocket),
	})
	if err != nil {
		fatal("repository read service: %v", err)
	}
	pullsHandler, err := api.NewPullsHandler(api.PullsHandlerConfig{Policy: snapshot, Worker: workerClient})
	if err != nil {
		fatal("pull request list service: %v", err)
	}
	// Repo search is optional: with no search_db_path the route is simply not
	// registered. The handler itself opens the database lazily, so a configured
	// path whose file has not been built yet still serves index_not_built.
	var searchHandler http.Handler
	var searchHumanHandler http.Handler
	if cfg.SearchDBPath != "" {
		searchService, err := api.NewSearchHandler(api.SearchHandlerConfig{Policy: snapshot, DBPath: cfg.SearchDBPath})
		if err != nil {
			fatal("repository search service: %v", err)
		}
		searchHandler = searchService
		// The UI's Refresh button asks the worker for an on-demand dataset
		// sync; the worker coalesces triggers.
		searchHumanHandler = api.NewSearchHumanHandler(workerClient.TriggerSearchSync)
	}
	// Bases resolves the public repository's HEAD through the worker, which is
	// where GitHub credentials live. BaseBranch is left at its "main" default so
	// it matches the branch NewSyncHumanHandler merges into — the branch a pre-PR
	// is diffed against and the branch it lands on must be the same one.
	syncHandler := api.NewSyncHandler(api.SyncHandlerConfig{Policy: snapshot, Store: db, MaxBodyBytes: cfg.MaxBodyBytes,
		Bases: workerClient, Proposals: syncProposals})
	queueHandler := api.NewQueueHandler(api.QueueHandlerConfig{Policy: snapshot, Store: db, MaxBodyBytes: cfg.MaxBodyBytes})
	syncHumanHandler := api.NewSyncHumanHandler(api.SyncHumanHandlerConfig{
		Policy: snapshot, Store: db, Broker: broker, Executor: executionCoordinator,
		Merges: &api.WorkerPullStateChecker{Worker: workerClient}, Bases: workerClient, MaxBodyBytes: cfg.MaxBodyBytes,
	})
	// The review page reads the public repo through the worker (same path the
	// propose flow uses) so a pre-PR renders as a real diff. Private
	// identities come from the configured agents: the page warns when one
	// would publish.
	uiHandler, err := ui.NewHandler(ui.Config{Store: db, Policy: snapshot, Pulls: workerClient,
		Bases: workerClient, PrivateIdentities: privateIdentitiesFrom(snapshot),
		ProposedPolicyPath: cfg.PolicyFile + ".proposed", SearchDBPath: cfg.SearchDBPath})
	if err != nil {
		fatal("ui: %v", err)
	}
	handler := httpapi.NewRouter(httpapi.RouterConfig{
		Readiness: readiness, AgentAuth: agentMiddleware.Wrap,
		// The bool is the retired publish-time step-up. It is ignored: the gate
		// was invented, never requested, and only ever blocked the reviewer.
		HumanAuth: func(_ bool, next http.Handler) http.Handler { return humanSessions.Protect(next) },
		Authority: authorityHandler, ReleaseAssets: releaseAssetHandler, Enrollment: enrollmentHandler, OAuth: oauthHandler,
		WorkOAuth: workOAuthHandler, MCP: workMCPHandler, RepositorySnapshots: repositorySnapshotHandler,
		Webhook: webhookHandler, Subscriptions: subscriptionHandler, Read: readHandler, Pulls: pullsHandler, Search: searchHandler,
		Sync: syncHandler, Queue: queueHandler, SyncHuman: syncHumanHandler, SearchHuman: searchHumanHandler,
		UI: uiHandler, UIAuth: humanSessions.ProtectPage, MaxConcurrent: cfg.MaxConcurrent,
	})
	httpServer := &http.Server{
		Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		// A large branch.push forwards to the worker, which uploads its blobs to
		// GitHub sequentially — a multi-MB / many-blob packet legitimately takes
		// well over 15s. The old 15s read/write timeouts killed the response
		// mid-upload, so nginx saw "upstream prematurely closed connection" and
		// returned 502. 120s matches the ctl + nginx proxy timeouts and covers the
		// largest packet under the 42 MiB body cap.
		ReadTimeout: 120 * time.Second, WriteTimeout: 120 * time.Second,
		IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	errorsChannel := make(chan error, 1)
	go func() { errorsChannel <- httpServer.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			fatal("shutdown: %v", err)
		}
	case err := <-errorsChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			fatal("serve: %v", err)
		}
	case err := <-serviceErrors:
		fatal("internal service: %v", err)
	}
}

func loadConfig(path string) (config, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var cfg config
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, err
	}
	if cfg.Listen == "" || cfg.DatabasePath == "" || cfg.TenantID == "" || cfg.PolicyFile == "" || cfg.WorkerSocket == "" || cfg.GitReadSocket == "" || cfg.GitReadBaseURL == "" || cfg.ReadSessionTTL == "" || cfg.AuthoritySocket == "" || cfg.WorkerUID == 0 || cfg.AuthoritySocketGID <= 0 || cfg.WorkerID == "" || cfg.CheckpointSocket == "" || cfg.WebhookSecretFile == "" || len(cfg.HumanApprovers) == 0 || cfg.MaxBodyBytes < commitpacket.MaxRequestBodyBytes || cfg.MaxConcurrent <= 0 || cfg.RateLimitRequests <= 0 || cfg.MinimumFreeBytes == 0 {
		return config{}, errors.New("required API configuration is incomplete")
	}
	if cfg.NotificationSocket != "" && (cfg.NotificationUID == 0 || cfg.NotificationSocketGID <= 0) || cfg.NotificationSocket == "" && (cfg.NotificationUID != 0 || cfg.NotificationSocketGID != 0) {
		return config{}, errors.New("optional notification RPC configuration is incomplete")
	}
	return cfg, nil
}

func readPolicy(path string) (policy.Snapshot, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return policy.Snapshot{}, err
	}
	var snapshot policy.Snapshot
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return policy.Snapshot{}, err
	}
	return snapshot, snapshot.Validate()
}

func ensurePolicy(ctx context.Context, broker *server.DurableBroker, tenantID string, configured policy.Snapshot) (policy.Snapshot, error) {
	status, err := broker.PolicyStatus(ctx, tenantID)
	if errors.Is(err, sqlite.ErrNotFound) {
		if err := broker.InstallPolicy(ctx, tenantID, configured); err != nil {
			return policy.Snapshot{}, err
		}
		return configured, nil
	}
	if err != nil {
		return policy.Snapshot{}, err
	}
	active, err := broker.PolicySnapshot(ctx, tenantID)
	if err != nil {
		return policy.Snapshot{}, err
	}
	if status.Generation < configured.Generation {
		return policy.Snapshot{}, errors.New("configured policy is newer than the active durable generation")
	}
	if status.Generation == configured.Generation {
		payload, err := json.Marshal(configured)
		if err != nil {
			return policy.Snapshot{}, err
		}
		digest := sha256.Sum256(payload)
		if status.PolicyHash != hex.EncodeToString(digest[:]) {
			return policy.Snapshot{}, errors.New("configured policy does not match active durable generation")
		}
	}
	// A newer durable generation is the audited source of truth. This is how a
	// human-approved remote enrollment survives restart without rewriting a
	// deployment-owned policy file from the request path.
	return active, nil
}

func policyReady(ctx context.Context, broker *server.DurableBroker, tenantID string, _ policy.Snapshot) error {
	_, err := broker.PolicySnapshot(ctx, tenantID)
	return err
}

func freeSpaceReady(path string, minimum uint64) error {
	var status unix.Statfs_t
	if err := unix.Statfs(path, &status); err != nil {
		return err
	}
	available := status.Bavail * uint64(status.Bsize)
	if available < minimum {
		return errors.New("durable volume is below its free-space threshold")
	}
	return nil
}

func requireLoopback(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("API must bind an explicit loopback IP")
	}
	return nil
}

func duration(value, name string) time.Duration {
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		fatal("%s must be a positive duration", name)
	}
	return parsed
}

func optionalDuration(value string, fallback time.Duration) time.Duration {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		fatal("optional duration must be positive when configured")
	}
	return parsed
}

func loadSecret(path string) ([]byte, error) {
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
	value = []byte(strings.TrimSpace(string(value)))
	if len(value) < 32 {
		return nil, errors.New("secret file must contain at least 32 bytes")
	}
	return value, nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// privateIdentitiesFrom lists the internal identifiers that must not cross into
// public content: every registered agent's id and display name. The review page
// warns when one of them appears in a pre-PR's published bytes.
func privateIdentitiesFrom(snapshot policy.Snapshot) []attribution.Identity {
	identities := make([]attribution.Identity, 0, len(snapshot.Agents))
	for id, agent := range snapshot.Agents {
		identities = append(identities, attribution.Identity{Name: id})
		if agent.FirstName != "" {
			identities = append(identities, attribution.Identity{Name: agent.FirstName})
		}
	}
	return identities
}
