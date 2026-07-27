package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/ingress"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type GitHubWebhookConfig struct {
	TenantID      string
	Secret        []byte
	MaxBodyBytes  int64
	MaxConcurrent int
}

type GitHubWebhookHandler struct {
	db          *sqlite.DB
	tenantID    string
	secret      []byte
	maxBody     int64
	concurrency chan struct{}
}

func NewGitHubWebhookHandler(db *sqlite.DB, config GitHubWebhookConfig) *GitHubWebhookHandler {
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 1 << 20
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 4
	}
	return &GitHubWebhookHandler{
		db: db, tenantID: config.TenantID, secret: append([]byte(nil), config.Secret...),
		maxBody: config.MaxBodyBytes, concurrency: make(chan struct{}, config.MaxConcurrent),
	}
}

func (handler *GitHubWebhookHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodPost || request.URL.Path != "/webhooks/github" {
		http.NotFound(response, request)
		return
	}
	if handler.db == nil || handler.tenantID == "" || len(handler.secret) < 32 {
		writeError(response, http.StatusServiceUnavailable, "webhook_unavailable")
		return
	}
	select {
	case handler.concurrency <- struct{}{}:
		defer func() { <-handler.concurrency }()
	default:
		writeError(response, http.StatusServiceUnavailable, "webhook_overloaded")
		return
	}
	deliveryID := strings.TrimSpace(request.Header.Get("X-GitHub-Delivery"))
	eventType := strings.TrimSpace(request.Header.Get("X-GitHub-Event"))
	if deliveryID == "" || len(deliveryID) > 128 || eventType == "" || len(eventType) > 64 {
		writeError(response, http.StatusForbidden, "webhook_rejected")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, handler.maxBody))
	if err != nil {
		writeError(response, http.StatusRequestEntityTooLarge, "webhook_too_large")
		return
	}
	if err := ingress.VerifyGitHubSignature(handler.secret, int(handler.maxBody), request.Header.Get("X-Hub-Signature-256"), body); err != nil {
		writeError(response, http.StatusForbidden, "webhook_rejected")
		return
	}
	digest := sha256.Sum256(body)
	err = handler.db.WithTx(request.Context(), func(tx *sqlite.Tx) error {
		return tx.PutWebhookReceipt(request.Context(), storage.WebhookReceipt{
			TenantID: handler.tenantID, Provider: "github", DeliveryID: deliveryID,
			EventType: eventType, BodyHash: hex.EncodeToString(digest[:]), ReceivedAt: time.Now().UTC(),
		})
	})
	if errors.Is(err, storage.ErrDuplicateWebhook) {
		writeError(response, http.StatusConflict, "webhook_replay")
		return
	}
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "webhook_unavailable")
		return
	}
	response.WriteHeader(http.StatusAccepted)
}
