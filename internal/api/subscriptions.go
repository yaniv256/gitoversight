package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

type SubscriptionStore interface {
	CreateNotificationSubscription(context.Context, storage.NotificationSubscription) error
	RevokeNotificationSubscription(context.Context, string, string, string, time.Time) error
	NotificationSubscriptions(context.Context, string, string) ([]storage.NotificationSubscription, error)
	NotificationStatus(context.Context, string, string, string) ([]storage.NotificationDelivery, error)
}

type SubscriptionHandlerConfig struct {
	MaxBodyBytes    int64
	AllowedAdapters []string
	Now             func() time.Time
}

type SubscriptionHandler struct {
	store   SubscriptionStore
	maxBody int64
	allowed map[string]struct{}
	now     func() time.Time
}

func NewSubscriptionHandler(store SubscriptionStore, config SubscriptionHandlerConfig) *SubscriptionHandler {
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 16 << 10
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	allowed := make(map[string]struct{}, len(config.AllowedAdapters))
	for _, adapter := range config.AllowedAdapters {
		if adapter = strings.TrimSpace(adapter); adapter != "" {
			allowed[adapter] = struct{}{}
		}
	}
	return &SubscriptionHandler{store: store, maxBody: config.MaxBodyBytes, allowed: allowed, now: config.Now}
}

func (handler *SubscriptionHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	if handler.store == nil {
		writeError(response, http.StatusServiceUnavailable, "notifications_unavailable")
		return
	}
	path := strings.Trim(request.URL.Path, "/")
	switch {
	case request.Method == http.MethodPost && path == "v1/subscriptions":
		handler.create(response, request, identity.TenantID, identity.AgentID)
	case request.Method == http.MethodGet && path == "v1/subscriptions":
		items, err := handler.store.NotificationSubscriptions(request.Context(), identity.TenantID, identity.AgentID)
		if err != nil {
			writeError(response, http.StatusServiceUnavailable, "notifications_unavailable")
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"subscriptions": items})
	case request.Method == http.MethodDelete && strings.HasPrefix(path, "v1/subscriptions/"):
		id := strings.TrimPrefix(path, "v1/subscriptions/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(response, request)
			return
		}
		if err := handler.store.RevokeNotificationSubscription(request.Context(), identity.TenantID, identity.AgentID, id, handler.now().UTC()); err != nil {
			writeError(response, http.StatusNotFound, "subscription_not_found")
			return
		}
		response.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodGet && strings.HasPrefix(path, "v1/notifications/"):
		id := strings.TrimPrefix(path, "v1/notifications/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(response, request)
			return
		}
		items, err := handler.store.NotificationStatus(request.Context(), identity.TenantID, identity.AgentID, id)
		if err != nil {
			writeError(response, http.StatusServiceUnavailable, "notifications_unavailable")
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"outbox_id": id, "deliveries": items})
	default:
		http.NotFound(response, request)
	}
}

func (handler *SubscriptionHandler) create(response http.ResponseWriter, request *http.Request, tenantID, agentID string) {
	var input struct {
		ID          string          `json:"id"`
		Adapter     string          `json:"adapter"`
		EventTypes  []string        `json:"event_types"`
		Destination json.RawMessage `json:"destination"`
	}
	if err := handler.decode(request, &input); err != nil || !validIdentifier(input.ID) || len(input.EventTypes) == 0 || len(input.EventTypes) > 32 || !json.Valid(input.Destination) {
		writeError(response, http.StatusBadRequest, "invalid_subscription")
		return
	}
	if _, ok := handler.allowed[input.Adapter]; !ok {
		writeError(response, http.StatusBadRequest, "adapter_not_allowed")
		return
	}
	if input.Adapter == "hive" && !validHiveDestination(input.Destination) {
		writeError(response, http.StatusBadRequest, "invalid_subscription")
		return
	}
	for _, eventType := range input.EventTypes {
		if !validEventType(eventType) {
			writeError(response, http.StatusBadRequest, "invalid_subscription")
			return
		}
	}
	item := storage.NotificationSubscription{TenantID: tenantID, ID: input.ID, AgentID: agentID, Adapter: input.Adapter, EventTypes: input.EventTypes, DestinationJSON: append([]byte(nil), input.Destination...), CreatedAt: handler.now().UTC()}
	if err := handler.store.CreateNotificationSubscription(request.Context(), item); err != nil {
		writeError(response, http.StatusConflict, "subscription_rejected")
		return
	}
	writeJSON(response, http.StatusCreated, item)
}

func (handler *SubscriptionHandler) decode(request *http.Request, destination any) error {
	if request.Header.Get("Content-Type") != "application/json" {
		return errors.New("application/json is required")
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, handler.maxBody+1))
	if err != nil || int64(len(payload)) > handler.maxBody {
		return errors.New("request body exceeds configured limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("exactly one JSON value is required")
	}
	return nil
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '-' && char != '_' && char != ':' {
			return false
		}
	}
	return true
}

func validEventType(value string) bool {
	if value == "*" {
		return true
	}
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '_' && char != '.' {
			return false
		}
	}
	return true
}

func validHiveDestination(payload []byte) bool {
	var value struct {
		Agent string `json:"agent"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&value) == nil && value.Agent != "" && decoder.Decode(&struct{}{}) == io.EOF
}
