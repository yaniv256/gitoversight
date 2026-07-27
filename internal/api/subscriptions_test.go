package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func TestSubscriptionAPIIsAgentAndTenantScoped(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error {
		if err := tx.EnsureTenant(ctx, "tenant-a", now); err != nil {
			return err
		}
		if err := tx.EnsureAgent(ctx, "tenant-a", "zara", now); err != nil {
			return err
		}
		return tx.EnsureAgent(ctx, "tenant-a", "elena", now)
	}); err != nil {
		t.Fatal(err)
	}

	handler := NewSubscriptionHandler(db, SubscriptionHandlerConfig{MaxBodyBytes: 4096, AllowedAdapters: []string{"hive"}})
	create := httptest.NewRequest(http.MethodPost, "/v1/subscriptions", jsonBody(t, map[string]any{
		"id": "sub-1", "adapter": "hive", "event_types": []string{"operation_submitted"}, "destination": map[string]string{"agent": "zara"},
	}))
	create.Header.Set("Content-Type", "application/json")
	create = create.WithContext(agentauth.WithIdentityForTrustedBoundary(create.Context(), agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "key-1"}))
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}

	list := authenticatedAgentRequest(t, http.MethodGet, "/v1/subscriptions", "tenant-a", "zara", nil)
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, list)
	if listed.Code != http.StatusOK {
		t.Fatalf("list=%d %s", listed.Code, listed.Body.String())
	}
	var body struct {
		Subscriptions []storage.NotificationSubscription `json:"subscriptions"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &body); err != nil || len(body.Subscriptions) != 1 || body.Subscriptions[0].AgentID != "zara" {
		t.Fatalf("body=%+v err=%v", body, err)
	}

	other := authenticatedAgentRequest(t, http.MethodGet, "/v1/subscriptions", "tenant-a", "elena", nil)
	otherResponse := httptest.NewRecorder()
	handler.ServeHTTP(otherResponse, other)
	var otherBody struct {
		Subscriptions []storage.NotificationSubscription `json:"subscriptions"`
	}
	if err := json.Unmarshal(otherResponse.Body.Bytes(), &otherBody); err != nil || len(otherBody.Subscriptions) != 0 {
		t.Fatalf("other body=%+v err=%v", otherBody, err)
	}

	revoke := authenticatedAgentRequest(t, http.MethodDelete, "/v1/subscriptions/sub-1", "tenant-a", "zara", nil)
	revoked := httptest.NewRecorder()
	handler.ServeHTTP(revoked, revoke)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("revoke=%d %s", revoked.Code, revoked.Body.String())
	}
}

func TestSubscriptionAPIRejectsUnauthenticatedAndUnknownAdapter(t *testing.T) {
	handler := NewSubscriptionHandler(nil, SubscriptionHandlerConfig{AllowedAdapters: []string{"hive"}})
	request := httptest.NewRequest(http.MethodGet, "/v1/subscriptions", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}

	store := &subscriptionStore{}
	handler = NewSubscriptionHandler(store, SubscriptionHandlerConfig{AllowedAdapters: []string{"hive"}})
	unknown := authenticatedAgentRequest(t, http.MethodPost, "/v1/subscriptions", "tenant-a", "zara", map[string]any{
		"id": "sub-1", "adapter": "slack", "event_types": []string{"operation_submitted"}, "destination": map[string]string{"channel": "private"},
	})
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusBadRequest || store.created.ID != "" {
		t.Fatalf("unknown adapter status=%d created=%+v", unknownResponse.Code, store.created)
	}
}

type subscriptionStore struct {
	created storage.NotificationSubscription
}

func (store *subscriptionStore) CreateNotificationSubscription(_ context.Context, item storage.NotificationSubscription) error {
	store.created = item
	return nil
}
func (*subscriptionStore) RevokeNotificationSubscription(context.Context, string, string, string, time.Time) error {
	return nil
}
func (*subscriptionStore) NotificationSubscriptions(context.Context, string, string) ([]storage.NotificationSubscription, error) {
	return nil, nil
}
func (*subscriptionStore) NotificationStatus(context.Context, string, string, string) ([]storage.NotificationDelivery, error) {
	return nil, nil
}

func authenticatedAgentRequest(t *testing.T, method, path, tenantID, agentID string, body any) *http.Request {
	t.Helper()
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, path, nil)
	} else {
		request = httptest.NewRequest(method, path, jsonBody(t, body))
		request.Header.Set("Content-Type", "application/json")
	}
	return request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: tenantID, AgentID: agentID, CredentialID: agentID + "-key"}))
}
