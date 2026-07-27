package api

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

func TestCreatePurgesExpiredSessions(t *testing.T) {
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	handler := testReadHandler(t, &now, rand.Reader)
	createTestReadSession(t, handler, "zara", http.StatusCreated)
	if len(handler.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(handler.sessions))
	}
	now = now.Add(2 * time.Minute)
	createTestReadSession(t, handler, "zara", http.StatusCreated)
	if len(handler.sessions) != 1 {
		t.Fatalf("expired session was retained; sessions = %d", len(handler.sessions))
	}
}

func TestCreateCapsLiveSessionsPerAgent(t *testing.T) {
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	handler := testReadHandler(t, &now, rand.Reader)
	for index := 0; index < maxAgentReadSessions; index++ {
		createTestReadSession(t, handler, "zara", http.StatusCreated)
	}
	createTestReadSession(t, handler, "zara", http.StatusTooManyRequests)
}

func testReadHandler(t *testing.T, now *time.Time, random io.Reader) *ReadHandler {
	t.Helper()
	handler, err := NewReadHandler(ReadHandlerConfig{
		Policy:     policy.Snapshot{Generation: 1, FallbackPermissions: policy.PermissionSet{Read: true}, Agents: map[string]policy.Agent{"zara": {UID: 1001, FirstName: "Zara"}}, Repositories: map[string]policy.Repository{"owner/repo": {Visibility: "private", Owners: []string{"zara"}}}},
		SessionTTL: time.Minute, GitBaseURL: "https://gitoversight.test/git", GitProxy: http.NotFoundHandler(), Random: random, Now: func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func createTestReadSession(t *testing.T, handler *ReadHandler, agent string, want int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"repository": "owner/repo"})
	request := httptest.NewRequest(http.MethodPost, "/v1/read-sessions", bytes.NewReader(body))
	request = request.WithContext(agentauth.WithIdentityForTrustedBoundary(request.Context(), agentauth.Identity{TenantID: "default", AgentID: agent, CredentialID: agent + "-1"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != want {
		t.Fatalf("status = %d, want %d: %s", response.Code, want, response.Body.String())
	}
}
