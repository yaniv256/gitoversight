package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// refreshSession builds an authenticated human session and returns the manager
// plus its live credentials, mirroring the humansession tests.
func refreshSession(t *testing.T) (*HumanSessionManager, HumanSessionCredentials) {
	t.Helper()
	manager := humanSessionManager(t, func() time.Time { return time.Unix(1000, 0).UTC() })
	pending, err := manager.Begin(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.Authenticate(context.Background(), pending.Token, "yaniv")
	if err != nil {
		t.Fatal(err)
	}
	return manager, session
}

func TestSearchRefreshWithoutCSRFRejected(t *testing.T) {
	t.Parallel()
	manager, session := refreshSession(t)
	var calls int32
	protected := manager.Protect(true, NewSearchHumanHandler(func() error {
		atomic.AddInt32(&calls, 1)
		return nil
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/human/search/refresh", nil)
	request.AddCookie(manager.Cookie(session.Token))
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatal("trigger fired without a CSRF token")
	}
}

func TestSearchRefreshFiresTriggerExactlyOnce(t *testing.T) {
	t.Parallel()
	manager, session := refreshSession(t)
	var calls int32
	protected := manager.Protect(true, NewSearchHumanHandler(func() error {
		atomic.AddInt32(&calls, 1)
		return nil
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/human/search/refresh", nil)
	request.AddCookie(manager.Cookie(session.Token))
	request.Header.Set("X-CSRF-Token", session.CSRF)
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("trigger fired %d times, want 1", got)
	}
}

func TestSearchRefreshTriggerFailure(t *testing.T) {
	t.Parallel()
	handler := NewSearchHumanHandler(func() error { return errors.New("worker unavailable") })
	request := humanPost("/v1/human/search/refresh", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("code = %d: %s", response.Code, response.Body.String())
	}
}

func TestSearchRefreshRejectsNonPostAndUnknownPath(t *testing.T) {
	t.Parallel()
	handler := NewSearchHumanHandler(func() error { return nil })
	get := httptest.NewRequest(http.MethodGet, "/v1/human/search/refresh", nil)
	get = get.WithContext(WithHumanApprover(get.Context(), HumanApprover{TenantID: "default", ID: "yaniv"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, get)
	if response.Code != http.StatusNotFound {
		t.Fatalf("GET code = %d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/search/other", ""))
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown path code = %d", response.Code)
	}
}

func TestSearchRefreshWithoutApproverUnauthorized(t *testing.T) {
	t.Parallel()
	handler := NewSearchHumanHandler(func() error { return nil })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/human/search/refresh", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d", response.Code)
	}
}

func TestSearchRefreshWithoutTriggerUnavailable(t *testing.T) {
	t.Parallel()
	handler := NewSearchHumanHandler(nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, humanPost("/v1/human/search/refresh", ""))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d", response.Code)
	}
}
