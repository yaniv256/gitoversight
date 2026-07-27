package contract_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/httpapi"
)

func TestProxySanitizerRejectsForwardingAmbiguityAndPreservesHost(t *testing.T) {
	next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != "gitoversight.example.test" {
			t.Fatalf("signed authority changed: %q", request.Host)
		}
		response.WriteHeader(http.StatusNoContent)
	})
	handler := httpapi.RejectForwardingAmbiguity(next)

	clean := httptest.NewRequest(http.MethodGet, "https://gitoversight.example.test/v1/policy", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, clean)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("clean request rejected: %d", recorder.Code)
	}

	ambiguous := httptest.NewRequest(http.MethodGet, "https://gitoversight.example.test/v1/policy", nil)
	ambiguous.Header.Set("Forwarded", "host=attacker.invalid")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, ambiguous)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous request status = %d", recorder.Code)
	}
}
