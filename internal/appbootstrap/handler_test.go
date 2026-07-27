package appbootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type converterStub struct {
	registration Registration
	err          error
	calls        int
}

func (stub *converterStub) Convert(context.Context, string) (Registration, error) {
	stub.calls++
	return stub.registration, stub.err
}

type storeStub struct {
	err   error
	calls int
}

func (stub *storeStub) Store(context.Context, Registration) error {
	stub.calls++
	return stub.err
}

func TestCallbackHandlerConvertsAndStoresExactlyOnceWithoutExposingSecrets(t *testing.T) {
	t.Parallel()
	converter := &converterStub{registration: validRegistration()}
	store := &storeStub{}
	handler, err := NewCallbackHandler(strings.Repeat("s", 43), converter, store)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/bootstrap/github-app/callback?state="+strings.Repeat("s", 43)+"&code=temporary-code", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || converter.calls != 1 || store.calls != 1 {
		t.Fatalf("status=%d converter=%d store=%d", response.Code, converter.calls, store.calls)
	}
	for _, secret := range []string{validRegistration().PEM, validRegistration().ClientSecret, validRegistration().WebhookSecret} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("callback response exposed secret")
		}
	}
	if !strings.Contains(response.Body.String(), validRegistration().Slug) || !strings.Contains(response.Body.String(), "/installations/new") {
		t.Fatalf("success response = %s", response.Body.String())
	}
	result := <-handler.Done()
	if !result.Success || result.AppID != 42 || result.Slug != validRegistration().Slug || result.InstallURL == "" {
		t.Fatalf("result = %#v", result)
	}

	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, request)
	if replay.Code != http.StatusConflict || converter.calls != 1 || store.calls != 1 {
		t.Fatalf("replay status=%d converter=%d store=%d", replay.Code, converter.calls, store.calls)
	}
}

func TestCallbackHandlerRejectsWrongStateBeforeConversion(t *testing.T) {
	t.Parallel()
	converter := &converterStub{registration: validRegistration()}
	store := &storeStub{}
	handler, err := NewCallbackHandler(strings.Repeat("s", 43), converter, store)
	if err != nil {
		t.Fatal(err)
	}
	wrong := httptest.NewRecorder()
	handler.ServeHTTP(wrong, httptest.NewRequest(http.MethodGet, "/bootstrap/github-app/callback?state=wrong&code=temporary-code", nil))
	if wrong.Code != http.StatusBadRequest || converter.calls != 0 || store.calls != 0 {
		t.Fatalf("wrong-state status=%d converter=%d store=%d", wrong.Code, converter.calls, store.calls)
	}
	valid := httptest.NewRecorder()
	handler.ServeHTTP(valid, httptest.NewRequest(http.MethodGet, "/bootstrap/github-app/callback?state="+strings.Repeat("s", 43)+"&code=temporary-code", nil))
	if valid.Code != http.StatusOK || converter.calls != 1 {
		t.Fatalf("valid status=%d converter=%d", valid.Code, converter.calls)
	}
}

func TestCallbackHandlerConsumesAttemptOnConversionOrStoreFailure(t *testing.T) {
	t.Parallel()
	for _, scenario := range []struct {
		name      string
		converter *converterStub
		store     *storeStub
	}{
		{name: "conversion", converter: &converterStub{err: errors.New("secret response detail")}, store: &storeStub{}},
		{name: "store", converter: &converterStub{registration: validRegistration()}, store: &storeStub{err: errors.New("secret filesystem detail")}},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			handler, err := NewCallbackHandler(strings.Repeat("s", 43), scenario.converter, scenario.store)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/bootstrap/github-app/callback?state="+strings.Repeat("s", 43)+"&code=temporary-code", nil)
			first := httptest.NewRecorder()
			handler.ServeHTTP(first, request)
			if first.Code != http.StatusInternalServerError || strings.Contains(first.Body.String(), "secret") {
				t.Fatalf("first response = %d %q", first.Code, first.Body.String())
			}
			result := <-handler.Done()
			if result.Success || result.Code == "" {
				t.Fatalf("result = %#v", result)
			}
			replay := httptest.NewRecorder()
			handler.ServeHTTP(replay, request)
			if replay.Code != http.StatusConflict || scenario.converter.calls != 1 {
				t.Fatalf("replay = %d calls=%d", replay.Code, scenario.converter.calls)
			}
		})
	}
}

func TestCallbackHandlerRejectsWrongMethodPathAndMissingCode(t *testing.T) {
	t.Parallel()
	for _, target := range []struct {
		method string
		url    string
		status int
	}{
		{method: http.MethodPost, url: "/bootstrap/github-app/callback?state=" + strings.Repeat("s", 43) + "&code=temporary-code", status: http.StatusMethodNotAllowed},
		{method: http.MethodGet, url: "/wrong?state=" + strings.Repeat("s", 43) + "&code=temporary-code", status: http.StatusNotFound},
		{method: http.MethodGet, url: "/bootstrap/github-app/callback?state=" + strings.Repeat("s", 43), status: http.StatusBadRequest},
	} {
		converter := &converterStub{registration: validRegistration()}
		handler, err := NewCallbackHandler(strings.Repeat("s", 43), converter, &storeStub{})
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(target.method, target.url, nil))
		if response.Code != target.status || converter.calls != 0 {
			t.Fatalf("%s %s status=%d calls=%d", target.method, target.url, response.Code, converter.calls)
		}
	}
}
