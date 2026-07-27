package appbootstrap

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"net/http"
	"sync"
)

type ManifestConverter interface {
	Convert(context.Context, string) (Registration, error)
}

type AttemptResult struct {
	Success    bool
	Code       string
	AppID      int64
	Slug       string
	InstallURL string
}

type CallbackHandler struct {
	expectedState string
	converter     ManifestConverter
	store         RegistrationStore
	done          chan AttemptResult
	mu            sync.Mutex
	consumed      bool
}

func NewCallbackHandler(expectedState string, converter ManifestConverter, store RegistrationStore) (*CallbackHandler, error) {
	if !validState(expectedState) {
		return nil, errors.New("callback state is invalid")
	}
	if converter == nil || store == nil {
		return nil, errors.New("callback converter and store are required")
	}
	return &CallbackHandler{expectedState: expectedState, converter: converter, store: store, done: make(chan AttemptResult, 1)}, nil
}

func (handler *CallbackHandler) Done() <-chan AttemptResult {
	return handler.done
}

func (handler *CallbackHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action https://github.com; base-uri 'none'; frame-ancestors 'none'")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.URL.Path != manifestCallbackPath {
		http.Error(response, "not found", http.StatusNotFound)
		return
	}
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state := request.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(state), []byte(handler.expectedState)) != 1 {
		http.Error(response, "invalid callback", http.StatusBadRequest)
		return
	}
	code := request.URL.Query().Get("code")
	if !manifestCodePattern.MatchString(code) {
		http.Error(response, "invalid callback", http.StatusBadRequest)
		return
	}
	if !handler.consume() {
		http.Error(response, "bootstrap callback already consumed", http.StatusConflict)
		return
	}
	registration, err := handler.converter.Convert(request.Context(), code)
	if err != nil {
		handler.finish(AttemptResult{Code: "conversion_failed"})
		http.Error(response, "GitHub App bootstrap failed closed; start a new manifest registration", http.StatusInternalServerError)
		return
	}
	if err := validateRegistration(registration); err != nil {
		handler.finish(AttemptResult{Code: "identity_mismatch"})
		http.Error(response, "GitHub App bootstrap failed closed; start a new manifest registration", http.StatusInternalServerError)
		return
	}
	if err := handler.store.Store(request.Context(), registration); err != nil {
		handler.finish(AttemptResult{Code: "secret_store_failed"})
		http.Error(response, "GitHub App bootstrap failed closed; start a new manifest registration", http.StatusInternalServerError)
		return
	}
	installURL := "https://github.com/apps/" + registration.Slug + "/installations/new"
	result := AttemptResult{Success: true, Code: "stored", AppID: registration.ID, Slug: registration.Slug, InstallURL: installURL}
	handler.finish(result)
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(response, "<!doctype html><html><body><h1>GitHub App credentials stored safely</h1><p>App: %s</p><p><a href=\"%s\">Install on selected repositories</a></p></body></html>", html.EscapeString(registration.Slug), html.EscapeString(installURL))
}

func (handler *CallbackHandler) consume() bool {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.consumed {
		return false
	}
	handler.consumed = true
	return true
}

func (handler *CallbackHandler) finish(result AttemptResult) {
	select {
	case handler.done <- result:
	default:
	}
}
