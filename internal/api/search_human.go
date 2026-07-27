package api

import (
	"net/http"
	"strings"
)

// SearchSyncTrigger asks the privileged worker to run an on-demand repo-search
// dataset refresh. workerrpc.Client.TriggerSearchSync satisfies it; the worker
// coalesces triggers so repeated calls are safe.
type SearchSyncTrigger func() error

// SearchHumanHandler serves POST /v1/human/search/refresh: a cookie+CSRF gated
// (via HumanSessionManager.Protect, wired in the router) request that schedules
// a dataset sync. It answers 202 — the sync completes asynchronously and the
// UI simply reloads to pick up whatever has landed.
type SearchHumanHandler struct {
	trigger SearchSyncTrigger
}

func NewSearchHumanHandler(trigger SearchSyncTrigger) *SearchHumanHandler {
	return &SearchHumanHandler{trigger: trigger}
}

func (handler *SearchHumanHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPost || strings.Trim(request.URL.Path, "/") != "v1/human/search/refresh" {
		http.NotFound(response, request)
		return
	}
	if _, ok := HumanApproverFromContext(request.Context()); !ok {
		writeError(response, http.StatusUnauthorized, "human_authentication_required")
		return
	}
	if handler.trigger == nil {
		writeError(response, http.StatusServiceUnavailable, "search_sync_unavailable")
		return
	}
	if err := handler.trigger(); err != nil {
		writeError(response, http.StatusBadGateway, "search_sync_trigger_failed")
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": "sync_scheduled"})
}
