package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type QueueHandlerConfig struct {
	Policy       policy.Snapshot
	Store        *sqlite.DB
	MaxBodyBytes int64
	Now          func() time.Time
}

type QueueHandler struct {
	policy  policy.Snapshot
	store   *sqlite.DB
	maxBody int64
	now     func() time.Time
}

func NewQueueHandler(config QueueHandlerConfig) *QueueHandler {
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 256 << 10
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &QueueHandler{policy: config.Policy, store: config.Store, maxBody: config.MaxBodyBytes, now: config.Now}
}

type queueOrderInput struct {
	Items []queueOrderItem `json:"items"`
}

type queueOrderItem struct {
	ItemID string `json:"item_id"`
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
}

func (handler *QueueHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	if handler.store == nil {
		writeError(response, http.StatusServiceUnavailable, "queue_unavailable")
		return
	}
	path := strings.Trim(request.URL.Path, "/")
	switch {
	case request.Method == http.MethodPost && path == "v1/queue/order":
		handler.setOrder(response, request, identity)
	case request.Method == http.MethodGet && path == "v1/queue/top":
		item, depth, err := handler.store.TopQueueItem(request.Context(), identity.TenantID)
		if err != nil {
			writeError(response, http.StatusServiceUnavailable, "queue_unavailable")
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"top": item, "depth": depth})
	default:
		http.NotFound(response, request)
	}
}

func (handler *QueueHandler) setOrder(response http.ResponseWriter, request *http.Request, identity agentauth.Identity) {
	decision := policy.Evaluate(handler.policy, policy.Request{Caller: identity.AgentID, Operation: "queue.set_order"})
	if decision.Code != policy.Allowed {
		writeJSON(response, http.StatusForbidden, map[string]any{"error": string(decision.Code), "reason": decision.Reason})
		return
	}
	var input queueOrderInput
	if err := decodeStrict(request, handler.maxBody, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_queue_input")
		return
	}
	items := make([]sqlite.QueueItem, 0, len(input.Items))
	for _, item := range input.Items {
		// Review-kind refs name PRs on GitHub and cannot be resolved inside the
		// broker's database. Handler-level validation against the worker PR read
		// lands with the views phase; until then the surface fails closed.
		if item.Kind == "review" {
			writeError(response, http.StatusUnprocessableEntity, "queue_ref_unvalidated")
			return
		}
		items = append(items, sqlite.QueueItem{ItemID: item.ItemID, Kind: item.Kind, Ref: item.Ref})
	}
	if err := handler.store.ReplaceQueueOrder(request.Context(), identity.TenantID, items, handler.now()); err != nil {
		if strings.Contains(err.Error(), "unknown_queue_ref") {
			writeError(response, http.StatusUnprocessableEntity, "unknown_queue_ref")
			return
		}
		writeError(response, http.StatusUnprocessableEntity, "queue_rejected")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"count": len(items)})
}
