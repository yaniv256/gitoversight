package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
)

type EnrollmentHandlerConfig struct {
	MaxBodyBytes int64
}

type EnrollmentHandler struct {
	credentials  *agentauth.CredentialService
	maxBodyBytes int64
}

type HumanApprover struct {
	TenantID  string
	ID        string
	SessionID string
}

type humanApproverContextKey struct{}

func WithHumanApprover(ctx context.Context, approver HumanApprover) context.Context {
	return context.WithValue(ctx, humanApproverContextKey{}, approver)
}

func HumanApproverFromContext(ctx context.Context) (HumanApprover, bool) {
	approver, ok := ctx.Value(humanApproverContextKey{}).(HumanApprover)
	return approver, ok && approver.TenantID != "" && approver.ID != ""
}

func NewEnrollmentHandler(credentials *agentauth.CredentialService, config EnrollmentHandlerConfig) *EnrollmentHandler {
	limit := config.MaxBodyBytes
	if limit <= 0 {
		limit = 16 << 10
	}
	return &EnrollmentHandler{credentials: credentials, maxBodyBytes: limit}
}

func (handler *EnrollmentHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || handler.credentials == nil {
		http.NotFound(response, request)
		return
	}
	path := strings.Trim(request.URL.Path, "/")
	if path == "v1/enrollments/challenge" {
		handler.challenge(response, request)
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "enrollments" || parts[2] == "" {
		http.NotFound(response, request)
		return
	}
	switch parts[3] {
	case "proof":
		handler.prove(response, request, parts[2])
	case "approve":
		handler.approve(response, request, parts[2])
	default:
		http.NotFound(response, request)
	}
}

func (handler *EnrollmentHandler) challenge(response http.ResponseWriter, request *http.Request) {
	var input struct {
		TenantID               string `json:"tenant_id"`
		AgentID                string `json:"agent_id"`
		CredentialID           string `json:"credential_id"`
		PublicKey              string `json:"public_key"`
		SupersedesCredentialID string `json:"supersedes_credential_id,omitempty"`
	}
	if err := handler.decode(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(input.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		writeError(response, http.StatusBadRequest, "invalid_public_key")
		return
	}
	challenge, err := handler.credentials.Begin(request.Context(), agentauth.EnrollmentRequest{
		TenantID: input.TenantID, AgentID: input.AgentID, CredentialID: input.CredentialID,
		PublicKey: ed25519.PublicKey(publicKey), SupersedesCredentialID: input.SupersedesCredentialID,
	})
	if err != nil {
		writeError(response, http.StatusBadRequest, "enrollment_rejected")
		return
	}
	writeJSON(response, http.StatusCreated, map[string]any{
		"id": challenge.ID, "tenant_id": challenge.TenantID,
		"proof_message": base64.RawURLEncoding.EncodeToString(challenge.ProofMessage),
		"expires_at":    challenge.ExpiresAt,
	})
}

func (handler *EnrollmentHandler) prove(response http.ResponseWriter, request *http.Request, enrollmentID string) {
	var input struct {
		TenantID string `json:"tenant_id"`
		Proof    string `json:"proof"`
	}
	if err := handler.decode(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	proof, err := base64.RawURLEncoding.DecodeString(input.Proof)
	if err != nil || len(proof) != ed25519.SignatureSize {
		writeError(response, http.StatusBadRequest, "invalid_proof")
		return
	}
	if err := handler.credentials.Complete(request.Context(), input.TenantID, enrollmentID, proof); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, agentauth.ErrEnrollmentNotFound) {
			status = http.StatusNotFound
		}
		writeError(response, status, "proof_rejected")
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (handler *EnrollmentHandler) approve(response http.ResponseWriter, request *http.Request, enrollmentID string) {
	approver, ok := HumanApproverFromContext(request.Context())
	if !ok {
		writeError(response, http.StatusUnauthorized, "human_authentication_required")
		return
	}
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := handler.decode(request, &input); err != nil || input.TenantID != approver.TenantID {
		writeError(response, http.StatusForbidden, "tenant_mismatch")
		return
	}
	credential, err := handler.credentials.Approve(request.Context(), input.TenantID, enrollmentID, approver.ID)
	if err != nil {
		writeError(response, http.StatusConflict, "approval_rejected")
		return
	}
	writeJSON(response, http.StatusCreated, map[string]any{
		"tenant_id": credential.TenantID, "agent_id": credential.AgentID,
		"credential_id": credential.ID, "approved_by": credential.ApprovedBy,
	})
}

func (handler *EnrollmentHandler) decode(request *http.Request, destination any) error {
	if request.Header.Get("Content-Type") != "application/json" {
		return errors.New("application/json is required")
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, handler.maxBodyBytes+1))
	if err != nil || int64(len(payload)) > handler.maxBodyBytes {
		return errors.New("request body exceeds configured limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("exactly one JSON object is required")
	}
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]string{"error": code})
}
