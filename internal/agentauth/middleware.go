package agentauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dadrus/httpsig"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

const (
	HeaderTenant     = "X-Governance-Tenant"
	HeaderAgent      = "X-Governance-Agent"
	HeaderCredential = "X-Governance-Credential"
	signatureTag     = "gitoversight-agent-v1"
)

var signedComponents = []string{
	"@method", "@authority", "@path", "@query", "content-digest",
	strings.ToLower(HeaderTenant), strings.ToLower(HeaderAgent), strings.ToLower(HeaderCredential),
}

type Identity struct {
	TenantID     string
	AgentID      string
	CredentialID string
}

type identityContextKey struct{}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	return identity, ok
}

// WithIdentityForTrustedBoundary attaches an identity only after a trusted
// authentication boundary has verified it. HTTP handlers must never populate
// this value from request JSON or headers directly.
func WithIdentityForTrustedBoundary(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

type MiddlewareConfig struct {
	MaxBodyBytes  int64
	SignatureTTL  time.Duration
	ClockSkew     time.Duration
	Now           func() time.Time
	SourceLimiter *FixedWindowLimiter
}

type Middleware struct {
	credentials *CredentialService
	config      MiddlewareConfig
}

func NewMiddleware(credentials *CredentialService, config MiddlewareConfig) (*Middleware, error) {
	if credentials == nil {
		return nil, errors.New("credential service is required")
	}
	if config.MaxBodyBytes <= 0 {
		return nil, errors.New("positive body limit is required")
	}
	if config.SignatureTTL <= 0 {
		return nil, errors.New("positive signature ttl is required")
	}
	if config.ClockSkew < 0 {
		return nil, errors.New("clock skew cannot be negative")
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Middleware{credentials: credentials, config: config}, nil
}

func (middleware *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if err := rejectAmbiguousRequest(request); err != nil {
			unauthorized(response)
			return
		}
		if err := bufferLimitedBody(request, middleware.config.MaxBodyBytes); err != nil {
			if errors.Is(err, errBodyTooLarge) {
				http.Error(response, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			unauthorized(response)
			return
		}

		tenantID := request.Header.Get(HeaderTenant)
		claimedAgentID := request.Header.Get(HeaderAgent)
		credentialID := request.Header.Get(HeaderCredential)
		resolver := &credentialResolver{
			ctx: request.Context(), service: middleware.credentials,
			tenantID: tenantID, credentialID: credentialID,
		}
		capture := &nonceCapture{}
		verifier, err := httpsig.NewVerifier(
			resolver,
			httpsig.WithRequiredTag(signatureTag,
				httpsig.WithRequiredComponents(signedComponents...),
				httpsig.WithValidityTolerance(middleware.config.ClockSkew),
				httpsig.WithMaxAge(middleware.config.SignatureTTL),
				httpsig.WithCreatedTimestampRequired(true),
				httpsig.WithExpiredTimestampRequired(true),
			),
			httpsig.WithNonceChecker(capture),
		)
		if err != nil || verifier.Verify(httpsig.MessageFromRequest(request)) != nil {
			unauthorized(response)
			return
		}
		if resolver.credential == nil || claimedAgentID == "" || claimedAgentID != resolver.credential.AgentID || !capture.present || strings.TrimSpace(capture.value) == "" {
			unauthorized(response)
			return
		}
		if middleware.config.SourceLimiter != nil && !middleware.config.SourceLimiter.Allow(tenantID+"/"+credentialID) {
			http.Error(response, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		nonceExpiry := middleware.config.Now().UTC().Add(middleware.config.SignatureTTL + middleware.config.ClockSkew)
		if err := middleware.credentials.ConsumeNonce(request.Context(), tenantID, credentialID, capture.value, nonceExpiry); err != nil {
			if errors.Is(err, storage.ErrDuplicateNonce) {
				unauthorized(response)
				return
			}
			http.Error(response, "authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		identity := Identity{TenantID: tenantID, AgentID: resolver.credential.AgentID, CredentialID: credentialID}
		next.ServeHTTP(response, request.WithContext(WithIdentityForTrustedBoundary(request.Context(), identity)))
	})
}

func SignRequest(request *http.Request, privateKey ed25519.PrivateKey, identity Identity, nonce string, ttl time.Duration) error {
	if request == nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("request and Ed25519 private key are required")
	}
	if identity.TenantID == "" || identity.AgentID == "" || identity.CredentialID == "" || strings.TrimSpace(nonce) == "" || ttl <= 0 {
		return errors.New("complete signing identity, nonce, and ttl are required")
	}
	if err := snapshotBody(request); err != nil {
		return err
	}
	request.Header.Set(HeaderTenant, identity.TenantID)
	request.Header.Set(HeaderAgent, identity.AgentID)
	request.Header.Set(HeaderCredential, identity.CredentialID)
	signer, err := httpsig.NewSigner(
		httpsig.Key{KeyID: credentialKeyID(identity.TenantID, identity.CredentialID), Algorithm: httpsig.Ed25519, Key: privateKey},
		httpsig.WithTTL(ttl),
		httpsig.WithTag(signatureTag),
		httpsig.WithNonce(httpsig.NonceGetterFunc(func(context.Context) (string, error) { return nonce, nil })),
		httpsig.WithComponents(signedComponents...),
		httpsig.WithContentDigestAlgorithm(httpsig.Sha256),
	)
	if err != nil {
		return err
	}
	headers, err := signer.Sign(httpsig.MessageFromRequest(request))
	if err != nil {
		return err
	}
	for name, values := range headers {
		request.Header.Del(name)
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	return nil
}

type credentialResolver struct {
	ctx          context.Context
	service      *CredentialService
	tenantID     string
	credentialID string
	credential   *Credential
}

func (resolver *credentialResolver) ResolveKey(_ context.Context, keyID string) (httpsig.Key, error) {
	if keyID != credentialKeyID(resolver.tenantID, resolver.credentialID) {
		return httpsig.Key{}, ErrCredentialNotFound
	}
	credential, err := resolver.service.Resolve(resolver.ctx, resolver.tenantID, resolver.credentialID)
	if err != nil {
		return httpsig.Key{}, err
	}
	resolver.credential = &credential
	return httpsig.Key{KeyID: keyID, Algorithm: httpsig.Ed25519, Key: credential.PublicKey}, nil
}

type nonceCapture struct {
	present bool
	value   string
}

func (capture *nonceCapture) CheckNonce(_ context.Context, nonce httpsig.NonceValue) error {
	capture.present = nonce.Present
	capture.value = nonce.Value
	if !nonce.Present || strings.TrimSpace(nonce.Value) == "" {
		return errors.New("signature nonce is required")
	}
	return nil
}

var errBodyTooLarge = errors.New("request body exceeds configured limit")

func bufferLimitedBody(request *http.Request, limit int64) error {
	if request.Body == nil {
		request.Body = http.NoBody
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	_ = request.Body.Close()
	if err != nil {
		return err
	}
	if int64(len(payload)) > limit {
		return errBodyTooLarge
	}
	setBody(request, payload)
	return nil
}

func snapshotBody(request *http.Request) error {
	if request.Body == nil {
		setBody(request, nil)
		return nil
	}
	payload, err := io.ReadAll(request.Body)
	_ = request.Body.Close()
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	setBody(request, payload)
	return nil
}

func setBody(request *http.Request, payload []byte) {
	copyPayload := append([]byte(nil), payload...)
	request.Body = io.NopCloser(bytes.NewReader(copyPayload))
	request.ContentLength = int64(len(copyPayload))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(copyPayload)), nil
	}
}

func rejectAmbiguousRequest(request *http.Request) error {
	if request == nil || request.Host == "" || request.URL == nil {
		return errors.New("request target is incomplete")
	}
	for _, name := range []string{HeaderTenant, HeaderCredential, "Signature", "Signature-Input", "Content-Digest"} {
		values := request.Header.Values(name)
		if len(values) != 1 || strings.TrimSpace(values[0]) == "" || strings.Contains(values[0], ",") {
			return fmt.Errorf("header %s must occur exactly once", name)
		}
	}
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Original-URL", "X-Rewrite-URL"} {
		if len(request.Header.Values(name)) != 0 {
			return fmt.Errorf("untrusted forwarding header %s", name)
		}
	}
	return nil
}

func credentialKeyID(tenantID, credentialID string) string { return tenantID + "/" + credentialID }

func unauthorized(response http.ResponseWriter) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusUnauthorized)
	_, _ = response.Write([]byte(`{"error":"unauthorized"}`))
}

func sourceAddress(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}
