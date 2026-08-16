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
	HeaderTenant       = "X-Governance-Tenant"
	HeaderAgent        = "X-Governance-Agent"
	HeaderCredential   = "X-Governance-Credential"
	HeaderRepository   = "X-Governance-Repository"
	HeaderAssetSize    = "X-Release-Asset-Size"
	HeaderAssetSHA256  = "X-Release-Asset-SHA256"
	signatureTag       = "gitoversight-agent-v1"
	uploadSignatureTag = "gitoversight-asset-upload-v1"
)

var signedComponents = []string{
	"@method", "@authority", "@path", "@query", "content-digest",
	strings.ToLower(HeaderTenant), strings.ToLower(HeaderAgent), strings.ToLower(HeaderCredential),
}

var uploadSignedComponents = []string{
	"@method", "@authority", "@path", "@query", "authorization", "content-type",
	strings.ToLower(HeaderTenant), strings.ToLower(HeaderAgent), strings.ToLower(HeaderCredential),
	strings.ToLower(HeaderRepository), strings.ToLower(HeaderAssetSize), strings.ToLower(HeaderAssetSHA256),
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

// UploadAuthenticator verifies a detached, body-independent signature for the
// one raw release-asset ingress route. It never reads, replaces, or closes the
// request body.
type UploadAuthenticator struct {
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

func (middleware *Middleware) UploadAuthenticator() *UploadAuthenticator {
	return &UploadAuthenticator{credentials: middleware.credentials, config: middleware.config}
}

func (authenticator *UploadAuthenticator) Verify(request *http.Request) (Identity, string, time.Time, error) {
	if authenticator == nil || authenticator.credentials == nil || request == nil {
		return Identity{}, "", time.Time{}, errors.New("upload authentication unavailable")
	}
	if err := rejectAmbiguousUploadRequest(request); err != nil {
		return Identity{}, "", time.Time{}, err
	}
	tenantID := request.Header.Get(HeaderTenant)
	claimedAgentID := request.Header.Get(HeaderAgent)
	credentialID := request.Header.Get(HeaderCredential)
	resolver := &credentialResolver{
		ctx: request.Context(), service: authenticator.credentials,
		tenantID: tenantID, credentialID: credentialID,
	}
	capture := &nonceCapture{}
	verifier, err := httpsig.NewVerifier(
		resolver,
		httpsig.WithRequiredTag(uploadSignatureTag,
			httpsig.WithRequiredComponents(uploadSignedComponents...),
			httpsig.WithValidityTolerance(authenticator.config.ClockSkew),
			httpsig.WithMaxAge(authenticator.config.SignatureTTL),
			httpsig.WithCreatedTimestampRequired(true),
			httpsig.WithExpiredTimestampRequired(true),
		),
		httpsig.WithNonceChecker(capture),
	)
	if err != nil || verifier.Verify(httpsig.MessageFromRequest(request)) != nil {
		return Identity{}, "", time.Time{}, errors.New("unauthorized")
	}
	if resolver.credential == nil || !capture.present || strings.TrimSpace(capture.value) == "" ||
		claimedAgentID == "" || claimedAgentID != resolver.credential.AgentID {
		return Identity{}, "", time.Time{}, errors.New("unauthorized")
	}
	if authenticator.config.SourceLimiter != nil && !authenticator.config.SourceLimiter.Allow(tenantID+"/"+credentialID) {
		return Identity{}, "", time.Time{}, errors.New("rate limit exceeded")
	}
	nonceExpiry := authenticator.config.Now().UTC().Add(authenticator.config.SignatureTTL + authenticator.config.ClockSkew)
	return Identity{TenantID: tenantID, AgentID: resolver.credential.AgentID, CredentialID: credentialID}, capture.value, nonceExpiry, nil
}

func (authenticator *UploadAuthenticator) ConsumeNonce(ctx context.Context, identity Identity, nonce string) error {
	if authenticator == nil || authenticator.credentials == nil {
		return errors.New("upload authentication unavailable")
	}
	nonceExpiry := authenticator.config.Now().UTC().Add(authenticator.config.SignatureTTL + authenticator.config.ClockSkew)
	if err := authenticator.credentials.ConsumeNonce(ctx, identity.TenantID, identity.CredentialID, nonce, nonceExpiry); err != nil {
		return errors.New("unauthorized")
	}
	return nil
}

// SignUploadRequest signs only canonical request metadata. In particular, it
// does not inspect or buffer request.Body.
func SignUploadRequest(request *http.Request, privateKey ed25519.PrivateKey, identity Identity, nonce string, ttl time.Duration) error {
	if request == nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("request and Ed25519 private key are required")
	}
	if identity.TenantID == "" || identity.AgentID == "" || identity.CredentialID == "" || strings.TrimSpace(nonce) == "" || ttl <= 0 {
		return errors.New("complete signing identity, nonce, and ttl are required")
	}
	request.Header.Set(HeaderTenant, identity.TenantID)
	request.Header.Set(HeaderAgent, identity.AgentID)
	request.Header.Set(HeaderCredential, identity.CredentialID)
	signer, err := httpsig.NewSigner(
		httpsig.Key{KeyID: credentialKeyID(identity.TenantID, identity.CredentialID), Algorithm: httpsig.Ed25519, Key: privateKey},
		httpsig.WithTTL(ttl),
		httpsig.WithTag(uploadSignatureTag),
		httpsig.WithNonce(httpsig.NonceGetterFunc(func(context.Context) (string, error) { return nonce, nil })),
		httpsig.WithComponents(uploadSignedComponents...),
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
		// Past this point the signature has VERIFIED: the caller holds the private
		// key for credentialID and has proven it. That changes what may safely be
		// said. Every branch above stays opaque — distinguishing "revoked" from
		// "no such credential" to an unauthenticated caller is a credential
		// enumeration oracle. But an agent who has already proven key possession
		// learns nothing from being told which of its own flags disagrees with its
		// own credential, and the alternative is what actually happened:
		//
		// A caller can send a Unix account name instead of the credential's
		// registered agent ID and incorrectly infer revocation from a generic
		// unauthorized response. A wrong flag and a revoked credential require
		// opposite recovery actions, so an authenticated caller receives this
		// bounded mismatch hint.
		if resolver.credential != nil && capture.present && strings.TrimSpace(capture.value) != "" &&
			claimedAgentID != resolver.credential.AgentID {
			unauthorizedWithHint(response, "agent_id_mismatch")
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

func rejectAmbiguousUploadRequest(request *http.Request) error {
	if request == nil || request.Host == "" || request.URL == nil || request.URL.IsAbs() {
		return errors.New("request target is incomplete")
	}
	for _, name := range []string{
		HeaderTenant, HeaderAgent, HeaderCredential, HeaderRepository, HeaderAssetSize,
		HeaderAssetSHA256, "Authorization", "Content-Type", "Signature", "Signature-Input",
	} {
		values := request.Header.Values(name)
		if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
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

// unauthorizedWithHint names the failing precondition. Use it ONLY after the
// signature has verified — the hint is safe there because the caller has already
// proven key possession, and it is an enumeration oracle before that. The
// top-level error string stays `unauthorized` so existing clients that match on
// it keep working; the reason travels alongside.
func unauthorizedWithHint(response http.ResponseWriter, reason string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusUnauthorized)
	_, _ = response.Write([]byte(`{"error":"unauthorized","reason":"` + reason + `"}`))
}

func sourceAddress(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}
