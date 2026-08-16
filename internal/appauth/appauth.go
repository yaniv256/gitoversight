package appauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrNotFound              = errors.New("oauth record not found")
	ErrInvalidGrant          = errors.New("oauth grant is invalid")
	ErrAuthorizationCodeUsed = errors.New("oauth authorization code already consumed")
	ErrRefreshTokenReplay    = errors.New("oauth refresh token replay detected")
	ErrTokenExpired          = errors.New("oauth token expired")
	ErrTokenRevoked          = errors.New("oauth token revoked")
)

type Client struct {
	Issuer       string
	Audience     string
	ID           string
	Name         string
	RedirectURIs []string
	CreatedAt    time.Time
}

type Binding struct {
	Issuer       string
	Audience     string
	ClientID     string
	TenantID     string
	AgentID      string
	Repositories []string
	AllPrivate   bool
}

type AuthorizationCode struct {
	Binding
	CodeHash      string
	RedirectURI   string
	PKCEChallenge string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
}

type AuthorizationCodeExchange struct {
	CodeHash      string
	Issuer        string
	Audience      string
	ClientID      string
	RedirectURI   string
	PKCEChallenge string
}

type TokenFamily struct {
	Binding
	ID               string
	CreatedAt        time.Time
	RevokedAt        *time.Time
	RevocationReason string
}

type AccessGrant struct {
	TokenFamily
	AccessTokenHash string
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

type TokenPair struct {
	AccessToken   string
	RefreshToken  string
	FamilyID      string
	AccessExpiry  time.Time
	RefreshExpiry time.Time
}

type Store interface {
	PutOAuthClient(context.Context, Client) error
	OAuthClient(context.Context, string, string) (Client, error)
	PutOAuthAuthorizationCode(context.Context, AuthorizationCode) error
	ConsumeOAuthAuthorizationCode(context.Context, AuthorizationCodeExchange, time.Time) (AuthorizationCode, error)
	PutOAuthTokenFamily(context.Context, TokenFamily, string, time.Time, string, time.Time) error
	ExchangeOAuthAuthorizationCode(context.Context, AuthorizationCodeExchange, time.Time, TokenFamily, string, time.Time, string, time.Time) (AuthorizationCode, error)
	OAuthAccessGrant(context.Context, string, time.Time) (AccessGrant, error)
	RotateOAuthRefreshToken(context.Context, string, string, time.Time, string, time.Time, time.Time) (AccessGrant, error)
	RevokeOAuthTokenFamily(context.Context, string, string, time.Time) error
	RevokeOAuthToken(context.Context, string, string, string, string, string, time.Time) error
	OAuthTokenFamilies(context.Context, string, string) ([]TokenFamily, error)
}

type Service struct {
	store Store
	now   func() time.Time
}

func NewService(store Store) *Service {
	return &Service{store: store, now: time.Now}
}

func (s *Service) RegisterClient(ctx context.Context, client Client) error {
	client.Issuer = strings.TrimSpace(client.Issuer)
	client.Audience = strings.TrimSpace(client.Audience)
	client.ID = strings.TrimSpace(client.ID)
	client.Name = strings.TrimSpace(client.Name)
	client.RedirectURIs = canonicalStrings(client.RedirectURIs)
	if client.Issuer == "" || client.Audience == "" || client.ID == "" || client.Name == "" || len(client.RedirectURIs) == 0 {
		return errors.New("oauth client is incomplete")
	}
	if client.CreatedAt.IsZero() {
		client.CreatedAt = s.now().UTC()
	}
	if existing, err := s.store.OAuthClient(ctx, client.Issuer, client.ID); err == nil {
		if existing.Audience != client.Audience || existing.Name != client.Name || !equalStrings(existing.RedirectURIs, client.RedirectURIs) {
			return errors.New("oauth client registration conflicts with existing client")
		}
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return s.store.PutOAuthClient(ctx, client)
}

type AuthorizationRequest struct {
	Binding
	RedirectURI   string
	PKCEChallenge string
	Lifetime      time.Duration
}

func (s *Service) IssueAuthorizationCode(ctx context.Context, request AuthorizationRequest) (string, error) {
	now := s.now().UTC()
	request.Binding = canonicalBinding(request.Binding)
	if err := validateBinding(request.Binding); err != nil {
		return "", err
	}
	client, err := s.store.OAuthClient(ctx, request.Issuer, request.ClientID)
	if err != nil {
		return "", err
	}
	if client.Audience != request.Audience || !contains(client.RedirectURIs, request.RedirectURI) {
		return "", ErrInvalidGrant
	}
	if strings.TrimSpace(request.PKCEChallenge) == "" {
		return "", errors.New("PKCE S256 challenge is required")
	}
	if request.Lifetime <= 0 {
		return "", errors.New("authorization code lifetime is required")
	}
	raw, err := randomSecret()
	if err != nil {
		return "", err
	}
	code := AuthorizationCode{Binding: request.Binding, CodeHash: hashSecret("code", raw), RedirectURI: request.RedirectURI, PKCEChallenge: request.PKCEChallenge, CreatedAt: now, ExpiresAt: now.Add(request.Lifetime)}
	if err := s.store.PutOAuthAuthorizationCode(ctx, code); err != nil {
		return "", err
	}
	return raw, nil
}

type ExchangeRequest struct {
	Code, Issuer, Audience, ClientID, RedirectURI, PKCEVerifier string
	AccessLifetime, RefreshLifetime                             time.Duration
}

func (s *Service) ExchangeAuthorizationCode(ctx context.Context, request ExchangeRequest) (TokenPair, AccessGrant, error) {
	now := s.now().UTC()
	if request.AccessLifetime <= 0 || request.RefreshLifetime <= 0 || !validPKCEVerifier(request.PKCEVerifier) {
		return TokenPair{}, AccessGrant{}, ErrInvalidGrant
	}
	familyID, err := randomSecret()
	if err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	access, err := randomSecret()
	if err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	refresh, err := randomSecret()
	if err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	accessExpiry, refreshExpiry := now.Add(request.AccessLifetime), now.Add(request.RefreshLifetime)
	family := TokenFamily{ID: familyID, CreatedAt: now}
	code, err := s.store.ExchangeOAuthAuthorizationCode(ctx, AuthorizationCodeExchange{
		CodeHash: hashSecret("code", request.Code), Issuer: request.Issuer,
		Audience: request.Audience, ClientID: request.ClientID,
		RedirectURI: request.RedirectURI, PKCEChallenge: pkceS256(request.PKCEVerifier),
	}, now, family, hashSecret("access", access), accessExpiry, hashSecret("refresh", refresh), refreshExpiry)
	if err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	family.Binding = code.Binding
	grant := AccessGrant{TokenFamily: family, AccessTokenHash: hashSecret("access", access), IssuedAt: now, ExpiresAt: accessExpiry}
	return TokenPair{AccessToken: access, RefreshToken: refresh, FamilyID: familyID, AccessExpiry: accessExpiry, RefreshExpiry: refreshExpiry}, grant, nil
}

// RFC 7636 requires code_verifier to contain 43-128 unreserved ASCII
// characters. Reject malformed values before entropy generation or storage so
// an invalid exchange cannot consume a valid authorization code.
func validPKCEVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '.' || character == '_' || character == '~' {
			continue
		}
		return false
	}
	return true
}

func (s *Service) ResolveAccessToken(ctx context.Context, raw string) (AccessGrant, error) {
	if strings.TrimSpace(raw) == "" {
		return AccessGrant{}, ErrInvalidGrant
	}
	return s.store.OAuthAccessGrant(ctx, hashSecret("access", raw), s.now().UTC())
}

func (s *Service) RotateRefreshToken(ctx context.Context, raw string, accessLifetime, refreshLifetime time.Duration) (TokenPair, AccessGrant, error) {
	if strings.TrimSpace(raw) == "" || accessLifetime <= 0 || refreshLifetime <= 0 {
		return TokenPair{}, AccessGrant{}, ErrInvalidGrant
	}
	now := s.now().UTC()
	access, err := randomSecret()
	if err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	refresh, err := randomSecret()
	if err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	accessExpiry, refreshExpiry := now.Add(accessLifetime), now.Add(refreshLifetime)
	grant, err := s.store.RotateOAuthRefreshToken(ctx, hashSecret("refresh", raw), hashSecret("access", access), accessExpiry, hashSecret("refresh", refresh), refreshExpiry, now)
	if err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	pair := TokenPair{AccessToken: access, RefreshToken: refresh, FamilyID: grant.ID, AccessExpiry: accessExpiry, RefreshExpiry: refreshExpiry}
	return pair, grant, nil
}

func (s *Service) RevokeFamily(ctx context.Context, familyID, reason string) error {
	if strings.TrimSpace(familyID) == "" || strings.TrimSpace(reason) == "" {
		return ErrInvalidGrant
	}
	return s.store.RevokeOAuthTokenFamily(ctx, familyID, reason, s.now().UTC())
}

func (s *Service) RevokeToken(ctx context.Context, raw, issuer, clientID, reason string) error {
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(issuer) == "" || strings.TrimSpace(clientID) == "" || strings.TrimSpace(reason) == "" {
		return ErrInvalidGrant
	}
	return s.store.RevokeOAuthToken(ctx, hashSecret("access", raw), hashSecret("refresh", raw), issuer, clientID, reason, s.now().UTC())
}

func (s *Service) TokenFamilies(ctx context.Context, tenantID, agentID string) ([]TokenFamily, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(agentID) == "" {
		return nil, ErrInvalidGrant
	}
	return s.store.OAuthTokenFamilies(ctx, tenantID, agentID)
}

func (s *Service) issueFamily(ctx context.Context, binding Binding, accessLifetime, refreshLifetime time.Duration, now time.Time) (TokenPair, AccessGrant, error) {
	if accessLifetime <= 0 || refreshLifetime <= 0 {
		return TokenPair{}, AccessGrant{}, ErrInvalidGrant
	}
	familyID, err := randomSecret()
	if err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	access, err := randomSecret()
	if err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	refresh, err := randomSecret()
	if err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	family := TokenFamily{Binding: canonicalBinding(binding), ID: familyID, CreatedAt: now}
	accessExpiry, refreshExpiry := now.Add(accessLifetime), now.Add(refreshLifetime)
	if err := s.store.PutOAuthTokenFamily(ctx, family, hashSecret("access", access), accessExpiry, hashSecret("refresh", refresh), refreshExpiry); err != nil {
		return TokenPair{}, AccessGrant{}, err
	}
	grant := AccessGrant{TokenFamily: family, AccessTokenHash: hashSecret("access", access), IssuedAt: now, ExpiresAt: accessExpiry}
	return TokenPair{AccessToken: access, RefreshToken: refresh, FamilyID: familyID, AccessExpiry: accessExpiry, RefreshExpiry: refreshExpiry}, grant, nil
}

func canonicalBinding(binding Binding) Binding {
	binding.Issuer = strings.TrimSpace(binding.Issuer)
	binding.Audience = strings.TrimSpace(binding.Audience)
	binding.ClientID = strings.TrimSpace(binding.ClientID)
	binding.TenantID = strings.TrimSpace(binding.TenantID)
	binding.AgentID = strings.TrimSpace(binding.AgentID)
	binding.Repositories = canonicalStrings(binding.Repositories)
	return binding
}

func validateBinding(binding Binding) error {
	if binding.Issuer == "" || binding.Audience == "" || binding.ClientID == "" || binding.TenantID == "" || binding.AgentID == "" {
		return errors.New("oauth binding is incomplete")
	}
	if binding.AllPrivate && len(binding.Repositories) > 0 {
		return errors.New("all-private and repository allow-list are mutually exclusive")
	}
	if !binding.AllPrivate && len(binding.Repositories) == 0 {
		return errors.New("oauth repository scope is empty")
	}
	return nil
}

func canonicalStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func equalStrings(left, right []string) bool {
	left, right = canonicalStrings(left), canonicalStrings(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func randomSecret() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate oauth secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func hashSecret(kind, raw string) string {
	sum := sha256.Sum256([]byte("gitoversight/oauth/" + kind + "/" + raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
