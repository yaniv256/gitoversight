package sqlite

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/appauth"
)

func TestOAuthClientRegistrationIsRestartIdempotentAndRejectsDrift(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	service := appauth.NewService(db)
	client := appauth.Client{
		Issuer: "https://gitoversight.example", Audience: "https://gitoversight.example/mcp",
		ID: "chatgpt-work", Name: "ChatGPT Work", RedirectURIs: []string{"https://chatgpt.com/aip/oauth/callback"},
	}
	if err := service.RegisterClient(ctx, client); err != nil {
		t.Fatalf("first startup registration: %v", err)
	}
	// A fresh service represents an API process restart against the same DB.
	if err := appauth.NewService(db).RegisterClient(ctx, client); err != nil {
		t.Fatalf("same-client restart registration: %v", err)
	}
	drifted := client
	drifted.RedirectURIs = []string{"https://attacker.example/callback"}
	if err := appauth.NewService(db).RegisterClient(ctx, drifted); err == nil {
		t.Fatal("client configuration drift was accepted")
	}
	stored, err := db.OAuthClient(ctx, client.Issuer, client.ID)
	if err != nil || len(stored.RedirectURIs) != 1 || stored.RedirectURIs[0] != client.RedirectURIs[0] {
		t.Fatalf("stored client changed after rejected drift: %+v, %v", stored, err)
	}
}

func TestOAuthAuthorizationExchangeStoresOnlyHashesAndExactBindings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedAgent(t, db, "tenant-a", "work-agent")
	service := appauth.NewService(db)
	redirect := "https://chatgpt.com/aip/oauth/callback"
	if err := service.RegisterClient(ctx, appauth.Client{
		Issuer: "https://gitoversight.example", Audience: "https://gitoversight.example/mcp",
		ID: "chatgpt-work", Name: "ChatGPT Work", RedirectURIs: []string{redirect},
	}); err != nil {
		t.Fatal(err)
	}

	verifier := "this-is-a-long-pkce-verifier-with-enough-entropy-for-the-test"
	code, err := service.IssueAuthorizationCode(ctx, appauth.AuthorizationRequest{
		Binding: appauth.Binding{
			Issuer: "https://gitoversight.example", Audience: "https://gitoversight.example/mcp",
			ClientID: "chatgpt-work", TenantID: "tenant-a", AgentID: "work-agent",
			Repositories: []string{"yaniv256/private-b", "yaniv256/private-a", "yaniv256/private-a"},
		},
		RedirectURI: redirect, PKCEChallenge: pkceChallenge(verifier), Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if code == "" {
		t.Fatal("authorization code is empty")
	}

	pair, grant, err := service.ExchangeAuthorizationCode(ctx, appauth.ExchangeRequest{
		Code: code, Issuer: "https://gitoversight.example", Audience: "https://gitoversight.example/mcp",
		ClientID: "chatgpt-work", RedirectURI: redirect, PKCEVerifier: verifier,
		AccessLifetime: 5 * time.Minute, RefreshLifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.FamilyID == "" {
		t.Fatalf("incomplete token pair: %+v", pair)
	}
	if grant.Issuer != "https://gitoversight.example" || grant.Audience != "https://gitoversight.example/mcp" || grant.ClientID != "chatgpt-work" || grant.TenantID != "tenant-a" || grant.AgentID != "work-agent" {
		t.Fatalf("grant lost exact binding: %+v", grant)
	}
	wantRepositories := []string{"yaniv256/private-a", "yaniv256/private-b"}
	if len(grant.Repositories) != len(wantRepositories) || grant.Repositories[0] != wantRepositories[0] || grant.Repositories[1] != wantRepositories[1] {
		t.Fatalf("repositories = %v, want %v", grant.Repositories, wantRepositories)
	}
	resolved, err := service.ResolveAccessToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ID != pair.FamilyID || resolved.AccessTokenHash == pair.AccessToken {
		t.Fatalf("resolved grant = %+v", resolved)
	}

	for _, check := range []struct{ table, column, raw string }{
		{"oauth_authorization_codes", "code_hash", code},
		{"oauth_access_tokens", "token_hash", pair.AccessToken},
		{"oauth_refresh_tokens", "token_hash", pair.RefreshToken},
	} {
		var count int
		query := `SELECT COUNT(*) FROM ` + check.table + ` WHERE ` + check.column + ` = ?`
		if err := db.sql.QueryRowContext(ctx, query, check.raw).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("raw secret persisted in %s.%s", check.table, check.column)
		}
	}
	if _, _, err := service.ExchangeAuthorizationCode(ctx, appauth.ExchangeRequest{
		Code: code, Issuer: "https://gitoversight.example", Audience: "https://gitoversight.example/mcp",
		ClientID: "chatgpt-work", RedirectURI: redirect, PKCEVerifier: verifier,
		AccessLifetime: time.Minute, RefreshLifetime: time.Hour,
	}); !errors.Is(err, appauth.ErrAuthorizationCodeUsed) {
		t.Fatalf("authorization code replay error = %v, want %v", err, appauth.ErrAuthorizationCodeUsed)
	}
}

func TestOAuthRefreshReplayRevokesWholeTokenFamily(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedAgent(t, db, "tenant-a", "work-agent")
	service := appauth.NewService(db)
	pair := issueOAuthPair(t, ctx, service, "tenant-a")

	replacement, replacementGrant, err := service.RotateRefreshToken(ctx, pair.RefreshToken, 5*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.FamilyID != pair.FamilyID || replacementGrant.ID != pair.FamilyID {
		t.Fatalf("rotation changed family: old=%s new=%+v", pair.FamilyID, replacement)
	}
	if _, err := service.ResolveAccessToken(ctx, replacement.AccessToken); err != nil {
		t.Fatalf("replacement access token rejected before replay: %v", err)
	}

	if _, _, err := service.RotateRefreshToken(ctx, pair.RefreshToken, 5*time.Minute, time.Hour); !errors.Is(err, appauth.ErrRefreshTokenReplay) {
		t.Fatalf("refresh replay error = %v, want %v", err, appauth.ErrRefreshTokenReplay)
	}
	for _, raw := range []string{pair.AccessToken, replacement.AccessToken} {
		if _, err := service.ResolveAccessToken(ctx, raw); !errors.Is(err, appauth.ErrTokenRevoked) {
			t.Fatalf("family access token after replay error = %v, want revoked", err)
		}
	}
	var reason string
	if err := db.sql.QueryRowContext(ctx, `SELECT revocation_reason FROM oauth_token_families WHERE id = ?`, pair.FamilyID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "refresh_token_replay" {
		t.Fatalf("revocation reason = %q", reason)
	}
}

func TestOAuthExchangeWrongVerifierDoesNotConsumeCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedAgent(t, db, "tenant-a", "agent")
	service := appauth.NewService(db)
	redirect := "https://chatgpt.com/aip/oauth/callback"
	if err := service.RegisterClient(ctx, appauth.Client{Issuer: "https://issuer", Audience: "https://audience", ID: "client", Name: "Work", RedirectURIs: []string{redirect}}); err != nil {
		t.Fatal(err)
	}
	verifier := "another-long-pkce-verifier-for-binding-mismatch-testing"
	code, err := service.IssueAuthorizationCode(ctx, appauth.AuthorizationRequest{Binding: appauth.Binding{Issuer: "https://issuer", Audience: "https://audience", ClientID: "client", TenantID: "tenant-a", AgentID: "agent", AllPrivate: true}, RedirectURI: redirect, PKCEChallenge: pkceChallenge(verifier), Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	request := appauth.ExchangeRequest{Code: code, Issuer: "https://issuer", Audience: "https://audience", ClientID: "client", RedirectURI: redirect, PKCEVerifier: "wrong-verifier-that-must-not-burn-the-code-123", AccessLifetime: time.Minute, RefreshLifetime: time.Hour}
	if _, _, err := service.ExchangeAuthorizationCode(ctx, request); !errors.Is(err, appauth.ErrInvalidGrant) {
		t.Fatalf("wrong verifier error = %v", err)
	}
	request.PKCEVerifier = verifier
	if _, _, err := service.ExchangeAuthorizationCode(ctx, request); err != nil {
		t.Fatalf("correct retry after wrong verifier failed: %v", err)
	}
}

func TestOAuthAuthorizationCodeRequiresRegisteredAgent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	service := appauth.NewService(db)
	redirect := "https://chatgpt.com/aip/oauth/callback"
	if err := service.RegisterClient(ctx, appauth.Client{Issuer: "https://issuer", Audience: "https://audience", ID: "client", Name: "Work", RedirectURIs: []string{redirect}}); err != nil {
		t.Fatal(err)
	}
	request := appauth.AuthorizationRequest{
		Binding:     appauth.Binding{Issuer: "https://issuer", Audience: "https://audience", ClientID: "client", TenantID: "tenant-a", AgentID: "new-work-agent", AllPrivate: true},
		RedirectURI: redirect, PKCEChallenge: pkceChallenge("registered-agent-boundary-verifier-value"), Lifetime: time.Minute,
	}
	if _, err := service.IssueAuthorizationCode(ctx, request); err == nil {
		t.Fatal("unregistered agent received an authorization code")
	}
	if got := countRowsForTenant(t, db, "agents", "tenant-a"); got != 0 {
		t.Fatalf("agent rows after rejected code = %d, want 0", got)
	}
	if got := countRowsForTenant(t, db, "oauth_authorization_codes", "tenant-a"); got != 0 {
		t.Fatalf("authorization-code rows after rejection = %d, want 0", got)
	}

	seedAgent(t, db, "tenant-a", "new-work-agent")
	if _, err := service.IssueAuthorizationCode(ctx, request); err != nil {
		t.Fatalf("registered agent did not receive authorization code: %v", err)
	}
}

func TestOAuthConcurrentRefreshReuseRevokesWinningFamily(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedAgent(t, db, "tenant-a", "work-agent")
	service := appauth.NewService(db)
	pair := issueOAuthPair(t, ctx, service, "tenant-a")

	start := make(chan struct{})
	type rotation struct {
		pair appauth.TokenPair
		err  error
	}
	results := make(chan rotation, 2)
	for range 2 {
		go func() {
			<-start
			rotated, _, err := service.RotateRefreshToken(ctx, pair.RefreshToken, 5*time.Minute, time.Hour)
			results <- rotation{pair: rotated, err: err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	var winner appauth.TokenPair
	var successes, replays int
	for _, result := range []rotation{first, second} {
		switch {
		case result.err == nil:
			successes++
			winner = result.pair
		case errors.Is(result.err, appauth.ErrRefreshTokenReplay):
			replays++
		default:
			t.Fatalf("unexpected concurrent rotation error: %v", result.err)
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("successes=%d replays=%d, want 1 and 1", successes, replays)
	}
	if _, err := service.ResolveAccessToken(ctx, winner.AccessToken); !errors.Is(err, appauth.ErrTokenRevoked) {
		t.Fatalf("winning token after concurrent replay error = %v, want revoked", err)
	}
	var reason string
	if err := db.sql.QueryRowContext(ctx, `SELECT revocation_reason FROM oauth_token_families WHERE id = ?`, pair.FamilyID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "refresh_token_replay" {
		t.Fatalf("revocation reason = %q", reason)
	}
}

func TestOAuthTokenInsertFailureDoesNotConsumeAuthorizationCode(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedAgent(t, db, "tenant-a", "work-agent")
	service := appauth.NewService(db)
	redirect := "https://chatgpt.com/aip/oauth/callback"
	if err := service.RegisterClient(ctx, appauth.Client{Issuer: "https://issuer", Audience: "https://audience", ID: "client", Name: "Work", RedirectURIs: []string{redirect}}); err != nil {
		t.Fatal(err)
	}
	verifier := "transactional-code-exchange-verifier-123456789"
	code, err := service.IssueAuthorizationCode(ctx, appauth.AuthorizationRequest{Binding: appauth.Binding{Issuer: "https://issuer", Audience: "https://audience", ClientID: "client", TenantID: "tenant-a", AgentID: "work-agent", AllPrivate: true}, RedirectURI: redirect, PKCEChallenge: pkceChallenge(verifier), Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `CREATE TRIGGER fail_oauth_family_insert BEFORE INSERT ON oauth_token_families BEGIN SELECT RAISE(ABORT, 'injected family failure'); END`); err != nil {
		t.Fatal(err)
	}
	exchange := appauth.ExchangeRequest{Code: code, Issuer: "https://issuer", Audience: "https://audience", ClientID: "client", RedirectURI: redirect, PKCEVerifier: verifier, AccessLifetime: 5 * time.Minute, RefreshLifetime: time.Hour}
	if _, _, err := service.ExchangeAuthorizationCode(ctx, exchange); err == nil {
		t.Fatal("exchange unexpectedly succeeded through injected token insert failure")
	}
	if _, err := db.sql.ExecContext(ctx, `DROP TRIGGER fail_oauth_family_insert`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ExchangeAuthorizationCode(ctx, exchange); err != nil {
		t.Fatalf("authorization code was consumed by failed token insertion: %v", err)
	}
}

func issueOAuthPair(t *testing.T, ctx context.Context, service *appauth.Service, tenantID string) appauth.TokenPair {
	t.Helper()
	redirect := "https://chatgpt.com/aip/oauth/callback"
	if err := service.RegisterClient(ctx, appauth.Client{Issuer: "https://issuer", Audience: "https://audience", ID: "client", Name: "Work", RedirectURIs: []string{redirect}}); err != nil {
		t.Fatal(err)
	}
	verifier := "a-third-long-pkce-verifier-for-the-rotation-test"
	code, err := service.IssueAuthorizationCode(ctx, appauth.AuthorizationRequest{Binding: appauth.Binding{Issuer: "https://issuer", Audience: "https://audience", ClientID: "client", TenantID: tenantID, AgentID: "work-agent", AllPrivate: true}, RedirectURI: redirect, PKCEChallenge: pkceChallenge(verifier), Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	pair, _, err := service.ExchangeAuthorizationCode(ctx, appauth.ExchangeRequest{Code: code, Issuer: "https://issuer", Audience: "https://audience", ClientID: "client", RedirectURI: redirect, PKCEVerifier: verifier, AccessLifetime: 5 * time.Minute, RefreshLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func seedAgent(t *testing.T, db *DB, tenantID, agentID string) {
	t.Helper()
	err := db.WithTx(context.Background(), func(tx *Tx) error {
		return tx.EnsureAgent(context.Background(), tenantID, agentID, time.Unix(1_720_000_000, 0).UTC())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func countRowsForTenant(t *testing.T, db *DB, table, tenantID string) int {
	t.Helper()
	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE tenant_id = ?`, tenantID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
