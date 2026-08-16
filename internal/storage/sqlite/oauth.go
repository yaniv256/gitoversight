package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/appauth"
)

func (db *DB) PutOAuthClient(ctx context.Context, client appauth.Client) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		if _, err := tx.tx.ExecContext(ctx, `INSERT INTO oauth_clients(issuer, client_id, audience, name, created_at) VALUES (?, ?, ?, ?, ?)`, client.Issuer, client.ID, client.Audience, client.Name, unix(client.CreatedAt)); err != nil {
			return err
		}
		for _, uri := range client.RedirectURIs {
			if _, err := tx.tx.ExecContext(ctx, `INSERT INTO oauth_client_redirect_uris(issuer, client_id, redirect_uri) VALUES (?, ?, ?)`, client.Issuer, client.ID, uri); err != nil {
				return err
			}
		}
		return nil
	})
}

func (db *DB) OAuthClient(ctx context.Context, issuer, clientID string) (appauth.Client, error) {
	var client appauth.Client
	var created int64
	err := db.sql.QueryRowContext(ctx, `SELECT issuer, audience, client_id, name, created_at FROM oauth_clients WHERE issuer = ? AND client_id = ?`, issuer, clientID).Scan(&client.Issuer, &client.Audience, &client.ID, &client.Name, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return appauth.Client{}, appauth.ErrNotFound
	}
	if err != nil {
		return appauth.Client{}, err
	}
	client.CreatedAt = fromUnix(created)
	rows, err := db.sql.QueryContext(ctx, `SELECT redirect_uri FROM oauth_client_redirect_uris WHERE issuer = ? AND client_id = ? ORDER BY redirect_uri`, issuer, clientID)
	if err != nil {
		return appauth.Client{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			return appauth.Client{}, err
		}
		client.RedirectURIs = append(client.RedirectURIs, uri)
	}
	return client, rows.Err()
}

func (db *DB) PutOAuthAuthorizationCode(ctx context.Context, code appauth.AuthorizationCode) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.tx.ExecContext(ctx, `INSERT INTO oauth_authorization_codes(code_hash, issuer, audience, client_id, tenant_id, agent_id, redirect_uri, pkce_challenge, all_private, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, code.CodeHash, code.Issuer, code.Audience, code.ClientID, code.TenantID, code.AgentID, code.RedirectURI, code.PKCEChallenge, code.AllPrivate, unix(code.CreatedAt), unix(code.ExpiresAt))
		if err != nil {
			return err
		}
		for _, repository := range code.Repositories {
			if _, err := tx.tx.ExecContext(ctx, `INSERT INTO oauth_authorization_code_repositories(code_hash, repository_id) VALUES (?, ?)`, code.CodeHash, repository); err != nil {
				return err
			}
		}
		return nil
	})
}

func (db *DB) ConsumeOAuthAuthorizationCode(ctx context.Context, exchange appauth.AuthorizationCodeExchange, now time.Time) (appauth.AuthorizationCode, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return appauth.AuthorizationCode{}, err
	}
	defer tx.Rollback()
	code, err := consumeOAuthAuthorizationCodeTx(ctx, tx, exchange, now)
	if err != nil {
		return appauth.AuthorizationCode{}, err
	}
	if err := tx.Commit(); err != nil {
		return appauth.AuthorizationCode{}, err
	}
	return code, nil
}

func consumeOAuthAuthorizationCodeTx(ctx context.Context, tx *sql.Tx, exchange appauth.AuthorizationCodeExchange, now time.Time) (appauth.AuthorizationCode, error) {
	result, err := tx.ExecContext(ctx, `UPDATE oauth_authorization_codes SET consumed_at = ?
		WHERE code_hash = ? AND issuer = ? AND audience = ? AND client_id = ?
		  AND redirect_uri = ? AND pkce_challenge = ? AND consumed_at IS NULL AND expires_at > ?`,
		unix(now), exchange.CodeHash, exchange.Issuer, exchange.Audience, exchange.ClientID,
		exchange.RedirectURI, exchange.PKCEChallenge, unix(now))
	if err != nil {
		return appauth.AuthorizationCode{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return appauth.AuthorizationCode{}, err
	}
	if count != 1 {
		var issuer, audience, clientID, redirectURI, challenge string
		var expires int64
		var consumed sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT issuer, audience, client_id, redirect_uri, pkce_challenge, expires_at, consumed_at FROM oauth_authorization_codes WHERE code_hash = ?`, exchange.CodeHash).Scan(&issuer, &audience, &clientID, &redirectURI, &challenge, &expires, &consumed)
		if errors.Is(err, sql.ErrNoRows) {
			return appauth.AuthorizationCode{}, appauth.ErrNotFound
		}
		if err != nil {
			return appauth.AuthorizationCode{}, err
		}
		if consumed.Valid {
			return appauth.AuthorizationCode{}, appauth.ErrAuthorizationCodeUsed
		}
		if !now.Before(fromUnix(expires)) {
			return appauth.AuthorizationCode{}, appauth.ErrTokenExpired
		}
		return appauth.AuthorizationCode{}, appauth.ErrInvalidGrant
	}
	var code appauth.AuthorizationCode
	var allPrivate bool
	var created, expires int64
	var consumed sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT code_hash, issuer, audience, client_id, tenant_id, agent_id, redirect_uri, pkce_challenge, all_private, created_at, expires_at, consumed_at FROM oauth_authorization_codes WHERE code_hash = ?`, exchange.CodeHash).Scan(&code.CodeHash, &code.Issuer, &code.Audience, &code.ClientID, &code.TenantID, &code.AgentID, &code.RedirectURI, &code.PKCEChallenge, &allPrivate, &created, &expires, &consumed)
	if err != nil {
		return appauth.AuthorizationCode{}, err
	}
	code.AllPrivate, code.CreatedAt, code.ExpiresAt = allPrivate, fromUnix(created), fromUnix(expires)
	value := now.UTC()
	code.ConsumedAt = &value
	code.Repositories, err = oauthRepositories(ctx, tx, "oauth_authorization_code_repositories", "code_hash", exchange.CodeHash)
	if err != nil {
		return appauth.AuthorizationCode{}, err
	}
	return code, nil
}

// ExchangeOAuthAuthorizationCode atomically consumes the validated one-time
// code and persists its complete token family. A storage failure rolls back the
// consumption, allowing the exact valid exchange to be retried safely.
func (db *DB) ExchangeOAuthAuthorizationCode(ctx context.Context, exchange appauth.AuthorizationCodeExchange, now time.Time, family appauth.TokenFamily, accessHash string, accessExpiry time.Time, refreshHash string, refreshExpiry time.Time) (appauth.AuthorizationCode, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return appauth.AuthorizationCode{}, err
	}
	defer tx.Rollback()
	code, err := consumeOAuthAuthorizationCodeTx(ctx, tx, exchange, now)
	if err != nil {
		return appauth.AuthorizationCode{}, err
	}
	family.Binding = code.Binding
	if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_token_families(id, issuer, audience, client_id, tenant_id, agent_id, all_private, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, family.ID, family.Issuer, family.Audience, family.ClientID, family.TenantID, family.AgentID, family.AllPrivate, unix(family.CreatedAt)); err != nil {
		return appauth.AuthorizationCode{}, err
	}
	for _, repository := range family.Repositories {
		if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_token_family_repositories(family_id, repository_id) VALUES (?, ?)`, family.ID, repository); err != nil {
			return appauth.AuthorizationCode{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_access_tokens(token_hash, family_id, issued_at, expires_at) VALUES (?, ?, ?, ?)`, accessHash, family.ID, unix(family.CreatedAt), unix(accessExpiry)); err != nil {
		return appauth.AuthorizationCode{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_refresh_tokens(token_hash, family_id, issued_at, expires_at) VALUES (?, ?, ?, ?)`, refreshHash, family.ID, unix(family.CreatedAt), unix(refreshExpiry)); err != nil {
		return appauth.AuthorizationCode{}, err
	}
	if err := tx.Commit(); err != nil {
		return appauth.AuthorizationCode{}, err
	}
	return code, nil
}

func (db *DB) PutOAuthTokenFamily(ctx context.Context, family appauth.TokenFamily, accessHash string, accessExpiry time.Time, refreshHash string, refreshExpiry time.Time) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		_, err := tx.tx.ExecContext(ctx, `INSERT INTO oauth_token_families(id, issuer, audience, client_id, tenant_id, agent_id, all_private, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, family.ID, family.Issuer, family.Audience, family.ClientID, family.TenantID, family.AgentID, family.AllPrivate, unix(family.CreatedAt))
		if err != nil {
			return err
		}
		for _, repository := range family.Repositories {
			if _, err := tx.tx.ExecContext(ctx, `INSERT INTO oauth_token_family_repositories(family_id, repository_id) VALUES (?, ?)`, family.ID, repository); err != nil {
				return err
			}
		}
		if _, err := tx.tx.ExecContext(ctx, `INSERT INTO oauth_access_tokens(token_hash, family_id, issued_at, expires_at) VALUES (?, ?, ?, ?)`, accessHash, family.ID, unix(family.CreatedAt), unix(accessExpiry)); err != nil {
			return err
		}
		_, err = tx.tx.ExecContext(ctx, `INSERT INTO oauth_refresh_tokens(token_hash, family_id, issued_at, expires_at) VALUES (?, ?, ?, ?)`, refreshHash, family.ID, unix(family.CreatedAt), unix(refreshExpiry))
		return err
	})
}

func (db *DB) OAuthAccessGrant(ctx context.Context, tokenHash string, now time.Time) (appauth.AccessGrant, error) {
	var grant appauth.AccessGrant
	var allPrivate bool
	var familyCreated, issued, expires int64
	var familyRevoked, tokenRevoked sql.NullInt64
	var reason sql.NullString
	err := db.sql.QueryRowContext(ctx, `SELECT f.id, f.issuer, f.audience, f.client_id, f.tenant_id, f.agent_id, f.all_private, f.created_at, f.revoked_at, f.revocation_reason, a.token_hash, a.issued_at, a.expires_at, a.revoked_at FROM oauth_access_tokens a JOIN oauth_token_families f ON f.id = a.family_id WHERE a.token_hash = ?`, tokenHash).Scan(&grant.ID, &grant.Issuer, &grant.Audience, &grant.ClientID, &grant.TenantID, &grant.AgentID, &allPrivate, &familyCreated, &familyRevoked, &reason, &grant.AccessTokenHash, &issued, &expires, &tokenRevoked)
	if errors.Is(err, sql.ErrNoRows) {
		return appauth.AccessGrant{}, appauth.ErrNotFound
	}
	if err != nil {
		return appauth.AccessGrant{}, err
	}
	if familyRevoked.Valid || tokenRevoked.Valid {
		return appauth.AccessGrant{}, appauth.ErrTokenRevoked
	}
	if !now.Before(fromUnix(expires)) {
		return appauth.AccessGrant{}, appauth.ErrTokenExpired
	}
	grant.AllPrivate, grant.CreatedAt, grant.IssuedAt, grant.ExpiresAt, grant.RevocationReason = allPrivate, fromUnix(familyCreated), fromUnix(issued), fromUnix(expires), reason.String
	grant.Repositories, err = oauthRepositories(ctx, db.sql, "oauth_token_family_repositories", "family_id", grant.ID)
	return grant, err
}

func (db *DB) RotateOAuthRefreshToken(ctx context.Context, oldHash, accessHash string, accessExpiry time.Time, refreshHash string, refreshExpiry, now time.Time) (appauth.AccessGrant, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return appauth.AccessGrant{}, err
	}
	defer tx.Rollback()
	var familyID string
	var expires int64
	var consumed, revoked, familyRevoked sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT r.family_id, r.expires_at, r.consumed_at, r.revoked_at, f.revoked_at FROM oauth_refresh_tokens r JOIN oauth_token_families f ON f.id = r.family_id WHERE r.token_hash = ?`, oldHash).Scan(&familyID, &expires, &consumed, &revoked, &familyRevoked)
	if errors.Is(err, sql.ErrNoRows) {
		return appauth.AccessGrant{}, appauth.ErrNotFound
	}
	if err != nil {
		return appauth.AccessGrant{}, err
	}
	if consumed.Valid {
		if err := revokeOAuthFamilyForReplay(ctx, tx, familyID, now); err != nil {
			return appauth.AccessGrant{}, err
		}
		if err := tx.Commit(); err != nil {
			return appauth.AccessGrant{}, err
		}
		return appauth.AccessGrant{}, appauth.ErrRefreshTokenReplay
	}
	if revoked.Valid || familyRevoked.Valid {
		return appauth.AccessGrant{}, appauth.ErrTokenRevoked
	}
	if !now.Before(fromUnix(expires)) {
		return appauth.AccessGrant{}, appauth.ErrTokenExpired
	}
	result, err := tx.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET consumed_at = ?, replaced_by_hash = ? WHERE token_hash = ? AND consumed_at IS NULL AND revoked_at IS NULL`, unix(now), refreshHash, oldHash)
	if err != nil {
		return appauth.AccessGrant{}, err
	}
	if err := requireOneRow(result, "oauth refresh token"); err != nil {
		if err := revokeOAuthFamilyForReplay(ctx, tx, familyID, now); err != nil {
			return appauth.AccessGrant{}, err
		}
		if err := tx.Commit(); err != nil {
			return appauth.AccessGrant{}, err
		}
		return appauth.AccessGrant{}, appauth.ErrRefreshTokenReplay
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_access_tokens(token_hash, family_id, issued_at, expires_at) VALUES (?, ?, ?, ?)`, accessHash, familyID, unix(now), unix(accessExpiry)); err != nil {
		return appauth.AccessGrant{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_refresh_tokens(token_hash, family_id, issued_at, expires_at) VALUES (?, ?, ?, ?)`, refreshHash, familyID, unix(now), unix(refreshExpiry)); err != nil {
		return appauth.AccessGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return appauth.AccessGrant{}, err
	}
	return db.OAuthAccessGrant(ctx, accessHash, now)
}

func revokeOAuthFamilyForReplay(ctx context.Context, tx *sql.Tx, familyID string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_token_families SET revoked_at = ?, revocation_reason = 'refresh_token_replay' WHERE id = ? AND revoked_at IS NULL`, unix(now), familyID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_access_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`, unix(now), familyID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`, unix(now), familyID)
	return err
}

func (db *DB) RevokeOAuthTokenFamily(ctx context.Context, familyID, reason string, now time.Time) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE oauth_token_families SET revoked_at = ?, revocation_reason = ? WHERE id = ? AND revoked_at IS NULL`, unix(now), reason, familyID)
		if err != nil {
			return err
		}
		if err := requireOneRow(result, "oauth token family"); err != nil {
			return err
		}
		if _, err := tx.tx.ExecContext(ctx, `UPDATE oauth_access_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`, unix(now), familyID); err != nil {
			return err
		}
		_, err = tx.tx.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`, unix(now), familyID)
		return err
	})
}

func (db *DB) RevokeOAuthToken(ctx context.Context, accessHash, refreshHash, issuer, clientID, reason string, now time.Time) error {
	if accessHash == "" || refreshHash == "" || issuer == "" || clientID == "" || reason == "" || now.IsZero() {
		return appauth.ErrInvalidGrant
	}
	return db.WithTx(ctx, func(tx *Tx) error {
		var familyID string
		err := tx.tx.QueryRowContext(ctx, `SELECT a.family_id FROM oauth_access_tokens a JOIN oauth_token_families f ON f.id = a.family_id WHERE a.token_hash = ? AND f.issuer = ? AND f.client_id = ? UNION SELECT r.family_id FROM oauth_refresh_tokens r JOIN oauth_token_families f ON f.id = r.family_id WHERE r.token_hash = ? AND f.issuer = ? AND f.client_id = ? LIMIT 1`, accessHash, issuer, clientID, refreshHash, issuer, clientID).Scan(&familyID)
		if errors.Is(err, sql.ErrNoRows) {
			return appauth.ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = tx.tx.ExecContext(ctx, `UPDATE oauth_token_families SET revoked_at = COALESCE(revoked_at, ?), revocation_reason = CASE WHEN revoked_at IS NULL THEN ? ELSE revocation_reason END WHERE id = ?`, unix(now), reason, familyID)
		return err
	})
}

func (db *DB) OAuthTokenFamilies(ctx context.Context, tenantID, agentID string) ([]appauth.TokenFamily, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, issuer, audience, client_id, tenant_id, agent_id, all_private, created_at, revoked_at, COALESCE(revocation_reason, '') FROM oauth_token_families WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC, id`, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var families []appauth.TokenFamily
	for rows.Next() {
		var family appauth.TokenFamily
		var allPrivate int
		var created int64
		var revoked sql.NullInt64
		if err := rows.Scan(&family.ID, &family.Issuer, &family.Audience, &family.ClientID, &family.TenantID, &family.AgentID, &allPrivate, &created, &revoked, &family.RevocationReason); err != nil {
			return nil, err
		}
		family.AllPrivate = allPrivate != 0
		family.CreatedAt = fromUnix(created)
		if revoked.Valid {
			value := fromUnix(revoked.Int64)
			family.RevokedAt = &value
		}
		family.Repositories, err = oauthRepositories(ctx, db.sql, "oauth_token_family_repositories", "family_id", family.ID)
		if err != nil {
			return nil, err
		}
		families = append(families, family)
	}
	return families, rows.Err()
}

type rowQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func oauthRepositories(ctx context.Context, queryer rowQueryer, table, key, value string) ([]string, error) {
	query := fmt.Sprintf(`SELECT repository_id FROM %s WHERE %s = ? ORDER BY repository_id`, table, key)
	rows, err := queryer.QueryContext(ctx, query, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var repositories []string
	for rows.Next() {
		var repository string
		if err := rows.Scan(&repository); err != nil {
			return nil, err
		}
		repositories = append(repositories, repository)
	}
	return repositories, rows.Err()
}

var _ appauth.Store = (*DB)(nil)
