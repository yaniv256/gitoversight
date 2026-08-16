CREATE TABLE oauth_clients (
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (issuer, client_id)
);

CREATE TABLE oauth_client_redirect_uris (
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    PRIMARY KEY (issuer, client_id, redirect_uri),
    FOREIGN KEY (issuer, client_id) REFERENCES oauth_clients(issuer, client_id) ON DELETE CASCADE
);

CREATE TABLE oauth_authorization_codes (
    code_hash TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    client_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    pkce_challenge TEXT NOT NULL,
    all_private INTEGER NOT NULL CHECK (all_private IN (0, 1)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    FOREIGN KEY (issuer, client_id) REFERENCES oauth_clients(issuer, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE oauth_authorization_code_repositories (
    code_hash TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    PRIMARY KEY (code_hash, repository_id),
    FOREIGN KEY (code_hash) REFERENCES oauth_authorization_codes(code_hash) ON DELETE CASCADE
);

CREATE INDEX oauth_authorization_codes_expiry_idx ON oauth_authorization_codes(expires_at);

CREATE TABLE oauth_token_families (
    id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    client_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    all_private INTEGER NOT NULL CHECK (all_private IN (0, 1)),
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revocation_reason TEXT,
    FOREIGN KEY (issuer, client_id) REFERENCES oauth_clients(issuer, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE oauth_token_family_repositories (
    family_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    PRIMARY KEY (family_id, repository_id),
    FOREIGN KEY (family_id) REFERENCES oauth_token_families(id) ON DELETE CASCADE
);

CREATE TABLE oauth_access_tokens (
    token_hash TEXT PRIMARY KEY,
    family_id TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    FOREIGN KEY (family_id) REFERENCES oauth_token_families(id) ON DELETE CASCADE
);

CREATE INDEX oauth_access_tokens_expiry_idx ON oauth_access_tokens(expires_at);

CREATE TABLE oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    family_id TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    replaced_by_hash TEXT,
    revoked_at INTEGER,
    FOREIGN KEY (family_id) REFERENCES oauth_token_families(id) ON DELETE CASCADE
);

CREATE INDEX oauth_refresh_tokens_expiry_idx ON oauth_refresh_tokens(expires_at);
