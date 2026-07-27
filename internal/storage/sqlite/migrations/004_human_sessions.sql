CREATE TABLE human_sessions (
    tenant_id TEXT NOT NULL,
    id_hash TEXT NOT NULL,
    human_id TEXT,
    csrf_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    authenticated_at INTEGER,
    recent_auth_until INTEGER,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    PRIMARY KEY (tenant_id, id_hash),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, human_id) REFERENCES humans(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX human_sessions_expiry_idx ON human_sessions (tenant_id, expires_at);
