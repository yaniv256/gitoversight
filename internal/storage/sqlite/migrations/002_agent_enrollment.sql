ALTER TABLE agent_credentials ADD COLUMN approved_at INTEGER;
ALTER TABLE agent_credentials ADD COLUMN approved_by TEXT;
ALTER TABLE agent_credentials ADD COLUMN supersedes_credential_id TEXT;

CREATE TABLE agent_enrollments (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    proof_message BLOB NOT NULL,
    supersedes_credential_id TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    proof_verified_at INTEGER,
    approved_at INTEGER,
    approved_by TEXT,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, credential_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE INDEX agent_enrollments_expiry_idx ON agent_enrollments (tenant_id, expires_at);
