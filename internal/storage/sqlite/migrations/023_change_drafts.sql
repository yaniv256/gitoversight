CREATE TABLE change_drafts (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    id TEXT NOT NULL,
    repository TEXT NOT NULL,
    base_commit TEXT NOT NULL,
    preview_hash TEXT NOT NULL,
    preview_json BLOB NOT NULL,
    changes_json BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX change_drafts_expiry_idx ON change_drafts(expires_at);
