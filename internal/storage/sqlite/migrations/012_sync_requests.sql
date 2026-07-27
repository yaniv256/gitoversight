CREATE TABLE sync_requests (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    private_repository TEXT NOT NULL,
    public_repository TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft',
    private_pr_number INTEGER,
    proposal_text TEXT,
    file_manifest_json TEXT,
    proposal_hash TEXT,
    commit_packet_json TEXT,
    packet_head_sha TEXT,
    authorized_text TEXT,
    public_pr_number INTEGER,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX sync_requests_state_idx
    ON sync_requests (tenant_id, state, updated_at);
