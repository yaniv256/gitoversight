CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);

CREATE TABLE humans (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    github_login TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, github_login),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE TABLE agents (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE TABLE agent_credentials (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE repositories (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('private', 'public')),
    protected INTEGER NOT NULL DEFAULT 0 CHECK (protected IN (0, 1)),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE TABLE repository_owners (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, repository_id, agent_id),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE branch_grants (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    branch TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, repository_id, agent_id, branch),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE standing_exceptions (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    agent_id TEXT,
    operation TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE policy_generations (
    tenant_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    policy_hash TEXT NOT NULL,
    activated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, generation),
    UNIQUE (tenant_id, policy_hash),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE TABLE operation_packets (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    repository TEXT NOT NULL,
    operation TEXT NOT NULL,
    packet_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    policy_generation INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, packet_hash),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE approvals (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    packet_hash TEXT NOT NULL,
    nonce TEXT NOT NULL,
    policy_generation INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    revoked_at INTEGER,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, nonce),
    FOREIGN KEY (tenant_id, operation_id) REFERENCES operation_packets(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, approver_id) REFERENCES humans(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE execution_grants (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    packet_hash TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    repository TEXT NOT NULL,
    operation TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    revoked_at INTEGER,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, operation_id) REFERENCES operation_packets(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE reconciliations (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('committed', 'absent', 'indeterminate')),
    evidence_json BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, operation_id) REFERENCES operation_packets(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    payload_json BLOB NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, event_hash),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE TABLE audit_checkpoints (
    tenant_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    event_hash TEXT NOT NULL,
    signature BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, sequence),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE TABLE notification_subscriptions (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    adapter TEXT NOT NULL,
    destination_json BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE outbox_deliveries (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json BLOB NOT NULL,
    state TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    available_at INTEGER,
    lease_until INTEGER,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE TABLE webhook_receipts (
    tenant_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    body_hash TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, provider, delivery_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE TABLE request_nonces (
    tenant_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, credential_id, nonce),
    FOREIGN KEY (tenant_id, credential_id) REFERENCES agent_credentials(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX operation_packets_state_idx ON operation_packets (tenant_id, state, created_at);
CREATE INDEX execution_grants_operation_idx ON execution_grants (tenant_id, operation_id);
CREATE INDEX outbox_deliveries_state_idx ON outbox_deliveries (tenant_id, state, available_at);
CREATE INDEX request_nonces_expiry_idx ON request_nonces (tenant_id, expires_at);
