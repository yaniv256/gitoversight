CREATE TABLE staged_assets (
    tenant_id             TEXT    NOT NULL,
    id                    TEXT    NOT NULL,
    agent_id              TEXT    NOT NULL,
    credential_id         TEXT    NOT NULL,
    repository            TEXT    NOT NULL,
    name                  TEXT    NOT NULL,
    content_type          TEXT    NOT NULL,
    expected_sha256       TEXT    NOT NULL,
    expected_size         INTEGER NOT NULL CHECK (expected_size >= 0),
    reserved_size         INTEGER NOT NULL CHECK (reserved_size >= 0),
    state                 TEXT    NOT NULL CHECK (state IN ('created', 'uploading', 'ready', 'pinned', 'abandoned', 'expired')),
    capability_hash       TEXT    NOT NULL,
    capability_expires_at INTEGER NOT NULL,
    capability_used_at    INTEGER,
    temp_id               TEXT,
    object_key            TEXT,
    operation_id          TEXT,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, operation_id) REFERENCES operation_packets(tenant_id, id) ON DELETE RESTRICT,
    CHECK (length(expected_sha256) = 64),
    CHECK (operation_id IS NULL OR state = 'pinned'),
    CHECK (object_key IS NULL OR state IN ('ready', 'pinned'))
);

CREATE UNIQUE INDEX staged_assets_operation_idx
    ON staged_assets (tenant_id, operation_id)
    WHERE operation_id IS NOT NULL;

CREATE UNIQUE INDEX staged_assets_capability_idx
    ON staged_assets (tenant_id, capability_hash);

CREATE INDEX staged_assets_expiry_idx
    ON staged_assets (tenant_id, state, expires_at);
