CREATE TABLE human_queue (
    tenant_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    position INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, item_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE INDEX human_queue_position_idx
    ON human_queue (tenant_id, state, position);
