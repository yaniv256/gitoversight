ALTER TABLE notification_subscriptions ADD COLUMN event_types_json BLOB NOT NULL DEFAULT '[]';

CREATE TABLE notification_deliveries (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    outbox_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    adapter TEXT NOT NULL,
    destination_json BLOB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'delivered', 'dead_letter')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    available_at INTEGER NOT NULL,
    lease_owner TEXT,
    lease_token TEXT,
    lease_until INTEGER,
    duplicate_risk INTEGER NOT NULL DEFAULT 0 CHECK (duplicate_risk IN (0, 1)),
    last_error TEXT,
    created_at INTEGER NOT NULL,
    delivered_at INTEGER,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, outbox_id, subscription_id),
    FOREIGN KEY (tenant_id, outbox_id) REFERENCES outbox_deliveries(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, subscription_id) REFERENCES notification_subscriptions(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX notification_deliveries_claim_idx
ON notification_deliveries (state, available_at, lease_until, created_at);
