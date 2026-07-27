ALTER TABLE outbox_deliveries ADD COLUMN audience_agent_id TEXT;

-- Legacy rows predate an enforceable audience and must never be broadcast.
-- They remain auditable but are terminal rather than guessed or widened.
UPDATE outbox_deliveries
SET state = 'dead_letter'
WHERE audience_agent_id IS NULL;

CREATE INDEX outbox_delivery_audience_idx
    ON outbox_deliveries (tenant_id, audience_agent_id, state, created_at);
