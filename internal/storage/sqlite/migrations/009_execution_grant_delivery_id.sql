ALTER TABLE execution_grants ADD COLUMN delivery_id TEXT;

CREATE UNIQUE INDEX execution_grants_delivery_idx
ON execution_grants (delivery_id)
WHERE delivery_id IS NOT NULL;
