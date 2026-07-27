ALTER TABLE execution_grants ADD COLUMN mutation_hash TEXT;
ALTER TABLE execution_grants ADD COLUMN approval_id TEXT;
ALTER TABLE execution_grants ADD COLUMN outcome TEXT;
ALTER TABLE execution_grants ADD COLUMN finalized_at INTEGER;
ALTER TABLE execution_grants ADD COLUMN actor_mode TEXT;

CREATE UNIQUE INDEX execution_grants_global_id_idx ON execution_grants (id);
DROP INDEX execution_grants_operation_idx;
CREATE UNIQUE INDEX execution_grants_operation_idx ON execution_grants (tenant_id, operation_id);
