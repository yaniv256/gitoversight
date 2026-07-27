DROP INDEX execution_grants_operation_idx;
CREATE UNIQUE INDEX execution_grants_operation_idx
ON execution_grants (tenant_id, operation_id)
WHERE revoked_at IS NULL;
