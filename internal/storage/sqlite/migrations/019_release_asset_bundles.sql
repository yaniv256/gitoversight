DROP INDEX staged_assets_operation_idx;

CREATE INDEX staged_assets_operation_idx
    ON staged_assets (tenant_id, operation_id)
    WHERE operation_id IS NOT NULL;
