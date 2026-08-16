CREATE TABLE derived_repositories (
    tenant_id TEXT NOT NULL,
    repository TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility = 'private'),
    owner_agent_id TEXT NOT NULL,
    source_operation_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, repository),
    UNIQUE (tenant_id, source_operation_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (tenant_id, source_operation_id) REFERENCES operation_packets(tenant_id, id)
);

INSERT OR IGNORE INTO derived_repositories
    (tenant_id, repository, visibility, owner_agent_id, source_operation_id, created_at)
SELECT tenant_id, repository, 'private', agent_id, id, COALESCE(updated_at, created_at)
FROM operation_packets
WHERE operation = 'repository.create'
  AND state = 'verified'
  AND json_valid(payload_json)
  AND json_extract(payload_json, '$.visibility') = 'private';
