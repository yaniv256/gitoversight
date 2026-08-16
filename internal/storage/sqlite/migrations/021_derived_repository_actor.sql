ALTER TABLE derived_repositories ADD COLUMN actor_subject TEXT NOT NULL DEFAULT '';

UPDATE derived_repositories
SET actor_subject = COALESCE((
    SELECT actor_subject
    FROM operation_packets
    WHERE operation_packets.tenant_id = derived_repositories.tenant_id
      AND operation_packets.id = derived_repositories.source_operation_id
), '');
