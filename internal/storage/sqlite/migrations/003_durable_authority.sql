ALTER TABLE policy_generations ADD COLUMN snapshot_json BLOB;

ALTER TABLE operation_packets ADD COLUMN branch TEXT;
ALTER TABLE operation_packets ADD COLUMN title TEXT;
ALTER TABLE operation_packets ADD COLUMN body TEXT;
ALTER TABLE operation_packets ADD COLUMN head_sha TEXT;
ALTER TABLE operation_packets ADD COLUMN manifest_hash TEXT;
ALTER TABLE operation_packets ADD COLUMN approval_id TEXT;
ALTER TABLE operation_packets ADD COLUMN approver TEXT;
ALTER TABLE operation_packets ADD COLUMN decision_code TEXT;
ALTER TABLE operation_packets ADD COLUMN reason TEXT;
ALTER TABLE operation_packets ADD COLUMN actor_mode TEXT;
ALTER TABLE operation_packets ADD COLUMN actor_subject TEXT;
ALTER TABLE operation_packets ADD COLUMN mutation_hash TEXT;
ALTER TABLE operation_packets ADD COLUMN payload_json BLOB;
ALTER TABLE operation_packets ADD COLUMN updated_at INTEGER;

ALTER TABLE approvals ADD COLUMN manifest_hash TEXT;
ALTER TABLE approvals ADD COLUMN repository TEXT;
ALTER TABLE approvals ADD COLUMN operation TEXT;
ALTER TABLE approvals ADD COLUMN head_sha TEXT;

CREATE INDEX operation_packets_owner_idx ON operation_packets (tenant_id, agent_id, created_at);
