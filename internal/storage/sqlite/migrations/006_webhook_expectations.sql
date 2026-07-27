ALTER TABLE operation_packets ADD COLUMN approval_nonce TEXT;
ALTER TABLE operation_packets ADD COLUMN approval_expires_at INTEGER;

CREATE UNIQUE INDEX operation_packets_review_expectation_idx
ON operation_packets (tenant_id, repository, head_sha, approver)
WHERE state = 'awaiting_approval';
