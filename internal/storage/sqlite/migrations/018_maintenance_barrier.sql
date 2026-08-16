CREATE TABLE maintenance_barrier (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    state      TEXT NOT NULL CHECK (state IN ('open', 'draining', 'quiescent')),
    updated_at INTEGER NOT NULL
);

INSERT INTO maintenance_barrier(singleton, generation, state, updated_at)
VALUES (1, 0, 'open', unixepoch());

CREATE TABLE maintenance_activity (
    kind         TEXT PRIMARY KEY,
    active_count INTEGER NOT NULL CHECK (active_count >= 0),
    updated_at   INTEGER NOT NULL
);
INSERT INTO maintenance_activity(kind, active_count, updated_at)
VALUES
    ('release_asset_maintenance', 0, unixepoch()),
    ('execution', 0, unixepoch()),
    ('reconciliation', 0, unixepoch());

CREATE TRIGGER maintenance_blocks_stage_issue
BEFORE INSERT ON staged_assets
WHEN (SELECT state FROM maintenance_barrier WHERE singleton = 1) <> 'open'
BEGIN
    SELECT RAISE(ABORT, 'maintenance barrier active');
END;

CREATE TRIGGER maintenance_blocks_stage_upload
BEFORE UPDATE OF state ON staged_assets
WHEN OLD.state = 'created' AND NEW.state = 'uploading'
 AND (SELECT state FROM maintenance_barrier WHERE singleton = 1) <> 'open'
BEGIN
    SELECT RAISE(ABORT, 'maintenance barrier active');
END;

CREATE TRIGGER maintenance_blocks_operation_submission
BEFORE INSERT ON operation_packets
WHEN (SELECT state FROM maintenance_barrier WHERE singleton = 1) <> 'open'
BEGIN
    SELECT RAISE(ABORT, 'maintenance barrier active');
END;

CREATE TRIGGER maintenance_blocks_execution_start
BEFORE UPDATE OF state ON operation_packets
WHEN NEW.state = 'executing' AND OLD.state <> 'executing'
 AND (SELECT state FROM maintenance_barrier WHERE singleton = 1) <> 'open'
BEGIN
    SELECT RAISE(ABORT, 'maintenance barrier active');
END;
