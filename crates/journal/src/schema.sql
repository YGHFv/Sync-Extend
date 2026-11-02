CREATE TABLE local_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE operations (
    op_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    origin_device_id TEXT NOT NULL,
    origin_seq INTEGER NOT NULL CHECK (origin_seq > 0),
    payload TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'received', 'materialized')),
    UNIQUE(space_id, origin_device_id, origin_seq)
) STRICT;

CREATE TABLE receive_cursors (
    space_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    contiguous_seq INTEGER NOT NULL CHECK (contiguous_seq >= 0),
    PRIMARY KEY(space_id, device_id)
) STRICT;

CREATE TABLE snapshots (
    snapshot_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    manifest TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('metadata_only', 'content_closed', 'materialized')),
    locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1))
) STRICT;

CREATE TABLE current_manifests (
    space_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id)
) STRICT;

PRAGMA user_version = 1;
