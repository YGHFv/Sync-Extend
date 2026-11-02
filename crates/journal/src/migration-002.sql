CREATE TABLE publications (
    transaction_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('preparing', 'ready', 'published', 'committed')),
    committed_snapshot TEXT REFERENCES snapshots(snapshot_id),
    cleaned INTEGER NOT NULL DEFAULT 0 CHECK (cleaned IN (0, 1)),
    CHECK ((state = 'committed') = (committed_snapshot IS NOT NULL)),
    CHECK (cleaned = 0 OR state = 'committed')
) STRICT;

CREATE UNIQUE INDEX one_active_publication_per_space ON publications(space_id)
WHERE state != 'committed' OR cleaned = 0;

CREATE TABLE publication_objects (
    transaction_id TEXT NOT NULL REFERENCES publications(transaction_id),
    content_id TEXT NOT NULL,
    PRIMARY KEY(transaction_id, content_id)
) STRICT;

CREATE TABLE snapshot_objects (
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    content_id TEXT NOT NULL,
    PRIMARY KEY(snapshot_id, content_id)
) STRICT;

PRAGMA user_version = 2;
