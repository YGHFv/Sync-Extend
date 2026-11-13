CREATE TABLE owner (
    space TEXT PRIMARY KEY,
    device TEXT NOT NULL,
    policy TEXT NOT NULL,
    max_bytes INTEGER NOT NULL CHECK(max_bytes > 0),
    expires INTEGER NOT NULL CHECK(expires > 0)
) STRICT;
CREATE TABLE traffic (
    request TEXT NOT NULL,
    content TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('ingress','egress')),
    bytes INTEGER NOT NULL CHECK(bytes >= 0),
    at_ms INTEGER NOT NULL CHECK(at_ms >= 0),
    PRIMARY KEY(request,content,direction)
) STRICT;
CREATE TABLE pages (
    storage_id TEXT PRIMARY KEY,
    envelope TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    retained_at_ms INTEGER NOT NULL CHECK(retained_at_ms >= 0)
) STRICT;
CREATE TABLE snapshots (
    storage_id TEXT PRIMARY KEY,
    envelope TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    retained_at_ms INTEGER NOT NULL CHECK(retained_at_ms >= 0)
) STRICT;
CREATE TRIGGER owner_update BEFORE UPDATE ON owner BEGIN SELECT RAISE(ABORT,'immutable storage traffic owner'); END;
CREATE TRIGGER owner_delete BEFORE DELETE ON owner BEGIN SELECT RAISE(ABORT,'retained storage traffic owner'); END;
CREATE TRIGGER owner_insert BEFORE INSERT ON owner WHEN EXISTS(SELECT 1 FROM owner)
BEGIN SELECT RAISE(ABORT,'one storage traffic owner'); END;
CREATE TRIGGER traffic_insert BEFORE INSERT ON traffic
WHEN NOT sync_storage_traffic_issue(NEW.request,NEW.content,NEW.direction,NEW.bytes,NEW.at_ms)
BEGIN SELECT RAISE(ABORT,'private storage traffic issuance'); END;
CREATE TRIGGER traffic_update BEFORE UPDATE ON traffic BEGIN SELECT RAISE(ABORT,'immutable storage traffic'); END;
CREATE TRIGGER traffic_delete BEFORE DELETE ON traffic BEGIN SELECT RAISE(ABORT,'retained storage traffic'); END;
CREATE TRIGGER page_insert BEFORE INSERT ON pages
WHEN NOT sync_storage_page_issue(NEW.storage_id,NEW.envelope_hash,NEW.retained_at_ms)
BEGIN SELECT RAISE(ABORT,'private storage page issuance'); END;
CREATE TRIGGER page_update BEFORE UPDATE ON pages BEGIN SELECT RAISE(ABORT,'immutable storage page'); END;
CREATE TRIGGER page_delete BEFORE DELETE ON pages BEGIN SELECT RAISE(ABORT,'retained storage page'); END;
CREATE TRIGGER snapshot_insert BEFORE INSERT ON snapshots
WHEN NOT sync_storage_page_issue(NEW.storage_id,NEW.envelope_hash,NEW.retained_at_ms)
BEGIN SELECT RAISE(ABORT,'private storage snapshot issuance'); END;
CREATE TRIGGER snapshot_update BEFORE UPDATE ON snapshots BEGIN SELECT RAISE(ABORT,'immutable storage snapshot'); END;
CREATE TRIGGER snapshot_delete BEFORE DELETE ON snapshots BEGIN SELECT RAISE(ABORT,'retained storage snapshot'); END;
PRAGMA user_version=1;
