CREATE TABLE read_leases (
    lease_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active','released','expired')),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > observed_at_ms),
    finished_at_ms INTEGER CHECK (finished_at_ms >= observed_at_ms),
    CHECK ((state = 'active') = (finished_at_ms IS NULL)),
    CHECK (state != 'expired' OR finished_at_ms >= expires_at_ms)
) STRICT;

CREATE TABLE read_lease_objects (
    lease_id TEXT NOT NULL REFERENCES read_leases(lease_id),
    content_id TEXT NOT NULL,
    PRIMARY KEY(lease_id,content_id)
) STRICT;

CREATE TABLE read_lease_clock (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0)
) STRICT;
INSERT INTO read_lease_clock VALUES (1,0);

CREATE TRIGGER read_lease_immutable
BEFORE UPDATE OF lease_id,space_id,snapshot_id,intent,intent_hash ON read_leases BEGIN
    SELECT RAISE(ABORT,'read lease intent is immutable');
END;

CREATE TRIGGER read_lease_transition BEFORE UPDATE ON read_leases
WHEN OLD.state != 'active'
    OR NEW.observed_at_ms < OLD.observed_at_ms
    OR NEW.expires_at_ms < OLD.expires_at_ms
    OR (NEW.state = 'active' AND NEW.observed_at_ms >= OLD.expires_at_ms)
    OR (NEW.state != 'active' AND
        (NEW.observed_at_ms != OLD.observed_at_ms OR NEW.expires_at_ms != OLD.expires_at_ms))
BEGIN
    SELECT RAISE(ABORT,'invalid read lease transition');
END;

CREATE TRIGGER read_lease_clock_monotonic BEFORE UPDATE ON read_lease_clock
WHEN NEW.observed_at_ms < OLD.observed_at_ms BEGIN
    SELECT RAISE(ABORT,'read lease clock moved backwards');
END;

PRAGMA user_version = 8;
