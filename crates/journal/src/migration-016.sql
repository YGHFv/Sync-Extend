CREATE TABLE reference_reservations (
    owner_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>=0)
) STRICT;
CREATE TABLE reference_reservation_objects (
    owner_id TEXT NOT NULL REFERENCES reference_reservations(owner_id),
    content_id TEXT NOT NULL,
    PRIMARY KEY(owner_id,content_id)
) STRICT;
CREATE INDEX reference_reservation_content ON reference_reservation_objects(content_id);
CREATE TRIGGER reference_reservation_admission BEFORE INSERT ON reference_reservations
WHEN EXISTS (SELECT 1 FROM reference_reservations WHERE owner_id=NEW.owner_id)
OR NOT EXISTS (SELECT 1 FROM local_state WHERE key='space_id' AND value=NEW.space_id)
BEGIN SELECT RAISE(ABORT,'invalid reference reservation admission'); END;
CREATE TRIGGER reference_reservation_immutable BEFORE UPDATE ON reference_reservations
BEGIN SELECT RAISE(ABORT,'reference reservation is immutable'); END;
CREATE TRIGGER reference_reservation_no_delete BEFORE DELETE ON reference_reservations
BEGIN SELECT RAISE(ABORT,'reference reservation release is unavailable'); END;
CREATE TRIGGER reference_reservation_pin_immutable BEFORE UPDATE ON reference_reservation_objects
BEGIN SELECT RAISE(ABORT,'reference reservation pins are immutable'); END;
CREATE TRIGGER reference_reservation_pin_no_delete BEFORE DELETE ON reference_reservation_objects
BEGIN SELECT RAISE(ABORT,'reference reservation release is unavailable'); END;
CREATE TRIGGER reference_reservation_pin_admission BEFORE INSERT ON reference_reservation_objects
WHEN NOT EXISTS (SELECT 1 FROM reference_reservations WHERE owner_id=NEW.owner_id)
OR NOT EXISTS (SELECT 1 FROM reference_reservations o, json_each(o.intent,'$.scope.files') f,
    json_each(f.value,'$.chunks') c WHERE o.owner_id=NEW.owner_id
    AND json_extract(c.value,'$.content_id')=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'invalid reference reservation pin'); END;
CREATE TRIGGER reference_reservation_fence_insert BEFORE INSERT ON reference_reservation_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER reference_reservation_invalidate AFTER INSERT ON reference_reservation_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m
    WHERE content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
CREATE TRIGGER reference_reservation_mark_fence BEFORE INSERT ON gc_marks
WHEN EXISTS (SELECT 1 FROM reference_reservation_objects WHERE content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'object reserved by durable worker'); END;
DROP TRIGGER gc_execution_admission;
CREATE TRIGGER gc_execution_admission BEFORE INSERT ON gc_executions
WHEN EXISTS (SELECT 1 FROM gc_executions
    WHERE execution_id=NEW.execution_id OR authorization_id=NEW.authorization_id)
OR EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
OR NOT EXISTS (SELECT 1 FROM gc_authorizations a JOIN gc_marks m USING(mark_id)
    JOIN gc_clock c ON c.singleton=1
    WHERE a.authorization_id=NEW.authorization_id AND m.content_id=NEW.content_id
    AND a.authorized_at_ms<=NEW.admitted_at_ms AND NEW.admitted_at_ms<a.expires_at_ms
    AND m.grace_until_ms<=NEW.admitted_at_ms AND c.observed_at_ms=NEW.admitted_at_ms
    AND NOT EXISTS (SELECT 1 FROM gc_revocations WHERE authorization_id=a.authorization_id)
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id)
    AND NOT EXISTS (SELECT 1 FROM gc_invalidations WHERE mark_id=m.mark_id)
    AND NOT EXISTS (SELECT 1 FROM snapshot_objects WHERE content_id=NEW.content_id)
    AND NOT EXISTS (SELECT 1 FROM publication_objects WHERE content_id=NEW.content_id)
    AND NOT EXISTS (SELECT 1 FROM mutation_objects WHERE content_id=NEW.content_id)
    AND NOT EXISTS (SELECT 1 FROM read_lease_objects WHERE content_id=NEW.content_id)
    AND NOT EXISTS (SELECT 1 FROM reference_reservation_objects WHERE content_id=NEW.content_id))
BEGIN SELECT RAISE(ABORT,'invalid GC execution admission'); END;
PRAGMA user_version=16;
