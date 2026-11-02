CREATE TABLE gc_marks (
    mark_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    content_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    marked_at_ms INTEGER NOT NULL CHECK (marked_at_ms >= 0),
    grace_until_ms INTEGER NOT NULL CHECK (grace_until_ms > marked_at_ms)
) STRICT;
CREATE TABLE gc_cancellations (
    mark_id TEXT PRIMARY KEY REFERENCES gc_marks(mark_id),
    cancelled_at_ms INTEGER NOT NULL CHECK (cancelled_at_ms >= 0)
) STRICT;
CREATE TABLE gc_invalidations (
    mark_id TEXT PRIMARY KEY REFERENCES gc_marks(mark_id)
) STRICT;
CREATE TABLE gc_clock (
    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0)
) STRICT;

CREATE INDEX gc_marks_by_content ON gc_marks(content_id);
CREATE INDEX gc_snapshot_content ON snapshot_objects(content_id);
CREATE INDEX gc_publication_content ON publication_objects(content_id);
CREATE INDEX gc_mutation_content ON mutation_objects(content_id);
CREATE INDEX gc_lease_content ON read_lease_objects(content_id);

CREATE TRIGGER gc_mark_admission BEFORE INSERT ON gc_marks
WHEN EXISTS (SELECT 1 FROM gc_marks WHERE mark_id=NEW.mark_id)
OR NEW.space_id != (SELECT value FROM local_state WHERE key='space_id')
OR NOT EXISTS (SELECT 1 FROM local_state WHERE key='space_id')
OR EXISTS (SELECT 1 FROM gc_marks m
    WHERE m.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id)
    AND NOT EXISTS (SELECT 1 FROM gc_invalidations WHERE mark_id=m.mark_id))
OR EXISTS (SELECT 1 FROM snapshot_objects WHERE content_id=NEW.content_id)
OR EXISTS (SELECT 1 FROM publication_objects WHERE content_id=NEW.content_id)
OR EXISTS (SELECT 1 FROM mutation_objects WHERE content_id=NEW.content_id)
OR EXISTS (SELECT 1 FROM read_lease_objects WHERE content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'invalid GC mark admission'); END;
CREATE TRIGGER gc_mark_immutable BEFORE UPDATE ON gc_marks
BEGIN SELECT RAISE(ABORT,'GC mark is immutable'); END;
CREATE TRIGGER gc_mark_no_delete BEFORE DELETE ON gc_marks
BEGIN SELECT RAISE(ABORT,'GC mark cannot be deleted'); END;

CREATE TRIGGER gc_cancel_admission BEFORE INSERT ON gc_cancellations
WHEN EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=NEW.mark_id)
OR NOT EXISTS (SELECT 1 FROM gc_marks
    WHERE mark_id=NEW.mark_id AND marked_at_ms<=NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'invalid GC cancellation'); END;
CREATE TRIGGER gc_cancel_immutable BEFORE UPDATE ON gc_cancellations
BEGIN SELECT RAISE(ABORT,'GC cancellation is immutable'); END;
CREATE TRIGGER gc_cancel_no_delete BEFORE DELETE ON gc_cancellations
BEGIN SELECT RAISE(ABORT,'GC cancellation cannot be deleted'); END;
CREATE TRIGGER gc_invalidation_immutable BEFORE UPDATE ON gc_invalidations
BEGIN SELECT RAISE(ABORT,'GC invalidation is immutable'); END;
CREATE TRIGGER gc_invalidation_no_delete BEFORE DELETE ON gc_invalidations
BEGIN SELECT RAISE(ABORT,'GC invalidation cannot be deleted'); END;
CREATE TRIGGER gc_clock_no_replace BEFORE INSERT ON gc_clock
WHEN EXISTS (SELECT 1 FROM gc_clock)
BEGIN SELECT RAISE(ABORT,'GC clock cannot be replaced'); END;
CREATE TRIGGER gc_clock_monotonic BEFORE UPDATE ON gc_clock
WHEN NEW.singleton!=OLD.singleton OR NEW.observed_at_ms<OLD.observed_at_ms
BEGIN SELECT RAISE(ABORT,'GC clock moved backward'); END;
CREATE TRIGGER gc_clock_no_delete BEFORE DELETE ON gc_clock
BEGIN SELECT RAISE(ABORT,'GC clock cannot be deleted'); END;

CREATE TRIGGER gc_snapshot_pin_insert AFTER INSERT ON snapshot_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m
    WHERE content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
CREATE TRIGGER gc_snapshot_pin_update AFTER UPDATE ON snapshot_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m
    WHERE content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
CREATE TRIGGER gc_publication_pin_insert AFTER INSERT ON publication_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m
    WHERE content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
CREATE TRIGGER gc_publication_pin_update AFTER UPDATE ON publication_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m
    WHERE content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
CREATE TRIGGER gc_mutation_pin_insert AFTER INSERT ON mutation_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m
    WHERE content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
CREATE TRIGGER gc_mutation_pin_update AFTER UPDATE ON mutation_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m
    WHERE content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
CREATE TRIGGER gc_lease_pin_insert AFTER INSERT ON read_lease_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m
    WHERE content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
CREATE TRIGGER gc_lease_pin_update AFTER UPDATE ON read_lease_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m
    WHERE content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
PRAGMA user_version = 10;
