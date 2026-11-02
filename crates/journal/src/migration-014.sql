CREATE TABLE gc_disposals (
    execution_id TEXT PRIMARY KEY REFERENCES gc_quarantines(execution_id),
    disposal_id TEXT NOT NULL UNIQUE,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    admitted_at_ms INTEGER NOT NULL CHECK (admitted_at_ms>=0)
) STRICT;
CREATE TABLE gc_disposal_restorations (
    execution_id TEXT PRIMARY KEY REFERENCES gc_disposals(execution_id),
    restored_at_watermark_ms INTEGER NOT NULL CHECK (restored_at_watermark_ms>=0)
) STRICT;
CREATE TRIGGER gc_disposal_admission BEFORE INSERT ON gc_disposals
WHEN EXISTS (SELECT 1 FROM gc_disposals WHERE execution_id=NEW.execution_id OR disposal_id=NEW.disposal_id)
OR NOT EXISTS (SELECT 1 FROM gc_quarantines q JOIN gc_executions e USING(execution_id)
    JOIN gc_authorizations a USING(authorization_id) JOIN gc_marks m USING(mark_id)
    JOIN gc_clock c ON c.singleton=1
    WHERE q.execution_id=NEW.execution_id AND q.state='quarantined'
    AND e.admitted_at_ms<=NEW.admitted_at_ms AND NEW.admitted_at_ms<a.expires_at_ms
    AND c.observed_at_ms=NEW.admitted_at_ms
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_revocations WHERE authorization_id=a.authorization_id)
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id)
    AND NOT EXISTS (SELECT 1 FROM gc_invalidations WHERE mark_id=m.mark_id)
    AND NOT EXISTS (SELECT 1 FROM snapshot_objects WHERE content_id=e.content_id)
    AND NOT EXISTS (SELECT 1 FROM publication_objects WHERE content_id=e.content_id)
    AND NOT EXISTS (SELECT 1 FROM mutation_objects WHERE content_id=e.content_id)
    AND NOT EXISTS (SELECT 1 FROM read_lease_objects WHERE content_id=e.content_id))
BEGIN SELECT RAISE(ABORT,'invalid GC disposal admission'); END;
CREATE TRIGGER gc_disposal_immutable BEFORE UPDATE ON gc_disposals
BEGIN SELECT RAISE(ABORT,'GC disposal is immutable'); END;
CREATE TRIGGER gc_disposal_no_delete BEFORE DELETE ON gc_disposals
BEGIN SELECT RAISE(ABORT,'GC disposal cannot be deleted'); END;
CREATE TRIGGER gc_disposal_restoration_admission BEFORE INSERT ON gc_disposal_restorations
WHEN EXISTS (SELECT 1 FROM gc_disposal_restorations WHERE execution_id=NEW.execution_id)
OR NOT EXISTS (SELECT 1 FROM gc_disposals d JOIN gc_quarantines q USING(execution_id)
    JOIN gc_execution_aborts b USING(execution_id) JOIN gc_clock c ON c.singleton=1
    WHERE d.execution_id=NEW.execution_id AND q.state='restored'
    AND d.admitted_at_ms<=NEW.restored_at_watermark_ms
    AND b.aborted_at_watermark_ms=NEW.restored_at_watermark_ms
    AND c.observed_at_ms=NEW.restored_at_watermark_ms)
BEGIN SELECT RAISE(ABORT,'invalid GC disposal restoration'); END;
CREATE TRIGGER gc_disposal_restoration_immutable BEFORE UPDATE ON gc_disposal_restorations
BEGIN SELECT RAISE(ABORT,'GC disposal restoration is immutable'); END;
CREATE TRIGGER gc_disposal_restoration_no_delete BEFORE DELETE ON gc_disposal_restorations
BEGIN SELECT RAISE(ABORT,'GC disposal restoration cannot be deleted'); END;
PRAGMA user_version=14;
