CREATE TABLE gc_execution_deletions (
    execution_id TEXT PRIMARY KEY REFERENCES gc_disposals(execution_id),
    deleted_at_watermark_ms INTEGER NOT NULL CHECK (deleted_at_watermark_ms>=0)
) STRICT;
CREATE TRIGGER gc_execution_deletion_admission BEFORE INSERT ON gc_execution_deletions
WHEN EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=NEW.execution_id)
OR NOT EXISTS (SELECT 1 FROM gc_disposals d JOIN gc_quarantines q USING(execution_id)
    JOIN gc_clock c ON c.singleton=1 WHERE d.execution_id=NEW.execution_id
    AND q.state='quarantined' AND d.admitted_at_ms<=NEW.deleted_at_watermark_ms
    AND c.observed_at_ms=NEW.deleted_at_watermark_ms
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=d.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_disposal_restorations WHERE execution_id=d.execution_id))
BEGIN SELECT RAISE(ABORT,'invalid GC deletion terminal'); END;
CREATE TRIGGER gc_execution_deletion_immutable BEFORE UPDATE ON gc_execution_deletions
BEGIN SELECT RAISE(ABORT,'GC deletion terminal is immutable'); END;
CREATE TRIGGER gc_execution_deletion_no_delete BEFORE DELETE ON gc_execution_deletions
BEGIN SELECT RAISE(ABORT,'GC deletion terminal cannot be deleted'); END;
CREATE TRIGGER gc_execution_deleted_no_abort BEFORE INSERT ON gc_execution_aborts
WHEN EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=NEW.execution_id)
BEGIN SELECT RAISE(ABORT,'deleted GC execution cannot abort'); END;
CREATE TRIGGER gc_deleted_quarantine_immutable BEFORE UPDATE ON gc_quarantines
WHEN EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=OLD.execution_id)
BEGIN SELECT RAISE(ABORT,'deleted GC quarantine is terminal'); END;
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
    AND NOT EXISTS (SELECT 1 FROM read_lease_objects WHERE content_id=NEW.content_id))
BEGIN SELECT RAISE(ABORT,'invalid GC execution admission'); END;
DROP TRIGGER gc_execution_snapshot_insert;
CREATE TRIGGER gc_execution_snapshot_insert BEFORE INSERT ON snapshot_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
DROP TRIGGER gc_execution_snapshot_update;
CREATE TRIGGER gc_execution_snapshot_update BEFORE UPDATE ON snapshot_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
DROP TRIGGER gc_execution_publication_insert;
CREATE TRIGGER gc_execution_publication_insert BEFORE INSERT ON publication_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
DROP TRIGGER gc_execution_publication_update;
CREATE TRIGGER gc_execution_publication_update BEFORE UPDATE ON publication_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
DROP TRIGGER gc_execution_mutation_insert;
CREATE TRIGGER gc_execution_mutation_insert BEFORE INSERT ON mutation_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
DROP TRIGGER gc_execution_mutation_update;
CREATE TRIGGER gc_execution_mutation_update BEFORE UPDATE ON mutation_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
DROP TRIGGER gc_execution_mark_insert;
CREATE TRIGGER gc_execution_mark_insert BEFORE INSERT ON gc_marks
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
DROP TRIGGER gc_execution_lease_insert;
CREATE TRIGGER gc_execution_lease_insert BEFORE INSERT ON read_lease_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
DROP TRIGGER gc_execution_lease_update;
CREATE TRIGGER gc_execution_lease_update BEFORE UPDATE ON read_lease_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
PRAGMA user_version=15;
