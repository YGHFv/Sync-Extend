CREATE TABLE gc_executions (
    execution_id TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL UNIQUE REFERENCES gc_authorizations(authorization_id),
    content_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    admitted_at_ms INTEGER NOT NULL CHECK (admitted_at_ms>=0)
) STRICT;
CREATE TABLE gc_execution_aborts (
    execution_id TEXT PRIMARY KEY REFERENCES gc_executions(execution_id),
    aborted_at_watermark_ms INTEGER NOT NULL CHECK (aborted_at_watermark_ms>=0)
) STRICT;
CREATE INDEX gc_executions_content ON gc_executions(content_id);

CREATE TRIGGER gc_execution_admission BEFORE INSERT ON gc_executions
WHEN EXISTS (SELECT 1 FROM gc_executions
    WHERE execution_id=NEW.execution_id OR authorization_id=NEW.authorization_id)
OR EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
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
CREATE TRIGGER gc_execution_immutable BEFORE UPDATE ON gc_executions
BEGIN SELECT RAISE(ABORT,'GC execution is immutable'); END;
CREATE TRIGGER gc_execution_no_delete BEFORE DELETE ON gc_executions
BEGIN SELECT RAISE(ABORT,'GC execution cannot be deleted'); END;
CREATE TRIGGER gc_execution_abort_admission BEFORE INSERT ON gc_execution_aborts
WHEN EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=NEW.execution_id)
OR NOT EXISTS (SELECT 1 FROM gc_executions e JOIN gc_clock c ON c.singleton=1
    WHERE e.execution_id=NEW.execution_id AND e.admitted_at_ms<=NEW.aborted_at_watermark_ms
    AND c.observed_at_ms=NEW.aborted_at_watermark_ms)
BEGIN SELECT RAISE(ABORT,'invalid GC execution abort'); END;
CREATE TRIGGER gc_execution_abort_immutable BEFORE UPDATE ON gc_execution_aborts
BEGIN SELECT RAISE(ABORT,'GC execution abort is immutable'); END;
CREATE TRIGGER gc_execution_abort_no_delete BEFORE DELETE ON gc_execution_aborts
BEGIN SELECT RAISE(ABORT,'GC execution abort cannot be deleted'); END;

CREATE TRIGGER gc_execution_snapshot_insert BEFORE INSERT ON snapshot_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER gc_execution_snapshot_update BEFORE UPDATE ON snapshot_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER gc_execution_publication_insert BEFORE INSERT ON publication_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER gc_execution_publication_update BEFORE UPDATE ON publication_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER gc_execution_mutation_insert BEFORE INSERT ON mutation_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER gc_execution_mutation_update BEFORE UPDATE ON mutation_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER gc_execution_mark_insert BEFORE INSERT ON gc_marks
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER gc_execution_lease_insert BEFORE INSERT ON read_lease_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER gc_execution_lease_update BEFORE UPDATE ON read_lease_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
PRAGMA user_version=12;
