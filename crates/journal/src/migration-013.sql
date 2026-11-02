CREATE TABLE gc_quarantines (
    execution_id TEXT PRIMARY KEY REFERENCES gc_executions(execution_id),
    plan_id TEXT NOT NULL UNIQUE,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared','quarantined','restore_pending','restored'))
) STRICT;
CREATE TRIGGER gc_quarantine_admission BEFORE INSERT ON gc_quarantines
WHEN NEW.state!='prepared'
OR EXISTS (SELECT 1 FROM gc_quarantines WHERE execution_id=NEW.execution_id OR plan_id=NEW.plan_id)
OR NOT EXISTS (SELECT 1 FROM gc_executions e WHERE e.execution_id=NEW.execution_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'invalid GC quarantine admission'); END;
CREATE TRIGGER gc_quarantine_transition BEFORE UPDATE ON gc_quarantines
WHEN NEW.execution_id!=OLD.execution_id OR NEW.plan_id!=OLD.plan_id
OR NEW.intent!=OLD.intent OR NEW.intent_hash!=OLD.intent_hash
OR NOT ((OLD.state='prepared' AND NEW.state IN ('quarantined','restore_pending'))
    OR (OLD.state='quarantined' AND NEW.state='restore_pending')
    OR (OLD.state='restore_pending' AND NEW.state='restored'))
BEGIN SELECT RAISE(ABORT,'invalid GC quarantine transition'); END;
CREATE TRIGGER gc_quarantine_no_delete BEFORE DELETE ON gc_quarantines
BEGIN SELECT RAISE(ABORT,'GC quarantine cannot be deleted'); END;
CREATE TRIGGER gc_execution_physical_abort BEFORE INSERT ON gc_execution_aborts
WHEN EXISTS (SELECT 1 FROM gc_quarantines WHERE execution_id=NEW.execution_id AND state!='restored')
BEGIN SELECT RAISE(ABORT,'GC quarantine requires guarded restoration'); END;
PRAGMA user_version=13;
