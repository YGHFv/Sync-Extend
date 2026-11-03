CREATE TABLE original_disposal_completions (
    transaction_id TEXT PRIMARY KEY REFERENCES original_disposals(transaction_id),
    plan_id TEXT NOT NULL UNIQUE CHECK (length(CAST(plan_id AS BLOB))=32),
    intent_hash TEXT NOT NULL CHECK (length(CAST(intent_hash AS BLOB))=64),
    completed_at_ms INTEGER NOT NULL CHECK (completed_at_ms>=0)
) STRICT;

CREATE TRIGGER original_completion_admission BEFORE INSERT ON original_disposal_completions
WHEN EXISTS (SELECT 1 FROM original_disposal_completions
    WHERE transaction_id=NEW.transaction_id OR plan_id=NEW.plan_id)
OR NOT EXISTS (SELECT 1 FROM original_disposals p
    WHERE p.transaction_id=NEW.transaction_id AND p.plan_id=NEW.plan_id
    AND p.intent_hash=NEW.intent_hash AND p.prepared_at_ms<=NEW.completed_at_ms)
BEGIN SELECT RAISE(ABORT,'invalid original disposal completion'); END;

CREATE TRIGGER original_completion_immutable BEFORE UPDATE ON original_disposal_completions
BEGIN SELECT RAISE(ABORT,'original completion is immutable'); END;
CREATE TRIGGER original_completion_no_delete BEFORE DELETE ON original_disposal_completions
BEGIN SELECT RAISE(ABORT,'original completion is terminal'); END;

PRAGMA user_version=20;
