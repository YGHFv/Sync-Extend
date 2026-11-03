CREATE TABLE original_disposals (
    transaction_id TEXT PRIMARY KEY REFERENCES mutations(transaction_id),
    execution_id TEXT NOT NULL UNIQUE,
    plan_id TEXT NOT NULL UNIQUE,
    space_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    prepared_at_ms INTEGER NOT NULL CHECK (prepared_at_ms>=0),
    CHECK (length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216)
) STRICT;

CREATE TRIGGER original_disposal_admission BEFORE INSERT ON original_disposals
WHEN EXISTS (SELECT 1 FROM original_disposals
    WHERE transaction_id=NEW.transaction_id OR execution_id=NEW.execution_id
    OR plan_id=NEW.plan_id)
OR NOT EXISTS (SELECT 1 FROM local_state WHERE key='space_id' AND value=NEW.space_id)
OR json_extract(NEW.intent,'$.plan_id') IS NOT NEW.plan_id
OR json_extract(NEW.intent,'$.scope.format_version') IS NOT 1
OR json_extract(NEW.intent,'$.scope.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.scope.execution_id') IS NOT NEW.execution_id
OR json_extract(NEW.intent,'$.scope.space_id') IS NOT NEW.space_id
OR json_extract(NEW.intent,'$.prepared_at_ms') IS NOT NEW.prepared_at_ms
OR json_extract(NEW.intent,'$.original_length') IS NOT json_extract(NEW.intent,'$.scope.content.length')
OR NOT EXISTS (
    SELECT 1 FROM mutations m JOIN snapshots b ON b.snapshot_id=m.baseline_root
    JOIN snapshots c ON c.snapshot_id=m.committed_snapshot
    WHERE m.transaction_id=NEW.transaction_id AND m.space_id=NEW.space_id
    AND b.space_id=NEW.space_id AND c.space_id=NEW.space_id AND m.state='committed'
    AND b.state='materialized' AND c.state='materialized'
    AND m.baseline_root IS NOT m.committed_snapshot
    AND json_extract(m.intent,'$.action.kind') IN ('delete','replace')
    AND json_extract(NEW.intent,'$.scope.action') IS json_extract(m.intent,'$.action.kind')
    AND json_extract(NEW.intent,'$.scope.mutation_intent_hash') IS m.intent_hash
    AND json_extract(NEW.intent,'$.scope.execution_hash') IS m.execution_hash
    AND json_extract(NEW.intent,'$.scope.baseline_snapshot') IS m.baseline_root
    AND json_extract(NEW.intent,'$.scope.committed_snapshot') IS m.committed_snapshot
    AND json_extract(NEW.intent,'$.scope.original_identity') IS json_extract(m.intent,'$.file_identity')
    AND json_extract(NEW.intent,'$.scope.content') IS json_extract(m.intent,'$.baseline_entry.content')
    AND json_extract(m.execution,'$.execution_id') IS NEW.execution_id
    AND json_extract(m.intent,'$.created_at_ms')<=NEW.prepared_at_ms
    AND b.created_at_ms<=NEW.prepared_at_ms AND c.created_at_ms<=NEW.prepared_at_ms
    AND NOT EXISTS (SELECT 1 FROM snapshot_prunings
        WHERE snapshot_id IN (m.baseline_root,m.committed_snapshot))
)
BEGIN SELECT RAISE(ABORT,'invalid committed original preparation'); END;

CREATE TRIGGER original_disposal_immutable BEFORE UPDATE ON original_disposals
BEGIN SELECT RAISE(ABORT,'original preparation is immutable'); END;
CREATE TRIGGER original_disposal_no_delete BEFORE DELETE ON original_disposals
BEGIN SELECT RAISE(ABORT,'original preparation is single use'); END;

PRAGMA user_version=19;
