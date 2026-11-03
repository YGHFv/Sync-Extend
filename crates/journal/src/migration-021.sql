CREATE TABLE tree_restore_preparations (
    transaction_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    baseline_root TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    target_root TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    prepared_at_ms INTEGER NOT NULL CHECK (prepared_at_ms>=0),
    step_count INTEGER NOT NULL CHECK (step_count BETWEEN 0 AND 1000000),
    reserved_rows INTEGER NOT NULL CHECK (reserved_rows>=2+3*step_count),
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes>=4096+4096*step_count),
    CHECK (length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    CHECK (length(transaction_id)=32 AND length(space_id)=32 AND length(baseline_root)=64
        AND length(target_root)=64 AND length(intent_hash)=64)
) STRICT;
CREATE TABLE tree_restore_steps (
    transaction_id TEXT NOT NULL REFERENCES tree_restore_preparations(transaction_id),
    step_index INTEGER NOT NULL CHECK (step_index>=0),
    step TEXT NOT NULL,
    step_hash TEXT NOT NULL,
    PRIMARY KEY(transaction_id,step_index),
    CHECK (length(CAST(step AS BLOB)) BETWEEN 1 AND 16777216),
    CHECK (length(transaction_id)=32 AND length(step_hash)=64)
) STRICT;
CREATE TABLE tree_restore_objects (
    transaction_id TEXT NOT NULL REFERENCES tree_restore_preparations(transaction_id),
    content_id TEXT NOT NULL,
    length INTEGER NOT NULL CHECK (length BETWEEN 1 AND 4194304),
    PRIMARY KEY(transaction_id,content_id),
    CHECK (length(transaction_id)=32 AND length(content_id)=64)
) STRICT;
CREATE INDEX tree_restore_content ON tree_restore_objects(content_id);
CREATE TABLE tree_restore_cancellations (
    transaction_id TEXT PRIMARY KEY REFERENCES tree_restore_preparations(transaction_id),
    intent_hash TEXT NOT NULL,
    cancelled_at_ms INTEGER NOT NULL CHECK (cancelled_at_ms>=0),
    CHECK (length(transaction_id)=32 AND length(intent_hash)=64)
) STRICT;

CREATE TRIGGER tree_restore_preparation_admission BEFORE INSERT ON tree_restore_preparations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations WHERE transaction_id=NEW.transaction_id)
OR EXISTS (SELECT 1 FROM tree_restore_preparations p WHERE p.space_id=NEW.space_id
    AND NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
OR NOT EXISTS (SELECT 1 FROM local_state WHERE key='space_id' AND value=NEW.space_id)
OR json_extract(NEW.intent,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.scope.format_version') IS NOT 1
OR json_extract(NEW.intent,'$.scope.space_id') IS NOT NEW.space_id
OR json_extract(NEW.intent,'$.scope.baseline_snapshot') IS NOT NEW.baseline_root
OR json_extract(NEW.intent,'$.scope.target_snapshot') IS NOT NEW.target_root
OR json_extract(NEW.intent,'$.prepared_at_ms') IS NOT NEW.prepared_at_ms
OR EXISTS (SELECT 1 FROM publications WHERE space_id=NEW.space_id AND (state!='committed' OR cleaned=0))
OR EXISTS (SELECT 1 FROM mutations WHERE space_id=NEW.space_id
    AND state IN ('prepared','executing','quarantined','moved','replaced'))
OR EXISTS (SELECT 1 FROM cleanup_plans WHERE space_id=NEW.space_id AND state='executing')
OR NOT EXISTS (SELECT 1 FROM snapshots b JOIN snapshots t ON t.snapshot_id=NEW.target_root
    JOIN current_manifests c ON c.space_id=NEW.space_id
    WHERE b.snapshot_id=NEW.baseline_root AND c.snapshot_id=b.snapshot_id
    AND b.space_id=NEW.space_id AND t.space_id=NEW.space_id
    AND b.state='materialized' AND t.state='materialized'
    AND b.created_at_ms<=NEW.prepared_at_ms AND t.created_at_ms<=NEW.prepared_at_ms
    AND NOT EXISTS (SELECT 1 FROM snapshot_prunings
        WHERE snapshot_id IN (NEW.baseline_root,NEW.target_root)))
BEGIN SELECT RAISE(ABORT,'invalid tree restore preparation'); END;
CREATE TRIGGER tree_restore_preparation_immutable BEFORE UPDATE ON tree_restore_preparations
BEGIN SELECT RAISE(ABORT,'tree restore preparation is immutable'); END;
CREATE TRIGGER tree_restore_preparation_no_delete BEFORE DELETE ON tree_restore_preparations
BEGIN SELECT RAISE(ABORT,'tree restore transaction is single use'); END;

CREATE TRIGGER tree_restore_step_admission BEFORE INSERT ON tree_restore_steps
WHEN EXISTS (SELECT 1 FROM tree_restore_steps
    WHERE transaction_id=NEW.transaction_id AND step_index=NEW.step_index)
OR NOT EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE p.transaction_id=NEW.transaction_id AND NEW.step_index<p.step_count
    AND NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
OR json_extract(NEW.step,'$.index') IS NOT NEW.step_index
OR json_type(NEW.step,'$.dependencies') IS NOT 'array'
OR EXISTS (SELECT 1 FROM json_each(NEW.step,'$.dependencies')
    WHERE type!='integer' OR value<0 OR value>=NEW.step_index)
BEGIN SELECT RAISE(ABORT,'invalid tree restore step'); END;
CREATE TRIGGER tree_restore_step_immutable BEFORE UPDATE ON tree_restore_steps
BEGIN SELECT RAISE(ABORT,'tree restore step is immutable'); END;
CREATE TRIGGER tree_restore_step_no_delete BEFORE DELETE ON tree_restore_steps
BEGIN SELECT RAISE(ABORT,'tree restore step is single use'); END;

CREATE TRIGGER tree_restore_pin_admission BEFORE INSERT ON tree_restore_objects
WHEN EXISTS (SELECT 1 FROM tree_restore_objects
    WHERE transaction_id=NEW.transaction_id AND content_id=NEW.content_id)
OR EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS (SELECT 1 FROM tree_restore_preparations p
    JOIN snapshot_objects o ON o.snapshot_id IN (p.baseline_root,p.target_root)
    WHERE p.transaction_id=NEW.transaction_id
    AND o.content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'invalid tree restore pin'); END;
CREATE TRIGGER tree_restore_pin_immutable BEFORE UPDATE ON tree_restore_objects
BEGIN SELECT RAISE(ABORT,'tree restore pins are immutable'); END;
CREATE TRIGGER tree_restore_pin_release BEFORE DELETE ON tree_restore_objects
WHEN NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=OLD.transaction_id)
BEGIN SELECT RAISE(ABORT,'active tree restore pins cannot be released'); END;
CREATE TRIGGER tree_restore_pin_gc_fence BEFORE INSERT ON tree_restore_objects
WHEN EXISTS (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER tree_restore_pin_invalidate AFTER INSERT ON tree_restore_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m
    WHERE content_id=NEW.content_id
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
CREATE TRIGGER tree_restore_gc_mark_fence BEFORE INSERT ON gc_marks
WHEN EXISTS (SELECT 1 FROM tree_restore_objects WHERE content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'object pinned by tree restore'); END;
CREATE TRIGGER tree_restore_gc_execution_fence BEFORE INSERT ON gc_executions
WHEN EXISTS (SELECT 1 FROM tree_restore_objects WHERE content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'object pinned by tree restore'); END;

CREATE TRIGGER tree_restore_cancel_admission BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE p.transaction_id=NEW.transaction_id AND p.intent_hash=NEW.intent_hash
    AND p.prepared_at_ms<=NEW.cancelled_at_ms
    AND p.step_count=(SELECT count(*) FROM tree_restore_steps WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'invalid tree restore cancellation'); END;
CREATE TRIGGER tree_restore_cancel_immutable BEFORE UPDATE ON tree_restore_cancellations
BEGIN SELECT RAISE(ABORT,'tree restore cancellation is immutable'); END;
CREATE TRIGGER tree_restore_cancel_no_delete BEFORE DELETE ON tree_restore_cancellations
BEGIN SELECT RAISE(ABORT,'tree restore cancellation is terminal'); END;

CREATE TRIGGER tree_restore_snapshot_pruning_fence BEFORE INSERT ON snapshot_prunings
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NEW.snapshot_id IN (p.baseline_root,p.target_root)
    AND NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'snapshot pinned by tree restore'); END;
CREATE TRIGGER tree_restore_snapshot_immutable BEFORE UPDATE OF snapshot_id,space_id,manifest,created_at_ms,state ON snapshots
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations
    WHERE OLD.snapshot_id IN (baseline_root,target_root) OR NEW.snapshot_id IN (baseline_root,target_root))
BEGIN SELECT RAISE(ABORT,'tree restore input metadata is immutable'); END;
CREATE TRIGGER tree_restore_snapshot_no_replace BEFORE INSERT ON snapshots
WHEN EXISTS (SELECT 1 FROM snapshots WHERE snapshot_id=NEW.snapshot_id)
AND EXISTS (SELECT 1 FROM tree_restore_preparations WHERE NEW.snapshot_id IN (baseline_root,target_root))
BEGIN SELECT RAISE(ABORT,'tree restore input cannot be replaced'); END;
CREATE TRIGGER tree_restore_snapshot_no_delete BEFORE DELETE ON snapshots
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations WHERE OLD.snapshot_id IN (baseline_root,target_root))
BEGIN SELECT RAISE(ABORT,'tree restore input cannot be deleted'); END;

CREATE TRIGGER tree_restore_writer_publications_insert BEFORE INSERT ON publications
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_publications_update BEFORE UPDATE ON publications
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_publications_delete BEFORE DELETE ON publications
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_mutations_insert BEFORE INSERT ON mutations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_mutations_update BEFORE UPDATE ON mutations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_mutations_delete BEFORE DELETE ON mutations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_current_manifests_insert BEFORE INSERT ON current_manifests
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_current_manifests_update BEFORE UPDATE ON current_manifests
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_current_manifests_delete BEFORE DELETE ON current_manifests
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_operations_insert BEFORE INSERT ON operations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_operations_update BEFORE UPDATE ON operations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_operations_delete BEFORE DELETE ON operations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_receive_cursors_insert BEFORE INSERT ON receive_cursors
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_receive_cursors_update BEFORE UPDATE ON receive_cursors
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_receive_cursors_delete BEFORE DELETE ON receive_cursors
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_local_state_insert BEFORE INSERT ON local_state
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_local_state_update BEFORE UPDATE ON local_state
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_local_state_delete BEFORE DELETE ON local_state
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_rename_observations_insert BEFORE INSERT ON rename_observations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_rename_observations_update BEFORE UPDATE ON rename_observations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_rename_observations_delete BEFORE DELETE ON rename_observations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_cleanup_plans_insert BEFORE INSERT ON cleanup_plans
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_cleanup_plans_update BEFORE UPDATE ON cleanup_plans
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_cleanup_plans_delete BEFORE DELETE ON cleanup_plans
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_original_disposals_insert BEFORE INSERT ON original_disposals
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_original_disposals_update BEFORE UPDATE ON original_disposals
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_original_disposals_delete BEFORE DELETE ON original_disposals
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_original_disposal_completions_insert BEFORE INSERT ON original_disposal_completions
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_original_disposal_completions_update BEFORE UPDATE ON original_disposal_completions
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_original_disposal_completions_delete BEFORE DELETE ON original_disposal_completions
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

CREATE TRIGGER tree_restore_writer_snapshots_insert BEFORE INSERT ON snapshots
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

PRAGMA user_version=21;
