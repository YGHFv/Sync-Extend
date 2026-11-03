CREATE TABLE tree_restore_histories (
    transaction_id TEXT PRIMARY KEY REFERENCES tree_restore_preparations(transaction_id),
    preparation_hash TEXT NOT NULL,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    projection_hash TEXT NOT NULL,
    final_snapshot_id TEXT NOT NULL,
    origin_device_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>=0),
    first_seq INTEGER NOT NULL CHECK (first_seq>0),
    last_seq INTEGER NOT NULL CHECK (last_seq>=first_seq),
    reserved_rows INTEGER NOT NULL CHECK (reserved_rows>=5),
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes>0),
    CHECK (length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    CHECK (length(transaction_id)=32 AND length(preparation_hash)=64
        AND length(intent_hash)=64 AND length(projection_hash)=64
        AND length(final_snapshot_id)=64 AND length(origin_device_id)=64)
) STRICT;

CREATE TRIGGER tree_restore_history_insert BEFORE INSERT ON tree_restore_histories
WHEN EXISTS (SELECT 1 FROM tree_restore_histories WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS (SELECT 1 FROM tree_restore_preparations p
    JOIN current_manifests c ON c.space_id=p.space_id AND c.snapshot_id=p.baseline_root
    WHERE p.transaction_id=NEW.transaction_id AND p.intent_hash=NEW.preparation_hash
    AND p.prepared_at_ms<=NEW.created_at_ms AND p.step_count>0
    AND p.step_count=NEW.last_seq-NEW.first_seq+1
    AND NEW.final_snapshot_id NOT IN (p.baseline_root,p.target_root)
    AND NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
OR NOT EXISTS (SELECT 1 FROM local_state WHERE key='device_id' AND value=NEW.origin_device_id)
OR EXISTS (SELECT 1 FROM snapshots WHERE snapshot_id=NEW.final_snapshot_id)
OR json_extract(NEW.intent,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.preparation_hash') IS NOT NEW.preparation_hash
OR json_extract(NEW.intent,'$.history.format_version') IS NOT 1
OR json_extract(NEW.intent,'$.history.origin_device_id') IS NOT NEW.origin_device_id
OR json_extract(NEW.intent,'$.history.created_at_ms') IS NOT NEW.created_at_ms
OR json_type(NEW.intent,'$.history.fresh_entry_ids') IS NOT 'object'
BEGIN SELECT RAISE(ABORT,'invalid tree restore history reservation'); END;
CREATE TRIGGER tree_restore_history_immutable BEFORE UPDATE ON tree_restore_histories
BEGIN SELECT RAISE(ABORT,'tree restore history is immutable'); END;
CREATE TRIGGER tree_restore_history_no_delete BEFORE DELETE ON tree_restore_histories
BEGIN SELECT RAISE(ABORT,'tree restore history is single use'); END;

CREATE TRIGGER tree_restore_history_cancel_time BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS (SELECT 1 FROM tree_restore_histories
    WHERE transaction_id=NEW.transaction_id AND created_at_ms>NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'tree restore cancellation precedes history reservation'); END;

PRAGMA user_version=22;
