CREATE TABLE tree_restore_native_reservations (
    transaction_id TEXT PRIMARY KEY REFERENCES tree_restore_preparations(transaction_id),
    preparation_hash TEXT NOT NULL,
    history_intent_hash TEXT NOT NULL,
    history_projection_hash TEXT NOT NULL,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    identity_fingerprint TEXT NOT NULL,
    captured_at_ms INTEGER NOT NULL CHECK (captured_at_ms>=0),
    binding_count INTEGER NOT NULL CHECK (binding_count>=3),
    reserved_rows INTEGER NOT NULL CHECK (reserved_rows=1),
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes>384),
    CHECK (length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    CHECK (length(transaction_id)=32 AND length(preparation_hash)=64
        AND length(history_intent_hash)=64 AND length(history_projection_hash)=64
        AND length(intent_hash)=64 AND length(identity_fingerprint)=64)
) STRICT;

CREATE TRIGGER tree_restore_native_insert BEFORE INSERT ON tree_restore_native_reservations
WHEN EXISTS (SELECT 1 FROM tree_restore_native_reservations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS (SELECT 1 FROM tree_restore_preparations p
    JOIN tree_restore_histories h USING(transaction_id)
    JOIN current_manifests c ON c.space_id=p.space_id AND c.snapshot_id=p.baseline_root
    WHERE p.transaction_id=NEW.transaction_id
    AND p.intent_hash=NEW.preparation_hash AND h.preparation_hash=NEW.preparation_hash
    AND h.intent_hash=NEW.history_intent_hash AND h.projection_hash=NEW.history_projection_hash
    AND h.created_at_ms<=NEW.captured_at_ms
    AND NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
OR json_extract(NEW.intent,'$.request.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.request.preparation_hash') IS NOT NEW.preparation_hash
OR json_extract(NEW.intent,'$.request.history_intent_hash') IS NOT NEW.history_intent_hash
OR json_extract(NEW.intent,'$.request.history_projection_hash') IS NOT NEW.history_projection_hash
OR json_extract(NEW.intent,'$.request.captured_at_ms') IS NOT NEW.captured_at_ms
OR json_extract(NEW.intent,'$.inventory.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.inventory.preparation_hash') IS NOT NEW.preparation_hash
OR json_type(NEW.intent,'$.inventory.entries') IS NOT 'object'
BEGIN SELECT RAISE(ABORT,'invalid tree restore native description reservation'); END;
CREATE TRIGGER tree_restore_native_immutable BEFORE UPDATE ON tree_restore_native_reservations
BEGIN SELECT RAISE(ABORT,'tree restore native description is immutable'); END;
CREATE TRIGGER tree_restore_native_no_delete BEFORE DELETE ON tree_restore_native_reservations
BEGIN SELECT RAISE(ABORT,'tree restore native description is single use'); END;
CREATE TRIGGER tree_restore_native_cancel_time BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS (SELECT 1 FROM tree_restore_native_reservations
    WHERE transaction_id=NEW.transaction_id AND captured_at_ms>NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'tree restore cancellation precedes native description'); END;

PRAGMA user_version=23;
