-- Immutable coordinator/step descriptions only; no executable admission.
CREATE TABLE tree_restore_execution_intents (
    transaction_id TEXT PRIMARY KEY REFERENCES tree_restore_preparations(transaction_id),
    preparation_hash TEXT NOT NULL,
    history_intent_hash TEXT NOT NULL,
    native_intent_hash TEXT NOT NULL,
    history_projection_hash TEXT NOT NULL,
    native_identity_fingerprint TEXT NOT NULL,
    execution_id TEXT NOT NULL UNIQUE,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    step_count INTEGER NOT NULL CHECK(step_count BETWEEN 1 AND 1000000),
    reserved_rows INTEGER NOT NULL CHECK(reserved_rows=1+step_count),
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>480+168*step_count),
    CHECK(length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    CHECK(length(transaction_id)=32 AND length(execution_id)=32
        AND length(preparation_hash)=64 AND length(history_intent_hash)=64
        AND length(native_intent_hash)=64 AND length(history_projection_hash)=64
        AND length(native_identity_fingerprint)=64 AND length(intent_hash)=64)
) STRICT;
CREATE TABLE tree_restore_execution_step_intents (
    transaction_id TEXT NOT NULL REFERENCES tree_restore_execution_intents(transaction_id),
    step_index INTEGER NOT NULL CHECK(step_index>=0),
    execution_id TEXT NOT NULL UNIQUE,
    coordinator_execution_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    PRIMARY KEY(transaction_id,step_index),
    CHECK(length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    CHECK(length(transaction_id)=32 AND length(execution_id)=32
        AND length(coordinator_execution_id)=32 AND length(intent_hash)=64)
) STRICT;

CREATE TRIGGER tree_execution_intent_insert BEFORE INSERT ON tree_restore_execution_intents
WHEN EXISTS(SELECT 1 FROM tree_restore_execution_intents WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_intents WHERE execution_id=NEW.execution_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents WHERE execution_id=NEW.execution_id)
OR EXISTS(SELECT 1 FROM tree_restore_preparations WHERE transaction_id=NEW.execution_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_preparations p
    JOIN tree_restore_histories h USING(transaction_id)
    JOIN tree_restore_native_reservations n USING(transaction_id)
    JOIN current_manifests c ON c.space_id=p.space_id AND c.snapshot_id=p.baseline_root
    WHERE p.transaction_id=NEW.transaction_id AND p.intent_hash=NEW.preparation_hash
    AND h.intent_hash=NEW.history_intent_hash AND h.projection_hash=NEW.history_projection_hash
    AND n.intent_hash=NEW.native_intent_hash AND n.identity_fingerprint=NEW.native_identity_fingerprint
    AND n.captured_at_ms<=NEW.created_at_ms AND p.step_count=NEW.step_count
    AND NOT EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
OR json_extract(NEW.intent,'$.input.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.input.preparation_hash') IS NOT NEW.preparation_hash
OR json_extract(NEW.intent,'$.input.history_intent_hash') IS NOT NEW.history_intent_hash
OR json_extract(NEW.intent,'$.input.native_intent_hash') IS NOT NEW.native_intent_hash
OR json_extract(NEW.intent,'$.input.history_projection_hash') IS NOT NEW.history_projection_hash
OR json_extract(NEW.intent,'$.input.native_identity_fingerprint') IS NOT NEW.native_identity_fingerprint
OR json_extract(NEW.intent,'$.input.execution_id') IS NOT NEW.execution_id
OR json_extract(NEW.intent,'$.input.created_at_ms') IS NOT NEW.created_at_ms
OR json_type(NEW.intent,'$.steps') IS NOT 'array'
OR json_array_length(NEW.intent,'$.steps') IS NOT NEW.step_count
OR json_type(NEW.intent,'$.input.step_execution_ids') IS NOT 'object'
OR (SELECT count(*) FROM json_each(NEW.intent,'$.input.step_execution_ids')) IS NOT NEW.step_count
OR (SELECT count(DISTINCT value) FROM json_each(NEW.intent,'$.input.step_execution_ids')) IS NOT NEW.step_count
OR EXISTS(SELECT 1 FROM json_each(NEW.intent,'$.input.step_execution_ids') m
    WHERE m.type!='text' OR length(m.value)!=32 OR m.value GLOB '*[^0-9a-f]*'
    OR m.value=NEW.execution_id
    OR EXISTS(SELECT 1 FROM tree_restore_preparations WHERE transaction_id=m.value)
    OR EXISTS(SELECT 1 FROM tree_restore_execution_intents WHERE execution_id=m.value)
    OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents WHERE execution_id=m.value))
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.execution_id GLOB '*[^0-9a-f]*'
OR NEW.preparation_hash GLOB '*[^0-9a-f]*' OR NEW.history_intent_hash GLOB '*[^0-9a-f]*'
OR NEW.native_intent_hash GLOB '*[^0-9a-f]*' OR NEW.history_projection_hash GLOB '*[^0-9a-f]*'
OR NEW.native_identity_fingerprint GLOB '*[^0-9a-f]*' OR NEW.intent_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid descriptive tree execution intent'); END;
CREATE TRIGGER tree_execution_intent_immutable BEFORE UPDATE ON tree_restore_execution_intents
BEGIN SELECT RAISE(ABORT,'descriptive tree execution intent immutable'); END;
CREATE TRIGGER tree_execution_intent_no_delete BEFORE DELETE ON tree_restore_execution_intents
BEGIN SELECT RAISE(ABORT,'descriptive tree execution intent single use'); END;

CREATE TRIGGER tree_execution_step_intent_insert BEFORE INSERT ON tree_restore_execution_step_intents
WHEN EXISTS(SELECT 1 FROM tree_restore_execution_step_intents
    WHERE transaction_id=NEW.transaction_id AND step_index=NEW.step_index)
OR EXISTS(SELECT 1 FROM tree_restore_execution_intents WHERE execution_id=NEW.execution_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents WHERE execution_id=NEW.execution_id)
OR EXISTS(SELECT 1 FROM tree_restore_preparations WHERE transaction_id=NEW.execution_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_execution_intents c
    JOIN tree_restore_steps s USING(transaction_id)
    WHERE c.transaction_id=NEW.transaction_id AND c.execution_id=NEW.coordinator_execution_id
    AND s.step_index=NEW.step_index AND NEW.step_index<c.step_count
    AND json_extract(c.intent,'$.input.step_execution_ids."'||NEW.step_index||'"')=NEW.execution_id
    AND json_extract(c.intent,'$.steps['||NEW.step_index||']')=json(NEW.intent)
    AND json_extract(NEW.intent,'$.step')=json(s.step)
    AND NOT EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=c.transaction_id))
OR json_extract(NEW.intent,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.intent,'$.step_execution_id') IS NOT NEW.execution_id
OR json_extract(NEW.intent,'$.step.index') IS NOT NEW.step_index
OR json_extract(NEW.intent,'$.identity_binding.step_index') IS NOT NEW.step_index
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.execution_id GLOB '*[^0-9a-f]*'
OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*' OR NEW.intent_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid descriptive tree step intent'); END;
CREATE TRIGGER tree_execution_step_intent_immutable BEFORE UPDATE ON tree_restore_execution_step_intents
BEGIN SELECT RAISE(ABORT,'descriptive tree step intent immutable'); END;
CREATE TRIGGER tree_execution_step_intent_no_delete BEFORE DELETE ON tree_restore_execution_step_intents
BEGIN SELECT RAISE(ABORT,'descriptive tree step intent single use'); END;
CREATE TRIGGER tree_execution_intent_cancel_time BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM tree_restore_execution_intents
    WHERE transaction_id=NEW.transaction_id AND created_at_ms>NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'tree cancellation precedes descriptive execution intent'); END;
CREATE TRIGGER tree_execution_intent_cancel_complete BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM tree_restore_execution_intents c
    WHERE c.transaction_id=NEW.transaction_id
    AND c.step_count!=(SELECT count(*) FROM tree_restore_execution_step_intents
        WHERE transaction_id=c.transaction_id))
BEGIN SELECT RAISE(ABORT,'incomplete descriptive execution intent'); END;

PRAGMA user_version=24;
