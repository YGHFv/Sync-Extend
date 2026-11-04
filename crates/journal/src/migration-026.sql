-- Exact per-original content references, not native action admission.
CREATE TABLE tree_restore_original_reservations (
    transaction_id TEXT PRIMARY KEY REFERENCES tree_restore_execution_intents(transaction_id),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    execution_intent_hash TEXT NOT NULL CHECK(length(execution_intent_hash)=64),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    closure_hash TEXT NOT NULL CHECK(length(closure_hash)=64),
    reserved_at_ms INTEGER NOT NULL CHECK(reserved_at_ms>=0),
    owner_count INTEGER NOT NULL CHECK(owner_count BETWEEN 0 AND 1000000),
    reference_count INTEGER NOT NULL CHECK(reference_count BETWEEN 0 AND 1000000),
    original_logical_bytes INTEGER NOT NULL CHECK(original_logical_bytes>=0),
    reserved_rows INTEGER NOT NULL CHECK(reserved_rows=1+owner_count+reference_count),
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=304+264*owner_count+144*reference_count),
    CHECK(length(transaction_id)=32)
) STRICT;
CREATE TABLE tree_restore_original_owners (
    transaction_id TEXT NOT NULL REFERENCES tree_restore_original_reservations(transaction_id),
    step_index INTEGER NOT NULL CHECK(step_index>=0),
    step_execution_id TEXT NOT NULL UNIQUE CHECK(length(step_execution_id)=32),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    original_entry_id TEXT NOT NULL CHECK(length(original_entry_id)=32),
    step_intent_hash TEXT NOT NULL CHECK(length(step_intent_hash)=64),
    intent TEXT NOT NULL CHECK(length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    PRIMARY KEY(transaction_id,step_index),
    FOREIGN KEY(transaction_id,step_index) REFERENCES tree_restore_execution_step_intents(transaction_id,step_index),
    CHECK(length(transaction_id)=32)
) STRICT;
CREATE TABLE tree_restore_original_objects (
    transaction_id TEXT NOT NULL CHECK(length(transaction_id)=32),
    step_index INTEGER NOT NULL CHECK(step_index>=0),
    step_execution_id TEXT NOT NULL CHECK(length(step_execution_id)=32),
    content_id TEXT NOT NULL CHECK(length(content_id)=64),
    length INTEGER NOT NULL CHECK(length BETWEEN 1 AND 4194304),
    PRIMARY KEY(transaction_id,step_index,content_id),
    FOREIGN KEY(transaction_id,step_index) REFERENCES tree_restore_original_owners(transaction_id,step_index)
) STRICT;
CREATE INDEX tree_original_content ON tree_restore_original_objects(content_id);
CREATE TRIGGER tree_original_reservation_insert BEFORE INSERT ON tree_restore_original_reservations
WHEN EXISTS(SELECT 1 FROM tree_restore_original_reservations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_execution_intents c WHERE c.transaction_id=NEW.transaction_id
    AND c.execution_id=NEW.coordinator_execution_id AND c.intent_hash=NEW.execution_intent_hash
    AND c.created_at_ms<=NEW.reserved_at_ms
    AND NOT EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=c.transaction_id))
OR json_extract(NEW.request,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.request,'$.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.request,'$.execution_intent_hash') IS NOT NEW.execution_intent_hash
OR json_extract(NEW.request,'$.reserved_at_ms') IS NOT NEW.reserved_at_ms
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.execution_intent_hash GLOB '*[^0-9a-f]*' OR NEW.request_hash GLOB '*[^0-9a-f]*'
OR NEW.closure_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid tree original reservation'); END;
CREATE TRIGGER tree_original_reservation_immutable BEFORE UPDATE ON tree_restore_original_reservations
BEGIN SELECT RAISE(ABORT,'tree original reservation immutable'); END;
CREATE TRIGGER tree_original_reservation_no_delete BEFORE DELETE ON tree_restore_original_reservations
BEGIN SELECT RAISE(ABORT,'tree original reservation retained'); END;
CREATE TRIGGER tree_original_owner_insert BEFORE INSERT ON tree_restore_original_owners
WHEN EXISTS(SELECT 1 FROM tree_restore_original_owners WHERE transaction_id=NEW.transaction_id AND step_index=NEW.step_index)
OR NOT EXISTS(SELECT 1 FROM tree_restore_original_reservations h
    JOIN tree_restore_execution_step_intents s USING(transaction_id)
    WHERE h.transaction_id=NEW.transaction_id AND s.step_index=NEW.step_index
    AND s.execution_id=NEW.step_execution_id AND s.intent_hash=NEW.step_intent_hash
    AND h.coordinator_execution_id=NEW.coordinator_execution_id
    AND json_extract(s.intent,'$.step.action') IN ('delete_file','replace_file')
    AND json_extract(s.intent,'$.step.baseline_entry.entry_id')=NEW.original_entry_id
    AND json_extract(s.intent,'$.step.baseline_entry.path')=json_extract(NEW.intent,'$.original_path')
    AND json_extract(s.intent,'$.step.baseline_entry.content')=json_extract(NEW.intent,'$.original_content')
    AND json_extract(s.intent,'$.identity_binding.slot.identity')=json_extract(NEW.intent,'$.original_identity')
    AND NOT EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=h.transaction_id)
    AND (SELECT count(*) FROM tree_restore_original_owners WHERE transaction_id=h.transaction_id)<h.owner_count)
OR json_extract(NEW.intent,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.intent,'$.step_execution_id') IS NOT NEW.step_execution_id
OR json_extract(NEW.intent,'$.step_index') IS NOT NEW.step_index
OR json_extract(NEW.intent,'$.step_intent_hash') IS NOT NEW.step_intent_hash
OR json_extract(NEW.intent,'$.original_entry_id') IS NOT NEW.original_entry_id
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.step_execution_id GLOB '*[^0-9a-f]*' OR NEW.original_entry_id GLOB '*[^0-9a-f]*'
OR NEW.step_intent_hash GLOB '*[^0-9a-f]*' OR NEW.intent_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid tree original owner'); END;
CREATE TRIGGER tree_original_owner_immutable BEFORE UPDATE ON tree_restore_original_owners
BEGIN SELECT RAISE(ABORT,'tree original owner immutable'); END;
CREATE TRIGGER tree_original_owner_no_delete BEFORE DELETE ON tree_restore_original_owners
BEGIN SELECT RAISE(ABORT,'tree original owner retained'); END;
CREATE TRIGGER tree_original_pin_insert BEFORE INSERT ON tree_restore_original_objects
WHEN EXISTS(SELECT 1 FROM tree_restore_original_objects
    WHERE transaction_id=NEW.transaction_id AND step_index=NEW.step_index AND content_id=NEW.content_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_original_owners o
    JOIN tree_restore_original_reservations h USING(transaction_id)
    JOIN json_each(o.intent,'$.original_content.chunks') c
    WHERE o.transaction_id=NEW.transaction_id AND o.step_index=NEW.step_index
    AND o.step_execution_id=NEW.step_execution_id
    AND json_extract(c.value,'$.content_id')=NEW.content_id AND json_extract(c.value,'$.length')=NEW.length
    AND NOT EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=o.transaction_id)
    AND (SELECT count(*) FROM tree_restore_original_objects WHERE transaction_id=h.transaction_id)<h.reference_count)
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.step_execution_id GLOB '*[^0-9a-f]*'
OR NEW.content_id GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid tree original own pin'); END;
CREATE TRIGGER tree_original_pin_immutable BEFORE UPDATE ON tree_restore_original_objects
BEGIN SELECT RAISE(ABORT,'tree original own pin immutable'); END;
CREATE TRIGGER tree_original_pin_release BEFORE DELETE ON tree_restore_original_objects
WHEN NOT EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=OLD.transaction_id)
BEGIN SELECT RAISE(ABORT,'active tree original own pin retained'); END;
CREATE TRIGGER tree_original_pin_gc_fence BEFORE INSERT ON tree_restore_original_objects
WHEN EXISTS(SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
    AND NOT EXISTS(SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'object fenced by GC execution'); END;
CREATE TRIGGER tree_original_pin_invalidate AFTER INSERT ON tree_restore_original_objects
BEGIN
    INSERT OR IGNORE INTO gc_invalidations SELECT mark_id FROM gc_marks m WHERE content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id);
END;
CREATE TRIGGER tree_original_gc_mark_fence BEFORE INSERT ON gc_marks
WHEN EXISTS(SELECT 1 FROM tree_restore_original_objects WHERE content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'object pinned by tree original'); END;
CREATE TRIGGER tree_original_gc_execution_fence BEFORE INSERT ON gc_executions
WHEN EXISTS(SELECT 1 FROM tree_restore_original_objects WHERE content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'object pinned by tree original'); END;
CREATE TRIGGER tree_original_cancel_time BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM tree_restore_original_reservations h WHERE transaction_id=NEW.transaction_id
    AND (h.reserved_at_ms>NEW.cancelled_at_ms
        OR h.owner_count!=(SELECT count(*) FROM tree_restore_original_owners WHERE transaction_id=h.transaction_id)
        OR h.reference_count!=(SELECT count(*) FROM tree_restore_original_objects WHERE transaction_id=h.transaction_id)))
BEGIN SELECT RAISE(ABORT,'tree original cancellation incomplete or early'); END;
-- Typed independent exact closure audit is mandatory, not a global protected union.
PRAGMA user_version=26;
