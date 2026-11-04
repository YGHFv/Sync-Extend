-- Exact creator directory/marker descriptions, never native action admission.
CREATE TABLE tree_restore_owner_intents (
    transaction_id TEXT PRIMARY KEY REFERENCES tree_restore_original_reservations(transaction_id),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    execution_intent_hash TEXT NOT NULL CHECK(length(execution_intent_hash)=64),
    original_request_hash TEXT NOT NULL CHECK(length(original_request_hash)=64),
    original_closure_hash TEXT NOT NULL CHECK(length(original_closure_hash)=64),
    intent TEXT NOT NULL CHECK(length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    marker_hash TEXT NOT NULL CHECK(length(marker_hash)=64),
    marker_length INTEGER NOT NULL CHECK(marker_length BETWEEN 1 AND 16777216),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    CHECK(length(transaction_id)=32)
) STRICT;
CREATE TABLE tree_restore_owner_records (
    transaction_id TEXT NOT NULL REFERENCES tree_restore_owner_intents(transaction_id),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    record_index INTEGER NOT NULL CHECK(record_index BETWEEN 0 AND 7),
    previous_hash TEXT NOT NULL CHECK(length(previous_hash)=64),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    record_hash TEXT NOT NULL CHECK(length(record_hash)=64),
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
    PRIMARY KEY(transaction_id,record_index),
    CHECK(length(transaction_id)=32)
) STRICT;
CREATE TRIGGER tree_owner_intent_insert BEFORE INSERT ON tree_restore_owner_intents
WHEN EXISTS(SELECT 1 FROM tree_restore_owner_intents WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_original_reservations o
    WHERE o.transaction_id=NEW.transaction_id AND o.coordinator_execution_id=NEW.coordinator_execution_id
    AND o.execution_intent_hash=NEW.execution_intent_hash AND o.request_hash=NEW.original_request_hash
    AND o.closure_hash=NEW.original_closure_hash AND o.reserved_at_ms<=NEW.created_at_ms
    AND NOT EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=o.transaction_id))
OR json_extract(NEW.intent,'$.input.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.input.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.intent,'$.input.execution_intent_hash') IS NOT NEW.execution_intent_hash
OR json_extract(NEW.intent,'$.input.original_request_hash') IS NOT NEW.original_request_hash
OR json_extract(NEW.intent,'$.input.original_closure_hash') IS NOT NEW.original_closure_hash
OR json_extract(NEW.intent,'$.input.created_at_ms') IS NOT NEW.created_at_ms
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.execution_intent_hash GLOB '*[^0-9a-f]*' OR NEW.original_request_hash GLOB '*[^0-9a-f]*'
OR NEW.original_closure_hash GLOB '*[^0-9a-f]*' OR NEW.intent_hash GLOB '*[^0-9a-f]*'
OR NEW.marker_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid descriptive tree owner intent'); END;
CREATE TRIGGER tree_owner_intent_immutable BEFORE UPDATE ON tree_restore_owner_intents
BEGIN SELECT RAISE(ABORT,'descriptive tree owner intent immutable'); END;
CREATE TRIGGER tree_owner_intent_no_delete BEFORE DELETE ON tree_restore_owner_intents
BEGIN SELECT RAISE(ABORT,'descriptive tree owner intent retained'); END;
CREATE TRIGGER tree_owner_record_insert BEFORE INSERT ON tree_restore_owner_records
WHEN EXISTS(SELECT 1 FROM tree_restore_owner_records WHERE transaction_id=NEW.transaction_id AND record_index=NEW.record_index)
OR NOT EXISTS(SELECT 1 FROM tree_restore_owner_intents o WHERE o.transaction_id=NEW.transaction_id
    AND o.coordinator_execution_id=NEW.coordinator_execution_id AND o.intent_hash=NEW.intent_hash
    AND o.created_at_ms<=NEW.recorded_at_ms
    AND NOT EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=o.transaction_id))
OR json_extract(NEW.record,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.record,'$.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.record,'$.intent_hash') IS NOT NEW.intent_hash
OR json_extract(NEW.record,'$.record_index') IS NOT NEW.record_index
OR json_extract(NEW.record,'$.previous_hash') IS NOT NEW.previous_hash
OR json_extract(NEW.record,'$.recorded_at_ms') IS NOT NEW.recorded_at_ms
OR (NEW.record_index=0 AND NEW.previous_hash IS NOT NEW.intent_hash)
OR (NEW.record_index>0 AND NOT EXISTS(SELECT 1 FROM tree_restore_owner_records p
    WHERE p.transaction_id=NEW.transaction_id AND p.record_index=NEW.record_index-1
    AND p.record_hash=NEW.previous_hash AND p.recorded_at_ms<=NEW.recorded_at_ms))
OR EXISTS(SELECT 1 FROM tree_restore_owner_records p WHERE p.transaction_id=NEW.transaction_id
    AND (p.record_index>=NEW.record_index OR p.recorded_at_ms>NEW.recorded_at_ms))
OR json_extract(NEW.record,'$.event.event') IS NOT CASE NEW.record_index
    WHEN 0 THEN 'create_intended' WHEN 1 THEN 'directory_bound'
    WHEN 2 THEN 'publication_intended' WHEN 3 THEN 'directory_published'
    WHEN 4 THEN 'marker_create_intended' WHEN 5 THEN 'marker_bound'
    WHEN 6 THEN 'marker_materialized' WHEN 7 THEN 'ready' END
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.intent_hash GLOB '*[^0-9a-f]*' OR NEW.previous_hash GLOB '*[^0-9a-f]*'
OR NEW.record_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid descriptive tree owner record'); END;
CREATE TRIGGER tree_owner_record_immutable BEFORE UPDATE ON tree_restore_owner_records
BEGIN SELECT RAISE(ABORT,'descriptive tree owner record immutable'); END;
CREATE TRIGGER tree_owner_record_no_delete BEFORE DELETE ON tree_restore_owner_records
BEGIN SELECT RAISE(ABORT,'descriptive tree owner record retained'); END;
CREATE TRIGGER tree_owner_cancel_time BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM tree_restore_owner_intents WHERE transaction_id=NEW.transaction_id AND created_at_ms>NEW.cancelled_at_ms)
OR EXISTS(SELECT 1 FROM tree_restore_owner_records WHERE transaction_id=NEW.transaction_id AND recorded_at_ms>NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'tree cancellation precedes owner description'); END;
-- Mandatory typed canonical audit; descriptive readiness grants no native action.
PRAGMA user_version=27;
