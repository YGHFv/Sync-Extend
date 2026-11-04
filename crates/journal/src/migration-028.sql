-- Final NEW history candidates are descriptions, never native/final admission.
CREATE TABLE tree_restore_final_descriptions (
    transaction_id TEXT PRIMARY KEY REFERENCES tree_restore_owner_intents(transaction_id),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    execution_intent_hash TEXT NOT NULL CHECK(length(execution_intent_hash)=64),
    original_request_hash TEXT NOT NULL CHECK(length(original_request_hash)=64),
    original_closure_hash TEXT NOT NULL CHECK(length(original_closure_hash)=64),
    owner_intent_hash TEXT NOT NULL CHECK(length(owner_intent_hash)=64),
    owner_records_hash TEXT NOT NULL CHECK(length(owner_records_hash)=64),
    step_records_hash TEXT NOT NULL CHECK(length(step_records_hash)=64),
    history_projection_hash TEXT NOT NULL CHECK(length(history_projection_hash)=64),
    final_snapshot_id TEXT NOT NULL CHECK(length(final_snapshot_id)=64),
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    described_at_ms INTEGER NOT NULL CHECK(described_at_ms>=0),
    step_count INTEGER NOT NULL CHECK(step_count BETWEEN 1 AND 1000000),
    final_entry_count INTEGER NOT NULL CHECK(final_entry_count BETWEEN 0 AND 1000000),
    original_count INTEGER NOT NULL CHECK(original_count BETWEEN 0 AND 1000000),
    reference_row_count INTEGER NOT NULL CHECK(reference_row_count BETWEEN 0 AND 1000000),
    input_encoded_bytes INTEGER NOT NULL CHECK(input_encoded_bytes BETWEEN 1 AND 16777216),
    peak_native_entries INTEGER NOT NULL CHECK(peak_native_entries BETWEEN 0 AND 1000000),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216),
    intent TEXT NOT NULL CHECK(length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    CHECK(length(transaction_id)=32)
) STRICT;
CREATE TABLE tree_restore_retained_descriptions (
    transaction_id TEXT NOT NULL REFERENCES tree_restore_final_descriptions(transaction_id),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    step_execution_id TEXT NOT NULL CHECK(length(step_execution_id)=32),
    step_index INTEGER NOT NULL CHECK(step_index BETWEEN 0 AND 999999),
    original_intent_hash TEXT NOT NULL CHECK(length(original_intent_hash)=64),
    final_intent_hash TEXT NOT NULL CHECK(length(final_intent_hash)=64),
    step_terminal_hash TEXT NOT NULL CHECK(length(step_terminal_hash)=64),
    new_operation_id TEXT NOT NULL CHECK(length(new_operation_id)=64),
    final_snapshot_id TEXT NOT NULL CHECK(length(final_snapshot_id)=64),
    description TEXT NOT NULL CHECK(length(CAST(description AS BLOB)) BETWEEN 1 AND 16777216),
    description_hash TEXT NOT NULL CHECK(length(description_hash)=64),
    PRIMARY KEY(transaction_id,step_index),
    CHECK(length(transaction_id)=32)
) STRICT;
CREATE TRIGGER tree_final_description_insert BEFORE INSERT ON tree_restore_final_descriptions
WHEN EXISTS(SELECT 1 FROM tree_restore_final_descriptions WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_owner_intents o
    JOIN tree_restore_execution_intents e USING(transaction_id)
    JOIN tree_restore_histories h USING(transaction_id)
    JOIN tree_restore_original_reservations r USING(transaction_id)
    WHERE o.transaction_id=NEW.transaction_id
    AND o.coordinator_execution_id=NEW.coordinator_execution_id
    AND e.execution_id=NEW.coordinator_execution_id AND e.intent_hash=NEW.execution_intent_hash
    AND o.execution_intent_hash=NEW.execution_intent_hash
    AND o.intent_hash=NEW.owner_intent_hash AND r.request_hash=NEW.original_request_hash
    AND r.closure_hash=NEW.original_closure_hash AND h.projection_hash=NEW.history_projection_hash
    AND h.final_snapshot_id=NEW.final_snapshot_id AND e.step_count=NEW.step_count
    AND r.owner_count=NEW.original_count AND r.reference_count=NEW.reference_row_count
    AND o.created_at_ms<=NEW.described_at_ms AND r.reserved_at_ms<=NEW.described_at_ms)
OR NOT EXISTS(SELECT 1 FROM tree_restore_owner_records o
    WHERE o.transaction_id=NEW.transaction_id AND o.record_index=7
    AND json_extract(o.record,'$.event.event')='ready' AND o.recorded_at_ms<=NEW.described_at_ms)
OR NEW.step_count IS NOT (SELECT count(*) FROM tree_restore_execution_records r
    WHERE r.transaction_id=NEW.transaction_id AND json_extract(r.record,'$.event.event')='terminal')
OR EXISTS(SELECT 1 FROM tree_restore_execution_records r WHERE r.transaction_id=NEW.transaction_id
    AND (r.recorded_at_ms>NEW.described_at_ms
    OR r.recorded_at_ms<(SELECT recorded_at_ms FROM tree_restore_owner_records
        WHERE transaction_id=NEW.transaction_id AND record_index=7)))
OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents s WHERE s.transaction_id=NEW.transaction_id
    AND (json_extract(NEW.intent,'$.new_operation_ids['||s.step_index||']')
        IS NOT json_extract(s.intent,'$.new_operation_id')
    OR json_extract(NEW.intent,'$.step_terminal_hashes."'||s.step_index||'"') IS NOT
        (SELECT record_hash FROM tree_restore_execution_records r
        WHERE r.transaction_id=s.transaction_id AND r.step_index=s.step_index
        AND json_extract(r.record,'$.event.event')='terminal')))
OR json_extract(NEW.request,'$.input') IS NOT json_extract(NEW.intent,'$.input')
OR json_extract(NEW.intent,'$.input.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.input.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.intent,'$.input.execution_intent_hash') IS NOT NEW.execution_intent_hash
OR json_extract(NEW.intent,'$.input.original_request_hash') IS NOT NEW.original_request_hash
OR json_extract(NEW.intent,'$.input.original_closure_hash') IS NOT NEW.original_closure_hash
OR json_extract(NEW.intent,'$.input.owner_intent_hash') IS NOT NEW.owner_intent_hash
OR json_extract(NEW.intent,'$.input.owner_records_hash') IS NOT NEW.owner_records_hash
OR json_extract(NEW.intent,'$.input.step_records_hash') IS NOT NEW.step_records_hash
OR json_extract(NEW.intent,'$.input.history_projection_hash') IS NOT NEW.history_projection_hash
OR json_extract(NEW.intent,'$.input.described_at_ms') IS NOT NEW.described_at_ms
OR json_extract(NEW.intent,'$.final_snapshot_id') IS NOT NEW.final_snapshot_id
OR json_array_length(NEW.intent,'$.new_operation_ids') IS NOT NEW.step_count
OR (SELECT count(*) FROM json_each(NEW.intent,'$.step_terminal_hashes')) IS NOT NEW.step_count
OR (SELECT count(*) FROM json_each(NEW.intent,'$.final_native_entries')) IS NOT NEW.final_entry_count
OR (SELECT count(*) FROM json_each(NEW.intent,'$.retained_originals')) IS NOT NEW.original_count
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.execution_intent_hash GLOB '*[^0-9a-f]*' OR NEW.original_request_hash GLOB '*[^0-9a-f]*'
OR NEW.original_closure_hash GLOB '*[^0-9a-f]*' OR NEW.owner_intent_hash GLOB '*[^0-9a-f]*'
OR NEW.owner_records_hash GLOB '*[^0-9a-f]*' OR NEW.step_records_hash GLOB '*[^0-9a-f]*'
OR NEW.history_projection_hash GLOB '*[^0-9a-f]*' OR NEW.final_snapshot_id GLOB '*[^0-9a-f]*'
OR NEW.intent_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid descriptive tree final candidate'); END;
CREATE TRIGGER tree_final_description_immutable BEFORE UPDATE ON tree_restore_final_descriptions
BEGIN SELECT RAISE(ABORT,'descriptive tree final candidate immutable'); END;
CREATE TRIGGER tree_final_description_no_delete BEFORE DELETE ON tree_restore_final_descriptions
BEGIN SELECT RAISE(ABORT,'descriptive tree final candidate retained'); END;
CREATE TRIGGER tree_retained_description_insert BEFORE INSERT ON tree_restore_retained_descriptions
WHEN EXISTS(SELECT 1 FROM tree_restore_retained_descriptions
    WHERE transaction_id=NEW.transaction_id AND step_index=NEW.step_index)
OR EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_final_descriptions f
    JOIN tree_restore_original_owners o ON o.transaction_id=f.transaction_id
    AND o.step_index=NEW.step_index
    WHERE f.transaction_id=NEW.transaction_id AND f.coordinator_execution_id=NEW.coordinator_execution_id
    AND o.coordinator_execution_id=NEW.coordinator_execution_id AND o.step_execution_id=NEW.step_execution_id
    AND o.intent_hash=NEW.original_intent_hash AND f.intent_hash=NEW.final_intent_hash
    AND f.final_snapshot_id=NEW.final_snapshot_id
    AND json_extract(f.intent,'$.retained_originals."'||NEW.step_index||'"')=json(NEW.description)
    AND json_extract(f.intent,'$.step_terminal_hashes."'||NEW.step_index||'"')=NEW.step_terminal_hash)
OR json_extract(NEW.description,'$.original.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.description,'$.original.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.description,'$.original.step_execution_id') IS NOT NEW.step_execution_id
OR json_extract(NEW.description,'$.original.step_index') IS NOT NEW.step_index
OR json_extract(NEW.description,'$.step_terminal_hash') IS NOT NEW.step_terminal_hash
OR json_extract(NEW.description,'$.new_operation_id') IS NOT NEW.new_operation_id
OR json_extract(NEW.description,'$.final_snapshot_id') IS NOT NEW.final_snapshot_id
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.step_execution_id GLOB '*[^0-9a-f]*' OR NEW.original_intent_hash GLOB '*[^0-9a-f]*'
OR NEW.final_intent_hash GLOB '*[^0-9a-f]*' OR NEW.step_terminal_hash GLOB '*[^0-9a-f]*'
OR NEW.new_operation_id GLOB '*[^0-9a-f]*' OR NEW.final_snapshot_id GLOB '*[^0-9a-f]*'
OR NEW.description_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid descriptive retained tree original'); END;
CREATE TRIGGER tree_retained_description_immutable BEFORE UPDATE ON tree_restore_retained_descriptions
BEGIN SELECT RAISE(ABORT,'descriptive retained tree original immutable'); END;
CREATE TRIGGER tree_retained_description_no_delete BEFORE DELETE ON tree_restore_retained_descriptions
BEGIN SELECT RAISE(ABORT,'descriptive retained tree original retained'); END;
CREATE TRIGGER tree_final_description_cancel_time BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM tree_restore_final_descriptions
    WHERE transaction_id=NEW.transaction_id AND described_at_ms>NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'tree cancellation precedes final description'); END;
-- Independent canonical typed audit is mandatory, never executable admission.
PRAGMA user_version=28;
