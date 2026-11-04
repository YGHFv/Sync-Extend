-- Immutable descriptive phase records, never native action admission.
CREATE TABLE tree_restore_execution_records (
    transaction_id TEXT NOT NULL CHECK(length(transaction_id)=32),
    step_index INTEGER NOT NULL CHECK(step_index>=0),
    record_index INTEGER NOT NULL CHECK(record_index BETWEEN 0 AND 6),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    step_execution_id TEXT NOT NULL CHECK(length(step_execution_id)=32),
    step_intent_hash TEXT NOT NULL CHECK(length(step_intent_hash)=64),
    previous_hash TEXT NOT NULL CHECK(length(previous_hash)=64),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    record_hash TEXT NOT NULL CHECK(length(record_hash)=64),
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
    PRIMARY KEY(transaction_id,step_index,record_index),
    FOREIGN KEY(transaction_id,step_index) REFERENCES tree_restore_execution_step_intents(transaction_id,step_index)
) STRICT;
CREATE TRIGGER tree_execution_record_insert BEFORE INSERT ON tree_restore_execution_records
WHEN EXISTS(SELECT 1 FROM tree_restore_execution_records WHERE transaction_id=NEW.transaction_id AND step_index=NEW.step_index AND record_index=NEW.record_index)
OR NOT EXISTS(SELECT 1 FROM tree_restore_execution_intents c
    JOIN tree_restore_execution_step_intents s USING(transaction_id)
    WHERE c.transaction_id=NEW.transaction_id AND s.step_index=NEW.step_index
    AND c.execution_id=NEW.coordinator_execution_id AND s.execution_id=NEW.step_execution_id
    AND s.intent_hash=NEW.step_intent_hash AND c.created_at_ms<=NEW.recorded_at_ms
    AND NOT EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=c.transaction_id))
OR json_extract(NEW.record,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.record,'$.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.record,'$.step_execution_id') IS NOT NEW.step_execution_id
OR json_extract(NEW.record,'$.step_index') IS NOT NEW.step_index
OR json_extract(NEW.record,'$.record_index') IS NOT NEW.record_index
OR json_extract(NEW.record,'$.step_intent_hash') IS NOT NEW.step_intent_hash
OR json_extract(NEW.record,'$.previous_hash') IS NOT NEW.previous_hash
OR json_extract(NEW.record,'$.recorded_at_ms') IS NOT NEW.recorded_at_ms
OR (NEW.record_index=0 AND NEW.previous_hash IS NOT NEW.step_intent_hash)
OR (NEW.record_index>0 AND NOT EXISTS(SELECT 1 FROM tree_restore_execution_records p
    WHERE p.transaction_id=NEW.transaction_id AND p.step_index=NEW.step_index
    AND p.record_index=NEW.record_index-1 AND p.record_hash=NEW.previous_hash
    AND p.recorded_at_ms<=NEW.recorded_at_ms))
OR EXISTS(SELECT 1 FROM tree_restore_execution_records p WHERE p.transaction_id=NEW.transaction_id
    AND (p.step_index>NEW.step_index OR p.recorded_at_ms>NEW.recorded_at_ms))
OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents s WHERE s.transaction_id=NEW.transaction_id
    AND s.step_index<NEW.step_index AND NOT EXISTS(SELECT 1 FROM tree_restore_execution_records p
        WHERE p.transaction_id=s.transaction_id AND p.step_index=s.step_index
        AND json_extract(p.record,'$.event.event')='terminal'))
OR NOT EXISTS(SELECT 1 FROM tree_restore_execution_step_intents s
    WHERE s.transaction_id=NEW.transaction_id AND s.step_index=NEW.step_index
    AND json_extract(NEW.record,'$.event.event')=CASE NEW.record_index
        WHEN 0 THEN 'action_intended'
        WHEN 1 THEN CASE json_extract(s.intent,'$.step.action')
            WHEN 'create_directory' THEN 'creator_bound'
            WHEN 'publish_new_file' THEN 'creator_bound'
            WHEN 'replace_file' THEN 'original_move_intended'
            WHEN 'delete_file' THEN 'original_move_intended'
            WHEN 'remove_empty_directory' THEN 'empty_disposition_intended' END
        WHEN 2 THEN CASE json_extract(s.intent,'$.step.action')
            WHEN 'create_directory' THEN 'publication_intended'
            WHEN 'publish_new_file' THEN 'materialized'
            WHEN 'replace_file' THEN 'original_retained'
            WHEN 'delete_file' THEN 'original_retained'
            WHEN 'remove_empty_directory' THEN 'terminal' END
        WHEN 3 THEN CASE json_extract(s.intent,'$.step.action')
            WHEN 'create_directory' THEN 'terminal'
            WHEN 'publish_new_file' THEN 'publication_intended'
            WHEN 'replace_file' THEN 'creator_bound'
            WHEN 'delete_file' THEN 'terminal' END
        WHEN 4 THEN CASE json_extract(s.intent,'$.step.action')
            WHEN 'publish_new_file' THEN 'terminal'
            WHEN 'replace_file' THEN 'materialized' END
        WHEN 5 THEN CASE json_extract(s.intent,'$.step.action')
            WHEN 'replace_file' THEN 'publication_intended' END
        WHEN 6 THEN CASE json_extract(s.intent,'$.step.action')
            WHEN 'replace_file' THEN 'terminal' END END)
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.step_execution_id GLOB '*[^0-9a-f]*' OR NEW.step_intent_hash GLOB '*[^0-9a-f]*'
OR NEW.previous_hash GLOB '*[^0-9a-f]*' OR NEW.record_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid descriptive tree execution record'); END;
CREATE TRIGGER tree_execution_record_immutable BEFORE UPDATE ON tree_restore_execution_records
BEGIN SELECT RAISE(ABORT,'descriptive tree execution record immutable'); END;
CREATE TRIGGER tree_execution_record_no_delete BEFORE DELETE ON tree_restore_execution_records
BEGIN SELECT RAISE(ABORT,'descriptive tree execution record retained'); END;
CREATE TRIGGER tree_execution_record_cancel_time BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM tree_restore_execution_records
    WHERE transaction_id=NEW.transaction_id AND recorded_at_ms>NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'tree cancellation precedes descriptive phase record'); END;
-- Independent typed audit is mandatory; SQL shape never native authority.
PRAGMA user_version=25;
