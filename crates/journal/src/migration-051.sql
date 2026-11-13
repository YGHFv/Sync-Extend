-- Original TREE owner activation only. All file/directory steps and Final remain closed.
DROP TRIGGER tree_native_record_insert;
DROP TRIGGER tree_native_action_attempts_insert_closed;

CREATE TRIGGER tree_native_record_insert BEFORE INSERT ON tree_native_action_records
WHEN CASE WHEN NEW.record_index=0 THEN
    EXISTS(SELECT 1 FROM main.tree_native_action_records WHERE transaction_id=NEW.transaction_id)
    OR NEW.action_ordinal IS NOT 0 OR NEW.previous_hash IS NOT NEW.layout_hash
    OR NOT EXISTS(
        SELECT 1 FROM main.tree_native_action_headers h
        JOIN main.tree_restore_owner_intents o USING(transaction_id)
        WHERE h.transaction_id=NEW.transaction_id AND h.space_id=NEW.space_id
        AND h.coordinator_execution_id=NEW.coordinator_execution_id AND h.admission_id=NEW.admission_id
        AND h.admission_hash=NEW.admission_hash AND h.protocol_hash=NEW.protocol_hash
        AND h.layout_hash=NEW.layout_hash AND h.created_at_ms=NEW.recorded_at_ms
        AND json_extract(NEW.record,'$.payload.intent.parent')=json_extract(o.intent,'$.parent')
        AND json_extract(NEW.record,'$.payload.intent.component')=json_extract(o.intent,'$.stage_component'))
    OR json_extract(NEW.record,'$.payload.phase') IS NOT 'intended'
    OR json_extract(NEW.record,'$.payload.intent.action') IS NOT 'create_owner_directory'
ELSE
    NEW.record_index NOT BETWEEN 1 AND 9 OR NEW.action_ordinal IS NOT NEW.record_index/2
    OR NOT EXISTS(SELECT 1 FROM main.tree_native_future_admissions f
        WHERE f.transaction_id=NEW.transaction_id AND f.space_id=NEW.space_id
        AND f.coordinator_execution_id=NEW.coordinator_execution_id
        AND f.admission_id=NEW.admission_id AND f.admission_hash=NEW.admission_hash
        AND f.protocol_hash=NEW.protocol_hash AND f.layout_hash=NEW.layout_hash)
    OR NOT EXISTS(SELECT 1 FROM main.tree_native_action_records r
        WHERE r.transaction_id=NEW.transaction_id AND r.record_index=NEW.record_index-1
        AND r.record_hash=NEW.previous_hash AND r.recorded_at_ms<=NEW.recorded_at_ms)
    OR (NEW.record_index%2=1 AND NOT EXISTS(
        SELECT 1 FROM main.tree_native_action_attempts a
        WHERE a.transaction_id=NEW.transaction_id AND a.action_ordinal=NEW.action_ordinal
        AND a.intended_record_hash=NEW.previous_hash AND a.attempted_at_ms<=NEW.recorded_at_ms))
    OR NOT sync_tree_native_issue(
        'tree_native_action_records',NEW.space_id,NEW.transaction_id,NEW.coordinator_execution_id,
        NEW.admission_id,NEW.admission_hash,NEW.protocol_hash,NEW.layout_hash,NEW.record_index,
        NEW.action_ordinal,NEW.previous_hash,NEW.record_hash,NEW.recorded_at_ms,NEW.record)
END
OR json_extract(NEW.record,'$.scope.format_version') IS NOT 1
OR json_extract(NEW.record,'$.scope.space_id') IS NOT NEW.space_id
OR json_extract(NEW.record,'$.scope.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.record,'$.scope.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.record,'$.scope.admission_id') IS NOT NEW.admission_id
OR json_extract(NEW.record,'$.scope.admission_hash') IS NOT NEW.admission_hash
OR json_extract(NEW.record,'$.scope.protocol_hash') IS NOT NEW.protocol_hash
OR json_extract(NEW.record,'$.record_index') IS NOT NEW.record_index
OR json_extract(NEW.record,'$.action_ordinal') IS NOT NEW.action_ordinal
OR json_extract(NEW.record,'$.previous_hash') IS NOT NEW.previous_hash
OR json_extract(NEW.record,'$.recorded_at_ms') IS NOT NEW.recorded_at_ms
BEGIN SELECT RAISE(ABORT,'invalid original tree owner record'); END;

CREATE TRIGGER tree_native_action_attempts_insert_closed BEFORE INSERT ON tree_native_action_attempts
WHEN NEW.action_ordinal NOT BETWEEN 0 AND 4
OR NEW.intended_record_index IS NOT 2*NEW.action_ordinal
OR EXISTS(SELECT 1 FROM main.tree_native_action_attempts
    WHERE transaction_id=NEW.transaction_id AND action_ordinal=NEW.action_ordinal)
OR EXISTS(SELECT 1 FROM main.tree_native_action_records
    WHERE transaction_id=NEW.transaction_id AND record_index>NEW.intended_record_index)
OR NOT EXISTS(
    SELECT 1 FROM main.tree_native_future_admissions f
    JOIN main.tree_native_future_generations g USING(transaction_id)
    JOIN main.tree_native_action_records r USING(transaction_id)
    WHERE f.transaction_id=NEW.transaction_id AND f.space_id=NEW.space_id
    AND f.coordinator_execution_id=NEW.coordinator_execution_id
    AND f.admission_id=NEW.admission_id AND f.admission_hash=NEW.admission_hash
    AND f.protocol_hash=NEW.protocol_hash AND f.layout_hash=NEW.layout_hash
    AND f.capacity_hash=NEW.full_capacity_hash
    AND g.purpose='action_attempt' AND g.ordinal=NEW.action_ordinal
    AND g.generation_id=NEW.attempt_id AND g.capacity_hash=f.capacity_hash
    AND r.record_index=NEW.intended_record_index AND r.record_hash=NEW.intended_record_hash
    AND json_extract(r.record,'$.payload.phase')='intended'
    AND r.recorded_at_ms<=NEW.attempted_at_ms)
OR json_extract(NEW.request,'$.format_version') IS NOT 1
OR json_extract(NEW.request,'$.scope.space_id') IS NOT NEW.space_id
OR json_extract(NEW.request,'$.scope.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.request,'$.scope.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.request,'$.scope.admission_id') IS NOT NEW.admission_id
OR json_extract(NEW.request,'$.scope.admission_hash') IS NOT NEW.admission_hash
OR json_extract(NEW.request,'$.scope.protocol_hash') IS NOT NEW.protocol_hash
OR json_extract(NEW.request,'$.layout_hash') IS NOT NEW.layout_hash
OR json_extract(NEW.request,'$.full_capacity_hash') IS NOT NEW.full_capacity_hash
OR json_extract(NEW.request,'$.intended_record_hash') IS NOT NEW.intended_record_hash
OR json_extract(NEW.request,'$.attempt_id') IS NOT NEW.attempt_id
OR json_extract(NEW.request,'$.action_ordinal') IS NOT NEW.action_ordinal
OR json_extract(NEW.request,'$.intended_record_index') IS NOT NEW.intended_record_index
OR json_extract(NEW.request,'$.attempted_at_ms') IS NOT NEW.attempted_at_ms
OR NOT sync_tree_native_issue(
    'tree_native_action_attempts',NEW.space_id,NEW.transaction_id,NEW.coordinator_execution_id,
    NEW.admission_id,NEW.admission_hash,NEW.protocol_hash,NEW.layout_hash,NEW.full_capacity_hash,
    NEW.intended_record_hash,NEW.attempt_id,NEW.action_ordinal,NEW.intended_record_index,
    NEW.attempted_at_ms,NEW.request_hash,NEW.request)
BEGIN SELECT RAISE(ABORT,'invalid one-shot original tree owner activation'); END;

PRAGMA user_version=51;
