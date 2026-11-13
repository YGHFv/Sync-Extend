-- Exact scoped original disposal and owner-empty cleanup; never recursive removal.

DROP TRIGGER tree_native_original_intents_insert_closed;
CREATE TRIGGER tree_native_original_intents_insert_closed BEFORE INSERT ON tree_native_original_intents
WHEN NOT sync_tree_native_issue('tree_native_original_intents',NEW.transaction_id,NEW.step_index,NEW.step_execution_id,NEW.disposal_id,NEW.finalization_id,NEW.committed_hash,NEW.retained_hash,NEW.intent_hash,NEW.intended_at_ms,NEW.intent)
BEGIN SELECT RAISE(ABORT,'exact tree disposal issuer required'); END;

DROP TRIGGER tree_native_original_absences_insert_closed;
CREATE TRIGGER tree_native_original_absences_insert_closed BEFORE INSERT ON tree_native_original_absences
WHEN NOT sync_tree_native_issue('tree_native_original_absences',NEW.transaction_id,NEW.step_index,NEW.disposal_id,NEW.intent_hash,NEW.absence_hash,NEW.observed_at_ms,NEW.record)
BEGIN SELECT RAISE(ABORT,'exact tree disposal issuer required'); END;

DROP TRIGGER tree_native_original_terminals_insert_closed;
CREATE TRIGGER tree_native_original_terminals_insert_closed BEFORE INSERT ON tree_native_original_terminals
WHEN NOT sync_tree_native_issue('tree_native_original_terminals',NEW.transaction_id,NEW.step_index,NEW.disposal_id,NEW.intent_hash,NEW.absence_hash,NEW.terminal_hash,NEW.own_closure_hash,NEW.reference_count,NEW.released_at_ms,NEW.record)
BEGIN SELECT RAISE(ABORT,'exact tree disposal issuer required'); END;

DROP TRIGGER tree_native_cleanup_intents_insert_closed;
CREATE TRIGGER tree_native_cleanup_intents_insert_closed BEFORE INSERT ON tree_native_cleanup_intents
WHEN NOT sync_tree_native_issue('tree_native_cleanup_intents',NEW.space_id,NEW.transaction_id,NEW.coordinator_execution_id,NEW.admission_id,NEW.admission_hash,NEW.protocol_hash,NEW.finalization_id,NEW.cleanup_id,NEW.owner_intent_hash,NEW.committed_hash,NEW.input_release_hash,NEW.original_terminals_hash,NEW.intent_hash,NEW.original_count,NEW.intended_at_ms,NEW.intent)
BEGIN SELECT RAISE(ABORT,'exact tree disposal issuer required'); END;

DROP TRIGGER tree_native_cleanup_records_insert_closed;
CREATE TRIGGER tree_native_cleanup_records_insert_closed BEFORE INSERT ON tree_native_cleanup_records
WHEN NOT sync_tree_native_issue('tree_native_cleanup_records',NEW.space_id,NEW.transaction_id,NEW.coordinator_execution_id,NEW.admission_id,NEW.admission_hash,NEW.protocol_hash,NEW.finalization_id,NEW.cleanup_id,NEW.intent_hash,NEW.record_index,NEW.previous_hash,NEW.record_hash,NEW.recorded_at_ms,NEW.record)
BEGIN SELECT RAISE(ABORT,'exact tree disposal issuer required'); END;

DROP TRIGGER tree_original_pin_release;
CREATE TRIGGER tree_original_pin_release BEFORE DELETE ON tree_restore_original_objects
WHEN NOT EXISTS(SELECT 1 FROM main.tree_restore_cancellations WHERE transaction_id=OLD.transaction_id)
AND NOT sync_tree_native_issue('tree_restore_original_objects:delete',OLD.transaction_id,OLD.step_index,OLD.step_execution_id,OLD.content_id,OLD.length)
BEGIN SELECT RAISE(ABORT,'exact tree original-only pin release required'); END;


-- Each admitted original release requires the exact committed original terminal
-- and a separate one-shot permit from the ordinary original pin-release trigger.
DROP TRIGGER tree_admission_original_pin_fence;
CREATE TRIGGER tree_admission_original_pin_fence BEFORE DELETE ON tree_restore_original_objects
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions WHERE transaction_id=OLD.transaction_id)
THEN NOT EXISTS(
    SELECT 1 FROM tree_native_original_terminals t
    JOIN tree_native_original_intents i ON i.transaction_id=t.transaction_id AND i.step_index=t.step_index
    AND i.disposal_id=t.disposal_id AND i.intent_hash=t.intent_hash
    JOIN tree_native_final_commits f ON f.transaction_id=i.transaction_id
    AND f.finalization_id=i.finalization_id AND f.committed_hash=i.committed_hash
    WHERE t.transaction_id=OLD.transaction_id AND t.step_index=OLD.step_index
    AND i.step_execution_id=OLD.step_execution_id)
OR NOT sync_tree_native_issue('tree_restore_original_objects:admission_delete',OLD.transaction_id,OLD.step_index,OLD.step_execution_id,OLD.content_id,OLD.length)
ELSE 0 END
BEGIN SELECT RAISE(ABORT,'admitted tree original references retained'); END;

PRAGMA user_version=54;
