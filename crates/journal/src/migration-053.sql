-- Exact connection-local Final row permits; no persisted/global writer flag.

DROP TRIGGER tree_native_final_intents_insert_closed;
CREATE TRIGGER tree_native_final_intents_insert_closed BEFORE INSERT ON tree_native_final_intents
WHEN NOT sync_tree_native_issue('tree_native_final_intents',NEW.transaction_id,NEW.coordinator_execution_id,NEW.admission_id,NEW.finalization_id,NEW.intent_hash,NEW.action_root,NEW.fresh_native_hash,NEW.rows_hash,NEW.snapshot_id,NEW.input_closure_hash,NEW.original_handoffs_hash,NEW.intended_at_ms,NEW.intent)
BEGIN SELECT RAISE(ABORT,'exact tree Final issuer required'); END;

DROP TRIGGER tree_native_final_commits_insert_closed;
CREATE TRIGGER tree_native_final_commits_insert_closed BEFORE INSERT ON tree_native_final_commits
WHEN NOT sync_tree_native_issue('tree_native_final_commits',NEW.transaction_id,NEW.coordinator_execution_id,NEW.admission_id,NEW.finalization_id,NEW.intent_hash,NEW.committed_hash,NEW.snapshot_id,NEW.rows_hash,NEW.committed_at_ms,NEW.record)
BEGIN SELECT RAISE(ABORT,'exact tree Final issuer required'); END;

DROP TRIGGER tree_native_input_releases_insert_closed;
CREATE TRIGGER tree_native_input_releases_insert_closed BEFORE INSERT ON tree_native_input_releases
WHEN NOT sync_tree_native_issue('tree_native_input_releases',NEW.transaction_id,NEW.finalization_id,NEW.committed_hash,NEW.input_closure_hash,NEW.reference_count,NEW.released_at_ms,NEW.record)
BEGIN SELECT RAISE(ABORT,'exact tree Final issuer required'); END;

DROP TRIGGER tree_native_retained_owners_insert_closed;
CREATE TRIGGER tree_native_retained_owners_insert_closed BEFORE INSERT ON tree_native_retained_owners
WHEN NOT sync_tree_native_issue('tree_native_retained_owners',NEW.transaction_id,NEW.finalization_id,NEW.step_index,NEW.step_execution_id,NEW.committed_hash,NEW.handoff_hash,NEW.retained_hash,NEW.record)
BEGIN SELECT RAISE(ABORT,'exact tree Final issuer required'); END;

DROP TRIGGER tree_restore_writer_operations_insert;
CREATE TRIGGER tree_restore_writer_operations_insert BEFORE INSERT ON operations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
AND NOT sync_tree_native_issue('operations:insert',NEW.op_id,NEW.space_id,NEW.origin_device_id,NEW.origin_seq,NEW.payload,NEW.state)
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_snapshots_insert;
CREATE TRIGGER tree_restore_writer_snapshots_insert BEFORE INSERT ON snapshots
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
AND NOT sync_tree_native_issue('snapshots:insert',NEW.snapshot_id,NEW.space_id,NEW.manifest,NEW.created_at_ms,NEW.state,NEW.locked)
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_current_manifests_update;
CREATE TRIGGER tree_restore_writer_current_manifests_update BEFORE UPDATE ON current_manifests
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
AND NOT sync_tree_native_issue('current_manifests:update',OLD.space_id,OLD.snapshot_id,NEW.space_id,NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_receive_cursors_update;
CREATE TRIGGER tree_restore_writer_receive_cursors_update BEFORE UPDATE ON receive_cursors
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id))
AND NOT sync_tree_native_issue('receive_cursors:update',OLD.space_id,OLD.device_id,OLD.contiguous_seq,NEW.space_id,NEW.device_id,NEW.contiguous_seq)
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_pin_release;
CREATE TRIGGER tree_restore_pin_release BEFORE DELETE ON tree_restore_objects
WHEN NOT EXISTS(SELECT 1 FROM main.tree_restore_cancellations WHERE transaction_id=OLD.transaction_id)
AND NOT sync_tree_native_issue('tree_restore_objects:delete',OLD.transaction_id,OLD.content_id,OLD.length)
BEGIN SELECT RAISE(ABORT,'exact tree input-only pin release required'); END;


-- The older irreversible-admission fence has its own one-shot permit.
-- Final and the exact input-release bundle must already exist in this SQL transaction.
DROP TRIGGER tree_admission_input_pin_fence;
CREATE TRIGGER tree_admission_input_pin_fence BEFORE DELETE ON tree_restore_objects
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions WHERE transaction_id=OLD.transaction_id)
THEN NOT EXISTS(
    SELECT 1 FROM tree_native_final_commits f JOIN tree_native_input_releases r
    ON r.transaction_id=f.transaction_id AND r.finalization_id=f.finalization_id AND r.committed_hash=f.committed_hash
    WHERE f.transaction_id=OLD.transaction_id)
OR NOT sync_tree_native_issue('tree_restore_objects:admission_delete',OLD.transaction_id,OLD.content_id,OLD.length)
ELSE 0 END
BEGIN SELECT RAISE(ABORT,'admitted tree input references retained'); END;

PRAGMA user_version=53;
