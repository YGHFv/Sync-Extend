-- Canonical immutable cleanup terminal frees only its own TREE gate.

DROP TRIGGER tree_restore_preparation_admission;
CREATE TRIGGER tree_restore_preparation_admission BEFORE INSERT ON tree_restore_preparations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations WHERE transaction_id=NEW.transaction_id)
OR EXISTS (SELECT 1 FROM tree_restore_preparations p WHERE p.space_id=NEW.space_id
    AND NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
OR NOT EXISTS (SELECT 1 FROM local_state WHERE key='space_id' AND value=NEW.space_id)
OR json_extract(NEW.intent,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.scope.format_version') IS NOT 1
OR json_extract(NEW.intent,'$.scope.space_id') IS NOT NEW.space_id
OR json_extract(NEW.intent,'$.scope.baseline_snapshot') IS NOT NEW.baseline_root
OR json_extract(NEW.intent,'$.scope.target_snapshot') IS NOT NEW.target_root
OR json_extract(NEW.intent,'$.prepared_at_ms') IS NOT NEW.prepared_at_ms
OR EXISTS (SELECT 1 FROM publications WHERE space_id=NEW.space_id AND (state!='committed' OR cleaned=0))
OR EXISTS (SELECT 1 FROM mutations WHERE space_id=NEW.space_id
    AND state IN ('prepared','executing','quarantined','moved','replaced'))
OR EXISTS (SELECT 1 FROM cleanup_plans WHERE space_id=NEW.space_id AND state='executing')
OR NOT EXISTS (SELECT 1 FROM snapshots b JOIN snapshots t ON t.snapshot_id=NEW.target_root
    JOIN current_manifests c ON c.space_id=NEW.space_id
    WHERE b.snapshot_id=NEW.baseline_root AND c.snapshot_id=b.snapshot_id
    AND b.space_id=NEW.space_id AND t.space_id=NEW.space_id
    AND b.state='materialized' AND t.state='materialized'
    AND b.created_at_ms<=NEW.prepared_at_ms AND t.created_at_ms<=NEW.prepared_at_ms
    AND NOT EXISTS (SELECT 1 FROM snapshot_prunings
        WHERE snapshot_id IN (NEW.baseline_root,NEW.target_root)))
BEGIN SELECT RAISE(ABORT,'invalid tree restore preparation'); END;

DROP TRIGGER tree_restore_writer_publications_insert;
CREATE TRIGGER tree_restore_writer_publications_insert BEFORE INSERT ON publications
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_publications_update;
CREATE TRIGGER tree_restore_writer_publications_update BEFORE UPDATE ON publications
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_publications_delete;
CREATE TRIGGER tree_restore_writer_publications_delete BEFORE DELETE ON publications
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_mutations_insert;
CREATE TRIGGER tree_restore_writer_mutations_insert BEFORE INSERT ON mutations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_mutations_update;
CREATE TRIGGER tree_restore_writer_mutations_update BEFORE UPDATE ON mutations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_mutations_delete;
CREATE TRIGGER tree_restore_writer_mutations_delete BEFORE DELETE ON mutations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_current_manifests_insert;
CREATE TRIGGER tree_restore_writer_current_manifests_insert BEFORE INSERT ON current_manifests
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_current_manifests_update;
CREATE TRIGGER tree_restore_writer_current_manifests_update BEFORE UPDATE ON current_manifests
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
AND NOT sync_tree_native_issue('current_manifests:update',OLD.space_id,OLD.snapshot_id,NEW.space_id,NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_current_manifests_delete;
CREATE TRIGGER tree_restore_writer_current_manifests_delete BEFORE DELETE ON current_manifests
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_operations_insert;
CREATE TRIGGER tree_restore_writer_operations_insert BEFORE INSERT ON operations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
AND NOT sync_tree_native_issue('operations:insert',NEW.op_id,NEW.space_id,NEW.origin_device_id,NEW.origin_seq,NEW.payload,NEW.state)
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_operations_update;
CREATE TRIGGER tree_restore_writer_operations_update BEFORE UPDATE ON operations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_operations_delete;
CREATE TRIGGER tree_restore_writer_operations_delete BEFORE DELETE ON operations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_receive_cursors_insert;
CREATE TRIGGER tree_restore_writer_receive_cursors_insert BEFORE INSERT ON receive_cursors
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_receive_cursors_update;
CREATE TRIGGER tree_restore_writer_receive_cursors_update BEFORE UPDATE ON receive_cursors
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
AND NOT sync_tree_native_issue('receive_cursors:update',OLD.space_id,OLD.device_id,OLD.contiguous_seq,NEW.space_id,NEW.device_id,NEW.contiguous_seq)
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_receive_cursors_delete;
CREATE TRIGGER tree_restore_writer_receive_cursors_delete BEFORE DELETE ON receive_cursors
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_local_state_insert;
CREATE TRIGGER tree_restore_writer_local_state_insert BEFORE INSERT ON local_state
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_local_state_update;
CREATE TRIGGER tree_restore_writer_local_state_update BEFORE UPDATE ON local_state
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_local_state_delete;
CREATE TRIGGER tree_restore_writer_local_state_delete BEFORE DELETE ON local_state
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_rename_observations_insert;
CREATE TRIGGER tree_restore_writer_rename_observations_insert BEFORE INSERT ON rename_observations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_rename_observations_update;
CREATE TRIGGER tree_restore_writer_rename_observations_update BEFORE UPDATE ON rename_observations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_cleanup_plans_insert;
CREATE TRIGGER tree_restore_writer_cleanup_plans_insert BEFORE INSERT ON cleanup_plans
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_cleanup_plans_update;
CREATE TRIGGER tree_restore_writer_cleanup_plans_update BEFORE UPDATE ON cleanup_plans
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_cleanup_plans_delete;
CREATE TRIGGER tree_restore_writer_cleanup_plans_delete BEFORE DELETE ON cleanup_plans
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_original_disposals_insert;
CREATE TRIGGER tree_restore_writer_original_disposals_insert BEFORE INSERT ON original_disposals
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_original_disposals_update;
CREATE TRIGGER tree_restore_writer_original_disposals_update BEFORE UPDATE ON original_disposals
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_original_disposals_delete;
CREATE TRIGGER tree_restore_writer_original_disposals_delete BEFORE DELETE ON original_disposals
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_original_disposal_completions_insert;
CREATE TRIGGER tree_restore_writer_original_disposal_completions_insert BEFORE INSERT ON original_disposal_completions
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_original_disposal_completions_update;
CREATE TRIGGER tree_restore_writer_original_disposal_completions_update BEFORE UPDATE ON original_disposal_completions
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_original_disposal_completions_delete;
CREATE TRIGGER tree_restore_writer_original_disposal_completions_delete BEFORE DELETE ON original_disposal_completions
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_snapshots_insert;
CREATE TRIGGER tree_restore_writer_snapshots_insert BEFORE INSERT ON snapshots
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
AND NOT sync_tree_native_issue('snapshots:insert',NEW.snapshot_id,NEW.space_id,NEW.manifest,NEW.created_at_ms,NEW.state,NEW.locked)
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

DROP TRIGGER tree_restore_writer_rename_observations_delete;
CREATE TRIGGER tree_restore_writer_rename_observations_delete BEFORE DELETE ON rename_observations
WHEN EXISTS (SELECT 1 FROM tree_restore_preparations p
    WHERE NOT EXISTS (SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=p.transaction_id)
    AND NOT EXISTS (SELECT 1 FROM tree_native_cleanup_records c WHERE c.transaction_id=p.transaction_id AND c.record_index=3))
AND NOT sync_tree_native_issue('rename_observations:delete',OLD.space_id,OLD.snapshot_id,OLD.observation,OLD.observation_hash)
BEGIN SELECT RAISE(ABORT,'prepared tree restore owns writer gate'); END;

PRAGMA user_version=55;
