-- Original signed single-file Rename; no legacy owner/staging allocation.
CREATE TABLE remote_rename_headers (
 transaction_id TEXT PRIMARY KEY, space_id TEXT NOT NULL, generation TEXT NOT NULL,
 header_hash TEXT NOT NULL, baseline_root TEXT NOT NULL REFERENCES snapshots(snapshot_id),
 reserved_rows INTEGER NOT NULL CHECK(reserved_rows>=0),
 reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0), header TEXT NOT NULL
) STRICT;
CREATE TABLE remote_rename_phases (
 transaction_id TEXT NOT NULL REFERENCES remote_rename_headers(transaction_id),
 generation TEXT NOT NULL, header_hash TEXT NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('executing','observed','final')),
 volume TEXT NOT NULL, full_id TEXT NOT NULL, snapshot_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,phase)
) STRICT;
CREATE TABLE remote_rename_objects (
 transaction_id TEXT NOT NULL REFERENCES remote_rename_headers(transaction_id),
 content_id TEXT NOT NULL, PRIMARY KEY(transaction_id,content_id)
) STRICT;
CREATE TRIGGER remote_rename_headers_insert BEFORE INSERT ON remote_rename_headers
WHEN sync_remote_rename_issue('headers',NEW.transaction_id,NEW.space_id,NEW.generation,
 NEW.header_hash,NEW.baseline_root,NEW.reserved_rows,NEW.reserved_bytes,NEW.header)!=1 OR
 EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final')) OR
 EXISTS(SELECT 1 FROM publications WHERE state!='committed' OR cleaned!=1) OR
 EXISTS(SELECT 1 FROM mutations WHERE state NOT IN ('cancelled','committed')) OR
 EXISTS(SELECT 1 FROM tree_restore_preparations t WHERE NOT EXISTS
 (SELECT 1 FROM tree_restore_cancellations c WHERE c.transaction_id=t.transaction_id))
BEGIN SELECT RAISE(ABORT,'remote Rename exact original private admission required'); END;
CREATE TRIGGER remote_rename_phases_insert BEFORE INSERT ON remote_rename_phases
WHEN sync_remote_rename_issue('phases',NEW.transaction_id,NEW.generation,NEW.header_hash,
 NEW.phase,NEW.volume,NEW.full_id,NEW.snapshot_id)!=1
BEGIN SELECT RAISE(ABORT,'remote Rename exact private phase required'); END;
CREATE TRIGGER remote_rename_objects_insert BEFORE INSERT ON remote_rename_objects
WHEN sync_remote_rename_write('admission')!=1 OR EXISTS
 (SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id AND NOT EXISTS
 (SELECT 1 FROM gc_execution_aborts a WHERE a.execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'remote Rename private pin admission required'); END;
CREATE TRIGGER remote_rename_objects_delete BEFORE DELETE ON remote_rename_objects
WHEN sync_remote_rename_write('final')!=1
BEGIN SELECT RAISE(ABORT,'remote Rename private final pin release required'); END;
CREATE TRIGGER remote_rename_headers_update BEFORE UPDATE ON remote_rename_headers
BEGIN SELECT RAISE(ABORT,'remote Rename immutable original receipt'); END;
CREATE TRIGGER remote_rename_headers_delete BEFORE DELETE ON remote_rename_headers
BEGIN SELECT RAISE(ABORT,'remote Rename immutable original receipt'); END;
CREATE TRIGGER remote_rename_phases_update BEFORE UPDATE ON remote_rename_phases
BEGIN SELECT RAISE(ABORT,'remote Rename immutable original receipt'); END;
CREATE TRIGGER remote_rename_phases_delete BEFORE DELETE ON remote_rename_phases
BEGIN SELECT RAISE(ABORT,'remote Rename immutable original receipt'); END;
CREATE TRIGGER remote_rename_objects_update BEFORE UPDATE ON remote_rename_objects
BEGIN SELECT RAISE(ABORT,'remote Rename immutable original pin'); END;
CREATE TRIGGER remote_rename_writer_operations_insert BEFORE INSERT ON operations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_operations_update BEFORE UPDATE ON operations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_operations_delete BEFORE DELETE ON operations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_current_manifests_insert BEFORE INSERT ON current_manifests
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_current_manifests_update BEFORE UPDATE ON current_manifests
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_current_manifests_delete BEFORE DELETE ON current_manifests
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_snapshots_insert BEFORE INSERT ON snapshots
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_snapshots_update BEFORE UPDATE ON snapshots
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_snapshots_delete BEFORE DELETE ON snapshots
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_snapshot_objects_insert BEFORE INSERT ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_snapshot_objects_update BEFORE UPDATE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_snapshot_objects_delete BEFORE DELETE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_rename_observations_insert BEFORE INSERT ON rename_observations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_rename_observations_update BEFORE UPDATE ON rename_observations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_rename_observations_delete BEFORE DELETE ON rename_observations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_publications_insert BEFORE INSERT ON publications
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_publications_update BEFORE UPDATE ON publications
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_publications_delete BEFORE DELETE ON publications
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_mutations_insert BEFORE INSERT ON mutations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_mutations_update BEFORE UPDATE ON mutations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_mutations_delete BEFORE DELETE ON mutations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_local_state_insert BEFORE INSERT ON local_state
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_local_state_update BEFORE UPDATE ON local_state
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_local_state_delete BEFORE DELETE ON local_state
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_tree_restore_preparations_insert BEFORE INSERT ON tree_restore_preparations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_tree_restore_preparations_update BEFORE UPDATE ON tree_restore_preparations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
CREATE TRIGGER remote_rename_writer_tree_restore_preparations_delete BEFORE DELETE ON tree_restore_preparations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'original remote Rename owns writer gate'); END;
PRAGMA user_version=39;
CREATE TRIGGER remote_rename_pruning_guard BEFORE INSERT ON snapshot_prunings
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NEW.snapshot_id=h.baseline_root OR
 NEW.snapshot_id=json_extract(h.header,'$.target_root'))
BEGIN SELECT RAISE(ABORT,'snapshot retained by original remote Rename'); END;
CREATE TRIGGER remote_rename_retained_snapshot_update BEFORE UPDATE OF snapshot_id,space_id,manifest,created_at_ms,state ON snapshots
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE OLD.snapshot_id=h.baseline_root OR OLD.snapshot_id=json_extract(h.header,'$.target_root'))
BEGIN SELECT RAISE(ABORT,'remote Rename retained snapshot immutable'); END;
CREATE TRIGGER remote_rename_retained_snapshot_delete BEFORE DELETE ON snapshots
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE OLD.snapshot_id=h.baseline_root OR OLD.snapshot_id=json_extract(h.header,'$.target_root'))
BEGIN SELECT RAISE(ABORT,'remote Rename retained snapshot cannot be removed'); END;
CREATE TRIGGER remote_rename_retained_operation_update BEFORE UPDATE ON operations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h JOIN remote_rename_phases p ON p.transaction_id=h.transaction_id AND p.phase='final'
 WHERE OLD.op_id=json_extract(h.header,'$.proof.operation.op_id') AND OLD.state='materialized')
BEGIN SELECT RAISE(ABORT,'remote Rename final original operation immutable'); END;
CREATE TRIGGER remote_rename_retained_operation_delete BEFORE DELETE ON operations
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE OLD.op_id=json_extract(h.header,'$.proof.operation.op_id'))
BEGIN SELECT RAISE(ABORT,'remote Rename original operation retained'); END;
CREATE TRIGGER remote_rename_writer_receive_cursors_insert BEFORE INSERT ON receive_cursors
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'remote Rename never advances received cursor'); END;
CREATE TRIGGER remote_rename_writer_receive_cursors_update BEFORE UPDATE ON receive_cursors
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'remote Rename never advances received cursor'); END;
CREATE TRIGGER remote_rename_writer_receive_cursors_delete BEFORE DELETE ON receive_cursors
WHEN EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS
 (SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final'))
BEGIN SELECT RAISE(ABORT,'remote Rename never advances received cursor'); END;
