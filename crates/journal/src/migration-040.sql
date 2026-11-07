-- Original signed Delete: distinct admitted source and one-shot quarantine directories.
CREATE TABLE remote_delete_headers (
 transaction_id TEXT PRIMARY KEY,
 space_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 header_hash TEXT NOT NULL,
 baseline_root TEXT NOT NULL REFERENCES snapshots(snapshot_id),
 reserved_rows INTEGER NOT NULL CHECK(reserved_rows>=0),
 reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),
 header TEXT NOT NULL
) STRICT;
CREATE TRIGGER remote_delete_headers_insert BEFORE INSERT ON remote_delete_headers
WHEN sync_remote_delete_issue('headers',NEW.transaction_id,NEW.space_id,NEW.generation,NEW.header_hash,NEW.baseline_root,NEW.reserved_rows,NEW.reserved_bytes,NEW.header)!=1 OR EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup')) OR EXISTS(SELECT 1 FROM remote_rename_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final')) OR EXISTS(SELECT 1 FROM publications WHERE state!='committed' OR cleaned!=1) OR EXISTS(SELECT 1 FROM mutations WHERE state NOT IN ('cancelled','committed')) OR EXISTS(SELECT 1 FROM tree_restore_preparations t WHERE NOT EXISTS(SELECT 1 FROM tree_restore_cancellations c WHERE c.transaction_id=t.transaction_id))
BEGIN SELECT RAISE(ABORT,'remote Delete exact original private issuance required'); END;
CREATE TRIGGER remote_delete_headers_update BEFORE UPDATE ON remote_delete_headers
BEGIN SELECT RAISE(ABORT,'remote Delete immutable original receipt'); END;
CREATE TRIGGER remote_delete_headers_delete BEFORE DELETE ON remote_delete_headers
BEGIN SELECT RAISE(ABORT,'remote Delete original receipt retained'); END;
CREATE TABLE remote_delete_activations (
 transaction_id TEXT NOT NULL REFERENCES remote_delete_headers(transaction_id),
 generation TEXT NOT NULL,
 step INTEGER NOT NULL CHECK(step IN (0,1)),
 header_hash TEXT NOT NULL,
 component TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind='directory'),
 parent_volume TEXT NOT NULL,
 parent_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,step)
) STRICT;
CREATE TRIGGER remote_delete_activations_insert BEFORE INSERT ON remote_delete_activations
WHEN sync_remote_delete_issue('activations',NEW.transaction_id,NEW.generation,NEW.step,NEW.header_hash,NEW.component,NEW.kind,NEW.parent_volume,NEW.parent_id)!=1
BEGIN SELECT RAISE(ABORT,'remote Delete exact original private issuance required'); END;
CREATE TRIGGER remote_delete_activations_update BEFORE UPDATE ON remote_delete_activations
BEGIN SELECT RAISE(ABORT,'remote Delete immutable original receipt'); END;
CREATE TRIGGER remote_delete_activations_delete BEFORE DELETE ON remote_delete_activations
BEGIN SELECT RAISE(ABORT,'remote Delete original receipt retained'); END;
CREATE TABLE remote_delete_creators (
 transaction_id TEXT NOT NULL REFERENCES remote_delete_headers(transaction_id),
 generation TEXT NOT NULL,
 step INTEGER NOT NULL CHECK(step IN (0,1)),
 header_hash TEXT NOT NULL,
 component TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind='directory'),
 parent_volume TEXT NOT NULL,
 parent_id TEXT NOT NULL,
 volume TEXT NOT NULL,
 full_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,step)
) STRICT;
CREATE TRIGGER remote_delete_creators_insert BEFORE INSERT ON remote_delete_creators
WHEN sync_remote_delete_issue('creators',NEW.transaction_id,NEW.generation,NEW.step,NEW.header_hash,NEW.component,NEW.kind,NEW.parent_volume,NEW.parent_id,NEW.volume,NEW.full_id)!=1
BEGIN SELECT RAISE(ABORT,'remote Delete exact original private issuance required'); END;
CREATE TRIGGER remote_delete_creators_update BEFORE UPDATE ON remote_delete_creators
BEGIN SELECT RAISE(ABORT,'remote Delete immutable original receipt'); END;
CREATE TRIGGER remote_delete_creators_delete BEFORE DELETE ON remote_delete_creators
BEGIN SELECT RAISE(ABORT,'remote Delete original receipt retained'); END;
CREATE TABLE remote_delete_phases (
 transaction_id TEXT NOT NULL REFERENCES remote_delete_headers(transaction_id),
 generation TEXT NOT NULL,
 header_hash TEXT NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('executing','observed','final','cleanup')),
 volume TEXT NOT NULL,
 full_id TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,phase)
) STRICT;
CREATE TRIGGER remote_delete_phases_insert BEFORE INSERT ON remote_delete_phases
WHEN sync_remote_delete_issue('phases',NEW.transaction_id,NEW.generation,NEW.header_hash,NEW.phase,NEW.volume,NEW.full_id,NEW.snapshot_id)!=1
BEGIN SELECT RAISE(ABORT,'remote Delete exact original private issuance required'); END;
CREATE TRIGGER remote_delete_phases_update BEFORE UPDATE ON remote_delete_phases
BEGIN SELECT RAISE(ABORT,'remote Delete immutable original receipt'); END;
CREATE TRIGGER remote_delete_phases_delete BEFORE DELETE ON remote_delete_phases
BEGIN SELECT RAISE(ABORT,'remote Delete original receipt retained'); END;
CREATE TABLE remote_delete_objects (
 transaction_id TEXT NOT NULL REFERENCES remote_delete_headers(transaction_id),
 content_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,content_id)
) STRICT;
CREATE TRIGGER remote_delete_objects_insert BEFORE INSERT ON remote_delete_objects
WHEN sync_remote_delete_issue('objects',NEW.transaction_id,NEW.content_id)!=1 OR EXISTS(SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id AND NOT EXISTS(SELECT 1 FROM gc_execution_aborts a WHERE a.execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'remote Delete exact original private issuance required'); END;
CREATE TRIGGER remote_delete_objects_update BEFORE UPDATE ON remote_delete_objects
BEGIN SELECT RAISE(ABORT,'remote Delete immutable original receipt'); END;
CREATE TRIGGER remote_delete_objects_delete BEFORE DELETE ON remote_delete_objects
WHEN sync_remote_delete_write('cleanup')!=1
BEGIN SELECT RAISE(ABORT,'remote Delete original receipt retained'); END;
CREATE TABLE remote_delete_dispositions (
 transaction_id TEXT NOT NULL REFERENCES remote_delete_headers(transaction_id),
 generation TEXT NOT NULL,
 step INTEGER NOT NULL CHECK(step IN (0,1,2)),
 header_hash TEXT NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('intended','absent','terminal')),
 volume TEXT NOT NULL,
 full_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,step,stage)
) STRICT;
CREATE TRIGGER remote_delete_dispositions_insert BEFORE INSERT ON remote_delete_dispositions
WHEN sync_remote_delete_issue('dispositions',NEW.transaction_id,NEW.generation,NEW.step,NEW.header_hash,NEW.stage,NEW.volume,NEW.full_id)!=1
BEGIN SELECT RAISE(ABORT,'remote Delete exact original private issuance required'); END;
CREATE TRIGGER remote_delete_dispositions_update BEFORE UPDATE ON remote_delete_dispositions
BEGIN SELECT RAISE(ABORT,'remote Delete immutable original receipt'); END;
CREATE TRIGGER remote_delete_dispositions_delete BEFORE DELETE ON remote_delete_dispositions
BEGIN SELECT RAISE(ABORT,'remote Delete original receipt retained'); END;
CREATE TRIGGER remote_delete_writer_operations_insert BEFORE INSERT ON operations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_operations_update BEFORE UPDATE ON operations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup')) AND NOT EXISTS(SELECT 1 FROM remote_delete_headers h JOIN remote_delete_phases p ON p.transaction_id=h.transaction_id AND p.phase='final' WHERE OLD.op_id=json_extract(h.header,'$.proof.operation.op_id') AND OLD.state='received' AND NEW.state='materialized' AND NEW.op_id=OLD.op_id AND NEW.space_id=OLD.space_id AND NEW.origin_device_id=OLD.origin_device_id AND NEW.origin_seq=OLD.origin_seq AND NEW.payload=OLD.payload)
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_operations_delete BEFORE DELETE ON operations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_current_manifests_insert BEFORE INSERT ON current_manifests
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_current_manifests_update BEFORE UPDATE ON current_manifests
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup')) AND NOT EXISTS(SELECT 1 FROM remote_delete_headers h JOIN remote_delete_phases p ON p.transaction_id=h.transaction_id AND p.phase='final' WHERE OLD.space_id=h.space_id AND NEW.space_id=OLD.space_id AND OLD.snapshot_id=h.baseline_root AND NEW.snapshot_id=json_extract(h.header,'$.target_root'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_current_manifests_delete BEFORE DELETE ON current_manifests
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_snapshots_insert BEFORE INSERT ON snapshots
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup')) AND NOT EXISTS(SELECT 1 FROM remote_delete_headers h JOIN remote_delete_phases p ON p.transaction_id=h.transaction_id AND p.phase='final' WHERE NEW.snapshot_id=json_extract(h.header,'$.target_root') AND NEW.space_id=h.space_id AND json(NEW.manifest)=json(json_extract(h.header,'$.target')) AND NEW.state='materialized' AND NEW.locked=0 AND NEW.created_at_ms=json_extract(h.header,'$.proof.operation.payload.created_at_ms'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_snapshots_update BEFORE UPDATE ON snapshots
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_snapshots_delete BEFORE DELETE ON snapshots
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_snapshot_objects_insert BEFORE INSERT ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup')) AND NOT EXISTS(SELECT 1 FROM remote_delete_headers h JOIN remote_delete_phases p ON p.transaction_id=h.transaction_id AND p.phase='final' WHERE NEW.snapshot_id=json_extract(h.header,'$.target_root') AND EXISTS(SELECT 1 FROM json_each(h.header,'$.target.entries') e,json_each(e.value,'$.content.chunks') c WHERE NEW.content_id=json_extract(c.value,'$.content_id')))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_snapshot_objects_update BEFORE UPDATE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_snapshot_objects_delete BEFORE DELETE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_rename_observations_insert BEFORE INSERT ON rename_observations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_rename_observations_update BEFORE UPDATE ON rename_observations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_rename_observations_delete BEFORE DELETE ON rename_observations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup')) AND NOT EXISTS(SELECT 1 FROM remote_delete_headers h JOIN remote_delete_phases p ON p.transaction_id=h.transaction_id AND p.phase='final' WHERE OLD.space_id=h.space_id)
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_publications_insert BEFORE INSERT ON publications
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_publications_update BEFORE UPDATE ON publications
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_publications_delete BEFORE DELETE ON publications
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_mutations_insert BEFORE INSERT ON mutations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_mutations_update BEFORE UPDATE ON mutations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_mutations_delete BEFORE DELETE ON mutations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_local_state_insert BEFORE INSERT ON local_state
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_local_state_update BEFORE UPDATE ON local_state
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_local_state_delete BEFORE DELETE ON local_state
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_tree_restore_preparations_insert BEFORE INSERT ON tree_restore_preparations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_tree_restore_preparations_update BEFORE UPDATE ON tree_restore_preparations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_tree_restore_preparations_delete BEFORE DELETE ON tree_restore_preparations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_receive_cursors_insert BEFORE INSERT ON receive_cursors
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_receive_cursors_update BEFORE UPDATE ON receive_cursors
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_receive_cursors_delete BEFORE DELETE ON receive_cursors
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_remote_rename_headers_insert BEFORE INSERT ON remote_rename_headers
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_remote_rename_headers_update BEFORE UPDATE ON remote_rename_headers
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_writer_remote_rename_headers_delete BEFORE DELETE ON remote_rename_headers
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NOT EXISTS(SELECT 1 FROM remote_delete_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'))
BEGIN SELECT RAISE(ABORT,'original remote Delete owns writer gate'); END;
CREATE TRIGGER remote_delete_pruning_guard BEFORE INSERT ON snapshot_prunings
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE NEW.snapshot_id=h.baseline_root OR NEW.snapshot_id=json_extract(h.header,'$.target_root'))
BEGIN SELECT RAISE(ABORT,'snapshot retained by original remote Delete'); END;
CREATE TRIGGER remote_delete_retained_snapshot_update BEFORE UPDATE OF snapshot_id,space_id,manifest,created_at_ms,state ON snapshots
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE OLD.snapshot_id=h.baseline_root OR OLD.snapshot_id=json_extract(h.header,'$.target_root'))
BEGIN SELECT RAISE(ABORT,'remote Delete retained snapshot immutable'); END;
CREATE TRIGGER remote_delete_retained_snapshot_delete BEFORE DELETE ON snapshots
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE OLD.snapshot_id=h.baseline_root OR OLD.snapshot_id=json_extract(h.header,'$.target_root'))
BEGIN SELECT RAISE(ABORT,'remote Delete retained snapshot cannot be removed'); END;
CREATE TRIGGER remote_delete_retained_operation_update BEFORE UPDATE ON operations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h JOIN remote_delete_phases p ON p.transaction_id=h.transaction_id AND p.phase='final' WHERE OLD.op_id=json_extract(h.header,'$.proof.operation.op_id') AND OLD.state='materialized')
BEGIN SELECT RAISE(ABORT,'remote Delete final original operation immutable'); END;
CREATE TRIGGER remote_delete_retained_operation_delete BEFORE DELETE ON operations
WHEN EXISTS(SELECT 1 FROM remote_delete_headers h WHERE OLD.op_id=json_extract(h.header,'$.proof.operation.op_id'))
BEGIN SELECT RAISE(ABORT,'remote Delete original operation retained'); END;
PRAGMA user_version=40;
