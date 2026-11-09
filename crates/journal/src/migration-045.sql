DROP TRIGGER conflict_resolution_writer_operations_insert;
CREATE TRIGGER conflict_resolution_writer_operations_insert BEFORE INSERT ON operations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('operations','insert',NEW.op_id,NEW.space_id,NEW.origin_device_id,NEW.origin_seq,NEW.payload,NEW.state)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_operations_update;
CREATE TRIGGER conflict_resolution_writer_operations_update BEFORE UPDATE ON operations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('operations','update',OLD.op_id,OLD.space_id,OLD.origin_device_id,OLD.origin_seq,OLD.payload,OLD.state,NEW.op_id,NEW.space_id,NEW.origin_device_id,NEW.origin_seq,NEW.payload,NEW.state)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_operations_delete;
CREATE TRIGGER conflict_resolution_writer_operations_delete BEFORE DELETE ON operations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('operations','delete',OLD.op_id,OLD.space_id,OLD.origin_device_id,OLD.origin_seq,OLD.payload,OLD.state)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_receive_cursors_insert;
CREATE TRIGGER conflict_resolution_writer_receive_cursors_insert BEFORE INSERT ON receive_cursors
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('receive_cursors','insert',NEW.space_id,NEW.device_id,NEW.contiguous_seq)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_receive_cursors_update;
CREATE TRIGGER conflict_resolution_writer_receive_cursors_update BEFORE UPDATE ON receive_cursors
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('receive_cursors','update',OLD.space_id,OLD.device_id,OLD.contiguous_seq,NEW.space_id,NEW.device_id,NEW.contiguous_seq)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_receive_cursors_delete;
CREATE TRIGGER conflict_resolution_writer_receive_cursors_delete BEFORE DELETE ON receive_cursors
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('receive_cursors','delete',OLD.space_id,OLD.device_id,OLD.contiguous_seq)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_current_manifests_insert;
CREATE TRIGGER conflict_resolution_writer_current_manifests_insert BEFORE INSERT ON current_manifests
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('current_manifests','insert',NEW.space_id,NEW.snapshot_id)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_current_manifests_update;
CREATE TRIGGER conflict_resolution_writer_current_manifests_update BEFORE UPDATE ON current_manifests
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('current_manifests','update',OLD.space_id,OLD.snapshot_id,NEW.space_id,NEW.snapshot_id)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_current_manifests_delete;
CREATE TRIGGER conflict_resolution_writer_current_manifests_delete BEFORE DELETE ON current_manifests
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('current_manifests','delete',OLD.space_id,OLD.snapshot_id)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_snapshots_insert;
CREATE TRIGGER conflict_resolution_writer_snapshots_insert BEFORE INSERT ON snapshots
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('snapshots','insert',NEW.snapshot_id,NEW.space_id,NEW.manifest,NEW.created_at_ms,NEW.state,NEW.locked)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_snapshots_update;
CREATE TRIGGER conflict_resolution_writer_snapshots_update BEFORE UPDATE ON snapshots
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('snapshots','update',OLD.snapshot_id,OLD.space_id,OLD.manifest,OLD.created_at_ms,OLD.state,OLD.locked,NEW.snapshot_id,NEW.space_id,NEW.manifest,NEW.created_at_ms,NEW.state,NEW.locked)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_snapshots_delete;
CREATE TRIGGER conflict_resolution_writer_snapshots_delete BEFORE DELETE ON snapshots
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('snapshots','delete',OLD.snapshot_id,OLD.space_id,OLD.manifest,OLD.created_at_ms,OLD.state,OLD.locked)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_snapshot_objects_insert;
CREATE TRIGGER conflict_resolution_writer_snapshot_objects_insert BEFORE INSERT ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('snapshot_objects','insert',NEW.snapshot_id,NEW.content_id)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_snapshot_objects_update;
CREATE TRIGGER conflict_resolution_writer_snapshot_objects_update BEFORE UPDATE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('snapshot_objects','update',OLD.snapshot_id,OLD.content_id,NEW.snapshot_id,NEW.content_id)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_snapshot_objects_delete;
CREATE TRIGGER conflict_resolution_writer_snapshot_objects_delete BEFORE DELETE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('snapshot_objects','delete',OLD.snapshot_id,OLD.content_id)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_rename_observations_insert;
CREATE TRIGGER conflict_resolution_writer_rename_observations_insert BEFORE INSERT ON rename_observations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('rename_observations','insert',NEW.space_id,NEW.snapshot_id,NEW.observation,NEW.observation_hash)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_rename_observations_update;
CREATE TRIGGER conflict_resolution_writer_rename_observations_update BEFORE UPDATE ON rename_observations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('rename_observations','update',OLD.space_id,OLD.snapshot_id,OLD.observation,OLD.observation_hash,NEW.space_id,NEW.snapshot_id,NEW.observation,NEW.observation_hash)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
DROP TRIGGER conflict_resolution_writer_rename_observations_delete;
CREATE TRIGGER conflict_resolution_writer_rename_observations_delete BEFORE DELETE ON rename_observations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions) AND sync_conflict_resolution_final('rename_observations','delete',OLD.space_id,OLD.snapshot_id,OLD.observation,OLD.observation_hash)!=1
BEGIN SELECT RAISE(ABORT,'exact whole original conflict Final DML required'); END;
PRAGMA user_version=45;
