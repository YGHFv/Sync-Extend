-- Prospective local own-prefix only; no native, Final, cancellation or release.
CREATE TABLE conflict_resolution_admissions (
 transaction_id TEXT NOT NULL PRIMARY KEY,
 space_id TEXT NOT NULL,
 resolver_device TEXT NOT NULL,
 plan_fingerprint TEXT NOT NULL,
 baseline_root TEXT NOT NULL,
 root_identity TEXT NOT NULL,
 header_hash TEXT NOT NULL,
 header TEXT NOT NULL
) STRICT;
CREATE TABLE conflict_resolution_signatures (
 transaction_id TEXT NOT NULL REFERENCES conflict_resolution_admissions(transaction_id),
 role TEXT NOT NULL CHECK(role IN ('original','resolving')),
 op_id TEXT NOT NULL,
 proof TEXT NOT NULL,
 PRIMARY KEY(transaction_id,role,op_id)
) STRICT;
CREATE TABLE conflict_resolution_sequences (
 transaction_id TEXT NOT NULL PRIMARY KEY REFERENCES conflict_resolution_admissions(transaction_id),
 device_id TEXT NOT NULL UNIQUE,
 first_sequence INTEGER NOT NULL CHECK(first_sequence>0),
 last_sequence INTEGER NOT NULL CHECK(last_sequence>=first_sequence)
) STRICT;
CREATE TABLE conflict_resolution_objects (
 transaction_id TEXT NOT NULL REFERENCES conflict_resolution_admissions(transaction_id),
 role TEXT NOT NULL CHECK(role IN ('original','projected')),
 content_id TEXT NOT NULL,
 length INTEGER NOT NULL CHECK(length>0 AND length<=4194304),
 PRIMARY KEY(transaction_id,role,content_id)
) STRICT;
CREATE TRIGGER conflict_resolution_admissions_insert BEFORE INSERT ON conflict_resolution_admissions
WHEN sync_conflict_resolution_issue('admissions',NEW.transaction_id,NEW.space_id,NEW.resolver_device,NEW.plan_fingerprint,NEW.baseline_root,NEW.root_identity,NEW.header_hash,NEW.header)!=1 OR EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'exact private conflict resolution issuance required'); END;
CREATE TRIGGER conflict_resolution_admissions_update BEFORE UPDATE ON conflict_resolution_admissions
BEGIN SELECT RAISE(ABORT,'immutable prospective conflict resolution retained'); END;
CREATE TRIGGER conflict_resolution_admissions_delete BEFORE DELETE ON conflict_resolution_admissions
BEGIN SELECT RAISE(ABORT,'immutable prospective conflict resolution retained'); END;
CREATE TRIGGER conflict_resolution_signatures_insert BEFORE INSERT ON conflict_resolution_signatures
WHEN sync_conflict_resolution_issue('signatures',NEW.transaction_id,NEW.role,NEW.op_id,NEW.proof)!=1
BEGIN SELECT RAISE(ABORT,'exact private conflict resolution issuance required'); END;
CREATE TRIGGER conflict_resolution_signatures_update BEFORE UPDATE ON conflict_resolution_signatures
BEGIN SELECT RAISE(ABORT,'immutable prospective conflict resolution retained'); END;
CREATE TRIGGER conflict_resolution_signatures_delete BEFORE DELETE ON conflict_resolution_signatures
BEGIN SELECT RAISE(ABORT,'immutable prospective conflict resolution retained'); END;
CREATE TRIGGER conflict_resolution_sequences_insert BEFORE INSERT ON conflict_resolution_sequences
WHEN sync_conflict_resolution_issue('sequences',NEW.transaction_id,NEW.device_id,NEW.first_sequence,NEW.last_sequence)!=1
BEGIN SELECT RAISE(ABORT,'exact private conflict resolution issuance required'); END;
CREATE TRIGGER conflict_resolution_sequences_update BEFORE UPDATE ON conflict_resolution_sequences
BEGIN SELECT RAISE(ABORT,'immutable prospective conflict resolution retained'); END;
CREATE TRIGGER conflict_resolution_sequences_delete BEFORE DELETE ON conflict_resolution_sequences
BEGIN SELECT RAISE(ABORT,'immutable prospective conflict resolution retained'); END;
CREATE TRIGGER conflict_resolution_objects_insert BEFORE INSERT ON conflict_resolution_objects
WHEN sync_conflict_resolution_issue('objects',NEW.transaction_id,NEW.role,NEW.content_id,NEW.length)!=1
BEGIN SELECT RAISE(ABORT,'exact private conflict resolution issuance required'); END;
CREATE TRIGGER conflict_resolution_objects_update BEFORE UPDATE ON conflict_resolution_objects
BEGIN SELECT RAISE(ABORT,'immutable prospective conflict resolution retained'); END;
CREATE TRIGGER conflict_resolution_objects_delete BEFORE DELETE ON conflict_resolution_objects
BEGIN SELECT RAISE(ABORT,'immutable prospective conflict resolution retained'); END;
CREATE TRIGGER conflict_resolution_writer_operations_insert BEFORE INSERT ON operations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_operations_update BEFORE UPDATE ON operations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_operations_delete BEFORE DELETE ON operations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_receive_cursors_insert BEFORE INSERT ON receive_cursors
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_receive_cursors_update BEFORE UPDATE ON receive_cursors
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_receive_cursors_delete BEFORE DELETE ON receive_cursors
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_current_manifests_insert BEFORE INSERT ON current_manifests
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_current_manifests_update BEFORE UPDATE ON current_manifests
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_current_manifests_delete BEFORE DELETE ON current_manifests
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_snapshots_insert BEFORE INSERT ON snapshots
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_snapshots_update BEFORE UPDATE ON snapshots
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_snapshots_delete BEFORE DELETE ON snapshots
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_snapshot_objects_insert BEFORE INSERT ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_snapshot_objects_update BEFORE UPDATE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_snapshot_objects_delete BEFORE DELETE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_rename_observations_insert BEFORE INSERT ON rename_observations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_rename_observations_update BEFORE UPDATE ON rename_observations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_rename_observations_delete BEFORE DELETE ON rename_observations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_local_state_insert BEFORE INSERT ON local_state
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_local_state_update BEFORE UPDATE ON local_state
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_local_state_delete BEFORE DELETE ON local_state
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_publications_insert BEFORE INSERT ON publications
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_publications_update BEFORE UPDATE ON publications
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_publications_delete BEFORE DELETE ON publications
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_mutations_insert BEFORE INSERT ON mutations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_mutations_update BEFORE UPDATE ON mutations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_mutations_delete BEFORE DELETE ON mutations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_cleanup_plans_insert BEFORE INSERT ON cleanup_plans
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_cleanup_plans_update BEFORE UPDATE ON cleanup_plans
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_cleanup_plans_delete BEFORE DELETE ON cleanup_plans
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_snapshot_prunings_insert BEFORE INSERT ON snapshot_prunings
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_snapshot_prunings_update BEFORE UPDATE ON snapshot_prunings
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_snapshot_prunings_delete BEFORE DELETE ON snapshot_prunings
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_tree_restore_preparations_insert BEFORE INSERT ON tree_restore_preparations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_tree_restore_preparations_update BEFORE UPDATE ON tree_restore_preparations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_tree_restore_preparations_delete BEFORE DELETE ON tree_restore_preparations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_tree_restore_histories_insert BEFORE INSERT ON tree_restore_histories
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_tree_restore_histories_update BEFORE UPDATE ON tree_restore_histories
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_tree_restore_histories_delete BEFORE DELETE ON tree_restore_histories
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_tree_restore_cancellations_insert BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_tree_restore_cancellations_update BEFORE UPDATE ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_tree_restore_cancellations_delete BEFORE DELETE ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_remote_rename_headers_insert BEFORE INSERT ON remote_rename_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_remote_rename_headers_update BEFORE UPDATE ON remote_rename_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_remote_rename_headers_delete BEFORE DELETE ON remote_rename_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_remote_delete_headers_insert BEFORE INSERT ON remote_delete_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_remote_delete_headers_update BEFORE UPDATE ON remote_delete_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_remote_delete_headers_delete BEFORE DELETE ON remote_delete_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_remote_replace_headers_insert BEFORE INSERT ON remote_replace_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_remote_replace_headers_update BEFORE UPDATE ON remote_replace_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_remote_replace_headers_delete BEFORE DELETE ON remote_replace_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_native_publication_headers_insert BEFORE INSERT ON native_publication_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_native_publication_headers_update BEFORE UPDATE ON native_publication_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_writer_native_publication_headers_delete BEFORE DELETE ON native_publication_headers
WHEN EXISTS(SELECT 1 FROM conflict_resolution_admissions)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution owns writer gate'); END;
CREATE TRIGGER conflict_resolution_objects_gc_invalidate AFTER INSERT ON conflict_resolution_objects
BEGIN INSERT OR IGNORE INTO gc_invalidations(mark_id)
 SELECT mark_id FROM gc_marks m WHERE content_id=NEW.content_id
 AND NOT EXISTS(SELECT 1 FROM gc_cancellations c WHERE c.mark_id=m.mark_id);
END;
CREATE TRIGGER conflict_resolution_objects_gc_execution BEFORE INSERT ON conflict_resolution_objects
WHEN EXISTS(SELECT 1 FROM gc_executions e WHERE e.content_id=NEW.content_id
 AND NOT EXISTS(SELECT 1 FROM gc_execution_aborts a WHERE a.execution_id=e.execution_id))
BEGIN SELECT RAISE(ABORT,'conflict branch has unfinished GC execution'); END;
CREATE TRIGGER conflict_resolution_gc_marks_guard BEFORE INSERT ON gc_marks
WHEN EXISTS(SELECT 1 FROM conflict_resolution_objects WHERE content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution branch pinned'); END;
CREATE TRIGGER conflict_resolution_gc_executions_guard BEFORE INSERT ON gc_executions
WHEN EXISTS(SELECT 1 FROM conflict_resolution_objects WHERE content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'prospective conflict resolution branch pinned'); END;
PRAGMA user_version=42;
