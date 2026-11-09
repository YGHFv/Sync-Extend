DROP TRIGGER conflict_resolution_objects_delete;
CREATE TRIGGER conflict_resolution_objects_delete BEFORE DELETE ON conflict_resolution_objects
WHEN sync_conflict_resolution_final('conflict_resolution_objects','delete',OLD.transaction_id,OLD.role,OLD.content_id,OLD.length)!=1
BEGIN SELECT RAISE(ABORT,'exact original complete history release required'); END;
DROP TRIGGER reference_reservation_pin_no_delete;
CREATE TRIGGER reference_reservation_pin_no_delete BEFORE DELETE ON reference_reservation_objects
WHEN NOT EXISTS(SELECT 1 FROM reference_snapshot_handoffs WHERE owner_id=OLD.owner_id)
AND sync_conflict_resolution_final('reference_reservation_objects','delete',OLD.owner_id,OLD.content_id)!=1
BEGIN SELECT RAISE(ABORT,'reference reservation release is unavailable'); END;
CREATE TRIGGER conflict_history_no_repin BEFORE INSERT ON reference_reservation_objects
WHEN EXISTS(SELECT 1 FROM conflict_resolution_native_branch_handoffs b
 JOIN conflict_resolution_native_phases p ON p.transaction_id=b.transaction_id AND p.phase='history_handoff'
 WHERE b.owner_id=NEW.owner_id)
BEGIN SELECT RAISE(ABORT,'complete conflict history handoff is terminal'); END;
CREATE TRIGGER conflict_history_objects_gc_mark BEFORE INSERT ON gc_marks
WHEN EXISTS(SELECT 1 FROM conflict_resolution_native_history_objects WHERE content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'original complete conflict history pinned'); END;
CREATE TRIGGER conflict_history_objects_gc_execution BEFORE INSERT ON gc_executions
WHEN EXISTS(SELECT 1 FROM conflict_resolution_native_history_objects WHERE content_id=NEW.content_id)
BEGIN SELECT RAISE(ABORT,'original complete conflict history pinned'); END;
PRAGMA user_version=46;
