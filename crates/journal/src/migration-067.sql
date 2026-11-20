-- Once scoped native cleanup is terminal, its immutable Delete receipt remains
-- an audit record but no longer keeps historical snapshot CAS objects pinned.
-- Active Delete owners still retain both sides until their filesystem cleanup
-- has reached its durable terminal phase.
DROP TRIGGER remote_delete_pruning_guard;
CREATE TRIGGER remote_delete_pruning_guard BEFORE INSERT ON snapshot_prunings
WHEN EXISTS(
    SELECT 1 FROM remote_delete_headers h
    WHERE (NEW.snapshot_id=h.baseline_root
       OR NEW.snapshot_id=json_extract(h.header,'$.target_root'))
      AND NOT EXISTS(
          SELECT 1 FROM remote_delete_phases p
          WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup'
      )
)
BEGIN SELECT RAISE(ABORT,'active original remote Delete retains snapshot'); END;
PRAGMA user_version=67;
