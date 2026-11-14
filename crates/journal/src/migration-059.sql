-- Worktree-free retirement admission fences content; it grants no physical effect.
CREATE TABLE storage_retirement_requests (
    request_id TEXT PRIMARY KEY NOT NULL CHECK(length(request_id)=32),
    space_id TEXT NOT NULL CHECK(length(space_id)=32),
    storage_id TEXT NOT NULL CHECK(length(storage_id)=64),
    owner_id TEXT NOT NULL REFERENCES reference_reservations(owner_id),
    device_id TEXT NOT NULL CHECK(length(device_id)=64),
    policy_hash TEXT NOT NULL CHECK(length(policy_hash)=64),
    content_id TEXT NOT NULL CHECK(length(content_id)=64),
    metadata_hash TEXT NOT NULL CHECK(length(metadata_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    requested_at_ms INTEGER NOT NULL CHECK(requested_at_ms>=0),
    grace_until_ms INTEGER NOT NULL CHECK(grace_until_ms>requested_at_ms),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>grace_until_ms),
    admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms>=grace_until_ms AND admitted_at_ms<expires_at_ms),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16384),
    config TEXT NOT NULL CHECK(length(CAST(config AS BLOB)) BETWEEN 1 AND 16777216)
) STRICT;
CREATE TABLE storage_retirement_clock (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0)
) STRICT;
CREATE TABLE storage_retirement_cancellations (
    request_id TEXT PRIMARY KEY NOT NULL REFERENCES storage_retirement_requests(request_id),
    cancelled_at_ms INTEGER NOT NULL CHECK(cancelled_at_ms>=0)
) STRICT;
CREATE INDEX storage_retirement_content ON storage_retirement_requests(content_id);
CREATE TRIGGER storage_retirement_request_insert BEFORE INSERT ON storage_retirement_requests
WHEN NOT sync_storage_retirement_issue(NEW.request_hash,NEW.admitted_at_ms)
OR NOT EXISTS(SELECT 1 FROM local_state WHERE key='storage_role' AND value='storage-v1')
OR EXISTS(SELECT 1 FROM local_state WHERE key='worktree')
OR NOT EXISTS(SELECT 1 FROM local_state WHERE key='space_id' AND value=NEW.space_id)
OR NOT EXISTS(SELECT 1 FROM local_state WHERE key='device_id' AND value=NEW.device_id)
OR NOT EXISTS(SELECT 1 FROM storage_retirement_clock WHERE singleton=1 AND observed_at_ms=NEW.admitted_at_ms)
OR EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
OR NOT EXISTS(SELECT 1 FROM reference_reservations r WHERE r.owner_id=NEW.owner_id AND r.space_id=NEW.space_id)
OR NOT (EXISTS(SELECT 1 FROM storage_page_handoffs h WHERE h.owner_id=NEW.owner_id AND h.storage_id=NEW.storage_id)
    OR EXISTS(SELECT 1 FROM storage_snapshot_handoffs h WHERE h.owner_id=NEW.owner_id AND h.storage_id=NEW.storage_id))
OR EXISTS(SELECT 1 FROM reference_reservation_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM snapshot_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM publication_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM mutation_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM read_lease_objects WHERE content_id=NEW.content_id)
OR json_extract(NEW.request,'$.request_id') IS NOT NEW.request_id
OR json_extract(NEW.request,'$.original_owner_id') IS NOT NEW.owner_id
OR json_extract(NEW.request,'$.storage_id') IS NOT NEW.storage_id
OR json_extract(NEW.request,'$.content_id') IS NOT NEW.content_id
OR json_extract(NEW.request,'$.storage_device') IS NOT NEW.device_id
OR json_extract(NEW.request,'$.storage_policy') IS NOT NEW.policy_hash
OR json_extract(NEW.request,'$.original_metadata_hash') IS NOT NEW.metadata_hash
OR json_extract(NEW.request,'$.requested_at_ms') IS NOT NEW.requested_at_ms
OR json_extract(NEW.request,'$.grace_until_ms') IS NOT NEW.grace_until_ms
OR json_extract(NEW.request,'$.expires_at_ms') IS NOT NEW.expires_at_ms
BEGIN SELECT RAISE(ABORT,'invalid storage-only retirement admission'); END;
CREATE TRIGGER storage_retirement_request_immutable BEFORE UPDATE ON storage_retirement_requests
BEGIN SELECT RAISE(ABORT,'storage retirement request immutable'); END;
CREATE TRIGGER storage_retirement_request_no_delete BEFORE DELETE ON storage_retirement_requests
BEGIN SELECT RAISE(ABORT,'storage retirement metadata retained'); END;
CREATE TRIGGER storage_retirement_clock_insert BEFORE INSERT ON storage_retirement_clock
WHEN EXISTS(SELECT 1 FROM storage_retirement_clock)
BEGIN SELECT RAISE(ABORT,'storage retirement clock already initialized'); END;
CREATE TRIGGER storage_retirement_clock_update BEFORE UPDATE ON storage_retirement_clock
WHEN NEW.singleton IS NOT OLD.singleton OR NEW.observed_at_ms<OLD.observed_at_ms
BEGIN SELECT RAISE(ABORT,'storage retirement clock rollback'); END;
CREATE TRIGGER storage_retirement_clock_no_delete BEFORE DELETE ON storage_retirement_clock
BEGIN SELECT RAISE(ABORT,'storage retirement clock retained'); END;
CREATE TRIGGER storage_retirement_cancel_insert BEFORE INSERT ON storage_retirement_cancellations
WHEN NOT sync_storage_retirement_cancel(NEW.request_id,NEW.cancelled_at_ms)
OR NOT EXISTS(SELECT 1 FROM storage_retirement_requests r JOIN storage_retirement_clock c ON c.singleton=1
    WHERE r.request_id=NEW.request_id AND r.admitted_at_ms<=NEW.cancelled_at_ms AND c.observed_at_ms=NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'invalid storage retirement cancellation'); END;
CREATE TRIGGER storage_retirement_cancel_immutable BEFORE UPDATE ON storage_retirement_cancellations
BEGIN SELECT RAISE(ABORT,'storage retirement cancellation immutable'); END;
CREATE TRIGGER storage_retirement_cancel_no_delete BEFORE DELETE ON storage_retirement_cancellations
BEGIN SELECT RAISE(ABORT,'storage retirement cancellation retained'); END;
CREATE TRIGGER storage_retirement_fence_snapshot_objects_insert BEFORE INSERT ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_snapshot_objects_update BEFORE UPDATE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_publication_objects_insert BEFORE INSERT ON publication_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_publication_objects_update BEFORE UPDATE ON publication_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_mutation_objects_insert BEFORE INSERT ON mutation_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_mutation_objects_update BEFORE UPDATE ON mutation_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_read_lease_objects_insert BEFORE INSERT ON read_lease_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_read_lease_objects_update BEFORE UPDATE ON read_lease_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_reference_reservation_objects_insert BEFORE INSERT ON reference_reservation_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_reference_reservation_objects_update BEFORE UPDATE ON reference_reservation_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_tree_restore_objects_insert BEFORE INSERT ON tree_restore_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_tree_restore_objects_update BEFORE UPDATE ON tree_restore_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_tree_restore_original_objects_insert BEFORE INSERT ON tree_restore_original_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_tree_restore_original_objects_update BEFORE UPDATE ON tree_restore_original_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_remote_replace_objects_insert BEFORE INSERT ON remote_replace_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_remote_replace_objects_update BEFORE UPDATE ON remote_replace_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_conflict_resolution_objects_insert BEFORE INSERT ON conflict_resolution_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_conflict_resolution_objects_update BEFORE UPDATE ON conflict_resolution_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_conflict_resolution_native_history_objects_insert BEFORE INSERT ON conflict_resolution_native_history_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_conflict_resolution_native_history_objects_update BEFORE UPDATE ON conflict_resolution_native_history_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_gc_marks_insert BEFORE INSERT ON gc_marks
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_gc_marks_update BEFORE UPDATE ON gc_marks
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_gc_executions_insert BEFORE INSERT ON gc_executions
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
CREATE TRIGGER storage_retirement_fence_gc_executions_update BEFORE UPDATE ON gc_executions
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
PRAGMA user_version=59;
