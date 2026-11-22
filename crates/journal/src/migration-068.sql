-- Independent Unix immutable admission and finite cancellation. No native effects.
CREATE TABLE unix_storage_retirement_v1_requests (
    request_id TEXT PRIMARY KEY NOT NULL CHECK(length(request_id)=32),
    space_id TEXT NOT NULL CHECK(length(space_id)=32),
    storage_id TEXT NOT NULL CHECK(length(storage_id)=64),
    owner_id TEXT NOT NULL REFERENCES reference_reservations(owner_id) CHECK(length(owner_id)=32),
    device_id TEXT NOT NULL CHECK(length(device_id)=64),
    policy_hash TEXT NOT NULL CHECK(length(policy_hash)=64),
    content_id TEXT NOT NULL CHECK(length(content_id)=64),
    metadata_hash TEXT NOT NULL CHECK(length(metadata_hash)=64),
    binding_hash TEXT NOT NULL CHECK(length(binding_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    requested_at_ms INTEGER NOT NULL CHECK(requested_at_ms>=0),
    grace_until_ms INTEGER NOT NULL CHECK(grace_until_ms>requested_at_ms),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>grace_until_ms),
    admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms>=grace_until_ms AND admitted_at_ms<expires_at_ms),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16384 AND json_valid(request)),
    config TEXT NOT NULL CHECK(length(CAST(config AS BLOB)) BETWEEN 1 AND 16777216 AND json_valid(config))
) STRICT;
CREATE TABLE unix_storage_retirement_v1_clock (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0)
) STRICT;
CREATE TABLE unix_storage_retirement_v1_cancellations (
    request_id TEXT PRIMARY KEY NOT NULL REFERENCES unix_storage_retirement_v1_requests(request_id) CHECK(length(request_id)=32),
    cancelled_at_ms INTEGER NOT NULL CHECK(cancelled_at_ms>=0)
) STRICT;
CREATE INDEX unix_storage_retirement_v1_content ON unix_storage_retirement_v1_requests(content_id);
CREATE TRIGGER unix_storage_retirement_v1_request_insert BEFORE INSERT ON unix_storage_retirement_v1_requests
WHEN NOT sync_unix_storage_retirement_issue(NEW.request_hash,NEW.admitted_at_ms)
OR (SELECT count(*) FROM main.local_state)!=3
OR NOT EXISTS(SELECT 1 FROM main.local_state WHERE key='storage_role' AND value='storage-v1')
OR NOT EXISTS(SELECT 1 FROM main.local_state WHERE key='space_id' AND value=NEW.space_id)
OR NOT EXISTS(SELECT 1 FROM main.local_state WHERE key='device_id' AND value=NEW.device_id)
OR NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_clock WHERE singleton=1 AND observed_at_ms=NEW.admitted_at_ms)
OR EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
OR EXISTS(SELECT 1 FROM main.storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.storage_retirement_cancellations c WHERE c.request_id=r.request_id))
OR NOT EXISTS(SELECT 1 FROM main.reference_reservations r WHERE r.owner_id=NEW.owner_id AND r.space_id=NEW.space_id)
OR (EXISTS(SELECT 1 FROM main.storage_page_handoffs h WHERE h.owner_id=NEW.owner_id AND h.storage_id=NEW.storage_id)
    + EXISTS(SELECT 1 FROM main.storage_snapshot_handoffs h WHERE h.owner_id=NEW.owner_id AND h.storage_id=NEW.storage_id))!=1
OR EXISTS(SELECT 1 FROM main.snapshot_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.publication_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.mutation_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.read_lease_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.reference_reservation_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.tree_restore_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.tree_restore_original_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.remote_replace_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.conflict_resolution_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_history_objects WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.gc_marks WHERE content_id=NEW.content_id)
OR EXISTS(SELECT 1 FROM main.gc_executions WHERE content_id=NEW.content_id)
OR json_extract(NEW.request,'$.type') IS NOT 'unix_storage_retirement_request_v1'
OR json_extract(NEW.request,'$.format_version') IS NOT 1
OR json_extract(NEW.request,'$.binding.format_version') IS NOT 1
OR json_extract(NEW.request,'$.space_id') IS NOT NEW.space_id
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
BEGIN SELECT RAISE(ABORT,'invalid original Unix storage retirement admission'); END;
CREATE TRIGGER unix_storage_retirement_v1_request_immutable BEFORE UPDATE ON unix_storage_retirement_v1_requests
BEGIN SELECT RAISE(ABORT,'Unix storage retirement request immutable'); END;
CREATE TRIGGER unix_storage_retirement_v1_request_no_delete BEFORE DELETE ON unix_storage_retirement_v1_requests
BEGIN SELECT RAISE(ABORT,'Unix storage retirement metadata retained'); END;
CREATE TRIGGER unix_storage_retirement_v1_clock_insert BEFORE INSERT ON unix_storage_retirement_v1_clock
WHEN NOT sync_unix_storage_retirement_clock('unix-retirement-clock-v1',NEW.observed_at_ms)
OR EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_clock)
BEGIN SELECT RAISE(ABORT,'Unix storage retirement clock issuance refused'); END;
CREATE TRIGGER unix_storage_retirement_v1_clock_update BEFORE UPDATE ON unix_storage_retirement_v1_clock
WHEN NOT sync_unix_storage_retirement_clock('unix-retirement-clock-v1',NEW.observed_at_ms)
OR NEW.singleton IS NOT OLD.singleton OR NEW.observed_at_ms<OLD.observed_at_ms
BEGIN SELECT RAISE(ABORT,'Unix storage retirement clock rollback or raw update'); END;
CREATE TRIGGER unix_storage_retirement_v1_clock_no_delete BEFORE DELETE ON unix_storage_retirement_v1_clock
BEGIN SELECT RAISE(ABORT,'Unix storage retirement clock retained'); END;
CREATE TRIGGER unix_storage_retirement_v1_cancel_insert BEFORE INSERT ON unix_storage_retirement_v1_cancellations
WHEN NOT sync_unix_storage_retirement_cancel(NEW.request_id,NEW.cancelled_at_ms)
OR NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r
    JOIN main.unix_storage_retirement_v1_clock c ON c.singleton=1
    WHERE r.request_id=NEW.request_id AND r.admitted_at_ms<=NEW.cancelled_at_ms AND c.observed_at_ms=NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'invalid Unix storage retirement cancellation'); END;
CREATE TRIGGER unix_storage_retirement_v1_cancel_immutable BEFORE UPDATE ON unix_storage_retirement_v1_cancellations
BEGIN SELECT RAISE(ABORT,'Unix storage retirement cancellation immutable'); END;
CREATE TRIGGER unix_storage_retirement_v1_cancel_no_delete BEFORE DELETE ON unix_storage_retirement_v1_cancellations
BEGIN SELECT RAISE(ABORT,'Unix storage retirement cancellation retained'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_snapshot_objects_insert BEFORE INSERT ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_snapshot_objects_update BEFORE UPDATE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_publication_objects_insert BEFORE INSERT ON publication_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_publication_objects_update BEFORE UPDATE ON publication_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_mutation_objects_insert BEFORE INSERT ON mutation_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_mutation_objects_update BEFORE UPDATE ON mutation_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_read_lease_objects_insert BEFORE INSERT ON read_lease_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_read_lease_objects_update BEFORE UPDATE ON read_lease_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_reference_reservation_objects_insert BEFORE INSERT ON reference_reservation_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_reference_reservation_objects_update BEFORE UPDATE ON reference_reservation_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_tree_restore_objects_insert BEFORE INSERT ON tree_restore_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_tree_restore_objects_update BEFORE UPDATE ON tree_restore_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_tree_restore_original_objects_insert BEFORE INSERT ON tree_restore_original_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_tree_restore_original_objects_update BEFORE UPDATE ON tree_restore_original_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_remote_replace_objects_insert BEFORE INSERT ON remote_replace_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_remote_replace_objects_update BEFORE UPDATE ON remote_replace_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_conflict_resolution_objects_insert BEFORE INSERT ON conflict_resolution_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_conflict_resolution_objects_update BEFORE UPDATE ON conflict_resolution_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_conflict_resolution_native_history_objects_insert BEFORE INSERT ON conflict_resolution_native_history_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_conflict_resolution_native_history_objects_update BEFORE UPDATE ON conflict_resolution_native_history_objects
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_gc_marks_insert BEFORE INSERT ON gc_marks
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_gc_marks_update BEFORE UPDATE ON gc_marks
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_gc_executions_insert BEFORE INSERT ON gc_executions
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
CREATE TRIGGER unix_storage_retirement_v1_fence_gc_executions_update BEFORE UPDATE ON gc_executions
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by Unix storage retirement'); END;
PRAGMA user_version=68;
