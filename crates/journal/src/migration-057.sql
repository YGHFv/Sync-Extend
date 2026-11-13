-- Exact storage-only original page handoff to all explicitly required applied targets.
CREATE TABLE storage_page_handoffs (
 owner_id TEXT NOT NULL PRIMARY KEY REFERENCES reference_reservations(owner_id),
 space_id TEXT NOT NULL,
 storage_id TEXT NOT NULL,
 record_hash TEXT NOT NULL,
 handed_off_at_ms INTEGER NOT NULL,
 record TEXT NOT NULL
) STRICT;
CREATE TRIGGER storage_page_handoffs_insert BEFORE INSERT ON storage_page_handoffs
WHEN NOT sync_storage_handoff_issue(NEW.owner_id,NEW.space_id,NEW.storage_id,NEW.record_hash,NEW.handed_off_at_ms,NEW.record)
BEGIN SELECT RAISE(ABORT,'exact current storage target receipt issuance required'); END;
CREATE TRIGGER storage_page_handoffs_update BEFORE UPDATE ON storage_page_handoffs
BEGIN SELECT RAISE(ABORT,'immutable storage page handoff'); END;
CREATE TRIGGER storage_page_handoffs_delete BEFORE DELETE ON storage_page_handoffs
BEGIN SELECT RAISE(ABORT,'retained storage page handoff'); END;
DROP TRIGGER reference_reservation_pin_no_delete;
CREATE TRIGGER reference_reservation_pin_no_delete BEFORE DELETE ON reference_reservation_objects
WHEN NOT EXISTS(SELECT 1 FROM reference_snapshot_handoffs WHERE owner_id=OLD.owner_id)
AND sync_conflict_resolution_final('reference_reservation_objects','delete',OLD.owner_id,OLD.content_id)!=1
AND NOT sync_storage_handoff_issue('reference_reservation_objects:delete',OLD.owner_id,OLD.content_id)
BEGIN SELECT RAISE(ABORT,'exact durable replacement owner required'); END;
CREATE TRIGGER storage_handoff_no_pin BEFORE INSERT ON reference_reservation_objects
WHEN EXISTS(SELECT 1 FROM storage_page_handoffs WHERE owner_id=NEW.owner_id)
BEGIN SELECT RAISE(ABORT,'storage page handoff is terminal'); END;
PRAGMA user_version=57;
