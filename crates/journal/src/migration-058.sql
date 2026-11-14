-- Exact snapshot owner handoff requires all explicit signed replacement storage receipts.
CREATE TABLE storage_snapshot_handoffs (
 owner_id TEXT NOT NULL PRIMARY KEY REFERENCES reference_reservations(owner_id),
 space_id TEXT NOT NULL,
 storage_id TEXT NOT NULL,
 record_hash TEXT NOT NULL,
 handed_off_at_ms INTEGER NOT NULL,
 record TEXT NOT NULL
) STRICT;
CREATE TRIGGER storage_snapshot_handoffs_insert BEFORE INSERT ON storage_snapshot_handoffs
WHEN NOT sync_storage_handoff_issue(NEW.owner_id,NEW.space_id,NEW.storage_id,NEW.record_hash,NEW.handed_off_at_ms,NEW.record)
BEGIN SELECT RAISE(ABORT,'exact signed replacement storage receipt required'); END;
CREATE TRIGGER storage_snapshot_handoffs_update BEFORE UPDATE ON storage_snapshot_handoffs
BEGIN SELECT RAISE(ABORT,'immutable storage snapshot handoff'); END;
CREATE TRIGGER storage_snapshot_handoffs_delete BEFORE DELETE ON storage_snapshot_handoffs
BEGIN SELECT RAISE(ABORT,'retained storage snapshot handoff'); END;
CREATE TRIGGER storage_snapshot_handoff_no_pin BEFORE INSERT ON reference_reservation_objects
WHEN EXISTS(SELECT 1 FROM storage_snapshot_handoffs WHERE owner_id=NEW.owner_id)
BEGIN SELECT RAISE(ABORT,'storage snapshot handoff is terminal'); END;
PRAGMA user_version=58;
