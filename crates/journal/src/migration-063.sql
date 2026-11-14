-- Restored payload requires independently closed original marker before fence release.
CREATE TABLE storage_retirement_terminal_events (
    request_id TEXT NOT NULL REFERENCES storage_retirement_owner_creations(request_id),
    step INTEGER NOT NULL CHECK(step BETWEEN 0 AND 1),
    kind TEXT NOT NULL CHECK(kind IN ('restored_cleanup_requested','restored_closed')),
    event_hash TEXT NOT NULL CHECK(length(event_hash)=64),
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
    PRIMARY KEY(request_id,step)
) STRICT;
CREATE TRIGGER storage_retirement_terminal_insert BEFORE INSERT ON storage_retirement_terminal_events
WHEN NOT sync_storage_retirement_terminal_issue(NEW.event_hash,NEW.recorded_at_ms)
OR NEW.step IS NOT (SELECT count(*) FROM storage_retirement_terminal_events WHERE request_id=NEW.request_id)
OR NEW.kind IS NOT CASE NEW.step WHEN 0 THEN 'restored_cleanup_requested' WHEN 1 THEN 'restored_closed' END
OR NOT EXISTS(SELECT 1 FROM storage_retirement_payload_events WHERE request_id=NEW.request_id AND step=3)
OR EXISTS(SELECT 1 FROM storage_retirement_disposal_events WHERE request_id=NEW.request_id)
OR EXISTS(SELECT 1 FROM storage_retirement_cancellations WHERE request_id=NEW.request_id)
OR NOT EXISTS(SELECT 1 FROM storage_retirement_clock WHERE singleton=1 AND observed_at_ms=NEW.recorded_at_ms)
OR EXISTS(SELECT 1 FROM storage_retirement_terminal_events WHERE request_id=NEW.request_id AND recorded_at_ms>NEW.recorded_at_ms)
BEGIN SELECT RAISE(ABORT,'invalid exact restored storage terminal issuance'); END;
CREATE TRIGGER storage_retirement_terminal_immutable BEFORE UPDATE ON storage_retirement_terminal_events
BEGIN SELECT RAISE(ABORT,'storage terminal immutable'); END;
CREATE TRIGGER storage_retirement_terminal_no_delete BEFORE DELETE ON storage_retirement_terminal_events
BEGIN SELECT RAISE(ABORT,'storage terminal retained'); END;
DROP TRIGGER storage_retirement_owner_cancel_refusal;
CREATE TRIGGER storage_retirement_terminal_cancel_refusal BEFORE INSERT ON storage_retirement_cancellations
WHEN EXISTS(SELECT 1 FROM storage_retirement_owner_activations WHERE request_id=NEW.request_id)
AND NOT EXISTS(SELECT 1 FROM storage_retirement_disposal_events
    WHERE request_id=NEW.request_id AND step=3 AND kind='closed' AND recorded_at_ms<=NEW.cancelled_at_ms)
AND NOT EXISTS(SELECT 1 FROM storage_retirement_terminal_events
    WHERE request_id=NEW.request_id AND step=1 AND kind='restored_closed' AND recorded_at_ms<=NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'storage exact native terminal required before fence release'); END;
PRAGMA user_version=63;
