-- Separate durable payload delete request/absence and original marker cleanup.
CREATE TABLE storage_retirement_disposal_events (
    request_id TEXT NOT NULL REFERENCES storage_retirement_owner_creations(request_id),
    step INTEGER NOT NULL CHECK(step BETWEEN 0 AND 3),
    kind TEXT NOT NULL CHECK(kind IN ('delete_requested','deleted','marker_cleanup_requested','closed')),
    event_hash TEXT NOT NULL CHECK(length(event_hash)=64),
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
    PRIMARY KEY(request_id,step)
) STRICT;
CREATE TRIGGER storage_retirement_disposal_insert BEFORE INSERT ON storage_retirement_disposal_events
WHEN NOT sync_storage_retirement_disposal_issue(NEW.event_hash,NEW.recorded_at_ms)
OR NEW.step IS NOT (SELECT count(*) FROM storage_retirement_disposal_events WHERE request_id=NEW.request_id)
OR NEW.kind IS NOT CASE NEW.step WHEN 0 THEN 'delete_requested' WHEN 1 THEN 'deleted'
    WHEN 2 THEN 'marker_cleanup_requested' WHEN 3 THEN 'closed' END
OR NOT EXISTS(SELECT 1 FROM storage_retirement_requests r JOIN storage_retirement_clock k ON k.singleton=1
    WHERE r.request_id=NEW.request_id AND k.observed_at_ms=NEW.recorded_at_ms
    AND (NEW.step!=0 OR NEW.recorded_at_ms<r.expires_at_ms))
OR NOT EXISTS(SELECT 1 FROM storage_retirement_payload_events WHERE request_id=NEW.request_id AND step=1)
OR EXISTS(SELECT 1 FROM storage_retirement_payload_events WHERE request_id=NEW.request_id AND step>=2)
OR EXISTS(SELECT 1 FROM storage_retirement_cancellations WHERE request_id=NEW.request_id)
OR EXISTS(SELECT 1 FROM storage_retirement_disposal_events WHERE request_id=NEW.request_id AND recorded_at_ms>NEW.recorded_at_ms)
BEGIN SELECT RAISE(ABORT,'invalid exact storage disposal event issuance'); END;
CREATE TRIGGER storage_retirement_disposal_immutable BEFORE UPDATE ON storage_retirement_disposal_events
BEGIN SELECT RAISE(ABORT,'storage disposal event immutable'); END;
CREATE TRIGGER storage_retirement_disposal_no_delete BEFORE DELETE ON storage_retirement_disposal_events
BEGIN SELECT RAISE(ABORT,'storage disposal event retained'); END;
CREATE TRIGGER storage_retirement_disposal_restore_refusal BEFORE INSERT ON storage_retirement_payload_events
WHEN EXISTS(SELECT 1 FROM storage_retirement_disposal_events WHERE request_id=NEW.request_id)
BEGIN SELECT RAISE(ABORT,'storage delete request prevents later restoration'); END;
PRAGMA user_version=62;
