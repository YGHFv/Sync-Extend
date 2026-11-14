-- Exact storage payload quarantine/restore requests, no delete authority.
CREATE TABLE storage_retirement_payload_events (
    request_id TEXT NOT NULL REFERENCES storage_retirement_owner_creations(request_id),
    step INTEGER NOT NULL CHECK(step BETWEEN 0 AND 3),
    kind TEXT NOT NULL CHECK(kind IN (
        'quarantine_requested','quarantined','restore_requested','restored')),
    event_hash TEXT NOT NULL CHECK(length(event_hash)=64),
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
    PRIMARY KEY(request_id,step)
) STRICT;
CREATE TRIGGER storage_retirement_payload_insert BEFORE INSERT ON storage_retirement_payload_events
WHEN NOT sync_storage_retirement_payload_issue(NEW.event_hash,NEW.recorded_at_ms)
OR NEW.step IS NOT (SELECT count(*) FROM storage_retirement_payload_events WHERE request_id=NEW.request_id)
OR NEW.kind IS NOT CASE NEW.step WHEN 0 THEN 'quarantine_requested' WHEN 1 THEN 'quarantined'
    WHEN 2 THEN 'restore_requested' WHEN 3 THEN 'restored' END
OR NOT EXISTS(SELECT 1 FROM storage_retirement_requests r
    JOIN storage_retirement_owner_creations c USING(request_id)
    JOIN storage_retirement_clock k ON k.singleton=1
    WHERE r.request_id=NEW.request_id AND c.created_at_ms<=NEW.recorded_at_ms
    AND k.observed_at_ms=NEW.recorded_at_ms
    AND (NEW.step!=0 OR NEW.recorded_at_ms<r.expires_at_ms))
OR EXISTS(SELECT 1 FROM storage_retirement_cancellations WHERE request_id=NEW.request_id)
OR EXISTS(SELECT 1 FROM storage_retirement_payload_events
    WHERE request_id=NEW.request_id AND recorded_at_ms>NEW.recorded_at_ms)
BEGIN SELECT RAISE(ABORT,'invalid exact storage payload event issuance'); END;
CREATE TRIGGER storage_retirement_payload_immutable BEFORE UPDATE ON storage_retirement_payload_events
BEGIN SELECT RAISE(ABORT,'storage payload event immutable'); END;
CREATE TRIGGER storage_retirement_payload_no_delete BEFORE DELETE ON storage_retirement_payload_events
BEGIN SELECT RAISE(ABORT,'storage payload event retained'); END;
PRAGMA user_version=61;
