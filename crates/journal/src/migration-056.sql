-- Bounded independently signed original/forwarder envelopes for client restart.
CREATE TABLE forwarded_page_inbox (
 request_id TEXT NOT NULL PRIMARY KEY,
 space_id TEXT NOT NULL,
 origin_device_id TEXT NOT NULL,
 forwarding_device_id TEXT NOT NULL,
 receiver_device_id TEXT NOT NULL,
 after_sequence INTEGER NOT NULL,
 last_sequence INTEGER NOT NULL,
 tip_sequence INTEGER NOT NULL,
 envelope_hash TEXT NOT NULL,
 envelope TEXT NOT NULL
) STRICT;
CREATE TRIGGER forwarded_page_inbox_insert BEFORE INSERT ON forwarded_page_inbox
WHEN sync_forwarded_page_issue(NEW.request_id,NEW.space_id,NEW.origin_device_id,NEW.forwarding_device_id,NEW.receiver_device_id,NEW.after_sequence,NEW.last_sequence,NEW.tip_sequence,NEW.envelope_hash,NEW.envelope)!=1
BEGIN SELECT RAISE(ABORT,'exact independently authenticated forwarded page required'); END;
CREATE TRIGGER forwarded_page_inbox_update BEFORE UPDATE ON forwarded_page_inbox
BEGIN SELECT RAISE(ABORT,'immutable forwarded page inbox'); END;
CREATE TRIGGER forwarded_page_inbox_delete BEFORE DELETE ON forwarded_page_inbox
BEGIN SELECT RAISE(ABORT,'immutable forwarded page inbox'); END;
PRAGMA user_version=56;
