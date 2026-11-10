-- Full original signed pages for bounded restart, not received/applied authority.
CREATE TABLE original_page_inbox (
 request_id TEXT NOT NULL PRIMARY KEY,
 space_id TEXT NOT NULL,
 origin_device_id TEXT NOT NULL,
 receiver_device_id TEXT NOT NULL,
 after_sequence INTEGER NOT NULL,
 last_sequence INTEGER NOT NULL,
 tip_sequence INTEGER NOT NULL,
 envelope_hash TEXT NOT NULL,
 envelope TEXT NOT NULL
) STRICT;
CREATE TRIGGER original_page_inbox_insert BEFORE INSERT ON original_page_inbox
WHEN sync_original_page_issue(NEW.request_id,NEW.space_id,NEW.origin_device_id,NEW.receiver_device_id,NEW.after_sequence,NEW.last_sequence,NEW.tip_sequence,NEW.envelope_hash,NEW.envelope)!=1
BEGIN SELECT RAISE(ABORT,'exact authenticated original page required'); END;
CREATE TRIGGER original_page_inbox_update BEFORE UPDATE ON original_page_inbox
BEGIN SELECT RAISE(ABORT,'immutable original page inbox'); END;
CREATE TRIGGER original_page_inbox_delete BEFORE DELETE ON original_page_inbox
BEGIN SELECT RAISE(ABORT,'immutable original page inbox'); END;
PRAGMA user_version=50;
