CREATE TABLE owner (
    slot INTEGER PRIMARY KEY CHECK(slot=1),
    policy TEXT NOT NULL CHECK(length(policy)<=16384),
    fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64),
    initialized_at_ms INTEGER NOT NULL CHECK(initialized_at_ms>=0)
) STRICT;
CREATE TABLE attempts (
    sequence INTEGER PRIMARY KEY CHECK(sequence>0),
    attempt_id TEXT NOT NULL UNIQUE CHECK(length(attempt_id)=32),
    record TEXT NOT NULL CHECK(length(record)<=2048)
) STRICT;
CREATE TRIGGER owner_update BEFORE UPDATE ON owner BEGIN SELECT RAISE(ABORT,'immutable pull attempt owner'); END;
CREATE TRIGGER owner_delete BEFORE DELETE ON owner BEGIN SELECT RAISE(ABORT,'retained pull attempt owner'); END;
CREATE TRIGGER owner_insert BEFORE INSERT ON owner WHEN EXISTS(SELECT 1 FROM owner)
BEGIN SELECT RAISE(ABORT,'one pull attempt owner'); END;
CREATE TRIGGER attempt_insert BEFORE INSERT ON attempts
WHEN NOT sync_storage_pull_attempt_issue(NEW.sequence,NEW.attempt_id,NEW.record)
BEGIN SELECT RAISE(ABORT,'private pull attempt issuance'); END;
CREATE TRIGGER attempt_update BEFORE UPDATE ON attempts BEGIN SELECT RAISE(ABORT,'immutable pull attempt'); END;
CREATE TRIGGER attempt_delete BEFORE DELETE ON attempts BEGIN SELECT RAISE(ABORT,'retained pull attempt'); END;
PRAGMA user_version=1;
