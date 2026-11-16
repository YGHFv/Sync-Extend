CREATE TABLE restore_completions(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 archive_digest TEXT NOT NULL CHECK(length(archive_digest)=64),
 ledger_id TEXT NOT NULL CHECK(length(ledger_id)=32),
 original_terminal TEXT NOT NULL CHECK(length(original_terminal)=64),
 manifest BLOB NOT NULL CHECK(length(manifest) BETWEEN 1 AND 33554432),
 manifest_hash TEXT NOT NULL CHECK(length(manifest_hash)=64)
) STRICT;
CREATE TRIGGER restore_completions_update BEFORE UPDATE ON restore_completions
BEGIN SELECT RAISE(ABORT,'restore completion immutable'); END;
CREATE TRIGGER restore_completions_delete BEFORE DELETE ON restore_completions
BEGIN SELECT RAISE(ABORT,'restore completion immutable'); END;
CREATE TRIGGER restore_records_completion_insert BEFORE INSERT ON restore_records
WHEN EXISTS(SELECT 1 FROM restore_completions)
BEGIN SELECT RAISE(ABORT,'restore original issuer completed'); END;
CREATE TRIGGER restore_completions_insert BEFORE INSERT ON restore_completions
WHEN EXISTS(SELECT 1 FROM restore_completions)
BEGIN SELECT RAISE(ABORT,'restore completion single insertion'); END;
PRAGMA user_version=3;
