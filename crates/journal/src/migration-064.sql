-- Retained native DAV descriptions. No native activation or effect is authorized.
CREATE TABLE webdav_native_admissions (
    transaction_id TEXT PRIMARY KEY NOT NULL CHECK(length(transaction_id)=32),
    space_id TEXT NOT NULL CHECK(length(space_id)=32),
    baseline_snapshot TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    plan_hash TEXT NOT NULL CHECK(length(plan_hash)=64),
    admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms>=0),
    description TEXT NOT NULL CHECK(length(CAST(description AS BLOB)) BETWEEN 1 AND 16777216),
    future_rows INTEGER NOT NULL CHECK(future_rows>=0),
    future_bytes INTEGER NOT NULL CHECK(future_bytes>=0)
) STRICT;
CREATE TABLE webdav_native_objects (
    transaction_id TEXT NOT NULL REFERENCES webdav_native_admissions(transaction_id),
    content_id TEXT NOT NULL CHECK(length(content_id)=64),
    length INTEGER NOT NULL CHECK(length>0),
    PRIMARY KEY(transaction_id,content_id)
) STRICT;
CREATE TABLE webdav_native_cancellations (
    transaction_id TEXT PRIMARY KEY NOT NULL REFERENCES webdav_native_admissions(transaction_id),
    cancelled_at_ms INTEGER NOT NULL CHECK(cancelled_at_ms>=0)
) STRICT;
CREATE TABLE webdav_native_clock (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0)
) STRICT;
CREATE TRIGGER webdav_native_admission_insert BEFORE INSERT ON webdav_native_admissions
WHEN NOT sync_webdav_native_description_issue(NEW.plan_hash,NEW.admitted_at_ms)
OR NOT EXISTS(SELECT 1 FROM webdav_native_clock WHERE singleton=1 AND observed_at_ms=NEW.admitted_at_ms)
OR NOT EXISTS(SELECT 1 FROM current_manifests WHERE space_id=NEW.space_id AND snapshot_id=NEW.baseline_snapshot)
OR EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'exact DAV description issuance required'); END;
CREATE TRIGGER webdav_native_admission_update BEFORE UPDATE ON webdav_native_admissions
BEGIN SELECT RAISE(ABORT,'DAV description immutable'); END;
CREATE TRIGGER webdav_native_admission_delete BEFORE DELETE ON webdav_native_admissions
BEGIN SELECT RAISE(ABORT,'DAV description retained'); END;
CREATE TRIGGER webdav_native_objects_insert BEFORE INSERT ON webdav_native_objects
WHEN NOT sync_webdav_native_object_issue(NEW.content_id,
    (SELECT admitted_at_ms FROM webdav_native_admissions WHERE transaction_id=NEW.transaction_id))
OR EXISTS(SELECT 1 FROM webdav_native_cancellations WHERE transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'exact DAV retained object issuance required'); END;
CREATE TRIGGER webdav_native_objects_update BEFORE UPDATE ON webdav_native_objects
BEGIN SELECT RAISE(ABORT,'DAV object immutable'); END;
CREATE TRIGGER webdav_native_objects_delete BEFORE DELETE ON webdav_native_objects
BEGIN SELECT RAISE(ABORT,'DAV object history retained'); END;
CREATE TRIGGER webdav_native_cancel_insert BEFORE INSERT ON webdav_native_cancellations
WHEN NOT sync_webdav_native_cancel_issue(NEW.transaction_id,NEW.cancelled_at_ms)
OR NOT EXISTS(SELECT 1 FROM webdav_native_clock WHERE singleton=1 AND observed_at_ms=NEW.cancelled_at_ms)
OR NOT EXISTS(SELECT 1 FROM webdav_native_admissions WHERE transaction_id=NEW.transaction_id
    AND admitted_at_ms<=NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'exact pre-native DAV cancellation required'); END;
CREATE TRIGGER webdav_native_cancel_update BEFORE UPDATE ON webdav_native_cancellations
BEGIN SELECT RAISE(ABORT,'DAV cancellation immutable'); END;
CREATE TRIGGER webdav_native_cancel_delete BEFORE DELETE ON webdav_native_cancellations
BEGIN SELECT RAISE(ABORT,'DAV cancellation retained'); END;
CREATE TRIGGER webdav_native_clock_update BEFORE UPDATE ON webdav_native_clock
WHEN NEW.singleton!=OLD.singleton OR NEW.observed_at_ms<OLD.observed_at_ms
BEGIN SELECT RAISE(ABORT,'DAV clock monotonic'); END;
CREATE TRIGGER webdav_native_clock_delete BEFORE DELETE ON webdav_native_clock
BEGIN SELECT RAISE(ABORT,'DAV clock retained'); END;
CREATE TRIGGER webdav_native_current_update BEFORE UPDATE ON current_manifests
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=OLD.space_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV description holds baseline'); END;
CREATE TRIGGER webdav_native_current_insert BEFORE INSERT ON current_manifests
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=NEW.space_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV description holds baseline'); END;
CREATE TRIGGER webdav_native_current_delete BEFORE DELETE ON current_manifests
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=OLD.space_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV description holds baseline'); END;
CREATE TRIGGER webdav_native_operations_insert BEFORE INSERT ON operations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=NEW.space_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV description holds causal history'); END;
CREATE TRIGGER webdav_native_operations_update BEFORE UPDATE ON operations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=OLD.space_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV description holds causal history'); END;
CREATE TRIGGER webdav_native_operations_delete BEFORE DELETE ON operations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=OLD.space_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV description holds causal history'); END;
CREATE TRIGGER webdav_native_snapshot_pruning BEFORE INSERT ON snapshot_prunings
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.baseline_snapshot=NEW.snapshot_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV original snapshot retained'); END;
CREATE TRIGGER webdav_native_snapshot_object_delete BEFORE DELETE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.baseline_snapshot=OLD.snapshot_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV original content retained'); END;
CREATE TRIGGER webdav_native_publication_insert BEFORE INSERT ON publications
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=NEW.space_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV description excludes publication'); END;
CREATE TRIGGER webdav_native_mutation_insert BEFORE INSERT ON mutations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=NEW.space_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV description excludes mutation'); END;
CREATE TRIGGER webdav_native_cleanup_update BEFORE UPDATE ON cleanup_plans
WHEN NEW.state='executing' AND EXISTS(
    SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=NEW.space_id AND c.transaction_id IS NULL)
BEGIN SELECT RAISE(ABORT,'DAV description excludes cleanup'); END;
PRAGMA user_version=64;
