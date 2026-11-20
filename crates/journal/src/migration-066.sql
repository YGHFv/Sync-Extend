-- Optional local-observation retention. Existing histories are not backdated.
CREATE TABLE deletion_retention_clock (
    space_id TEXT NOT NULL PRIMARY KEY CHECK(length(space_id)=32),
    clock_revision INTEGER NOT NULL CHECK(clock_revision=1),
    watermark_ms INTEGER NOT NULL CHECK(watermark_ms>0),
    record TEXT NOT NULL CHECK(json_valid(record) AND length(CAST(record AS BLOB)) BETWEEN 1 AND 4096),
    record_hash TEXT NOT NULL CHECK(length(record_hash)=64)
) STRICT;
CREATE TABLE deletion_retention_policies (
    space_id TEXT NOT NULL CHECK(length(space_id)=32),
    revision INTEGER NOT NULL CHECK(revision>0),
    minimum_days INTEGER NOT NULL CHECK(minimum_days BETWEEN 0 AND 4294967295),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>0),
    record TEXT NOT NULL CHECK(json_valid(record) AND length(CAST(record AS BLOB)) BETWEEN 1 AND 4096),
    record_hash TEXT NOT NULL CHECK(length(record_hash)=64),
    PRIMARY KEY(space_id,revision),
    FOREIGN KEY(space_id) REFERENCES deletion_retention_clock(space_id)
) STRICT;
CREATE TABLE deletion_retention_observations (
    space_id TEXT NOT NULL CHECK(length(space_id)=32),
    operation_id TEXT NOT NULL CHECK(length(operation_id)=64),
    entry_id TEXT NOT NULL CHECK(length(entry_id)=32),
    effective_snapshot TEXT NOT NULL CHECK(length(effective_snapshot)=64),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>0),
    clock_revision INTEGER NOT NULL CHECK(clock_revision=1),
    record TEXT NOT NULL CHECK(json_valid(record) AND length(CAST(record AS BLOB)) BETWEEN 1 AND 4096),
    record_hash TEXT NOT NULL CHECK(length(record_hash)=64),
    PRIMARY KEY(space_id,operation_id),
    FOREIGN KEY(operation_id) REFERENCES operations(op_id),
    FOREIGN KEY(effective_snapshot) REFERENCES snapshots(snapshot_id),
    FOREIGN KEY(space_id) REFERENCES deletion_retention_clock(space_id)
) STRICT;
CREATE TRIGGER deletion_retention_clock_insert BEFORE INSERT ON deletion_retention_clock
WHEN NOT sync_deletion_retention_issue(NEW.record_hash,NEW.watermark_ms)
OR json_extract(NEW.record,'$.format_version') IS NOT 1
OR json_extract(NEW.record,'$.space_id') IS NOT NEW.space_id
OR json_extract(NEW.record,'$.clock_revision') IS NOT NEW.clock_revision
OR json_extract(NEW.record,'$.watermark_ms') IS NOT NEW.watermark_ms
BEGIN SELECT RAISE(ABORT,'exact local retention clock issuance required'); END;
CREATE TRIGGER deletion_retention_clock_update BEFORE UPDATE ON deletion_retention_clock
WHEN NEW.space_id IS NOT OLD.space_id OR NEW.clock_revision IS NOT OLD.clock_revision
OR NEW.watermark_ms<OLD.watermark_ms
OR NOT sync_deletion_retention_issue(NEW.record_hash,NEW.watermark_ms)
OR json_extract(NEW.record,'$.format_version') IS NOT 1
OR json_extract(NEW.record,'$.space_id') IS NOT NEW.space_id
OR json_extract(NEW.record,'$.clock_revision') IS NOT NEW.clock_revision
OR json_extract(NEW.record,'$.watermark_ms') IS NOT NEW.watermark_ms
BEGIN SELECT RAISE(ABORT,'monotone exact local retention clock required'); END;
CREATE TRIGGER deletion_retention_clock_delete BEFORE DELETE ON deletion_retention_clock
BEGIN SELECT RAISE(ABORT,'retention clock retained'); END;
CREATE TRIGGER deletion_retention_policy_insert BEFORE INSERT ON deletion_retention_policies
WHEN NOT sync_deletion_retention_issue(NEW.record_hash,NEW.observed_at_ms)
OR json_extract(NEW.record,'$.format_version') IS NOT 1
OR json_extract(NEW.record,'$.space_id') IS NOT NEW.space_id
OR json_extract(NEW.record,'$.revision') IS NOT NEW.revision
OR json_extract(NEW.record,'$.minimum_days') IS NOT NEW.minimum_days
OR json_extract(NEW.record,'$.observed_at_ms') IS NOT NEW.observed_at_ms
OR NEW.revision IS NOT coalesce((SELECT max(revision)+1 FROM deletion_retention_policies WHERE space_id=NEW.space_id),1)
OR json_extract(NEW.record,'$.previous') IS NOT
    (SELECT record_hash FROM deletion_retention_policies WHERE space_id=NEW.space_id ORDER BY revision DESC LIMIT 1)
OR NOT EXISTS(SELECT 1 FROM deletion_retention_clock WHERE space_id=NEW.space_id AND watermark_ms=NEW.observed_at_ms)
BEGIN SELECT RAISE(ABORT,'exact explicit retention policy revision required'); END;
CREATE TRIGGER deletion_retention_policy_update BEFORE UPDATE ON deletion_retention_policies
BEGIN SELECT RAISE(ABORT,'retention policy history immutable'); END;
CREATE TRIGGER deletion_retention_policy_delete BEFORE DELETE ON deletion_retention_policies
BEGIN SELECT RAISE(ABORT,'retention policy history retained'); END;
CREATE TRIGGER deletion_retention_observation_insert BEFORE INSERT ON deletion_retention_observations
WHEN NOT sync_deletion_retention_issue(NEW.record_hash,NEW.observed_at_ms)
OR json_extract(NEW.record,'$.format_version') IS NOT 1
OR json_extract(NEW.record,'$.space_id') IS NOT NEW.space_id
OR json_extract(NEW.record,'$.operation_id') IS NOT NEW.operation_id
OR json_extract(NEW.record,'$.entry_id') IS NOT NEW.entry_id
OR json_extract(NEW.record,'$.effective_snapshot') IS NOT NEW.effective_snapshot
OR json_extract(NEW.record,'$.observed_at_ms') IS NOT NEW.observed_at_ms
OR json_extract(NEW.record,'$.clock_revision') IS NOT NEW.clock_revision
OR json_extract(NEW.record,'$.basis') NOT IN ('local_effective_commit','legacy_local_observation')
OR NOT EXISTS(SELECT 1 FROM deletion_retention_clock
    WHERE space_id=NEW.space_id AND clock_revision=NEW.clock_revision AND watermark_ms=NEW.observed_at_ms)
OR NOT EXISTS(SELECT 1 FROM operations o
    WHERE o.op_id=NEW.operation_id AND o.space_id=NEW.space_id AND o.state='materialized'
    AND json_extract(o.payload,'$.payload.change.type')='delete'
    AND json_extract(o.payload,'$.payload.change.entry_id')=NEW.entry_id)
OR NOT EXISTS(SELECT 1 FROM current_manifests c JOIN snapshots s USING(snapshot_id)
    JOIN json_each(s.manifest,'$.tombstones') t
    WHERE c.space_id=NEW.space_id AND s.space_id=NEW.space_id
    AND c.snapshot_id=NEW.effective_snapshot AND s.state='materialized'
    AND t.key=NEW.entry_id AND t.value=NEW.operation_id)
BEGIN SELECT RAISE(ABORT,'actual local observation of effective Delete required'); END;
CREATE TRIGGER deletion_retention_observation_update BEFORE UPDATE ON deletion_retention_observations
BEGIN SELECT RAISE(ABORT,'first deletion observation immutable'); END;
CREATE TRIGGER deletion_retention_observation_delete BEFORE DELETE ON deletion_retention_observations
BEGIN SELECT RAISE(ABORT,'deletion observation audit retained'); END;
PRAGMA user_version=66;
