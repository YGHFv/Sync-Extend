-- Exact admission-bound protocol descriptions, never actual native evidence.
CREATE TABLE tree_restore_protocol_descriptions (
    transaction_id TEXT PRIMARY KEY REFERENCES tree_restore_coordinator_admissions(transaction_id),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    admission_id TEXT NOT NULL CHECK(length(admission_id)=32),
    protocol_hash TEXT NOT NULL CHECK(length(protocol_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216)
) STRICT;
CREATE TABLE tree_restore_protocol_records (
    transaction_id TEXT NOT NULL REFERENCES tree_restore_protocol_descriptions(transaction_id),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    admission_id TEXT NOT NULL CHECK(length(admission_id)=32),
    admission_hash TEXT NOT NULL CHECK(length(admission_hash)=64),
    protocol_hash TEXT NOT NULL CHECK(length(protocol_hash)=64),
    record_index INTEGER NOT NULL CHECK(record_index>=0),
    previous_hash TEXT NOT NULL CHECK(length(previous_hash)=64),
    record_hash TEXT NOT NULL CHECK(length(record_hash)=64),
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,record_index)
) STRICT;
CREATE TRIGGER tree_protocol_description_insert BEFORE INSERT ON tree_restore_protocol_descriptions
WHEN EXISTS(SELECT 1 FROM tree_restore_protocol_descriptions WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions a
    WHERE a.transaction_id=NEW.transaction_id AND a.coordinator_execution_id=NEW.coordinator_execution_id
    AND a.admission_id=NEW.admission_id AND a.admitted_at_ms=NEW.created_at_ms
    AND json_extract(NEW.request,'$.input.admission.input.transaction_id')=a.transaction_id
    AND json_extract(NEW.request,'$.input.admission.input.coordinator_execution_id')=a.coordinator_execution_id
    AND json_extract(NEW.request,'$.input.admission.input.admission_id')=a.admission_id
    AND json_extract(NEW.request,'$.input.admission.intent_hash')=a.intent_hash
    AND json_extract(NEW.request,'$.input.admission.request_hash')=a.request_hash
    AND json_extract(NEW.request,'$.input.admission.input')=json_extract(a.request,'$.input')
    AND json_extract(NEW.request,'$.input.admission.limits')=json_extract(a.request,'$.limits'))
OR json_extract(NEW.request,'$.input.format_version') IS NOT 1
OR NEW.protocol_hash GLOB '*[^0-9a-f]*' OR NEW.request_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid tree protocol description'); END;
CREATE TRIGGER tree_protocol_description_immutable BEFORE UPDATE ON tree_restore_protocol_descriptions
BEGIN SELECT RAISE(ABORT,'tree protocol description immutable'); END;
CREATE TRIGGER tree_protocol_description_no_delete BEFORE DELETE ON tree_restore_protocol_descriptions
BEGIN SELECT RAISE(ABORT,'tree protocol description retained'); END;
CREATE TRIGGER tree_protocol_record_insert BEFORE INSERT ON tree_restore_protocol_records
WHEN EXISTS(SELECT 1 FROM tree_restore_protocol_records WHERE transaction_id=NEW.transaction_id AND record_index=NEW.record_index)
OR NOT EXISTS(SELECT 1 FROM tree_restore_protocol_descriptions p
    JOIN tree_restore_coordinator_admissions a USING(transaction_id)
    WHERE p.transaction_id=NEW.transaction_id
    AND p.coordinator_execution_id=NEW.coordinator_execution_id AND p.admission_id=NEW.admission_id
    AND p.protocol_hash=NEW.protocol_hash AND a.intent_hash=NEW.admission_hash
    AND NEW.record_index=(SELECT count(*) FROM tree_restore_protocol_records WHERE transaction_id=p.transaction_id)
    AND NEW.previous_hash=coalesce((SELECT record_hash FROM tree_restore_protocol_records
        WHERE transaction_id=p.transaction_id ORDER BY record_index DESC LIMIT 1),p.protocol_hash)
    AND NEW.recorded_at_ms>=coalesce((SELECT recorded_at_ms FROM tree_restore_protocol_records
        WHERE transaction_id=p.transaction_id ORDER BY record_index DESC LIMIT 1),p.created_at_ms))
OR json_extract(NEW.record,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.record,'$.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.record,'$.admission_id') IS NOT NEW.admission_id
OR json_extract(NEW.record,'$.admission_hash') IS NOT NEW.admission_hash
OR json_extract(NEW.record,'$.protocol_hash') IS NOT NEW.protocol_hash
OR json_extract(NEW.record,'$.record_index') IS NOT NEW.record_index
OR json_extract(NEW.record,'$.previous_hash') IS NOT NEW.previous_hash
OR json_extract(NEW.record,'$.recorded_at_ms') IS NOT NEW.recorded_at_ms
OR json_extract(NEW.record,'$.event.record.recorded_at_ms') IS NOT NEW.recorded_at_ms
OR (NEW.record_index<8 AND (json_extract(NEW.record,'$.event.kind') IS NOT 'owner'
    OR json_extract(NEW.record,'$.event.record.record_index') IS NOT NEW.record_index))
OR (NEW.record_index>=8 AND (json_extract(NEW.record,'$.event.kind') IS NOT 'step'
    OR json_extract(NEW.record,'$.event.owner_ready_record_hash') IS NOT
        (SELECT record_hash FROM tree_restore_protocol_records WHERE transaction_id=NEW.transaction_id AND record_index=7)))
OR NEW.record_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid tree protocol record'); END;
CREATE TRIGGER tree_protocol_record_immutable BEFORE UPDATE ON tree_restore_protocol_records
BEGIN SELECT RAISE(ABORT,'tree protocol record immutable'); END;
CREATE TRIGGER tree_protocol_record_no_delete BEFORE DELETE ON tree_restore_protocol_records
BEGIN SELECT RAISE(ABORT,'tree protocol record retained'); END;
PRAGMA user_version=31;
