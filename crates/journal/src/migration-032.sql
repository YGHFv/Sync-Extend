-- Intended-only namespace. No native execution or complete future capacity is admitted.
CREATE TABLE tree_native_capacity_admissions (
    space_id TEXT NOT NULL CHECK(length(CAST(space_id AS BLOB))=32 AND space_id NOT GLOB '*[^0-9a-f]*'),
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    coordinator_execution_id TEXT NOT NULL CHECK(length(CAST(coordinator_execution_id AS BLOB))=32 AND coordinator_execution_id NOT GLOB '*[^0-9a-f]*'),
    admission_id TEXT NOT NULL CHECK(length(CAST(admission_id AS BLOB))=32 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    admission_hash TEXT NOT NULL CHECK(length(CAST(admission_hash AS BLOB))=64 AND admission_hash NOT GLOB '*[^0-9a-f]*'),
    protocol_hash TEXT NOT NULL CHECK(length(CAST(protocol_hash AS BLOB))=64 AND protocol_hash NOT GLOB '*[^0-9a-f]*'),
    layout_hash TEXT NOT NULL CHECK(length(CAST(layout_hash AS BLOB))=64 AND layout_hash NOT GLOB '*[^0-9a-f]*'),
    inventory_hash TEXT NOT NULL CHECK(length(CAST(inventory_hash AS BLOB))=64 AND inventory_hash NOT GLOB '*[^0-9a-f]*'),
    request_hash TEXT NOT NULL CHECK(length(CAST(request_hash AS BLOB))=64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
    capacity_hash TEXT NOT NULL CHECK(length(CAST(capacity_hash AS BLOB))=64 AND capacity_hash NOT GLOB '*[^0-9a-f]*'),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    max_entries INTEGER NOT NULL CHECK(max_entries>=0),
    prior_rows INTEGER NOT NULL CHECK(prior_rows>=0),
    prior_bytes INTEGER NOT NULL CHECK(prior_bytes>=0),
    prior_budget_rows INTEGER NOT NULL CHECK(prior_budget_rows>=0),
    prior_budget_bytes INTEGER NOT NULL CHECK(prior_budget_bytes>=0),
    stored_rows INTEGER NOT NULL CHECK(stored_rows>=0),
    stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216),
    capacity TEXT NOT NULL CHECK(length(CAST(capacity AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id),
    FOREIGN KEY(transaction_id) REFERENCES tree_restore_coordinator_admissions(transaction_id)
) STRICT;
CREATE TABLE tree_native_action_headers (
    space_id TEXT NOT NULL CHECK(length(CAST(space_id AS BLOB))=32 AND space_id NOT GLOB '*[^0-9a-f]*'),
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    coordinator_execution_id TEXT NOT NULL CHECK(length(CAST(coordinator_execution_id AS BLOB))=32 AND coordinator_execution_id NOT GLOB '*[^0-9a-f]*'),
    admission_id TEXT NOT NULL CHECK(length(CAST(admission_id AS BLOB))=32 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    admission_hash TEXT NOT NULL CHECK(length(CAST(admission_hash AS BLOB))=64 AND admission_hash NOT GLOB '*[^0-9a-f]*'),
    protocol_hash TEXT NOT NULL CHECK(length(CAST(protocol_hash AS BLOB))=64 AND protocol_hash NOT GLOB '*[^0-9a-f]*'),
    layout_hash TEXT NOT NULL CHECK(length(CAST(layout_hash AS BLOB))=64 AND layout_hash NOT GLOB '*[^0-9a-f]*'),
    capacity_hash TEXT NOT NULL CHECK(length(CAST(capacity_hash AS BLOB))=64 AND capacity_hash NOT GLOB '*[^0-9a-f]*'),
    request_hash TEXT NOT NULL CHECK(length(CAST(request_hash AS BLOB))=64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_capacity_admissions(transaction_id)
) STRICT;
CREATE TABLE tree_native_action_records (
    space_id TEXT NOT NULL CHECK(length(CAST(space_id AS BLOB))=32 AND space_id NOT GLOB '*[^0-9a-f]*'),
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    coordinator_execution_id TEXT NOT NULL CHECK(length(CAST(coordinator_execution_id AS BLOB))=32 AND coordinator_execution_id NOT GLOB '*[^0-9a-f]*'),
    admission_id TEXT NOT NULL CHECK(length(CAST(admission_id AS BLOB))=32 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    admission_hash TEXT NOT NULL CHECK(length(CAST(admission_hash AS BLOB))=64 AND admission_hash NOT GLOB '*[^0-9a-f]*'),
    protocol_hash TEXT NOT NULL CHECK(length(CAST(protocol_hash AS BLOB))=64 AND protocol_hash NOT GLOB '*[^0-9a-f]*'),
    layout_hash TEXT NOT NULL CHECK(length(CAST(layout_hash AS BLOB))=64 AND layout_hash NOT GLOB '*[^0-9a-f]*'),
    record_index INTEGER NOT NULL CHECK(record_index>=0),
    action_ordinal INTEGER NOT NULL CHECK(action_ordinal>=0),
    previous_hash TEXT NOT NULL CHECK(length(CAST(previous_hash AS BLOB))=64 AND previous_hash NOT GLOB '*[^0-9a-f]*'),
    record_hash TEXT NOT NULL CHECK(length(CAST(record_hash AS BLOB))=64 AND record_hash NOT GLOB '*[^0-9a-f]*'),
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,record_index),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_action_headers(transaction_id)
) STRICT;

CREATE TRIGGER tree_native_capacity_insert BEFORE INSERT ON tree_native_capacity_admissions
WHEN EXISTS(SELECT 1 FROM tree_native_capacity_admissions WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions a
    JOIN tree_restore_preparations p USING(transaction_id)
    WHERE a.transaction_id=NEW.transaction_id AND p.space_id=NEW.space_id
    AND a.coordinator_execution_id=NEW.coordinator_execution_id AND a.admission_id=NEW.admission_id
    AND a.intent_hash=NEW.admission_hash AND a.admitted_at_ms<=NEW.created_at_ms)
OR EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_owner_records WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_records WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_protocol_records WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_final_descriptions WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_disposition_reservations WHERE transaction_id=NEW.transaction_id)
OR NEW.stored_rows IS NOT 3 OR NEW.stored_bytes<1504 OR NEW.max_entries NOT BETWEEN 1 AND 1000000
OR NEW.prior_rows+NEW.stored_rows>NEW.max_entries
OR NEW.prior_bytes+NEW.stored_bytes>NEW.max_entries*1024
OR NEW.prior_budget_rows+NEW.stored_rows>NEW.max_entries
OR NEW.prior_budget_bytes+NEW.stored_bytes>NEW.max_entries*1024
OR json_extract(NEW.request,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.request,'$.created_at_ms') IS NOT NEW.created_at_ms
OR json_extract(NEW.capacity,'$.format_version') IS NOT 1
OR json_extract(NEW.capacity,'$.accounting') IS NOT 'intended-only-three-actual-rows-not-complete-future-capacity-v1'
OR json_extract(NEW.capacity,'$.scope.format_version') IS NOT 1
OR json_extract(NEW.capacity,'$.scope.space_id') IS NOT NEW.space_id
OR json_extract(NEW.capacity,'$.scope.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.capacity,'$.scope.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.capacity,'$.scope.admission_id') IS NOT NEW.admission_id
OR json_extract(NEW.capacity,'$.scope.admission_hash') IS NOT NEW.admission_hash
OR json_extract(NEW.capacity,'$.scope.protocol_hash') IS NOT NEW.protocol_hash
OR json_extract(NEW.capacity,'$.layout_hash') IS NOT NEW.layout_hash
OR json_extract(NEW.capacity,'$.max_entries') IS NOT NEW.max_entries
OR json_extract(NEW.capacity,'$.prior.fingerprint') IS NOT NEW.inventory_hash
OR json_extract(NEW.capacity,'$.prior.rows') IS NOT NEW.prior_rows
OR json_extract(NEW.capacity,'$.prior.logical_bytes') IS NOT NEW.prior_bytes
OR json_extract(NEW.capacity,'$.prior.conservative_rows') IS NOT NEW.prior_budget_rows
OR json_extract(NEW.capacity,'$.prior.conservative_bytes') IS NOT NEW.prior_budget_bytes
OR json_extract(NEW.capacity,'$.request') IS NOT NEW.request
BEGIN SELECT RAISE(ABORT,'invalid tree native prewrite capacity'); END;

CREATE TRIGGER tree_native_header_insert BEFORE INSERT ON tree_native_action_headers
WHEN EXISTS(SELECT 1 FROM tree_native_action_headers WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_native_capacity_admissions c
    WHERE c.transaction_id=NEW.transaction_id AND c.space_id=NEW.space_id
    AND c.coordinator_execution_id=NEW.coordinator_execution_id AND c.admission_id=NEW.admission_id
    AND c.admission_hash=NEW.admission_hash AND c.protocol_hash=NEW.protocol_hash
    AND c.layout_hash=NEW.layout_hash AND c.capacity_hash=NEW.capacity_hash
    AND c.created_at_ms=NEW.created_at_ms)
OR json_extract(NEW.request,'$.scope.format_version') IS NOT 1
OR json_extract(NEW.request,'$.scope.space_id') IS NOT NEW.space_id
OR json_extract(NEW.request,'$.scope.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.request,'$.scope.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.request,'$.scope.admission_id') IS NOT NEW.admission_id
OR json_extract(NEW.request,'$.scope.admission_hash') IS NOT NEW.admission_hash
OR json_extract(NEW.request,'$.scope.protocol_hash') IS NOT NEW.protocol_hash
OR json_extract(NEW.request,'$.layout_hash') IS NOT NEW.layout_hash
OR json_extract(NEW.request,'$.capacity_hash') IS NOT NEW.capacity_hash
OR json_extract(NEW.request,'$.created_at_ms') IS NOT NEW.created_at_ms
BEGIN SELECT RAISE(ABORT,'invalid tree native prewrite header'); END;

CREATE TRIGGER tree_native_record_insert BEFORE INSERT ON tree_native_action_records
WHEN EXISTS(SELECT 1 FROM tree_native_action_records WHERE transaction_id=NEW.transaction_id)
OR NEW.record_index IS NOT 0 OR NEW.action_ordinal IS NOT 0
OR NEW.previous_hash IS NOT NEW.layout_hash
OR NOT EXISTS(SELECT 1 FROM tree_native_action_headers h
    JOIN tree_restore_owner_intents o USING(transaction_id)
    WHERE h.transaction_id=NEW.transaction_id AND h.space_id=NEW.space_id
    AND h.coordinator_execution_id=NEW.coordinator_execution_id AND h.admission_id=NEW.admission_id
    AND h.admission_hash=NEW.admission_hash AND h.protocol_hash=NEW.protocol_hash
    AND h.layout_hash=NEW.layout_hash AND h.created_at_ms=NEW.recorded_at_ms
    AND json_extract(NEW.record,'$.payload.intent.parent')=json_extract(o.intent,'$.parent')
    AND json_extract(NEW.record,'$.payload.intent.component')=json_extract(o.intent,'$.stage_component'))
OR json_extract(NEW.record,'$.scope.format_version') IS NOT 1
OR json_extract(NEW.record,'$.scope.space_id') IS NOT NEW.space_id
OR json_extract(NEW.record,'$.scope.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.record,'$.scope.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.record,'$.scope.admission_id') IS NOT NEW.admission_id
OR json_extract(NEW.record,'$.scope.admission_hash') IS NOT NEW.admission_hash
OR json_extract(NEW.record,'$.scope.protocol_hash') IS NOT NEW.protocol_hash
OR json_extract(NEW.record,'$.record_index') IS NOT NEW.record_index
OR json_extract(NEW.record,'$.action_ordinal') IS NOT NEW.action_ordinal
OR json_extract(NEW.record,'$.previous_hash') IS NOT NEW.previous_hash
OR json_extract(NEW.record,'$.recorded_at_ms') IS NOT NEW.recorded_at_ms
OR json_extract(NEW.record,'$.payload.phase') IS NOT 'intended'
OR json_extract(NEW.record,'$.payload.intent.action') IS NOT 'create_owner_directory'
BEGIN SELECT RAISE(ABORT,'invalid tree native initial intention; observed issuance unavailable'); END;

CREATE TRIGGER tree_native_capacity_immutable BEFORE UPDATE ON tree_native_capacity_admissions
BEGIN SELECT RAISE(ABORT,'tree native capacity immutable'); END;
CREATE TRIGGER tree_native_capacity_no_delete BEFORE DELETE ON tree_native_capacity_admissions
BEGIN SELECT RAISE(ABORT,'tree native capacity retained'); END;
CREATE TRIGGER tree_native_header_immutable BEFORE UPDATE ON tree_native_action_headers
BEGIN SELECT RAISE(ABORT,'tree native header immutable'); END;
CREATE TRIGGER tree_native_header_no_delete BEFORE DELETE ON tree_native_action_headers
BEGIN SELECT RAISE(ABORT,'tree native header retained'); END;
CREATE TRIGGER tree_native_record_immutable BEFORE UPDATE ON tree_native_action_records
BEGIN SELECT RAISE(ABORT,'tree native intention immutable'); END;
CREATE TRIGGER tree_native_record_no_delete BEFORE DELETE ON tree_native_action_records
BEGIN SELECT RAISE(ABORT,'tree native intention retained'); END;

CREATE TRIGGER tree_native_owner_description_fence BEFORE INSERT ON tree_restore_owner_records
WHEN EXISTS(SELECT 1 FROM tree_native_capacity_admissions WHERE transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'native prewrite excludes descriptive progress'); END;
CREATE TRIGGER tree_native_step_description_fence BEFORE INSERT ON tree_restore_execution_records
WHEN EXISTS(SELECT 1 FROM tree_native_capacity_admissions WHERE transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'native prewrite excludes descriptive progress'); END;
CREATE TRIGGER tree_native_protocol_description_fence BEFORE INSERT ON tree_restore_protocol_records
WHEN EXISTS(SELECT 1 FROM tree_native_capacity_admissions WHERE transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'native prewrite excludes descriptive progress'); END;
CREATE TRIGGER tree_native_final_description_fence BEFORE INSERT ON tree_restore_final_descriptions
WHEN EXISTS(SELECT 1 FROM tree_native_capacity_admissions WHERE transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'native prewrite excludes descriptive finalization'); END;
CREATE TRIGGER tree_native_disposition_description_fence BEFORE INSERT ON tree_restore_disposition_reservations
WHEN EXISTS(SELECT 1 FROM tree_native_capacity_admissions WHERE transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'native prewrite excludes descriptive disposal'); END;

PRAGMA user_version=32;
