-- Irreversible coordinator fence only; no native action or final writer permission.
CREATE TABLE tree_restore_coordinator_admissions (
    transaction_id TEXT PRIMARY KEY REFERENCES tree_restore_owner_intents(transaction_id),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    admission_id TEXT NOT NULL UNIQUE CHECK(length(admission_id)=32),
    preparation_hash TEXT NOT NULL CHECK(length(preparation_hash)=64),
    execution_intent_hash TEXT NOT NULL CHECK(length(execution_intent_hash)=64),
    original_request_hash TEXT NOT NULL CHECK(length(original_request_hash)=64),
    original_closure_hash TEXT NOT NULL CHECK(length(original_closure_hash)=64),
    owner_intent_hash TEXT NOT NULL CHECK(length(owner_intent_hash)=64),
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216),
    admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms>=0),
    CHECK(length(transaction_id)=32)
) STRICT;
CREATE TRIGGER tree_admission_insert BEFORE INSERT ON tree_restore_coordinator_admissions
WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions
    WHERE transaction_id=NEW.transaction_id OR admission_id=NEW.admission_id)
OR EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_owner_intents o
    JOIN tree_restore_original_reservations r USING(transaction_id)
    JOIN tree_restore_execution_intents e USING(transaction_id)
    JOIN tree_restore_preparations p USING(transaction_id)
    JOIN current_manifests c ON c.space_id=p.space_id
    WHERE o.transaction_id=NEW.transaction_id
    AND o.coordinator_execution_id=NEW.coordinator_execution_id
    AND e.execution_id=NEW.coordinator_execution_id AND e.preparation_hash=NEW.preparation_hash
    AND e.intent_hash=NEW.execution_intent_hash
    AND r.request_hash=NEW.original_request_hash AND r.closure_hash=NEW.original_closure_hash
    AND o.intent_hash=NEW.owner_intent_hash AND o.original_request_hash=r.request_hash
    AND o.original_closure_hash=r.closure_hash AND o.created_at_ms<=NEW.admitted_at_ms
    AND r.reserved_at_ms<=NEW.admitted_at_ms AND e.created_at_ms<=NEW.admitted_at_ms
    AND c.snapshot_id=p.baseline_root
    AND r.owner_count=(SELECT count(*) FROM tree_restore_original_owners
        WHERE transaction_id=NEW.transaction_id)
    AND r.reference_count=(SELECT count(*) FROM tree_restore_original_objects
        WHERE transaction_id=NEW.transaction_id))
OR EXISTS(SELECT 1 FROM tree_restore_owner_records WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_records WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_final_descriptions WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_disposition_reservations WHERE transaction_id=NEW.transaction_id)
OR json_extract(NEW.request,'$.input.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.request,'$.input.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.request,'$.input.admission_id') IS NOT NEW.admission_id
OR json_extract(NEW.request,'$.input.preparation_hash') IS NOT NEW.preparation_hash
OR json_extract(NEW.request,'$.input.execution_intent_hash') IS NOT NEW.execution_intent_hash
OR json_extract(NEW.request,'$.input.original_request_hash') IS NOT NEW.original_request_hash
OR json_extract(NEW.request,'$.input.original_closure_hash') IS NOT NEW.original_closure_hash
OR json_extract(NEW.request,'$.input.owner_intent_hash') IS NOT NEW.owner_intent_hash
OR json_extract(NEW.request,'$.input.admitted_at_ms') IS NOT NEW.admitted_at_ms
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.admission_id GLOB '*[^0-9a-f]*' OR NEW.preparation_hash GLOB '*[^0-9a-f]*'
OR NEW.execution_intent_hash GLOB '*[^0-9a-f]*' OR NEW.original_request_hash GLOB '*[^0-9a-f]*'
OR NEW.original_closure_hash GLOB '*[^0-9a-f]*' OR NEW.owner_intent_hash GLOB '*[^0-9a-f]*'
OR NEW.intent_hash GLOB '*[^0-9a-f]*' OR NEW.request_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid irreversible tree admission'); END;
CREATE TRIGGER tree_admission_immutable BEFORE UPDATE ON tree_restore_coordinator_admissions
BEGIN SELECT RAISE(ABORT,'irreversible tree admission immutable'); END;
CREATE TRIGGER tree_admission_no_delete BEFORE DELETE ON tree_restore_coordinator_admissions
BEGIN SELECT RAISE(ABORT,'irreversible tree admission retained'); END;
CREATE TRIGGER tree_admission_cancel_fence BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions WHERE transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'admitted tree can never cancel'); END;
CREATE TRIGGER tree_admission_input_pin_fence BEFORE DELETE ON tree_restore_objects
WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions WHERE transaction_id=OLD.transaction_id)
BEGIN SELECT RAISE(ABORT,'admitted tree input references retained'); END;
CREATE TRIGGER tree_admission_original_pin_fence BEFORE DELETE ON tree_restore_original_objects
WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions WHERE transaction_id=OLD.transaction_id)
BEGIN SELECT RAISE(ABORT,'admitted tree original references retained'); END;
CREATE TRIGGER tree_admission_owner_record_time BEFORE INSERT ON tree_restore_owner_records
WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions
    WHERE transaction_id=NEW.transaction_id AND admitted_at_ms>NEW.recorded_at_ms)
BEGIN SELECT RAISE(ABORT,'owner description precedes irreversible admission'); END;
CREATE TRIGGER tree_admission_step_record_time BEFORE INSERT ON tree_restore_execution_records
WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions
    WHERE transaction_id=NEW.transaction_id AND admitted_at_ms>NEW.recorded_at_ms)
BEGIN SELECT RAISE(ABORT,'step description precedes irreversible admission'); END;
PRAGMA user_version=30;

-- Bidirectional retained historical generation namespaces.
CREATE TRIGGER tree_admission_generation_tree_restore_preparations_insert BEFORE INSERT ON tree_restore_preparations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.transaction_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_tree_restore_preparations_update BEFORE UPDATE ON tree_restore_preparations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.transaction_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_tree_restore_execution_intents_insert BEFORE INSERT ON tree_restore_execution_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.execution_id=d.admission_id
        OR EXISTS(SELECT 1 FROM json_each(NEW.intent,'$.input.step_execution_ids') j
            WHERE j.value=d.admission_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_tree_restore_execution_intents_update BEFORE UPDATE ON tree_restore_execution_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.execution_id=d.admission_id
        OR EXISTS(SELECT 1 FROM json_each(NEW.intent,'$.input.step_execution_ids') j
            WHERE j.value=d.admission_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_tree_restore_execution_step_intents_insert BEFORE INSERT ON tree_restore_execution_step_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.execution_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_tree_restore_execution_step_intents_update BEFORE UPDATE ON tree_restore_execution_step_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.execution_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_tree_restore_histories_insert BEFORE INSERT ON tree_restore_histories
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE EXISTS(SELECT 1 FROM
        json_each(NEW.intent,'$.history.fresh_entry_ids') j WHERE j.value=d.admission_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_tree_restore_histories_update BEFORE UPDATE ON tree_restore_histories
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE EXISTS(SELECT 1 FROM
        json_each(NEW.intent,'$.history.fresh_entry_ids') j WHERE j.value=d.admission_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_publications_insert BEFORE INSERT ON publications
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.transaction_id=d.admission_id
        OR json_extract(NEW.intent,'$.entry_id')=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_publications_update BEFORE UPDATE ON publications
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.transaction_id=d.admission_id
        OR json_extract(NEW.intent,'$.entry_id')=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_mutations_insert BEFORE INSERT ON mutations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.transaction_id=d.admission_id
        OR json_extract(NEW.execution,'$.execution_id')=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_mutations_update BEFORE UPDATE ON mutations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.transaction_id=d.admission_id
        OR json_extract(NEW.execution,'$.execution_id')=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_reference_reservations_insert BEFORE INSERT ON reference_reservations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.owner_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_reference_reservations_update BEFORE UPDATE ON reference_reservations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.owner_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_gc_executions_insert BEFORE INSERT ON gc_executions
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.execution_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_gc_executions_update BEFORE UPDATE ON gc_executions
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.execution_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_operations_insert BEFORE INSERT ON operations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE coalesce(json_extract(NEW.payload,'$.payload.change.entry.entry_id'),
        json_extract(NEW.payload,'$.payload.change.entry_id'))=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_operations_update BEFORE UPDATE ON operations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE coalesce(json_extract(NEW.payload,'$.payload.change.entry.entry_id'),
        json_extract(NEW.payload,'$.payload.change.entry_id'))=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_snapshots_insert BEFORE INSERT ON snapshots
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE EXISTS(SELECT 1 FROM json_each(NEW.manifest,'$.entries') j
        WHERE j.key=d.admission_id)
        OR EXISTS(SELECT 1 FROM json_each(NEW.manifest,'$.tombstones') j
            WHERE j.key=d.admission_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_snapshots_update BEFORE UPDATE ON snapshots
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE EXISTS(SELECT 1 FROM json_each(NEW.manifest,'$.entries') j
        WHERE j.key=d.admission_id)
        OR EXISTS(SELECT 1 FROM json_each(NEW.manifest,'$.tombstones') j
            WHERE j.key=d.admission_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_read_leases_insert BEFORE INSERT ON read_leases
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.lease_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_read_leases_update BEFORE UPDATE ON read_leases
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.lease_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_gc_marks_insert BEFORE INSERT ON gc_marks
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.mark_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_gc_marks_update BEFORE UPDATE ON gc_marks
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.mark_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_gc_authorizations_insert BEFORE INSERT ON gc_authorizations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.authorization_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_gc_authorizations_update BEFORE UPDATE ON gc_authorizations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.authorization_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_gc_disposals_insert BEFORE INSERT ON gc_disposals
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.disposal_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_gc_disposals_update BEFORE UPDATE ON gc_disposals
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions)
    THEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions d WHERE NEW.disposal_id=d.admission_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_new BEFORE INSERT ON tree_restore_coordinator_admissions
WHEN EXISTS(SELECT 1 FROM tree_restore_preparations WHERE transaction_id=NEW.admission_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_intents WHERE execution_id=NEW.admission_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents WHERE execution_id=NEW.admission_id)
OR EXISTS(SELECT 1 FROM publications WHERE transaction_id=NEW.admission_id
    OR json_extract(intent,'$.entry_id')=NEW.admission_id)
OR EXISTS(SELECT 1 FROM mutations WHERE transaction_id=NEW.admission_id
    OR json_extract(execution,'$.execution_id')=NEW.admission_id)
OR EXISTS(SELECT 1 FROM reference_reservations WHERE owner_id=NEW.admission_id)
OR EXISTS(SELECT 1 FROM read_leases WHERE lease_id=NEW.admission_id)
OR EXISTS(SELECT 1 FROM gc_marks WHERE mark_id=NEW.admission_id)
OR EXISTS(SELECT 1 FROM gc_authorizations WHERE authorization_id=NEW.admission_id)
OR EXISTS(SELECT 1 FROM gc_executions WHERE execution_id=NEW.admission_id)
OR EXISTS(SELECT 1 FROM gc_disposals WHERE disposal_id=NEW.admission_id)
OR EXISTS(SELECT 1 FROM tree_restore_histories h,
    json_each(h.intent,'$.history.fresh_entry_ids') j WHERE j.value=NEW.admission_id)
OR EXISTS(SELECT 1 FROM operations WHERE coalesce(
    json_extract(payload,'$.payload.change.entry.entry_id'),
    json_extract(payload,'$.payload.change.entry_id'))=NEW.admission_id)
OR EXISTS(SELECT 1 FROM snapshots s,json_each(s.manifest,'$.entries') j
    WHERE j.key=NEW.admission_id)
OR EXISTS(SELECT 1 FROM snapshots s,json_each(s.manifest,'$.tombstones') j
    WHERE j.key=NEW.admission_id)
OR EXISTS(SELECT 1 FROM tree_restore_disposition_intents WHERE disposition_id=NEW.admission_id)
BEGIN SELECT RAISE(ABORT,'tree admission historical generation collision'); END;

CREATE TRIGGER tree_admission_generation_disposition_insert BEFORE INSERT ON tree_restore_disposition_intents
WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions WHERE admission_id=NEW.disposition_id)
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;

CREATE TRIGGER tree_admission_generation_disposition_update BEFORE UPDATE ON tree_restore_disposition_intents
WHEN EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions WHERE admission_id=NEW.disposition_id)
BEGIN SELECT RAISE(ABORT,'tree admission generation already used'); END;
