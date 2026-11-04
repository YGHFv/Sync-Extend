-- Immutable original disposition descriptions, never native disposal permission.
CREATE TABLE tree_restore_disposition_reservations (
    transaction_id TEXT PRIMARY KEY REFERENCES tree_restore_final_descriptions(transaction_id),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    final_description_hash TEXT NOT NULL CHECK(length(final_description_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    plan_hash TEXT NOT NULL CHECK(length(plan_hash)=64),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216),
    described_at_ms INTEGER NOT NULL CHECK(described_at_ms>=0),
    owner_count INTEGER NOT NULL CHECK(owner_count BETWEEN 0 AND 1000000),
    reserved_rows INTEGER NOT NULL CHECK(reserved_rows=1+owner_count),
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>288+336*owner_count),
    CHECK(length(transaction_id)=32)
) STRICT;
CREATE TABLE tree_restore_disposition_intents (
    transaction_id TEXT NOT NULL REFERENCES tree_restore_disposition_reservations(transaction_id),
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    step_execution_id TEXT NOT NULL CHECK(length(step_execution_id)=32),
    disposition_id TEXT NOT NULL UNIQUE CHECK(length(disposition_id)=32),
    step_index INTEGER NOT NULL CHECK(step_index BETWEEN 0 AND 999999),
    described_at_ms INTEGER NOT NULL CHECK(described_at_ms>=0),
    final_description_hash TEXT NOT NULL CHECK(length(final_description_hash)=64),
    retained_description_hash TEXT NOT NULL CHECK(length(retained_description_hash)=64),
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    intent TEXT NOT NULL CHECK(length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,step_index),
    FOREIGN KEY(transaction_id,step_index)
        REFERENCES tree_restore_retained_descriptions(transaction_id,step_index),
    CHECK(length(transaction_id)=32)
) STRICT;
CREATE TABLE tree_restore_disposition_records (
    transaction_id TEXT NOT NULL,
    coordinator_execution_id TEXT NOT NULL CHECK(length(coordinator_execution_id)=32),
    disposition_id TEXT NOT NULL CHECK(length(disposition_id)=32),
    step_index INTEGER NOT NULL CHECK(step_index BETWEEN 0 AND 999999),
    record_index INTEGER NOT NULL CHECK(record_index BETWEEN 0 AND 3),
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    previous_hash TEXT NOT NULL CHECK(length(previous_hash)=64),
    record_hash TEXT NOT NULL CHECK(length(record_hash)=64),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,step_index,record_index),
    FOREIGN KEY(transaction_id,step_index)
        REFERENCES tree_restore_disposition_intents(transaction_id,step_index),
    CHECK(length(transaction_id)=32)
) STRICT;
CREATE TRIGGER tree_disposition_reservation_insert BEFORE INSERT ON tree_restore_disposition_reservations
WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_reservations WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_final_descriptions f
    WHERE f.transaction_id=NEW.transaction_id
    AND f.coordinator_execution_id=NEW.coordinator_execution_id
    AND f.intent_hash=NEW.final_description_hash AND f.described_at_ms<=NEW.described_at_ms
    AND f.original_count=NEW.owner_count
    AND f.original_count=(SELECT count(*) FROM tree_restore_retained_descriptions
        WHERE transaction_id=f.transaction_id))
OR json_extract(NEW.request,'$.input.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.request,'$.input.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.request,'$.input.final_description_hash') IS NOT NEW.final_description_hash
OR json_extract(NEW.request,'$.input.described_at_ms') IS NOT NEW.described_at_ms
OR json_type(NEW.request,'$.input.disposition_ids') IS NOT 'object'
OR (SELECT count(*) FROM json_each(NEW.request,'$.input.disposition_ids')) IS NOT NEW.owner_count
OR (SELECT count(DISTINCT value) FROM json_each(NEW.request,'$.input.disposition_ids')) IS NOT NEW.owner_count
OR EXISTS(SELECT 1 FROM json_each(NEW.request,'$.input.disposition_ids') j
    WHERE j.type!='text' OR length(j.value)!=32 OR j.value GLOB '*[^0-9a-f]*'
    OR NOT EXISTS(SELECT 1 FROM tree_restore_retained_descriptions r
        WHERE r.transaction_id=NEW.transaction_id AND CAST(r.step_index AS TEXT)=j.key)
    OR EXISTS(SELECT 1 FROM tree_restore_disposition_intents WHERE disposition_id=j.value)
    OR EXISTS(SELECT 1 FROM tree_restore_preparations WHERE transaction_id=j.value)
    OR EXISTS(SELECT 1 FROM tree_restore_execution_intents WHERE execution_id=j.value)
    OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents WHERE execution_id=j.value))
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.final_description_hash GLOB '*[^0-9a-f]*' OR NEW.request_hash GLOB '*[^0-9a-f]*'
OR NEW.plan_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid descriptive tree disposition reservation'); END;
CREATE TRIGGER tree_disposition_reservation_immutable BEFORE UPDATE ON tree_restore_disposition_reservations
BEGIN SELECT RAISE(ABORT,'descriptive tree disposition reservation immutable'); END;
CREATE TRIGGER tree_disposition_reservation_no_delete BEFORE DELETE ON tree_restore_disposition_reservations
BEGIN SELECT RAISE(ABORT,'descriptive tree disposition reservation retained'); END;

CREATE TRIGGER tree_disposition_intent_insert BEFORE INSERT ON tree_restore_disposition_intents
WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents
    WHERE disposition_id=NEW.disposition_id
    OR (transaction_id=NEW.transaction_id AND step_index=NEW.step_index))
OR EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_disposition_reservations h
    JOIN tree_restore_retained_descriptions r ON r.transaction_id=h.transaction_id
    AND r.step_index=NEW.step_index
    WHERE h.transaction_id=NEW.transaction_id AND h.coordinator_execution_id=NEW.coordinator_execution_id
    AND h.final_description_hash=NEW.final_description_hash AND h.described_at_ms=NEW.described_at_ms
    AND r.coordinator_execution_id=NEW.coordinator_execution_id AND r.step_execution_id=NEW.step_execution_id
    AND r.final_intent_hash=NEW.final_description_hash AND r.description_hash=NEW.retained_description_hash
    AND json_extract(NEW.intent,'$.retained')=json(r.description)
    AND json_extract(h.request,'$.input.disposition_ids."'||NEW.step_index||'"')=NEW.disposition_id)
OR json_extract(NEW.intent,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.intent,'$.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.intent,'$.step_index') IS NOT NEW.step_index
OR json_extract(NEW.intent,'$.disposition_id') IS NOT NEW.disposition_id
OR json_extract(NEW.intent,'$.final_description_hash') IS NOT NEW.final_description_hash
OR json_extract(NEW.intent,'$.retained_description_hash') IS NOT NEW.retained_description_hash
OR json_extract(NEW.intent,'$.described_at_ms') IS NOT NEW.described_at_ms
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.step_execution_id GLOB '*[^0-9a-f]*' OR NEW.disposition_id GLOB '*[^0-9a-f]*'
OR NEW.final_description_hash GLOB '*[^0-9a-f]*' OR NEW.retained_description_hash GLOB '*[^0-9a-f]*'
OR NEW.intent_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid descriptive tree disposition intent'); END;
CREATE TRIGGER tree_disposition_intent_immutable BEFORE UPDATE ON tree_restore_disposition_intents
BEGIN SELECT RAISE(ABORT,'descriptive tree disposition intent immutable'); END;
CREATE TRIGGER tree_disposition_intent_no_delete BEFORE DELETE ON tree_restore_disposition_intents
BEGIN SELECT RAISE(ABORT,'descriptive tree disposition generation single use'); END;

CREATE TRIGGER tree_disposition_record_insert BEFORE INSERT ON tree_restore_disposition_records
WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_records
    WHERE transaction_id=NEW.transaction_id AND step_index=NEW.step_index AND record_index=NEW.record_index)
OR EXISTS(SELECT 1 FROM tree_restore_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM tree_restore_disposition_intents i
    WHERE i.transaction_id=NEW.transaction_id AND i.step_index=NEW.step_index
    AND i.coordinator_execution_id=NEW.coordinator_execution_id AND i.disposition_id=NEW.disposition_id
    AND i.intent_hash=NEW.intent_hash AND i.described_at_ms<=NEW.recorded_at_ms
    AND ((NEW.record_index<3 AND json_extract(NEW.record,'$.event.original')
        =json_extract(i.intent,'$.retained.original.original_identity'))
    OR (NEW.record_index=3 AND json_extract(NEW.record,'$.event.component')
        =json_extract(i.intent,'$.retained.retained_component'))))
OR NOT EXISTS(SELECT 1 FROM tree_restore_disposition_reservations h
    WHERE h.transaction_id=NEW.transaction_id
    AND h.owner_count=(SELECT count(*) FROM tree_restore_disposition_intents
        WHERE transaction_id=h.transaction_id))
OR json_extract(NEW.record,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.record,'$.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.record,'$.step_index') IS NOT NEW.step_index
OR json_extract(NEW.record,'$.disposition_id') IS NOT NEW.disposition_id
OR json_extract(NEW.record,'$.record_index') IS NOT NEW.record_index
OR json_extract(NEW.record,'$.recorded_at_ms') IS NOT NEW.recorded_at_ms
OR json_extract(NEW.record,'$.intent_hash') IS NOT NEW.intent_hash
OR json_extract(NEW.record,'$.previous_hash') IS NOT NEW.previous_hash
OR json_extract(NEW.record,'$.event.event') IS NOT CASE NEW.record_index
    WHEN 0 THEN 'disposition_intended' WHEN 1 THEN 'disposition_requested'
    WHEN 2 THEN 'handle_closed' WHEN 3 THEN 'absence_described' END
OR (NEW.record_index=0 AND NEW.previous_hash IS NOT NEW.intent_hash)
OR (NEW.record_index>0 AND NOT EXISTS(SELECT 1 FROM tree_restore_disposition_records p
    WHERE p.transaction_id=NEW.transaction_id AND p.step_index=NEW.step_index
    AND p.record_index=NEW.record_index-1 AND p.record_hash=NEW.previous_hash
    AND p.recorded_at_ms<=NEW.recorded_at_ms))
OR EXISTS(SELECT 1 FROM tree_restore_disposition_records p
    WHERE p.transaction_id=NEW.transaction_id
    AND (p.step_index>NEW.step_index OR p.recorded_at_ms>NEW.recorded_at_ms
        OR (p.step_index=NEW.step_index AND p.record_index>=NEW.record_index)))
OR EXISTS(SELECT 1 FROM tree_restore_disposition_intents i
    WHERE i.transaction_id=NEW.transaction_id AND i.step_index<NEW.step_index
    AND NOT EXISTS(SELECT 1 FROM tree_restore_disposition_records p
        WHERE p.transaction_id=i.transaction_id AND p.step_index=i.step_index AND p.record_index=3))
OR NEW.transaction_id GLOB '*[^0-9a-f]*' OR NEW.coordinator_execution_id GLOB '*[^0-9a-f]*'
OR NEW.disposition_id GLOB '*[^0-9a-f]*' OR NEW.intent_hash GLOB '*[^0-9a-f]*'
OR NEW.previous_hash GLOB '*[^0-9a-f]*' OR NEW.record_hash GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT,'invalid descriptive tree disposition record'); END;
CREATE TRIGGER tree_disposition_record_immutable BEFORE UPDATE ON tree_restore_disposition_records
BEGIN SELECT RAISE(ABORT,'descriptive tree disposition record immutable'); END;
CREATE TRIGGER tree_disposition_record_no_delete BEFORE DELETE ON tree_restore_disposition_records
BEGIN SELECT RAISE(ABORT,'descriptive tree disposition record retained'); END;
CREATE TRIGGER tree_disposition_cancel_time BEFORE INSERT ON tree_restore_cancellations
WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_reservations
    WHERE transaction_id=NEW.transaction_id AND described_at_ms>NEW.cancelled_at_ms)
OR EXISTS(SELECT 1 FROM tree_restore_disposition_records
    WHERE transaction_id=NEW.transaction_id AND recorded_at_ms>NEW.cancelled_at_ms)
OR EXISTS(SELECT 1 FROM tree_restore_disposition_reservations h
    WHERE h.transaction_id=NEW.transaction_id
    AND h.owner_count!=(SELECT count(*) FROM tree_restore_disposition_intents
        WHERE transaction_id=h.transaction_id))
BEGIN SELECT RAISE(ABORT,'tree cancellation precedes or truncates disposition descriptions'); END;
-- Generation guard triggers will be appended by the local preparation script.
PRAGMA user_version=29;

-- Bidirectional disposition generation guards.

CREATE TRIGGER tree_disposition_generation_tree_restore_preparations_insert BEFORE INSERT ON tree_restore_preparations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.transaction_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_tree_restore_preparations_update BEFORE UPDATE ON tree_restore_preparations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.transaction_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_tree_restore_execution_intents_insert BEFORE INSERT ON tree_restore_execution_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.execution_id=d.disposition_id
        OR EXISTS(SELECT 1 FROM json_each(NEW.intent,'$.input.step_execution_ids') j
            WHERE j.value=d.disposition_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_tree_restore_execution_intents_update BEFORE UPDATE ON tree_restore_execution_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.execution_id=d.disposition_id
        OR EXISTS(SELECT 1 FROM json_each(NEW.intent,'$.input.step_execution_ids') j
            WHERE j.value=d.disposition_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_tree_restore_execution_step_intents_insert BEFORE INSERT ON tree_restore_execution_step_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.execution_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_tree_restore_execution_step_intents_update BEFORE UPDATE ON tree_restore_execution_step_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.execution_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_tree_restore_histories_insert BEFORE INSERT ON tree_restore_histories
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE EXISTS(SELECT 1 FROM
        json_each(NEW.intent,'$.history.fresh_entry_ids') j WHERE j.value=d.disposition_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_tree_restore_histories_update BEFORE UPDATE ON tree_restore_histories
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE EXISTS(SELECT 1 FROM
        json_each(NEW.intent,'$.history.fresh_entry_ids') j WHERE j.value=d.disposition_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_publications_insert BEFORE INSERT ON publications
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.transaction_id=d.disposition_id
        OR json_extract(NEW.intent,'$.entry_id')=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_publications_update BEFORE UPDATE ON publications
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.transaction_id=d.disposition_id
        OR json_extract(NEW.intent,'$.entry_id')=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_mutations_insert BEFORE INSERT ON mutations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.transaction_id=d.disposition_id
        OR json_extract(NEW.execution,'$.execution_id')=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_mutations_update BEFORE UPDATE ON mutations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.transaction_id=d.disposition_id
        OR json_extract(NEW.execution,'$.execution_id')=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_reference_reservations_insert BEFORE INSERT ON reference_reservations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.owner_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_reference_reservations_update BEFORE UPDATE ON reference_reservations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.owner_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_gc_executions_insert BEFORE INSERT ON gc_executions
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.execution_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_gc_executions_update BEFORE UPDATE ON gc_executions
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.execution_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_operations_insert BEFORE INSERT ON operations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE coalesce(json_extract(NEW.payload,'$.payload.change.entry.entry_id'),
        json_extract(NEW.payload,'$.payload.change.entry_id'))=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_operations_update BEFORE UPDATE ON operations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE coalesce(json_extract(NEW.payload,'$.payload.change.entry.entry_id'),
        json_extract(NEW.payload,'$.payload.change.entry_id'))=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_snapshots_insert BEFORE INSERT ON snapshots
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE EXISTS(SELECT 1 FROM json_each(NEW.manifest,'$.entries') j
        WHERE j.key=d.disposition_id)
        OR EXISTS(SELECT 1 FROM json_each(NEW.manifest,'$.tombstones') j
            WHERE j.key=d.disposition_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_snapshots_update BEFORE UPDATE ON snapshots
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE EXISTS(SELECT 1 FROM json_each(NEW.manifest,'$.entries') j
        WHERE j.key=d.disposition_id)
        OR EXISTS(SELECT 1 FROM json_each(NEW.manifest,'$.tombstones') j
            WHERE j.key=d.disposition_id)) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_new BEFORE INSERT ON tree_restore_disposition_intents
WHEN EXISTS(SELECT 1 FROM tree_restore_preparations WHERE transaction_id=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_intents WHERE execution_id=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents WHERE execution_id=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM publications WHERE transaction_id=NEW.disposition_id
    OR json_extract(intent,'$.entry_id')=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM mutations WHERE transaction_id=NEW.disposition_id
    OR json_extract(execution,'$.execution_id')=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM reference_reservations WHERE owner_id=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM read_leases WHERE lease_id=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM gc_marks WHERE mark_id=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM gc_authorizations WHERE authorization_id=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM gc_executions WHERE execution_id=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM gc_disposals WHERE disposal_id=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM tree_restore_histories h,
    json_each(h.intent,'$.history.fresh_entry_ids') j WHERE j.value=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM operations WHERE coalesce(
    json_extract(payload,'$.payload.change.entry.entry_id'),
    json_extract(payload,'$.payload.change.entry_id'))=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM snapshots s,json_each(s.manifest,'$.entries') j
    WHERE j.key=NEW.disposition_id)
OR EXISTS(SELECT 1 FROM snapshots s,json_each(s.manifest,'$.tombstones') j
    WHERE j.key=NEW.disposition_id)
BEGIN SELECT RAISE(ABORT,'tree disposition historical generation collision'); END;
PRAGMA user_version=29;

CREATE TRIGGER tree_disposition_generation_read_leases_insert BEFORE INSERT ON read_leases
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.lease_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_read_leases_update BEFORE UPDATE ON read_leases
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.lease_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_gc_marks_insert BEFORE INSERT ON gc_marks
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.mark_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_gc_marks_update BEFORE UPDATE ON gc_marks
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.mark_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_gc_authorizations_insert BEFORE INSERT ON gc_authorizations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.authorization_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_gc_authorizations_update BEFORE UPDATE ON gc_authorizations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.authorization_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_gc_disposals_insert BEFORE INSERT ON gc_disposals
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.disposal_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;

CREATE TRIGGER tree_disposition_generation_gc_disposals_update BEFORE UPDATE ON gc_disposals
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents)
    THEN EXISTS(SELECT 1 FROM tree_restore_disposition_intents d WHERE NEW.disposal_id=d.disposition_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree disposition generation already used'); END;
