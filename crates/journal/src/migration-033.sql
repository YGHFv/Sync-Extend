-- TREE component-only admission. This is not a complete ordinary/global guard.
CREATE TABLE tree_native_future_admissions (
    space_id TEXT NOT NULL CHECK(length(CAST(space_id AS BLOB))=32 AND space_id NOT GLOB '*[^0-9a-f]*'),
    transaction_id TEXT NOT NULL PRIMARY KEY CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    coordinator_execution_id TEXT NOT NULL CHECK(length(CAST(coordinator_execution_id AS BLOB))=32 AND coordinator_execution_id NOT GLOB '*[^0-9a-f]*'),
    admission_id TEXT NOT NULL CHECK(length(CAST(admission_id AS BLOB))=32 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    admission_hash TEXT NOT NULL CHECK(length(CAST(admission_hash AS BLOB))=64 AND admission_hash NOT GLOB '*[^0-9a-f]*'),
    protocol_hash TEXT NOT NULL CHECK(length(CAST(protocol_hash AS BLOB))=64 AND protocol_hash NOT GLOB '*[^0-9a-f]*'),
    layout_hash TEXT NOT NULL CHECK(length(CAST(layout_hash AS BLOB))=64 AND layout_hash NOT GLOB '*[^0-9a-f]*'),
    prewrite_capacity_hash TEXT NOT NULL CHECK(length(CAST(prewrite_capacity_hash AS BLOB))=64 AND prewrite_capacity_hash NOT GLOB '*[^0-9a-f]*'),
    initial_intended_hash TEXT NOT NULL CHECK(length(CAST(initial_intended_hash AS BLOB))=64 AND initial_intended_hash NOT GLOB '*[^0-9a-f]*'),
    inventory_hash TEXT NOT NULL CHECK(length(CAST(inventory_hash AS BLOB))=64 AND inventory_hash NOT GLOB '*[^0-9a-f]*'),
    request_hash TEXT NOT NULL CHECK(length(CAST(request_hash AS BLOB))=64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
    capacity_hash TEXT NOT NULL CHECK(length(CAST(capacity_hash AS BLOB))=64 AND capacity_hash NOT GLOB '*[^0-9a-f]*'),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    max_entries INTEGER NOT NULL CHECK(max_entries BETWEEN 1 AND 1000000),
    action_count INTEGER NOT NULL CHECK(action_count BETWEEN 1 AND 500000),
    original_count INTEGER NOT NULL CHECK(original_count>=0),
    prior_rows INTEGER NOT NULL CHECK(prior_rows>=0),
    prior_bytes INTEGER NOT NULL CHECK(prior_bytes>=0),
    prior_budget_rows INTEGER NOT NULL CHECK(prior_budget_rows>=0),
    prior_budget_bytes INTEGER NOT NULL CHECK(prior_budget_bytes>=0),
    stored_rows INTEGER NOT NULL CHECK(stored_rows>=3),
    stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),
    future_rows INTEGER NOT NULL CHECK(future_rows>=0),
    future_bytes INTEGER NOT NULL CHECK(future_bytes>=0),
    new_rows INTEGER NOT NULL CHECK(new_rows>=0),
    new_bytes INTEGER NOT NULL CHECK(new_bytes>=0),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216),
    capacity TEXT NOT NULL CHECK(length(CAST(capacity AS BLOB)) BETWEEN 1 AND 16777216),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_capacity_admissions(transaction_id)
) STRICT;

CREATE TABLE tree_native_future_generations (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    generation_id TEXT NOT NULL CHECK(length(CAST(generation_id AS BLOB))=32 AND generation_id NOT GLOB '*[^0-9a-f]*'),
    purpose TEXT NOT NULL CHECK(purpose IN ('action_attempt','original_disposal','finalization','owner_cleanup')),
    ordinal INTEGER NOT NULL CHECK(ordinal>=0),
    capacity_hash TEXT NOT NULL CHECK(length(CAST(capacity_hash AS BLOB))=64 AND capacity_hash NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY(transaction_id,purpose,ordinal),
    UNIQUE(generation_id),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;

CREATE TRIGGER tree_native_future_admission_insert BEFORE INSERT ON tree_native_future_admissions
WHEN EXISTS(SELECT 1 FROM tree_native_future_admissions WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(
    SELECT 1 FROM tree_native_capacity_admissions c
    JOIN tree_native_action_headers h USING(transaction_id)
    JOIN tree_native_action_records r USING(transaction_id)
    WHERE c.transaction_id=NEW.transaction_id AND c.space_id=NEW.space_id
    AND c.coordinator_execution_id=NEW.coordinator_execution_id
    AND c.admission_id=NEW.admission_id AND c.admission_hash=NEW.admission_hash
    AND c.protocol_hash=NEW.protocol_hash AND c.layout_hash=NEW.layout_hash
    AND c.capacity_hash=NEW.prewrite_capacity_hash AND h.capacity_hash=c.capacity_hash
    AND r.record_index=0 AND r.action_ordinal=0 AND r.record_hash=NEW.initial_intended_hash
    AND r.recorded_at_ms<=NEW.created_at_ms
)
OR NEW.stored_rows IS NOT 3+NEW.action_count+NEW.original_count
OR NEW.future_rows IS NOT 3*NEW.action_count+7+4*NEW.original_count
OR NEW.prior_rows+NEW.stored_rows+NEW.future_rows>NEW.max_entries
OR NEW.prior_bytes+NEW.stored_bytes+NEW.future_bytes>NEW.max_entries*1024
OR NEW.prior_budget_rows+NEW.stored_rows+NEW.future_rows>NEW.max_entries
OR NEW.prior_budget_bytes+NEW.stored_bytes+NEW.future_bytes>NEW.max_entries*1024
OR json_extract(NEW.request,'$.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.request,'$.created_at_ms') IS NOT NEW.created_at_ms
OR json_extract(NEW.capacity,'$.format_version') IS NOT 1
OR json_extract(NEW.capacity,'$.accounting') IS NOT 'tree-future-component-only-not-global-capacity-v1'
OR json_extract(NEW.capacity,'$.scope.format_version') IS NOT 1
OR json_extract(NEW.capacity,'$.scope.space_id') IS NOT NEW.space_id
OR json_extract(NEW.capacity,'$.scope.transaction_id') IS NOT NEW.transaction_id
OR json_extract(NEW.capacity,'$.scope.coordinator_execution_id') IS NOT NEW.coordinator_execution_id
OR json_extract(NEW.capacity,'$.scope.admission_id') IS NOT NEW.admission_id
OR json_extract(NEW.capacity,'$.scope.admission_hash') IS NOT NEW.admission_hash
OR json_extract(NEW.capacity,'$.scope.protocol_hash') IS NOT NEW.protocol_hash
OR json_extract(NEW.capacity,'$.layout_hash') IS NOT NEW.layout_hash
OR json_extract(NEW.capacity,'$.prewrite_capacity_hash') IS NOT NEW.prewrite_capacity_hash
OR json_extract(NEW.capacity,'$.initial_intended_hash') IS NOT NEW.initial_intended_hash
OR json_extract(NEW.capacity,'$.prior.fingerprint') IS NOT NEW.inventory_hash
OR json_extract(NEW.capacity,'$.prior.rows') IS NOT NEW.prior_rows
OR json_extract(NEW.capacity,'$.prior.logical_bytes') IS NOT NEW.prior_bytes
OR json_extract(NEW.capacity,'$.prior.conservative_rows') IS NOT NEW.prior_budget_rows
OR json_extract(NEW.capacity,'$.prior.conservative_bytes') IS NOT NEW.prior_budget_bytes
OR json_extract(NEW.capacity,'$.request') IS NOT NEW.request
OR json_extract(NEW.capacity,'$.max_entries') IS NOT NEW.max_entries
OR json_extract(NEW.capacity,'$.action_count') IS NOT NEW.action_count
OR json_extract(NEW.capacity,'$.original_count') IS NOT NEW.original_count
OR json_array_length(NEW.capacity,'$.obligations') IS NOT NEW.future_rows
OR json_extract(NEW.capacity,'$.new_charge.rows') IS NOT NEW.new_rows
OR json_extract(NEW.capacity,'$.new_charge.logical_bytes') IS NOT NEW.new_bytes
OR NEW.prior_rows+NEW.stored_rows+NEW.future_rows+NEW.new_rows>
    json_extract(NEW.request,'$.inventory_limits.max_rows')
OR NEW.prior_bytes+NEW.stored_bytes+NEW.future_bytes+NEW.new_bytes>
    json_extract(NEW.request,'$.inventory_limits.max_logical_bytes')
BEGIN SELECT RAISE(ABORT,'invalid tree future component admission'); END;

CREATE TRIGGER tree_native_future_generation_insert BEFORE INSERT ON tree_native_future_generations
WHEN EXISTS(SELECT 1 FROM tree_native_future_generations WHERE generation_id=NEW.generation_id
    OR (transaction_id=NEW.transaction_id AND purpose=NEW.purpose AND ordinal=NEW.ordinal))
OR NOT EXISTS(
    SELECT 1 FROM tree_native_future_admissions f
    WHERE f.transaction_id=NEW.transaction_id AND f.capacity_hash=NEW.capacity_hash
    AND (
        (NEW.purpose='finalization' AND NEW.ordinal=0
            AND json_extract(f.capacity,'$.generations.finalization_id')=NEW.generation_id)
        OR (NEW.purpose='owner_cleanup' AND NEW.ordinal=0
            AND json_extract(f.capacity,'$.generations.cleanup_id')=NEW.generation_id)
        OR (NEW.purpose='action_attempt' AND NEW.ordinal<f.action_count
            AND json_extract(f.capacity,'$.generations.attempt_ids."' || NEW.ordinal || '"')=NEW.generation_id)
        OR (NEW.purpose='original_disposal'
            AND json_extract(f.capacity,'$.generations.disposal_ids."' || NEW.ordinal || '"')=NEW.generation_id)
    )
)
BEGIN SELECT RAISE(ABORT,'invalid tree future generation'); END;

CREATE TRIGGER tree_native_future_admission_immutable BEFORE UPDATE ON tree_native_future_admissions
BEGIN SELECT RAISE(ABORT,'tree future component admission immutable'); END;
CREATE TRIGGER tree_native_future_admission_retained BEFORE DELETE ON tree_native_future_admissions
BEGIN SELECT RAISE(ABORT,'tree future component admission retained'); END;
CREATE TRIGGER tree_native_future_generation_immutable BEFORE UPDATE ON tree_native_future_generations
BEGIN SELECT RAISE(ABORT,'tree future generation immutable'); END;
CREATE TRIGGER tree_native_future_generation_retained BEFORE DELETE ON tree_native_future_generations
BEGIN SELECT RAISE(ABORT,'tree future generation single use'); END;


-- Future effect namespaces: all inserts remain closed until a private issuer exists.
-- Component-only capacity/generation storage is the separate preceding DDL.
CREATE TABLE tree_native_action_attempts (
    space_id TEXT NOT NULL CHECK(length(CAST(space_id AS BLOB))=32 AND space_id NOT GLOB '*[^0-9a-f]*'),
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    coordinator_execution_id TEXT NOT NULL CHECK(length(CAST(coordinator_execution_id AS BLOB))=32 AND coordinator_execution_id NOT GLOB '*[^0-9a-f]*'),
    admission_id TEXT NOT NULL CHECK(length(CAST(admission_id AS BLOB))=32 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    admission_hash TEXT NOT NULL CHECK(length(CAST(admission_hash AS BLOB))=64 AND admission_hash NOT GLOB '*[^0-9a-f]*'),
    protocol_hash TEXT NOT NULL CHECK(length(CAST(protocol_hash AS BLOB))=64 AND protocol_hash NOT GLOB '*[^0-9a-f]*'),
    layout_hash TEXT NOT NULL CHECK(length(CAST(layout_hash AS BLOB))=64 AND layout_hash NOT GLOB '*[^0-9a-f]*'),
    full_capacity_hash TEXT NOT NULL CHECK(length(CAST(full_capacity_hash AS BLOB))=64 AND full_capacity_hash NOT GLOB '*[^0-9a-f]*'),
    intended_record_hash TEXT NOT NULL CHECK(length(CAST(intended_record_hash AS BLOB))=64 AND intended_record_hash NOT GLOB '*[^0-9a-f]*'),
    attempt_id TEXT NOT NULL CHECK(length(CAST(attempt_id AS BLOB))=32 AND attempt_id NOT GLOB '*[^0-9a-f]*'),
    action_ordinal INTEGER NOT NULL CHECK(action_ordinal>=0),
    intended_record_index INTEGER NOT NULL CHECK(intended_record_index>=0),
    attempted_at_ms INTEGER NOT NULL CHECK(attempted_at_ms>=0),
    request_hash TEXT NOT NULL CHECK(length(CAST(request_hash AS BLOB))=64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
    request TEXT NOT NULL CHECK(length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,action_ordinal),
    UNIQUE(attempt_id),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;
CREATE TRIGGER tree_native_action_attempts_insert_closed BEFORE INSERT ON tree_native_action_attempts
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_action_attempts_update_closed BEFORE UPDATE ON tree_native_action_attempts
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_action_attempts_delete_closed BEFORE DELETE ON tree_native_action_attempts
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TABLE tree_native_final_intents (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    coordinator_execution_id TEXT NOT NULL CHECK(length(CAST(coordinator_execution_id AS BLOB))=32 AND coordinator_execution_id NOT GLOB '*[^0-9a-f]*'),
    admission_id TEXT NOT NULL CHECK(length(CAST(admission_id AS BLOB))=32 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    finalization_id TEXT NOT NULL CHECK(length(CAST(finalization_id AS BLOB))=32 AND finalization_id NOT GLOB '*[^0-9a-f]*'),
    intent_hash TEXT NOT NULL CHECK(length(CAST(intent_hash AS BLOB))=64 AND intent_hash NOT GLOB '*[^0-9a-f]*'),
    action_root TEXT NOT NULL CHECK(length(CAST(action_root AS BLOB))=64 AND action_root NOT GLOB '*[^0-9a-f]*'),
    fresh_native_hash TEXT NOT NULL CHECK(length(CAST(fresh_native_hash AS BLOB))=64 AND fresh_native_hash NOT GLOB '*[^0-9a-f]*'),
    rows_hash TEXT NOT NULL CHECK(length(CAST(rows_hash AS BLOB))=64 AND rows_hash NOT GLOB '*[^0-9a-f]*'),
    snapshot_id TEXT NOT NULL CHECK(length(CAST(snapshot_id AS BLOB))=64 AND snapshot_id NOT GLOB '*[^0-9a-f]*'),
    input_closure_hash TEXT NOT NULL CHECK(length(CAST(input_closure_hash AS BLOB))=64 AND input_closure_hash NOT GLOB '*[^0-9a-f]*'),
    original_handoffs_hash TEXT NOT NULL CHECK(length(CAST(original_handoffs_hash AS BLOB))=64 AND original_handoffs_hash NOT GLOB '*[^0-9a-f]*'),
    intended_at_ms INTEGER NOT NULL CHECK(intended_at_ms>=0),
    intent TEXT NOT NULL CHECK(length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;
CREATE TRIGGER tree_native_final_intents_insert_closed BEFORE INSERT ON tree_native_final_intents
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_final_intents_update_closed BEFORE UPDATE ON tree_native_final_intents
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_final_intents_delete_closed BEFORE DELETE ON tree_native_final_intents
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TABLE tree_native_final_commits (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    coordinator_execution_id TEXT NOT NULL CHECK(length(CAST(coordinator_execution_id AS BLOB))=32 AND coordinator_execution_id NOT GLOB '*[^0-9a-f]*'),
    admission_id TEXT NOT NULL CHECK(length(CAST(admission_id AS BLOB))=32 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    finalization_id TEXT NOT NULL CHECK(length(CAST(finalization_id AS BLOB))=32 AND finalization_id NOT GLOB '*[^0-9a-f]*'),
    intent_hash TEXT NOT NULL CHECK(length(CAST(intent_hash AS BLOB))=64 AND intent_hash NOT GLOB '*[^0-9a-f]*'),
    committed_hash TEXT NOT NULL CHECK(length(CAST(committed_hash AS BLOB))=64 AND committed_hash NOT GLOB '*[^0-9a-f]*'),
    snapshot_id TEXT NOT NULL CHECK(length(CAST(snapshot_id AS BLOB))=64 AND snapshot_id NOT GLOB '*[^0-9a-f]*'),
    rows_hash TEXT NOT NULL CHECK(length(CAST(rows_hash AS BLOB))=64 AND rows_hash NOT GLOB '*[^0-9a-f]*'),
    committed_at_ms INTEGER NOT NULL CHECK(committed_at_ms>=0),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;
CREATE TRIGGER tree_native_final_commits_insert_closed BEFORE INSERT ON tree_native_final_commits
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_final_commits_update_closed BEFORE UPDATE ON tree_native_final_commits
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_final_commits_delete_closed BEFORE DELETE ON tree_native_final_commits
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TABLE tree_native_input_releases (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    finalization_id TEXT NOT NULL CHECK(length(CAST(finalization_id AS BLOB))=32 AND finalization_id NOT GLOB '*[^0-9a-f]*'),
    committed_hash TEXT NOT NULL CHECK(length(CAST(committed_hash AS BLOB))=64 AND committed_hash NOT GLOB '*[^0-9a-f]*'),
    input_closure_hash TEXT NOT NULL CHECK(length(CAST(input_closure_hash AS BLOB))=64 AND input_closure_hash NOT GLOB '*[^0-9a-f]*'),
    reference_count INTEGER NOT NULL CHECK(reference_count>=0),
    released_at_ms INTEGER NOT NULL CHECK(released_at_ms>=0),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;
CREATE TRIGGER tree_native_input_releases_insert_closed BEFORE INSERT ON tree_native_input_releases
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_input_releases_update_closed BEFORE UPDATE ON tree_native_input_releases
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_input_releases_delete_closed BEFORE DELETE ON tree_native_input_releases
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TABLE tree_native_retained_owners (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    finalization_id TEXT NOT NULL CHECK(length(CAST(finalization_id AS BLOB))=32 AND finalization_id NOT GLOB '*[^0-9a-f]*'),
    step_index INTEGER NOT NULL CHECK(step_index>=0),
    step_execution_id TEXT NOT NULL CHECK(length(CAST(step_execution_id AS BLOB))=32 AND step_execution_id NOT GLOB '*[^0-9a-f]*'),
    committed_hash TEXT NOT NULL CHECK(length(CAST(committed_hash AS BLOB))=64 AND committed_hash NOT GLOB '*[^0-9a-f]*'),
    handoff_hash TEXT NOT NULL CHECK(length(CAST(handoff_hash AS BLOB))=64 AND handoff_hash NOT GLOB '*[^0-9a-f]*'),
    retained_hash TEXT NOT NULL CHECK(length(CAST(retained_hash AS BLOB))=64 AND retained_hash NOT GLOB '*[^0-9a-f]*'),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,step_index),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;
CREATE TRIGGER tree_native_retained_owners_insert_closed BEFORE INSERT ON tree_native_retained_owners
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_retained_owners_update_closed BEFORE UPDATE ON tree_native_retained_owners
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_retained_owners_delete_closed BEFORE DELETE ON tree_native_retained_owners
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TABLE tree_native_original_intents (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    step_index INTEGER NOT NULL CHECK(step_index>=0),
    step_execution_id TEXT NOT NULL CHECK(length(CAST(step_execution_id AS BLOB))=32 AND step_execution_id NOT GLOB '*[^0-9a-f]*'),
    disposal_id TEXT NOT NULL CHECK(length(CAST(disposal_id AS BLOB))=32 AND disposal_id NOT GLOB '*[^0-9a-f]*'),
    finalization_id TEXT NOT NULL CHECK(length(CAST(finalization_id AS BLOB))=32 AND finalization_id NOT GLOB '*[^0-9a-f]*'),
    committed_hash TEXT NOT NULL CHECK(length(CAST(committed_hash AS BLOB))=64 AND committed_hash NOT GLOB '*[^0-9a-f]*'),
    retained_hash TEXT NOT NULL CHECK(length(CAST(retained_hash AS BLOB))=64 AND retained_hash NOT GLOB '*[^0-9a-f]*'),
    intent_hash TEXT NOT NULL CHECK(length(CAST(intent_hash AS BLOB))=64 AND intent_hash NOT GLOB '*[^0-9a-f]*'),
    intended_at_ms INTEGER NOT NULL CHECK(intended_at_ms>=0),
    intent TEXT NOT NULL CHECK(length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,step_index),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;
CREATE TRIGGER tree_native_original_intents_insert_closed BEFORE INSERT ON tree_native_original_intents
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_original_intents_update_closed BEFORE UPDATE ON tree_native_original_intents
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_original_intents_delete_closed BEFORE DELETE ON tree_native_original_intents
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TABLE tree_native_original_absences (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    step_index INTEGER NOT NULL CHECK(step_index>=0),
    disposal_id TEXT NOT NULL CHECK(length(CAST(disposal_id AS BLOB))=32 AND disposal_id NOT GLOB '*[^0-9a-f]*'),
    intent_hash TEXT NOT NULL CHECK(length(CAST(intent_hash AS BLOB))=64 AND intent_hash NOT GLOB '*[^0-9a-f]*'),
    absence_hash TEXT NOT NULL CHECK(length(CAST(absence_hash AS BLOB))=64 AND absence_hash NOT GLOB '*[^0-9a-f]*'),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,step_index),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;
CREATE TRIGGER tree_native_original_absences_insert_closed BEFORE INSERT ON tree_native_original_absences
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_original_absences_update_closed BEFORE UPDATE ON tree_native_original_absences
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_original_absences_delete_closed BEFORE DELETE ON tree_native_original_absences
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TABLE tree_native_original_terminals (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    step_index INTEGER NOT NULL CHECK(step_index>=0),
    disposal_id TEXT NOT NULL CHECK(length(CAST(disposal_id AS BLOB))=32 AND disposal_id NOT GLOB '*[^0-9a-f]*'),
    intent_hash TEXT NOT NULL CHECK(length(CAST(intent_hash AS BLOB))=64 AND intent_hash NOT GLOB '*[^0-9a-f]*'),
    absence_hash TEXT NOT NULL CHECK(length(CAST(absence_hash AS BLOB))=64 AND absence_hash NOT GLOB '*[^0-9a-f]*'),
    terminal_hash TEXT NOT NULL CHECK(length(CAST(terminal_hash AS BLOB))=64 AND terminal_hash NOT GLOB '*[^0-9a-f]*'),
    own_closure_hash TEXT NOT NULL CHECK(length(CAST(own_closure_hash AS BLOB))=64 AND own_closure_hash NOT GLOB '*[^0-9a-f]*'),
    reference_count INTEGER NOT NULL CHECK(reference_count>=0),
    released_at_ms INTEGER NOT NULL CHECK(released_at_ms>=0),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,step_index),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;
CREATE TRIGGER tree_native_original_terminals_insert_closed BEFORE INSERT ON tree_native_original_terminals
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_original_terminals_update_closed BEFORE UPDATE ON tree_native_original_terminals
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_original_terminals_delete_closed BEFORE DELETE ON tree_native_original_terminals
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TABLE tree_native_cleanup_intents (
    space_id TEXT NOT NULL CHECK(length(CAST(space_id AS BLOB))=32 AND space_id NOT GLOB '*[^0-9a-f]*'),
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    coordinator_execution_id TEXT NOT NULL CHECK(length(CAST(coordinator_execution_id AS BLOB))=32 AND coordinator_execution_id NOT GLOB '*[^0-9a-f]*'),
    admission_id TEXT NOT NULL CHECK(length(CAST(admission_id AS BLOB))=32 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    admission_hash TEXT NOT NULL CHECK(length(CAST(admission_hash AS BLOB))=64 AND admission_hash NOT GLOB '*[^0-9a-f]*'),
    protocol_hash TEXT NOT NULL CHECK(length(CAST(protocol_hash AS BLOB))=64 AND protocol_hash NOT GLOB '*[^0-9a-f]*'),
    finalization_id TEXT NOT NULL CHECK(length(CAST(finalization_id AS BLOB))=32 AND finalization_id NOT GLOB '*[^0-9a-f]*'),
    cleanup_id TEXT NOT NULL CHECK(length(CAST(cleanup_id AS BLOB))=32 AND cleanup_id NOT GLOB '*[^0-9a-f]*'),
    owner_intent_hash TEXT NOT NULL CHECK(length(CAST(owner_intent_hash AS BLOB))=64 AND owner_intent_hash NOT GLOB '*[^0-9a-f]*'),
    committed_hash TEXT NOT NULL CHECK(length(CAST(committed_hash AS BLOB))=64 AND committed_hash NOT GLOB '*[^0-9a-f]*'),
    input_release_hash TEXT NOT NULL CHECK(length(CAST(input_release_hash AS BLOB))=64 AND input_release_hash NOT GLOB '*[^0-9a-f]*'),
    original_terminals_hash TEXT NOT NULL CHECK(length(CAST(original_terminals_hash AS BLOB))=64 AND original_terminals_hash NOT GLOB '*[^0-9a-f]*'),
    intent_hash TEXT NOT NULL CHECK(length(CAST(intent_hash AS BLOB))=64 AND intent_hash NOT GLOB '*[^0-9a-f]*'),
    original_count INTEGER NOT NULL CHECK(original_count>=0),
    intended_at_ms INTEGER NOT NULL CHECK(intended_at_ms>=0),
    intent TEXT NOT NULL CHECK(length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;
CREATE TRIGGER tree_native_cleanup_intents_insert_closed BEFORE INSERT ON tree_native_cleanup_intents
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_cleanup_intents_update_closed BEFORE UPDATE ON tree_native_cleanup_intents
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_cleanup_intents_delete_closed BEFORE DELETE ON tree_native_cleanup_intents
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TABLE tree_native_cleanup_records (
    space_id TEXT NOT NULL CHECK(length(CAST(space_id AS BLOB))=32 AND space_id NOT GLOB '*[^0-9a-f]*'),
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    coordinator_execution_id TEXT NOT NULL CHECK(length(CAST(coordinator_execution_id AS BLOB))=32 AND coordinator_execution_id NOT GLOB '*[^0-9a-f]*'),
    admission_id TEXT NOT NULL CHECK(length(CAST(admission_id AS BLOB))=32 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    admission_hash TEXT NOT NULL CHECK(length(CAST(admission_hash AS BLOB))=64 AND admission_hash NOT GLOB '*[^0-9a-f]*'),
    protocol_hash TEXT NOT NULL CHECK(length(CAST(protocol_hash AS BLOB))=64 AND protocol_hash NOT GLOB '*[^0-9a-f]*'),
    finalization_id TEXT NOT NULL CHECK(length(CAST(finalization_id AS BLOB))=32 AND finalization_id NOT GLOB '*[^0-9a-f]*'),
    cleanup_id TEXT NOT NULL CHECK(length(CAST(cleanup_id AS BLOB))=32 AND cleanup_id NOT GLOB '*[^0-9a-f]*'),
    intent_hash TEXT NOT NULL CHECK(length(CAST(intent_hash AS BLOB))=64 AND intent_hash NOT GLOB '*[^0-9a-f]*'),
    record_index INTEGER NOT NULL CHECK(record_index>=0),
    previous_hash TEXT NOT NULL CHECK(length(CAST(previous_hash AS BLOB))=64 AND previous_hash NOT GLOB '*[^0-9a-f]*'),
    record_hash TEXT NOT NULL CHECK(length(CAST(record_hash AS BLOB))=64 AND record_hash NOT GLOB '*[^0-9a-f]*'),
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,record_index),
    FOREIGN KEY(transaction_id) REFERENCES tree_native_future_admissions(transaction_id)
) STRICT;
CREATE TRIGGER tree_native_cleanup_records_insert_closed BEFORE INSERT ON tree_native_cleanup_records
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_cleanup_records_update_closed BEFORE UPDATE ON tree_native_cleanup_records
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;
CREATE TRIGGER tree_native_cleanup_records_delete_closed BEFORE DELETE ON tree_native_cleanup_records
BEGIN SELECT RAISE(ABORT,'tree native private issuer not implemented'); END;

-- Immutable future generation exclusion. No native effect table exemption.
CREATE TRIGGER future_generation_tree_restore_preparations_insert BEFORE INSERT ON tree_restore_preparations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.transaction_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_preparations_update BEFORE UPDATE ON tree_restore_preparations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.transaction_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_execution_intents_insert BEFORE INSERT ON tree_restore_execution_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.execution_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_execution_intents_update BEFORE UPDATE ON tree_restore_execution_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.execution_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_execution_step_intents_insert BEFORE INSERT ON tree_restore_execution_step_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.execution_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_execution_step_intents_update BEFORE UPDATE ON tree_restore_execution_step_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.execution_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_coordinator_admissions_insert BEFORE INSERT ON tree_restore_coordinator_admissions
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.admission_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_coordinator_admissions_update BEFORE UPDATE ON tree_restore_coordinator_admissions
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.admission_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_disposition_intents_insert BEFORE INSERT ON tree_restore_disposition_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.disposition_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_disposition_intents_update BEFORE UPDATE ON tree_restore_disposition_intents
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.disposition_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_publications_insert BEFORE INSERT ON publications
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.transaction_id=g.generation_id OR json_extract(NEW.intent,'$.entry_id')=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_publications_update BEFORE UPDATE ON publications
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.transaction_id=g.generation_id OR json_extract(NEW.intent,'$.entry_id')=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_mutations_insert BEFORE INSERT ON mutations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.transaction_id=g.generation_id OR json_extract(NEW.execution,'$.execution_id')=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_mutations_update BEFORE UPDATE ON mutations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.transaction_id=g.generation_id OR json_extract(NEW.execution,'$.execution_id')=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_reference_reservations_insert BEFORE INSERT ON reference_reservations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.owner_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_reference_reservations_update BEFORE UPDATE ON reference_reservations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.owner_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_read_leases_insert BEFORE INSERT ON read_leases
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.lease_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_read_leases_update BEFORE UPDATE ON read_leases
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.lease_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_gc_marks_insert BEFORE INSERT ON gc_marks
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.mark_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_gc_marks_update BEFORE UPDATE ON gc_marks
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.mark_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_gc_authorizations_insert BEFORE INSERT ON gc_authorizations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.authorization_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_gc_authorizations_update BEFORE UPDATE ON gc_authorizations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.authorization_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_gc_executions_insert BEFORE INSERT ON gc_executions
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.execution_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_gc_executions_update BEFORE UPDATE ON gc_executions
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.execution_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_gc_disposals_insert BEFORE INSERT ON gc_disposals
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.disposal_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_gc_disposals_update BEFORE UPDATE ON gc_disposals
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.disposal_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_gc_quarantines_insert BEFORE INSERT ON gc_quarantines
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.plan_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_gc_quarantines_update BEFORE UPDATE ON gc_quarantines
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.plan_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_original_disposals_insert BEFORE INSERT ON original_disposals
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.plan_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_original_disposals_update BEFORE UPDATE ON original_disposals
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g
    WHERE NEW.plan_id=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_histories_history_fresh_entry_ids_insert BEFORE INSERT ON tree_restore_histories
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g,
    json_each(NEW.intent,'$.history.fresh_entry_ids') j WHERE j.value=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_tree_restore_histories_history_fresh_entry_ids_update BEFORE UPDATE ON tree_restore_histories
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g,
    json_each(NEW.intent,'$.history.fresh_entry_ids') j WHERE j.value=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_snapshots_entries_insert BEFORE INSERT ON snapshots
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g,
    json_each(NEW.manifest,'$.entries') j WHERE j.key=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_snapshots_entries_update BEFORE UPDATE ON snapshots
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g,
    json_each(NEW.manifest,'$.entries') j WHERE j.key=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_snapshots_tombstones_insert BEFORE INSERT ON snapshots
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g,
    json_each(NEW.manifest,'$.tombstones') j WHERE j.key=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_snapshots_tombstones_update BEFORE UPDATE ON snapshots
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g,
    json_each(NEW.manifest,'$.tombstones') j WHERE j.key=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_operations_insert BEFORE INSERT ON operations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g WHERE coalesce(json_extract(NEW.payload,'$.payload.change.entry.entry_id'),json_extract(NEW.payload,'$.payload.change.entry_id'))=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_operations_update BEFORE UPDATE ON operations
WHEN CASE WHEN EXISTS(SELECT 1 FROM tree_native_future_generations)
    THEN EXISTS(SELECT 1 FROM tree_native_future_generations g WHERE coalesce(json_extract(NEW.payload,'$.payload.change.entry.entry_id'),json_extract(NEW.payload,'$.payload.change.entry_id'))=g.generation_id) ELSE 0 END
BEGIN SELECT RAISE(ABORT,'tree future generation already used'); END;
CREATE TRIGGER future_generation_historical BEFORE INSERT ON tree_native_future_generations
WHEN EXISTS(SELECT 1 FROM tree_restore_preparations t WHERE t.transaction_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_intents t WHERE t.execution_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents t WHERE t.execution_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions t WHERE t.admission_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM tree_restore_disposition_intents t WHERE t.disposition_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM publications t WHERE t.transaction_id=NEW.generation_id OR json_extract(t.intent,'$.entry_id')=NEW.generation_id)
OR EXISTS(SELECT 1 FROM mutations t WHERE t.transaction_id=NEW.generation_id OR json_extract(t.execution,'$.execution_id')=NEW.generation_id)
OR EXISTS(SELECT 1 FROM reference_reservations t WHERE t.owner_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM read_leases t WHERE t.lease_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM gc_marks t WHERE t.mark_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM gc_authorizations t WHERE t.authorization_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM gc_executions t WHERE t.execution_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM gc_disposals t WHERE t.disposal_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM gc_quarantines t WHERE t.plan_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM original_disposals t WHERE t.plan_id=NEW.generation_id)
OR EXISTS(SELECT 1 FROM tree_restore_histories t,json_each(t.intent,'$.history.fresh_entry_ids') j WHERE j.value=NEW.generation_id)
OR EXISTS(SELECT 1 FROM snapshots t,json_each(t.manifest,'$.entries') j WHERE j.key=NEW.generation_id)
OR EXISTS(SELECT 1 FROM snapshots t,json_each(t.manifest,'$.tombstones') j WHERE j.key=NEW.generation_id)
OR EXISTS(SELECT 1 FROM operations t WHERE coalesce(json_extract(t.payload,'$.payload.change.entry.entry_id'),json_extract(t.payload,'$.payload.change.entry_id'))=NEW.generation_id)
BEGIN SELECT RAISE(ABORT,'tree future historical generation collision'); END;

PRAGMA user_version=33;
