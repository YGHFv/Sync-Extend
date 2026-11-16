-- D01 draft: exact durable execution reservation and one-attempt activation.
-- Integrate as a fresh migration only after the actual published schema64 parent.
CREATE TABLE webdav_native_execution_admissions (
    transaction_id TEXT PRIMARY KEY NOT NULL REFERENCES webdav_native_admissions(transaction_id),
    description_hash TEXT NOT NULL CHECK(length(description_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    plan_hash TEXT NOT NULL CHECK(length(plan_hash)=64),
    max_records INTEGER NOT NULL CHECK(max_records>0),
    max_record_bytes INTEGER NOT NULL CHECK(max_record_bytes>0),
    max_total_bytes INTEGER NOT NULL CHECK(max_total_bytes>0),
    admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms>=0),
    admission_hash TEXT NOT NULL CHECK(length(admission_hash)=64)
) STRICT;
CREATE TABLE webdav_native_execution_records (
    transaction_id TEXT NOT NULL REFERENCES webdav_native_execution_admissions(transaction_id),
    record_index INTEGER NOT NULL CHECK(record_index>=0),
    record_hash TEXT NOT NULL CHECK(length(record_hash)=64),
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,record_index)
) STRICT;
CREATE TRIGGER webdav_native_execution_admission_insert
BEFORE INSERT ON webdav_native_execution_admissions
WHEN NOT sync_webdav_native_execution_admission_issue(NEW.admission_hash,NEW.admitted_at_ms)
OR EXISTS(SELECT 1 FROM webdav_native_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM webdav_native_admissions a
    WHERE a.transaction_id=NEW.transaction_id AND a.request_hash=NEW.request_hash
    AND a.plan_hash=NEW.plan_hash AND a.admitted_at_ms<=NEW.admitted_at_ms)
OR NOT EXISTS(SELECT 1 FROM webdav_native_clock WHERE singleton=1 AND observed_at_ms=NEW.admitted_at_ms)
BEGIN SELECT RAISE(ABORT,'exact durable DAV execution admission required'); END;
CREATE TRIGGER webdav_native_execution_admission_update
BEFORE UPDATE ON webdav_native_execution_admissions
BEGIN SELECT RAISE(ABORT,'DAV execution admission immutable'); END;
CREATE TRIGGER webdav_native_execution_admission_delete
BEFORE DELETE ON webdav_native_execution_admissions
BEGIN SELECT RAISE(ABORT,'DAV execution admission retained'); END;
CREATE TRIGGER webdav_native_execution_record_insert
BEFORE INSERT ON webdav_native_execution_records
WHEN NOT sync_webdav_native_execution_record_issue(NEW.record_hash,NEW.recorded_at_ms)
OR EXISTS(SELECT 1 FROM webdav_native_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM webdav_native_execution_admissions
    WHERE transaction_id=NEW.transaction_id AND admitted_at_ms<=NEW.recorded_at_ms)
OR NEW.record_index!=(SELECT count(*) FROM webdav_native_execution_records WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM webdav_native_clock WHERE singleton=1 AND observed_at_ms=NEW.recorded_at_ms)
BEGIN SELECT RAISE(ABORT,'exact ordered DAV execution record required'); END;
CREATE TRIGGER webdav_native_execution_record_update
BEFORE UPDATE ON webdav_native_execution_records
BEGIN SELECT RAISE(ABORT,'DAV execution record immutable'); END;
CREATE TRIGGER webdav_native_execution_record_delete
BEFORE DELETE ON webdav_native_execution_records
BEGIN SELECT RAISE(ABORT,'DAV execution record retained'); END;
DROP TRIGGER webdav_native_cancel_insert;
CREATE TRIGGER webdav_native_cancel_insert BEFORE INSERT ON webdav_native_cancellations
WHEN NOT sync_webdav_native_cancel_issue(NEW.transaction_id,NEW.cancelled_at_ms)
OR NOT EXISTS(SELECT 1 FROM webdav_native_clock WHERE singleton=1 AND observed_at_ms=NEW.cancelled_at_ms)
OR NOT EXISTS(SELECT 1 FROM webdav_native_admissions WHERE transaction_id=NEW.transaction_id
    AND admitted_at_ms<=NEW.cancelled_at_ms)
OR EXISTS(SELECT 1 FROM webdav_native_execution_records WHERE transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'exact empty-history DAV cancellation required'); END;


-- D01-D05 draft only. Bind to the real published schema before integration.
-- No raw SQL caller can mint a private native receipt or rewrite its lineage.
CREATE TABLE webdav_native_execution_templates (
    transaction_id TEXT NOT NULL REFERENCES webdav_native_execution_admissions(transaction_id),
    template_index INTEGER NOT NULL CHECK(template_index>=0),
    template_hash TEXT NOT NULL CHECK(length(template_hash)=64),
    max_new_rows INTEGER NOT NULL CHECK(max_new_rows>=0),
    max_new_bytes INTEGER NOT NULL CHECK(max_new_bytes>=0),
    issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>=0),
    template TEXT NOT NULL CHECK(length(CAST(template AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,template_index)
) STRICT;
CREATE TABLE webdav_native_execution_bindings (
    transaction_id TEXT NOT NULL REFERENCES webdav_native_execution_admissions(transaction_id),
    binding_index INTEGER NOT NULL CHECK(binding_index>=0),
    binding_hash TEXT NOT NULL CHECK(length(binding_hash)=64),
    issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>=0),
    binding TEXT NOT NULL CHECK(length(CAST(binding AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,binding_index)
) STRICT;
CREATE TABLE webdav_native_execution_receipts (
    transaction_id TEXT NOT NULL REFERENCES webdav_native_execution_admissions(transaction_id),
    receipt_index INTEGER NOT NULL CHECK(receipt_index>=0),
    template_index INTEGER NOT NULL CHECK(template_index>=0),
    receipt_hash TEXT NOT NULL CHECK(length(receipt_hash)=64),
    issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>=0),
    receipt TEXT NOT NULL CHECK(length(CAST(receipt AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id,receipt_index),
    UNIQUE(transaction_id,template_index),
    FOREIGN KEY(transaction_id,template_index)
        REFERENCES webdav_native_execution_templates(transaction_id,template_index)
) STRICT;
CREATE TRIGGER webdav_native_execution_template_insert
BEFORE INSERT ON webdav_native_execution_templates
WHEN NOT sync_webdav_native_execution_template_issue(NEW.template_hash,NEW.issued_at_ms)
OR EXISTS(SELECT 1 FROM webdav_native_cancellations WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM webdav_native_execution_records WHERE transaction_id=NEW.transaction_id)
OR NEW.template_index!=(SELECT count(*) FROM webdav_native_execution_templates
    WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM webdav_native_clock WHERE singleton=1 AND observed_at_ms=NEW.issued_at_ms)
BEGIN SELECT RAISE(ABORT,'exact complete pre-activation DAV template issue required'); END;
CREATE TRIGGER webdav_native_execution_template_update
BEFORE UPDATE ON webdav_native_execution_templates
BEGIN SELECT RAISE(ABORT,'DAV execution template immutable'); END;
CREATE TRIGGER webdav_native_execution_template_delete
BEFORE DELETE ON webdav_native_execution_templates
BEGIN SELECT RAISE(ABORT,'DAV execution template retained'); END;
CREATE TRIGGER webdav_native_execution_binding_insert
BEFORE INSERT ON webdav_native_execution_bindings
WHEN NOT sync_webdav_native_execution_binding_issue(NEW.binding_hash,NEW.issued_at_ms)
OR EXISTS(SELECT 1 FROM webdav_native_cancellations WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM webdav_native_execution_records WHERE transaction_id=NEW.transaction_id)
OR NEW.binding_index!=(SELECT count(*) FROM webdav_native_execution_bindings
    WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM webdav_native_clock WHERE singleton=1 AND observed_at_ms=NEW.issued_at_ms)
BEGIN SELECT RAISE(ABORT,'exact privately retained original DAV binding issue required'); END;
CREATE TRIGGER webdav_native_execution_binding_update
BEFORE UPDATE ON webdav_native_execution_bindings
BEGIN SELECT RAISE(ABORT,'DAV execution original binding immutable'); END;
CREATE TRIGGER webdav_native_execution_binding_delete
BEFORE DELETE ON webdav_native_execution_bindings
BEGIN SELECT RAISE(ABORT,'DAV execution original binding retained'); END;
CREATE TRIGGER webdav_native_execution_receipt_insert
BEFORE INSERT ON webdav_native_execution_receipts
WHEN NOT sync_webdav_native_execution_receipt_issue(NEW.receipt_hash,NEW.issued_at_ms)
OR EXISTS(SELECT 1 FROM webdav_native_cancellations WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM webdav_native_execution_records WHERE transaction_id=NEW.transaction_id)
OR NEW.receipt_index!=(SELECT count(*) FROM webdav_native_execution_receipts
    WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM webdav_native_clock WHERE singleton=1 AND observed_at_ms=NEW.issued_at_ms)
BEGIN SELECT RAISE(ABORT,'exact live native DAV receipt issue required'); END;
CREATE TRIGGER webdav_native_execution_receipt_update
BEFORE UPDATE ON webdav_native_execution_receipts
BEGIN SELECT RAISE(ABORT,'DAV execution private receipt immutable'); END;
CREATE TRIGGER webdav_native_execution_receipt_delete
BEFORE DELETE ON webdav_native_execution_receipts
BEGIN SELECT RAISE(ABORT,'DAV execution private receipt retained'); END;

-- Draft appended to actual schema65 only after binding complete private admission.
CREATE TABLE webdav_native_execution_manifests (
    transaction_id TEXT PRIMARY KEY NOT NULL
        REFERENCES webdav_native_execution_admissions(transaction_id),
    manifest_hash TEXT NOT NULL CHECK(length(manifest_hash)=64),
    template_count INTEGER NOT NULL CHECK(template_count>0),
    binding_count INTEGER NOT NULL CHECK(binding_count>0),
    max_receipts INTEGER NOT NULL CHECK(max_receipts>0),
    future_rows INTEGER NOT NULL CHECK(future_rows>=0),
    future_bytes INTEGER NOT NULL CHECK(future_bytes>=0),
    admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms>=0),
    manifest TEXT NOT NULL CHECK(length(CAST(manifest AS BLOB)) BETWEEN 1 AND 16777216)
) STRICT;
CREATE TRIGGER webdav_native_execution_manifest_insert
BEFORE INSERT ON webdav_native_execution_manifests
WHEN NOT sync_webdav_native_execution_manifest_issue(NEW.manifest_hash,NEW.admitted_at_ms)
OR EXISTS(SELECT 1 FROM webdav_native_cancellations WHERE transaction_id=NEW.transaction_id)
OR EXISTS(SELECT 1 FROM webdav_native_execution_records WHERE transaction_id=NEW.transaction_id)
OR NOT EXISTS(SELECT 1 FROM webdav_native_execution_admissions
    WHERE transaction_id=NEW.transaction_id AND admitted_at_ms=NEW.admitted_at_ms)
OR NEW.template_count!=(SELECT count(*) FROM webdav_native_execution_templates
    WHERE transaction_id=NEW.transaction_id)
OR NEW.binding_count!=(SELECT count(*) FROM webdav_native_execution_bindings
    WHERE transaction_id=NEW.transaction_id)
OR NEW.max_receipts!=NEW.template_count
OR NOT json_valid(NEW.manifest)
OR json_type(NEW.manifest,'$.template_hashes') IS NOT 'array'
OR json_array_length(NEW.manifest,'$.template_hashes') IS NOT NEW.template_count
OR json_type(NEW.manifest,'$.binding_hashes') IS NOT 'array'
OR json_array_length(NEW.manifest,'$.binding_hashes') IS NOT NEW.binding_count
OR EXISTS(SELECT 1 FROM webdav_native_execution_templates t
    WHERE t.transaction_id=NEW.transaction_id
    AND t.template_hash IS NOT json_extract(NEW.manifest,'$.template_hashes['||t.template_index||']'))
OR EXISTS(SELECT 1 FROM webdav_native_execution_bindings b
    WHERE b.transaction_id=NEW.transaction_id
    AND b.binding_hash IS NOT json_extract(NEW.manifest,'$.binding_hashes['||b.binding_index||']'))
OR json_type(NEW.manifest,'$.future') IS NOT 'array'
OR json_array_length(NEW.manifest,'$.future')!=3
OR EXISTS(SELECT 1 FROM json_each(NEW.manifest,'$.future') f
    WHERE json_type(f.value,'$.rows') IS NOT 'integer'
    OR json_extract(f.value,'$.rows')<0
    OR json_type(f.value,'$.bytes') IS NOT 'integer'
    OR json_extract(f.value,'$.bytes')<0)
OR NEW.future_rows IS NOT (SELECT sum(json_extract(f.value,'$.rows'))
    FROM json_each(NEW.manifest,'$.future') f)
OR NEW.future_bytes IS NOT (SELECT sum(json_extract(f.value,'$.bytes'))
    FROM json_each(NEW.manifest,'$.future') f)
OR json_extract(NEW.manifest,'$.scope.transaction_id') IS NOT NEW.transaction_id
OR NOT EXISTS(SELECT 1 FROM webdav_native_execution_admissions a
    WHERE a.transaction_id=NEW.transaction_id
    AND a.description_hash IS json_extract(NEW.manifest,'$.scope.description_hash')
    AND a.request_hash IS json_extract(NEW.manifest,'$.scope.request_hash')
    AND a.plan_hash IS json_extract(NEW.manifest,'$.scope.plan_hash'))
OR json_extract(NEW.manifest,'$.future[0].table') IS NOT 'webdav_native_execution_records'
OR json_extract(NEW.manifest,'$.future[1].table') IS NOT 'webdav_native_execution_receipts'
OR json_extract(NEW.manifest,'$.future[2].table') IS NOT 'original_planner_final_main_rows'
OR json_extract(NEW.manifest,'$.future[0].rows') IS NOT
    (SELECT max_records FROM webdav_native_execution_admissions
        WHERE transaction_id=NEW.transaction_id)
OR json_extract(NEW.manifest,'$.future[0].bytes') IS NOT
    (SELECT max_records*112+max_total_bytes FROM webdav_native_execution_admissions
        WHERE transaction_id=NEW.transaction_id)
OR json_extract(NEW.manifest,'$.future[1].rows') IS NOT NEW.max_receipts
OR json_type(NEW.manifest,'$.native_peak') IS NOT 'object'
OR json_type(NEW.manifest,'$.native_peak.payload_file_lengths') IS NOT 'array'
OR json_type(NEW.manifest,'$.native_peak.additional_namespace_paths') IS NOT 'integer'
OR json_extract(NEW.manifest,'$.native_peak.additional_namespace_paths')<3
OR json_type(NEW.manifest,'$.native_peak.additional_directory_objects') IS NOT 'integer'
OR json_extract(NEW.manifest,'$.native_peak.additional_directory_objects')<2
OR json_type(NEW.manifest,'$.native_peak.additional_file_objects') IS NOT 'integer'
OR json_extract(NEW.manifest,'$.native_peak.additional_file_objects')<1
OR json_array_length(NEW.manifest,'$.native_peak.payload_file_lengths') IS NOT
    json_extract(NEW.manifest,'$.native_peak.additional_file_objects')
OR json_extract(NEW.manifest,'$.native_peak.payload_file_lengths[0]') IS NOT 97
OR EXISTS(SELECT 1 FROM json_each(NEW.manifest,'$.native_peak.payload_file_lengths') p
    WHERE p.type IS NOT 'integer' OR p.value<0)
OR json_extract(NEW.manifest,'$.native_peak.additional_logical_file_bytes') IS NOT
    (SELECT sum(p.value) FROM json_each(NEW.manifest,'$.native_peak.payload_file_lengths') p)
OR json_type(NEW.manifest,'$.native_peak.prospective_namespace_paths') IS NOT 'integer'
OR json_extract(NEW.manifest,'$.native_peak.prospective_namespace_paths') <
    json_extract(NEW.manifest,'$.native_peak.additional_namespace_paths')+4
OR json_extract(NEW.manifest,'$.admitted_at_ms') IS NOT NEW.admitted_at_ms
OR NOT EXISTS(SELECT 1 FROM webdav_native_execution_admissions a
    WHERE a.transaction_id=NEW.transaction_id
    AND a.max_records=json_extract(NEW.manifest,'$.limits.execution_records')
    AND a.max_record_bytes=json_extract(NEW.manifest,'$.limits.max_execution_record_json')
    AND a.max_total_bytes=json_extract(NEW.manifest,'$.limits.max_total_execution_json'))
OR NOT EXISTS(SELECT 1 FROM webdav_native_clock
    WHERE singleton=1 AND observed_at_ms=NEW.admitted_at_ms)
BEGIN SELECT RAISE(ABORT,'complete exact pre-activation DAV budget manifest required'); END;
CREATE TRIGGER webdav_native_execution_manifest_update
BEFORE UPDATE ON webdav_native_execution_manifests
BEGIN SELECT RAISE(ABORT,'DAV budget manifest immutable'); END;
CREATE TRIGGER webdav_native_execution_manifest_delete
BEFORE DELETE ON webdav_native_execution_manifests
BEGIN SELECT RAISE(ABORT,'DAV budget manifest retained'); END;

-- Complete catalog gate supplements Rust full-value and private proof audit.
CREATE TRIGGER webdav_native_execution_template_sealed
BEFORE INSERT ON webdav_native_execution_templates
WHEN EXISTS(SELECT 1 FROM webdav_native_execution_manifests
    WHERE transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'DAV complete template set already sealed'); END;
CREATE TRIGGER webdav_native_execution_binding_sealed
BEFORE INSERT ON webdav_native_execution_bindings
WHEN EXISTS(SELECT 1 FROM webdav_native_execution_manifests
    WHERE transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'DAV complete binding set already sealed'); END;
CREATE TRIGGER webdav_native_execution_record_complete_manifest
BEFORE INSERT ON webdav_native_execution_records
WHEN NOT EXISTS(SELECT 1 FROM webdav_native_execution_manifests m
    WHERE m.transaction_id=NEW.transaction_id
    AND m.template_count=(SELECT count(*) FROM webdav_native_execution_templates
        WHERE transaction_id=NEW.transaction_id)
    AND m.binding_count=(SELECT count(*) FROM webdav_native_execution_bindings
        WHERE transaction_id=NEW.transaction_id)
    AND m.max_receipts=m.template_count
    AND m.admitted_at_ms<=NEW.recorded_at_ms)
BEGIN SELECT RAISE(ABORT,'full original DAV budget manifest required before activation'); END;
CREATE TRIGGER webdav_native_execution_receipt_complete_manifest
BEFORE INSERT ON webdav_native_execution_receipts
WHEN NOT EXISTS(SELECT 1 FROM webdav_native_execution_manifests m
    WHERE m.transaction_id=NEW.transaction_id
    AND NEW.receipt_index<m.max_receipts
    AND NEW.template_index<m.template_count
    AND m.admitted_at_ms<=NEW.issued_at_ms)
BEGIN SELECT RAISE(ABORT,'full bounded DAV budget manifest required before receipt'); END;

-- D04 exact row permits; active original owner still excludes unrelated writers.
DROP TRIGGER webdav_native_operations_insert;
CREATE TRIGGER webdav_native_final_operations_insert
BEFORE INSERT ON operations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=NEW.space_id)
AND NOT sync_webdav_original_final_row_issue('operations','insert',NULL,json_array(NEW.op_id,NEW.space_id,NEW.origin_device_id,NEW.origin_seq,NEW.payload,NEW.state))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
DROP TRIGGER webdav_native_operations_update;
CREATE TRIGGER webdav_native_final_operations_update
BEFORE UPDATE ON operations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=NEW.space_id)
AND NOT sync_webdav_original_final_row_issue('operations','update',json_array(OLD.op_id,OLD.space_id,OLD.origin_device_id,OLD.origin_seq,OLD.payload,OLD.state),json_array(NEW.op_id,NEW.space_id,NEW.origin_device_id,NEW.origin_seq,NEW.payload,NEW.state))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
DROP TRIGGER webdav_native_operations_delete;
CREATE TRIGGER webdav_native_final_operations_delete
BEFORE DELETE ON operations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=OLD.space_id)
AND NOT sync_webdav_original_final_row_issue('operations','delete',json_array(OLD.op_id,OLD.space_id,OLD.origin_device_id,OLD.origin_seq,OLD.payload,OLD.state),NULL)
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_receive_cursors_insert
BEFORE INSERT ON receive_cursors
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=NEW.space_id)
AND NOT sync_webdav_original_final_row_issue('receive_cursors','insert',NULL,json_array(NEW.space_id,NEW.device_id,NEW.contiguous_seq))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_receive_cursors_update
BEFORE UPDATE ON receive_cursors
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=NEW.space_id)
AND NOT sync_webdav_original_final_row_issue('receive_cursors','update',json_array(OLD.space_id,OLD.device_id,OLD.contiguous_seq),json_array(NEW.space_id,NEW.device_id,NEW.contiguous_seq))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_receive_cursors_delete
BEFORE DELETE ON receive_cursors
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=OLD.space_id)
AND NOT sync_webdav_original_final_row_issue('receive_cursors','delete',json_array(OLD.space_id,OLD.device_id,OLD.contiguous_seq),NULL)
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_snapshots_insert
BEFORE INSERT ON snapshots
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=NEW.space_id)
AND NOT sync_webdav_original_final_row_issue('snapshots','insert',NULL,json_array(NEW.snapshot_id,NEW.space_id,NEW.manifest,NEW.created_at_ms,NEW.state,NEW.locked))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_snapshots_update
BEFORE UPDATE ON snapshots
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=NEW.space_id)
AND NOT sync_webdav_original_final_row_issue('snapshots','update',json_array(OLD.snapshot_id,OLD.space_id,OLD.manifest,OLD.created_at_ms,OLD.state,OLD.locked),json_array(NEW.snapshot_id,NEW.space_id,NEW.manifest,NEW.created_at_ms,NEW.state,NEW.locked))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_snapshots_delete
BEFORE DELETE ON snapshots
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=OLD.space_id)
AND NOT sync_webdav_original_final_row_issue('snapshots','delete',json_array(OLD.snapshot_id,OLD.space_id,OLD.manifest,OLD.created_at_ms,OLD.state,OLD.locked),NULL)
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
DROP TRIGGER webdav_native_current_insert;
CREATE TRIGGER webdav_native_final_current_manifests_insert
BEFORE INSERT ON current_manifests
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=NEW.space_id)
AND NOT sync_webdav_original_final_row_issue('current_manifests','insert',NULL,json_array(NEW.space_id,NEW.snapshot_id))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
DROP TRIGGER webdav_native_current_update;
CREATE TRIGGER webdav_native_final_current_manifests_update
BEFORE UPDATE ON current_manifests
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=NEW.space_id)
AND NOT sync_webdav_original_final_row_issue('current_manifests','update',json_array(OLD.space_id,OLD.snapshot_id),json_array(NEW.space_id,NEW.snapshot_id))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
DROP TRIGGER webdav_native_current_delete;
CREATE TRIGGER webdav_native_final_current_manifests_delete
BEFORE DELETE ON current_manifests
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=OLD.space_id)
AND NOT sync_webdav_original_final_row_issue('current_manifests','delete',json_array(OLD.space_id,OLD.snapshot_id),NULL)
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_snapshot_objects_insert
BEFORE INSERT ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal'))
AND NOT sync_webdav_original_final_row_issue('snapshot_objects','insert',NULL,json_array(NEW.snapshot_id,NEW.content_id))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_snapshot_objects_update
BEFORE UPDATE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal'))
AND NOT sync_webdav_original_final_row_issue('snapshot_objects','update',json_array(OLD.snapshot_id,OLD.content_id),json_array(NEW.snapshot_id,NEW.content_id))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_snapshot_objects_delete
BEFORE DELETE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal'))
AND NOT sync_webdav_original_final_row_issue('snapshot_objects','delete',json_array(OLD.snapshot_id,OLD.content_id),NULL)
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_rename_observations_insert
BEFORE INSERT ON rename_observations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=NEW.space_id)
AND NOT sync_webdav_original_final_row_issue('rename_observations','insert',NULL,json_array(NEW.space_id,NEW.snapshot_id,NEW.observation,NEW.observation_hash))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_rename_observations_update
BEFORE UPDATE ON rename_observations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=NEW.space_id)
AND NOT sync_webdav_original_final_row_issue('rename_observations','update',json_array(OLD.space_id,OLD.snapshot_id,OLD.observation,OLD.observation_hash),json_array(NEW.space_id,NEW.snapshot_id,NEW.observation,NEW.observation_hash))
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;
CREATE TRIGGER webdav_native_final_rename_observations_delete
BEFORE DELETE ON rename_observations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a
LEFT JOIN webdav_native_cancellations c USING(transaction_id)
WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal') AND a.space_id=OLD.space_id)
AND NOT sync_webdav_original_final_row_issue('rename_observations','delete',json_array(OLD.space_id,OLD.snapshot_id,OLD.observation,OLD.observation_hash),NULL)
BEGIN SELECT RAISE(ABORT,'exact original DAV causal Final row required'); END;

DROP TRIGGER webdav_native_snapshot_pruning;
CREATE TRIGGER webdav_native_snapshot_pruning BEFORE INSERT ON snapshot_prunings
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.baseline_snapshot=NEW.snapshot_id AND c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal'))
BEGIN SELECT RAISE(ABORT,'DAV original snapshot retained'); END;
DROP TRIGGER webdav_native_snapshot_object_delete;
CREATE TRIGGER webdav_native_snapshot_object_delete BEFORE DELETE ON snapshot_objects
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.baseline_snapshot=OLD.snapshot_id AND c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal'))
BEGIN SELECT RAISE(ABORT,'DAV original content retained'); END;
DROP TRIGGER webdav_native_publication_insert;
CREATE TRIGGER webdav_native_publication_insert BEFORE INSERT ON publications
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=NEW.space_id AND c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal'))
BEGIN SELECT RAISE(ABORT,'DAV description excludes publication'); END;
DROP TRIGGER webdav_native_mutation_insert;
CREATE TRIGGER webdav_native_mutation_insert BEFORE INSERT ON mutations
WHEN EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=NEW.space_id AND c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal'))
BEGIN SELECT RAISE(ABORT,'DAV description excludes mutation'); END;
DROP TRIGGER webdav_native_cleanup_update;
CREATE TRIGGER webdav_native_cleanup_update BEFORE UPDATE ON cleanup_plans
WHEN NEW.state='executing' AND EXISTS(
    SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE a.space_id=NEW.space_id AND c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal'))
BEGIN SELECT RAISE(ABORT,'DAV description excludes cleanup'); END;
DROP TRIGGER webdav_native_admission_insert;
CREATE TRIGGER webdav_native_admission_insert BEFORE INSERT ON webdav_native_admissions
WHEN NOT sync_webdav_native_description_issue(NEW.plan_hash,NEW.admitted_at_ms)
OR NOT EXISTS(SELECT 1 FROM webdav_native_clock WHERE singleton=1 AND observed_at_ms=NEW.admitted_at_ms)
OR NOT EXISTS(SELECT 1 FROM current_manifests WHERE space_id=NEW.space_id AND snapshot_id=NEW.baseline_snapshot)
OR EXISTS(SELECT 1 FROM webdav_native_admissions a LEFT JOIN webdav_native_cancellations c USING(transaction_id)
    WHERE c.transaction_id IS NULL AND NOT EXISTS(SELECT 1 FROM webdav_native_execution_receipts t
    WHERE t.transaction_id=a.transaction_id AND json_extract(t.receipt,'$.stage.stage')='terminal'))
BEGIN SELECT RAISE(ABORT,'exact DAV description issuance required'); END;

PRAGMA user_version=65;
