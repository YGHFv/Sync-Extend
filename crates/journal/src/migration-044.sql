-- Whole future liabilities only; no creators, native effects, Final or release.
CREATE TABLE conflict_resolution_native_headers (
 transaction_id TEXT NOT NULL,
 parent_hash TEXT NOT NULL,
 binding_hash TEXT NOT NULL,
 generation TEXT NOT NULL,
 header_hash TEXT NOT NULL,
 layout_hash TEXT NOT NULL,
 reserved_rows INTEGER NOT NULL CHECK(reserved_rows>=0),
 reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),
 native_peak INTEGER NOT NULL CHECK(native_peak>=0),
 header TEXT NOT NULL,
 PRIMARY KEY(transaction_id),
 FOREIGN KEY(transaction_id) REFERENCES conflict_resolution_native_bindings(transaction_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_headers_insert BEFORE INSERT ON conflict_resolution_native_headers
WHEN sync_conflict_resolution_issue('native_headers',NEW.transaction_id,NEW.parent_hash,NEW.binding_hash,NEW.generation,NEW.header_hash,NEW.layout_hash,NEW.reserved_rows,NEW.reserved_bytes,NEW.native_peak,NEW.header)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_headers_update BEFORE UPDATE ON conflict_resolution_native_headers
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_headers_delete BEFORE DELETE ON conflict_resolution_native_headers
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TABLE conflict_resolution_native_templates (
 transaction_id TEXT NOT NULL,
 name TEXT NOT NULL,
 template_hash TEXT NOT NULL,
 reserved_rows INTEGER NOT NULL CHECK(reserved_rows>=0),
 reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),
 template TEXT NOT NULL,
 PRIMARY KEY(transaction_id,name),
 FOREIGN KEY(transaction_id) REFERENCES conflict_resolution_native_headers(transaction_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_templates_insert BEFORE INSERT ON conflict_resolution_native_templates
WHEN sync_conflict_resolution_issue('native_templates',NEW.transaction_id,NEW.name,NEW.template_hash,NEW.reserved_rows,NEW.reserved_bytes,NEW.template)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_templates_update BEFORE UPDATE ON conflict_resolution_native_templates
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_templates_delete BEFORE DELETE ON conflict_resolution_native_templates
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TABLE conflict_resolution_native_activations (
 transaction_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 step INTEGER NOT NULL CHECK(step>=0),
 header_hash TEXT NOT NULL,
 component TEXT NOT NULL,
 kind TEXT NOT NULL,
 parent_volume TEXT NOT NULL,
 parent_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,step),
 FOREIGN KEY(transaction_id) REFERENCES conflict_resolution_native_headers(transaction_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_activations_insert BEFORE INSERT ON conflict_resolution_native_activations
WHEN sync_conflict_resolution_issue('native_activations',NEW.transaction_id,NEW.generation,NEW.step,NEW.header_hash,NEW.component,NEW.kind,NEW.parent_volume,NEW.parent_id)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_activations_update BEFORE UPDATE ON conflict_resolution_native_activations
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_activations_delete BEFORE DELETE ON conflict_resolution_native_activations
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TABLE conflict_resolution_native_creators (
 transaction_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 step INTEGER NOT NULL CHECK(step>=0),
 header_hash TEXT NOT NULL,
 component TEXT NOT NULL,
 kind TEXT NOT NULL,
 parent_volume TEXT NOT NULL,
 parent_id TEXT NOT NULL,
 volume TEXT NOT NULL,
 full_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,step),
 FOREIGN KEY(transaction_id) REFERENCES conflict_resolution_native_headers(transaction_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_creators_insert BEFORE INSERT ON conflict_resolution_native_creators
WHEN sync_conflict_resolution_issue('native_creators',NEW.transaction_id,NEW.generation,NEW.step,NEW.header_hash,NEW.component,NEW.kind,NEW.parent_volume,NEW.parent_id,NEW.volume,NEW.full_id)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_creators_update BEFORE UPDATE ON conflict_resolution_native_creators
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_creators_delete BEFORE DELETE ON conflict_resolution_native_creators
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TABLE conflict_resolution_native_phases (
 transaction_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 header_hash TEXT NOT NULL,
 phase TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,phase),
 FOREIGN KEY(transaction_id) REFERENCES conflict_resolution_native_headers(transaction_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_phases_insert BEFORE INSERT ON conflict_resolution_native_phases
WHEN sync_conflict_resolution_issue('native_phases',NEW.transaction_id,NEW.generation,NEW.header_hash,NEW.phase,NEW.snapshot_id)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_phases_update BEFORE UPDATE ON conflict_resolution_native_phases
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_phases_delete BEFORE DELETE ON conflict_resolution_native_phases
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TABLE conflict_resolution_native_steps (
 transaction_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 header_hash TEXT NOT NULL,
 entry_id TEXT NOT NULL,
 action TEXT NOT NULL,
 phase TEXT NOT NULL,
 volume TEXT NOT NULL,
 full_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,entry_id,action,phase),
 FOREIGN KEY(transaction_id) REFERENCES conflict_resolution_native_headers(transaction_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_steps_insert BEFORE INSERT ON conflict_resolution_native_steps
WHEN sync_conflict_resolution_issue('native_steps',NEW.transaction_id,NEW.generation,NEW.header_hash,NEW.entry_id,NEW.action,NEW.phase,NEW.volume,NEW.full_id)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_steps_update BEFORE UPDATE ON conflict_resolution_native_steps
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_steps_delete BEFORE DELETE ON conflict_resolution_native_steps
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TABLE conflict_resolution_native_dispositions (
 transaction_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 header_hash TEXT NOT NULL,
 component TEXT NOT NULL,
 stage TEXT NOT NULL,
 volume TEXT NOT NULL,
 full_id TEXT NOT NULL,
 PRIMARY KEY(transaction_id,component,stage),
 FOREIGN KEY(transaction_id) REFERENCES conflict_resolution_native_headers(transaction_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_dispositions_insert BEFORE INSERT ON conflict_resolution_native_dispositions
WHEN sync_conflict_resolution_issue('native_dispositions',NEW.transaction_id,NEW.generation,NEW.header_hash,NEW.component,NEW.stage,NEW.volume,NEW.full_id)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_dispositions_update BEFORE UPDATE ON conflict_resolution_native_dispositions
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_dispositions_delete BEFORE DELETE ON conflict_resolution_native_dispositions
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TABLE conflict_resolution_native_history (
 transaction_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 parent_hash TEXT NOT NULL,
 target_root TEXT NOT NULL,
 record_hash TEXT NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(transaction_id),
 FOREIGN KEY(transaction_id) REFERENCES conflict_resolution_native_headers(transaction_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_history_insert BEFORE INSERT ON conflict_resolution_native_history
WHEN sync_conflict_resolution_issue('native_history',NEW.transaction_id,NEW.generation,NEW.parent_hash,NEW.target_root,NEW.record_hash,NEW.record)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_history_update BEFORE UPDATE ON conflict_resolution_native_history
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_history_delete BEFORE DELETE ON conflict_resolution_native_history
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TABLE conflict_resolution_native_events (
 transaction_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 event_index INTEGER NOT NULL CHECK(event_index>=0),
 record_hash TEXT NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(transaction_id,event_index),
 FOREIGN KEY(transaction_id) REFERENCES conflict_resolution_native_headers(transaction_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_events_insert BEFORE INSERT ON conflict_resolution_native_events
WHEN sync_conflict_resolution_issue('native_events',NEW.transaction_id,NEW.generation,NEW.event_index,NEW.record_hash,NEW.record)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_events_update BEFORE UPDATE ON conflict_resolution_native_events
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_events_delete BEFORE DELETE ON conflict_resolution_native_events
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TABLE conflict_resolution_native_history_objects (
 transaction_id TEXT NOT NULL,
 role TEXT NOT NULL,
 content_id TEXT NOT NULL,
 length INTEGER NOT NULL CHECK(length>=0),
 PRIMARY KEY(transaction_id,role,content_id),
 FOREIGN KEY(transaction_id) REFERENCES conflict_resolution_native_headers(transaction_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_history_objects_insert BEFORE INSERT ON conflict_resolution_native_history_objects
WHEN sync_conflict_resolution_issue('native_history_objects',NEW.transaction_id,NEW.role,NEW.content_id,NEW.length)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_history_objects_update BEFORE UPDATE ON conflict_resolution_native_history_objects
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_history_objects_delete BEFORE DELETE ON conflict_resolution_native_history_objects
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TABLE conflict_resolution_native_branch_handoffs (
 transaction_id TEXT NOT NULL REFERENCES conflict_resolution_native_headers(transaction_id),
 owner_id TEXT NOT NULL REFERENCES reference_reservations(owner_id),
 intent_hash TEXT NOT NULL,
 history_hash TEXT NOT NULL,
 PRIMARY KEY(transaction_id,owner_id)
) STRICT;
CREATE TRIGGER conflict_resolution_native_branch_handoffs_insert BEFORE INSERT ON conflict_resolution_native_branch_handoffs
WHEN sync_conflict_resolution_issue('native_branch_handoffs',NEW.transaction_id,NEW.owner_id,NEW.intent_hash,NEW.history_hash)!=1
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_branch_handoffs_update BEFORE UPDATE ON conflict_resolution_native_branch_handoffs
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
CREATE TRIGGER conflict_resolution_native_branch_handoffs_delete BEFORE DELETE ON conflict_resolution_native_branch_handoffs
BEGIN SELECT RAISE(ABORT,'immutable exact original whole conflict future issuance required'); END;
PRAGMA user_version=44;
