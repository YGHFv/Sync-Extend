-- Immutable original baseline keys only; no native effects or future liability.
CREATE TABLE conflict_resolution_native_bindings (
 transaction_id TEXT NOT NULL PRIMARY KEY REFERENCES conflict_resolution_admissions(transaction_id),
 parent_hash TEXT NOT NULL,
 binding_hash TEXT NOT NULL,
 binding TEXT NOT NULL
) STRICT;
CREATE TRIGGER conflict_resolution_native_bindings_insert BEFORE INSERT ON conflict_resolution_native_bindings
WHEN sync_conflict_resolution_issue('native_bindings',NEW.transaction_id,NEW.parent_hash,NEW.binding_hash,NEW.binding)!=1
BEGIN SELECT RAISE(ABORT,'exact private original conflict baseline issuance required'); END;
CREATE TRIGGER conflict_resolution_native_bindings_update BEFORE UPDATE ON conflict_resolution_native_bindings
BEGIN SELECT RAISE(ABORT,'immutable original conflict baseline retained'); END;
CREATE TRIGGER conflict_resolution_native_bindings_delete BEFORE DELETE ON conflict_resolution_native_bindings
BEGIN SELECT RAISE(ABORT,'immutable original conflict baseline retained'); END;
PRAGMA user_version=43;
