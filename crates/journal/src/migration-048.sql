-- Equivalent history is an exact metadata transition, never new native authority.
CREATE TABLE conflict_resolution_equivalent_histories (
 transaction_id TEXT NOT NULL PRIMARY KEY,
 base_transaction_id TEXT NOT NULL REFERENCES conflict_resolution_admissions(transaction_id),
 receiver_device TEXT NOT NULL,
 resolver_device TEXT NOT NULL,
 target_root TEXT NOT NULL,
 record_hash TEXT NOT NULL,
 record TEXT NOT NULL
) STRICT;
CREATE TABLE conflict_resolution_equivalent_signatures (
 transaction_id TEXT NOT NULL REFERENCES conflict_resolution_equivalent_histories(transaction_id),
 op_id TEXT NOT NULL,
 proof TEXT NOT NULL,
 PRIMARY KEY(transaction_id,op_id)
) STRICT;
CREATE TRIGGER conflict_resolution_equivalent_histories_insert BEFORE INSERT ON conflict_resolution_equivalent_histories
WHEN sync_conflict_resolution_issue('equivalent_histories',NEW.transaction_id,NEW.base_transaction_id,NEW.receiver_device,NEW.resolver_device,NEW.target_root,NEW.record_hash,NEW.record)!=1
BEGIN SELECT RAISE(ABORT,'exact live native equivalent history required'); END;
CREATE TRIGGER conflict_resolution_equivalent_histories_update BEFORE UPDATE ON conflict_resolution_equivalent_histories
BEGIN SELECT RAISE(ABORT,'immutable equivalent signed conflict history'); END;
CREATE TRIGGER conflict_resolution_equivalent_histories_delete BEFORE DELETE ON conflict_resolution_equivalent_histories
BEGIN SELECT RAISE(ABORT,'immutable equivalent signed conflict history'); END;
CREATE TRIGGER conflict_resolution_equivalent_signatures_insert BEFORE INSERT ON conflict_resolution_equivalent_signatures
WHEN sync_conflict_resolution_issue('equivalent_signatures',NEW.transaction_id,NEW.op_id,NEW.proof)!=1
BEGIN SELECT RAISE(ABORT,'exact live native equivalent signature required'); END;
CREATE TRIGGER conflict_resolution_equivalent_signatures_update BEFORE UPDATE ON conflict_resolution_equivalent_signatures
BEGIN SELECT RAISE(ABORT,'immutable equivalent signed conflict history'); END;
CREATE TRIGGER conflict_resolution_equivalent_signatures_delete BEFORE DELETE ON conflict_resolution_equivalent_signatures
BEGIN SELECT RAISE(ABORT,'immutable equivalent signed conflict history'); END;
CREATE TRIGGER conflict_equivalent_operations_update BEFORE UPDATE ON operations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_equivalent_signatures WHERE op_id=OLD.op_id)
BEGIN SELECT RAISE(ABORT,'immutable equivalent signed operation'); END;
CREATE TRIGGER conflict_equivalent_operations_delete BEFORE DELETE ON operations
WHEN EXISTS(SELECT 1 FROM conflict_resolution_equivalent_signatures WHERE op_id=OLD.op_id)
BEGIN SELECT RAISE(ABORT,'immutable equivalent signed operation'); END;
PRAGMA user_version=48;
