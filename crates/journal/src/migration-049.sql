-- Individually authenticated original envelopes, not received/applied authority.
CREATE TABLE original_operation_provenance (
 space_id TEXT NOT NULL,
 origin_device_id TEXT NOT NULL,
 origin_seq INTEGER NOT NULL,
 op_id TEXT NOT NULL,
 proof_hash TEXT NOT NULL,
 proof TEXT NOT NULL,
 PRIMARY KEY(space_id,origin_device_id,origin_seq),
 UNIQUE(space_id,op_id)
) STRICT;
CREATE TRIGGER original_operation_provenance_insert BEFORE INSERT ON original_operation_provenance
WHEN sync_original_operation_issue(NEW.space_id,NEW.origin_device_id,NEW.origin_seq,NEW.op_id,NEW.proof_hash,NEW.proof)!=1
BEGIN SELECT RAISE(ABORT,'exact authenticated original provenance required'); END;
CREATE TRIGGER original_operation_provenance_update BEFORE UPDATE ON original_operation_provenance
BEGIN SELECT RAISE(ABORT,'immutable original signing provenance'); END;
CREATE TRIGGER original_operation_provenance_delete BEFORE DELETE ON original_operation_provenance
BEGIN SELECT RAISE(ABORT,'immutable original signing provenance'); END;
PRAGMA user_version=49;
