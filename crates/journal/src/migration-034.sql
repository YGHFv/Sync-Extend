-- Distinct original native creators, never executable schema33 TREE intentions.
CREATE TABLE native_publication_headers (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    space_id TEXT NOT NULL CHECK(length(CAST(space_id AS BLOB))=32 AND space_id NOT GLOB '*[^0-9a-f]*'),
    generation TEXT NOT NULL CHECK(length(CAST(generation AS BLOB))=32 AND generation NOT GLOB '*[^0-9a-f]*'),
    header_hash TEXT NOT NULL CHECK(length(CAST(header_hash AS BLOB))=64 AND header_hash NOT GLOB '*[^0-9a-f]*'),
    reserved_rows INTEGER NOT NULL CHECK(reserved_rows>=0),
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),
    header TEXT NOT NULL CHECK(length(CAST(header AS BLOB)) BETWEEN 1 AND 16777216),
    PRIMARY KEY(transaction_id),
    UNIQUE(generation),
    FOREIGN KEY(transaction_id) REFERENCES publications(transaction_id)
) STRICT;
CREATE TRIGGER native_publication_headers_insert BEFORE INSERT ON native_publication_headers
WHEN sync_native_publication_issue('headers',NEW.transaction_id,NEW.space_id,NEW.generation,NEW.header_hash,NEW.reserved_rows,NEW.reserved_bytes,NEW.header)!=1
BEGIN SELECT RAISE(ABORT,'native publication private issuer required'); END;
CREATE TRIGGER native_publication_headers_update BEFORE UPDATE ON native_publication_headers
BEGIN SELECT RAISE(ABORT,'native publication immutable retained ledger'); END;
CREATE TRIGGER native_publication_headers_delete BEFORE DELETE ON native_publication_headers
BEGIN SELECT RAISE(ABORT,'native publication immutable retained ledger'); END;
CREATE TABLE native_publication_activations (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    generation TEXT NOT NULL CHECK(length(CAST(generation AS BLOB))=32 AND generation NOT GLOB '*[^0-9a-f]*'),
    step INTEGER NOT NULL CHECK(step>=0),
    header_hash TEXT NOT NULL CHECK(length(CAST(header_hash AS BLOB))=64 AND header_hash NOT GLOB '*[^0-9a-f]*'),
    component TEXT NOT NULL CHECK(length(CAST(component AS BLOB)) BETWEEN 1 AND 255),
    kind TEXT NOT NULL CHECK(length(CAST(kind AS BLOB)) BETWEEN 1 AND 255),
    parent_volume TEXT NOT NULL CHECK(length(CAST(parent_volume AS BLOB))=16 AND parent_volume NOT GLOB '*[^0-9a-f]*'),
    parent_id TEXT NOT NULL CHECK(length(CAST(parent_id AS BLOB))=32 AND parent_id NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY(transaction_id,step),
    FOREIGN KEY(transaction_id) REFERENCES native_publication_headers(transaction_id)
) STRICT;
CREATE TRIGGER native_publication_activations_insert BEFORE INSERT ON native_publication_activations
WHEN sync_native_publication_issue('activations',NEW.transaction_id,NEW.generation,NEW.step,NEW.header_hash,NEW.component,NEW.kind,NEW.parent_volume,NEW.parent_id)!=1
BEGIN SELECT RAISE(ABORT,'native publication private issuer required'); END;
CREATE TRIGGER native_publication_activations_update BEFORE UPDATE ON native_publication_activations
BEGIN SELECT RAISE(ABORT,'native publication immutable retained ledger'); END;
CREATE TRIGGER native_publication_activations_delete BEFORE DELETE ON native_publication_activations
BEGIN SELECT RAISE(ABORT,'native publication immutable retained ledger'); END;
CREATE TABLE native_publication_creators (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    generation TEXT NOT NULL CHECK(length(CAST(generation AS BLOB))=32 AND generation NOT GLOB '*[^0-9a-f]*'),
    step INTEGER NOT NULL CHECK(step>=0),
    header_hash TEXT NOT NULL CHECK(length(CAST(header_hash AS BLOB))=64 AND header_hash NOT GLOB '*[^0-9a-f]*'),
    component TEXT NOT NULL CHECK(length(CAST(component AS BLOB)) BETWEEN 1 AND 255),
    kind TEXT NOT NULL CHECK(length(CAST(kind AS BLOB)) BETWEEN 1 AND 255),
    parent_volume TEXT NOT NULL CHECK(length(CAST(parent_volume AS BLOB))=16 AND parent_volume NOT GLOB '*[^0-9a-f]*'),
    parent_id TEXT NOT NULL CHECK(length(CAST(parent_id AS BLOB))=32 AND parent_id NOT GLOB '*[^0-9a-f]*'),
    volume TEXT NOT NULL CHECK(length(CAST(volume AS BLOB))=16 AND volume NOT GLOB '*[^0-9a-f]*'),
    full_id TEXT NOT NULL CHECK(length(CAST(full_id AS BLOB))=32 AND full_id NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY(transaction_id,step),
    FOREIGN KEY(transaction_id) REFERENCES native_publication_headers(transaction_id)
) STRICT;
CREATE TRIGGER native_publication_creators_insert BEFORE INSERT ON native_publication_creators
WHEN sync_native_publication_issue('creators',NEW.transaction_id,NEW.generation,NEW.step,NEW.header_hash,NEW.component,NEW.kind,NEW.parent_volume,NEW.parent_id,NEW.volume,NEW.full_id)!=1
BEGIN SELECT RAISE(ABORT,'native publication private issuer required'); END;
CREATE TRIGGER native_publication_creators_update BEFORE UPDATE ON native_publication_creators
BEGIN SELECT RAISE(ABORT,'native publication immutable retained ledger'); END;
CREATE TRIGGER native_publication_creators_delete BEFORE DELETE ON native_publication_creators
BEGIN SELECT RAISE(ABORT,'native publication immutable retained ledger'); END;
CREATE TABLE native_publication_phases (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    generation TEXT NOT NULL CHECK(length(CAST(generation AS BLOB))=32 AND generation NOT GLOB '*[^0-9a-f]*'),
    attempt INTEGER NOT NULL CHECK(attempt>=0),
    header_hash TEXT NOT NULL CHECK(length(CAST(header_hash AS BLOB))=64 AND header_hash NOT GLOB '*[^0-9a-f]*'),
    phase TEXT NOT NULL CHECK(length(CAST(phase AS BLOB)) BETWEEN 1 AND 255),
    identity_hash TEXT NOT NULL CHECK(length(CAST(identity_hash AS BLOB))=64 AND identity_hash NOT GLOB '*[^0-9a-f]*'),
    content_id TEXT NOT NULL CHECK(length(CAST(content_id AS BLOB))=64 AND content_id NOT GLOB '*[^0-9a-f]*'),
    target_hash TEXT NOT NULL CHECK(length(CAST(target_hash AS BLOB))=64 AND target_hash NOT GLOB '*[^0-9a-f]*'),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0),
    source_parent_volume TEXT NOT NULL CHECK(length(CAST(source_parent_volume AS BLOB))=16 AND source_parent_volume NOT GLOB '*[^0-9a-f]*'),
    source_parent_id TEXT NOT NULL CHECK(length(CAST(source_parent_id AS BLOB))=32 AND source_parent_id NOT GLOB '*[^0-9a-f]*'),
    target_parent_volume TEXT NOT NULL CHECK(length(CAST(target_parent_volume AS BLOB))=16 AND target_parent_volume NOT GLOB '*[^0-9a-f]*'),
    target_parent_id TEXT NOT NULL CHECK(length(CAST(target_parent_id AS BLOB))=32 AND target_parent_id NOT GLOB '*[^0-9a-f]*'),
    target_path TEXT NOT NULL CHECK(length(CAST(target_path AS BLOB)) BETWEEN 1 AND 4096),
    PRIMARY KEY(transaction_id,attempt,phase),
    FOREIGN KEY(transaction_id) REFERENCES native_publication_headers(transaction_id)
) STRICT;
CREATE TRIGGER native_publication_phases_insert BEFORE INSERT ON native_publication_phases
WHEN 1
BEGIN SELECT RAISE(ABORT,'native publication private issuer required'); END;
CREATE TRIGGER native_publication_phases_update BEFORE UPDATE ON native_publication_phases
BEGIN SELECT RAISE(ABORT,'native publication immutable retained ledger'); END;
CREATE TRIGGER native_publication_phases_delete BEFORE DELETE ON native_publication_phases
BEGIN SELECT RAISE(ABORT,'native publication immutable retained ledger'); END;
CREATE TABLE native_publication_dispositions (
    transaction_id TEXT NOT NULL CHECK(length(CAST(transaction_id AS BLOB))=32 AND transaction_id NOT GLOB '*[^0-9a-f]*'),
    generation TEXT NOT NULL CHECK(length(CAST(generation AS BLOB))=32 AND generation NOT GLOB '*[^0-9a-f]*'),
    step INTEGER NOT NULL CHECK(step>=0),
    header_hash TEXT NOT NULL CHECK(length(CAST(header_hash AS BLOB))=64 AND header_hash NOT GLOB '*[^0-9a-f]*'),
    stage TEXT NOT NULL CHECK(length(CAST(stage AS BLOB)) BETWEEN 1 AND 255),
    identity_hash TEXT NOT NULL CHECK(length(CAST(identity_hash AS BLOB))=64 AND identity_hash NOT GLOB '*[^0-9a-f]*'),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0),
    PRIMARY KEY(transaction_id,step,stage),
    FOREIGN KEY(transaction_id) REFERENCES native_publication_headers(transaction_id)
) STRICT;
CREATE TRIGGER native_publication_dispositions_insert BEFORE INSERT ON native_publication_dispositions
BEGIN SELECT RAISE(ABORT,'native disposition private issuer not implemented'); END;
CREATE TRIGGER native_publication_dispositions_update BEFORE UPDATE ON native_publication_dispositions
BEGIN SELECT RAISE(ABORT,'native publication immutable retained ledger'); END;
CREATE TRIGGER native_publication_dispositions_delete BEFORE DELETE ON native_publication_dispositions
BEGIN SELECT RAISE(ABORT,'native publication immutable retained ledger'); END;
PRAGMA user_version=34;
