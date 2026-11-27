-- Extend inert source storage to exact registered catalogs. The Journal loader
-- executes this whole rebuild in one transaction. No archived cell is rewritten;
-- old source images, signatures, row/hold digests and writer events are preserved.
CREATE TEMP TABLE migration073_native_history_sources AS SELECT * FROM main.native_history_sources;
CREATE TEMP TABLE migration073_native_history_source_tables AS SELECT * FROM main.native_history_source_tables;
CREATE TEMP TABLE migration073_native_history_source_rows AS SELECT * FROM main.native_history_source_rows;
CREATE TEMP TABLE migration073_native_history_holds AS SELECT * FROM main.native_history_holds;
CREATE TEMP TABLE migration073_native_history_hold_rows AS SELECT * FROM main.native_history_hold_rows;
CREATE TEMP TABLE migration073_native_history_hold_objects AS SELECT * FROM main.native_history_hold_objects;
CREATE TEMP TABLE migration073_native_history_projection_rows AS SELECT * FROM main.native_history_projection_rows;
CREATE TEMP TABLE migration073_native_history_projection_root_columns AS SELECT * FROM main.native_history_projection_root_columns;
CREATE TEMP TABLE migration073_native_history_fresh_writers AS SELECT * FROM main.native_history_fresh_writers;
CREATE TEMP TABLE migration073_native_history_fresh_writer_events AS SELECT * FROM main.native_history_fresh_writer_events;
DROP TRIGGER native_history_sources_immutable;
DROP TRIGGER native_history_sources_no_delete;
DROP TRIGGER native_history_source_tables_immutable;
DROP TRIGGER native_history_source_tables_no_delete;
DROP TRIGGER native_history_source_rows_immutable;
DROP TRIGGER native_history_source_rows_no_delete;
DROP TRIGGER native_history_holds_immutable;
DROP TRIGGER native_history_holds_no_release;
DROP TRIGGER native_history_hold_rows_immutable;
DROP TRIGGER native_history_hold_rows_no_release;
DROP TRIGGER native_history_hold_objects_immutable;
DROP TRIGGER native_history_hold_objects_no_release;
DROP TRIGGER native_history_projection_rows_immutable;
DROP TRIGGER native_history_projection_rows_no_delete;
DROP TRIGGER native_history_projection_root_columns_immutable;
DROP TRIGGER native_history_projection_root_columns_no_delete;
DROP TRIGGER native_history_fresh_writer_insert;
DROP TRIGGER native_history_fresh_writer_transition;
DROP TRIGGER native_history_fresh_writer_no_delete;
DROP TRIGGER native_history_fresh_writer_event_insert;
DROP TRIGGER native_history_fresh_writer_event_immutable;
DROP TRIGGER native_history_fresh_writer_event_no_delete;
DROP TABLE native_history_fresh_writer_events;
DROP TABLE native_history_fresh_writers;
DROP TABLE native_history_projection_root_columns;
DROP TABLE native_history_projection_rows;
DROP TABLE native_history_hold_objects;
DROP TABLE native_history_hold_rows;
DROP TABLE native_history_holds;
DROP TABLE native_history_source_rows;
DROP TABLE native_history_source_tables;
DROP TABLE native_history_sources;
CREATE TABLE native_history_sources (
    source_digest TEXT PRIMARY KEY NOT NULL CHECK(length(source_digest)=64 AND source_digest NOT GLOB '*[^0-9a-f]*'),
    format_version INTEGER NOT NULL CHECK(format_version=1),
    source_schema INTEGER NOT NULL CHECK(source_schema IN (69,70,71,72,73)),
    space_id TEXT NOT NULL CHECK(length(space_id)=32 AND space_id NOT GLOB '*[^0-9a-f]*'),
    image BLOB NOT NULL CHECK(length(image) BETWEEN 512 AND 268435456),
    image_digest TEXT NOT NULL CHECK(length(image_digest)=64 AND image_digest NOT GLOB '*[^0-9a-f]*'),
    catalog_digest TEXT NOT NULL CHECK(length(catalog_digest)=64 AND catalog_digest NOT GLOB '*[^0-9a-f]*'),
    rows_digest TEXT NOT NULL CHECK(length(rows_digest)=64 AND rows_digest NOT GLOB '*[^0-9a-f]*'),
    registry_digest TEXT NOT NULL CHECK(length(registry_digest)=64 AND registry_digest NOT GLOB '*[^0-9a-f]*'),
    table_count INTEGER NOT NULL CHECK((source_schema=69 AND table_count=141) OR (source_schema IN (70,71,72,73) AND table_count=151)),
    row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 100000),
    hold_count INTEGER NOT NULL CHECK(hold_count BETWEEN 1 AND 100000),
    projection_row_count INTEGER NOT NULL CHECK(projection_row_count BETWEEN 0 AND 100000),
    root_mapping_count INTEGER NOT NULL CHECK(root_mapping_count BETWEEN 0 AND 1),
    logical_bytes INTEGER NOT NULL CHECK(logical_bytes>=0),
    bound_max_entries INTEGER NOT NULL CHECK(bound_max_entries BETWEEN 1 AND 100000),
    bound_inventory_rows INTEGER NOT NULL CHECK(bound_inventory_rows BETWEEN 1 AND 100000),
    bound_inventory_logical_bytes INTEGER NOT NULL CHECK(bound_inventory_logical_bytes>0),
    bound_rows INTEGER NOT NULL CHECK(bound_rows BETWEEN 1 AND 100000),
    bound_logical_bytes INTEGER NOT NULL CHECK(bound_logical_bytes>0),
    bound_vm_instructions INTEGER NOT NULL CHECK(bound_vm_instructions BETWEEN 1000 AND 250000000),
    bound_query_nanos INTEGER NOT NULL CHECK(bound_query_nanos BETWEEN 1 AND 300000000000)
) STRICT;
CREATE TABLE native_history_source_tables (
    source_digest TEXT NOT NULL REFERENCES native_history_sources(source_digest),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 150),
    table_name TEXT NOT NULL CHECK(length(CAST(table_name AS BLOB)) BETWEEN 1 AND 128),
    row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 100000),
    logical_bytes INTEGER NOT NULL CHECK(logical_bytes>=0),
    digest TEXT NOT NULL CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY(source_digest,ordinal),
    UNIQUE(source_digest,table_name)
) STRICT;
CREATE TABLE native_history_source_rows (
    source_digest TEXT NOT NULL REFERENCES native_history_sources(source_digest),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 99999),
    table_name TEXT NOT NULL CHECK(length(CAST(table_name AS BLOB)) BETWEEN 1 AND 128),
    primary_key TEXT NOT NULL CHECK(length(CAST(primary_key AS BLOB)) BETWEEN 1 AND 65536 AND json_valid(primary_key)),
    columns_json TEXT NOT NULL CHECK(length(CAST(columns_json AS BLOB)) BETWEEN 1 AND 268435456 AND json_valid(columns_json)),
    logical_bytes INTEGER NOT NULL CHECK(logical_bytes>=0),
    fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64 AND fingerprint NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY(source_digest,ordinal),
    UNIQUE(source_digest,table_name,primary_key)
) STRICT;
CREATE TABLE native_history_holds (
    source_digest TEXT NOT NULL REFERENCES native_history_sources(source_digest),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 99999),
    family TEXT NOT NULL CHECK(length(CAST(family AS BLOB)) BETWEEN 1 AND 64),
    anchor_table TEXT NOT NULL CHECK(length(CAST(anchor_table AS BLOB)) BETWEEN 1 AND 128),
    anchor_key TEXT NOT NULL CHECK(length(CAST(anchor_key AS BLOB)) BETWEEN 1 AND 65536 AND json_valid(anchor_key)),
    row_count INTEGER NOT NULL CHECK(row_count BETWEEN 1 AND 100000),
    object_count INTEGER NOT NULL CHECK(object_count BETWEEN 0 AND 100000),
    digest TEXT NOT NULL CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY(source_digest,ordinal),
    UNIQUE(source_digest,family,anchor_table,anchor_key)
) STRICT;
CREATE TABLE native_history_hold_rows (
    source_digest TEXT NOT NULL,
    hold_ordinal INTEGER NOT NULL CHECK(hold_ordinal BETWEEN 0 AND 99999),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 99999),
    row_ordinal INTEGER NOT NULL CHECK(row_ordinal BETWEEN 0 AND 99999),
    PRIMARY KEY(source_digest,hold_ordinal,ordinal),
    UNIQUE(source_digest,hold_ordinal,row_ordinal),
    FOREIGN KEY(source_digest,hold_ordinal) REFERENCES native_history_holds(source_digest,ordinal),
    FOREIGN KEY(source_digest,row_ordinal) REFERENCES native_history_source_rows(source_digest,ordinal)
) STRICT;
CREATE TABLE native_history_hold_objects (
    source_digest TEXT NOT NULL,
    hold_ordinal INTEGER NOT NULL CHECK(hold_ordinal BETWEEN 0 AND 99999),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 99999),
    kind TEXT NOT NULL CHECK(kind IN ('cas_chunk','file_content_digest','native_marker_digest')),
    content_id TEXT NOT NULL CHECK(length(content_id)=64 AND content_id NOT GLOB '*[^0-9a-f]*'),
    length INTEGER NOT NULL CHECK(length BETWEEN 0 AND 4194304),
    source_row_ordinal INTEGER NOT NULL CHECK(source_row_ordinal BETWEEN 0 AND 99999),
    source_column TEXT NOT NULL CHECK(length(CAST(source_column AS BLOB)) BETWEEN 1 AND 256),
    PRIMARY KEY(source_digest,hold_ordinal,ordinal),
    FOREIGN KEY(source_digest,hold_ordinal) REFERENCES native_history_holds(source_digest,ordinal),
    FOREIGN KEY(source_digest,source_row_ordinal) REFERENCES native_history_source_rows(source_digest,ordinal)
) STRICT;
CREATE TABLE native_history_projection_rows (
    source_digest TEXT NOT NULL REFERENCES native_history_sources(source_digest),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 99999),
    row_ordinal INTEGER NOT NULL CHECK(row_ordinal BETWEEN 0 AND 99999),
    PRIMARY KEY(source_digest,ordinal),
    UNIQUE(source_digest,row_ordinal),
    FOREIGN KEY(source_digest,row_ordinal) REFERENCES native_history_source_rows(source_digest,ordinal)
) STRICT;
CREATE TABLE native_history_projection_root_columns (
    source_digest TEXT NOT NULL REFERENCES native_history_sources(source_digest),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 0),
    row_ordinal INTEGER NOT NULL CHECK(row_ordinal BETWEEN 0 AND 99999),
    column_name TEXT NOT NULL CHECK(length(CAST(column_name AS BLOB)) BETWEEN 1 AND 128),
    original_value TEXT NOT NULL CHECK(length(CAST(original_value AS BLOB)) BETWEEN 1 AND 32768),
    projected_value TEXT NOT NULL CHECK(length(CAST(projected_value AS BLOB)) BETWEEN 1 AND 32768 AND projected_value!=original_value),
    PRIMARY KEY(source_digest,ordinal),
    FOREIGN KEY(source_digest,row_ordinal) REFERENCES native_history_source_rows(source_digest,ordinal)
) STRICT;
CREATE TABLE native_history_fresh_writers (
    writer_id TEXT PRIMARY KEY NOT NULL CHECK(length(writer_id)=32 AND writer_id NOT GLOB '*[^0-9a-f]*'),
    source_digest TEXT NOT NULL REFERENCES native_history_sources(source_digest) CHECK(length(source_digest)=64),
    projection_digest TEXT NOT NULL CHECK(length(projection_digest)=64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
    image_digest TEXT NOT NULL CHECK(length(image_digest)=64 AND image_digest NOT GLOB '*[^0-9a-f]*'),
    space_id TEXT NOT NULL CHECK(length(space_id)=32 AND space_id NOT GLOB '*[^0-9a-f]*'),
    device_id TEXT NOT NULL CHECK(length(device_id)=64 AND device_id NOT GLOB '*[^0-9a-f]*'),
    worktree TEXT NOT NULL CHECK(length(CAST(worktree AS BLOB)) BETWEEN 1 AND 32768),
    creator_id TEXT NOT NULL CHECK(length(creator_id)=32 AND creator_id NOT GLOB '*[^0-9a-f]*'),
    nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL CHECK(state IN ('admitted','created','replaced','closed','reopened')),
    created_snapshot TEXT CHECK(created_snapshot IS NULL OR (length(created_snapshot)=64 AND created_snapshot NOT GLOB '*[^0-9a-f]*')),
    replaced_snapshot TEXT CHECK(replaced_snapshot IS NULL OR (length(replaced_snapshot)=64 AND replaced_snapshot NOT GLOB '*[^0-9a-f]*')),
    admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms>=0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=admitted_at_ms),
    UNIQUE(source_digest,creator_id)
) STRICT;
CREATE TABLE native_history_fresh_writer_events (
    writer_id TEXT NOT NULL REFERENCES native_history_fresh_writers(writer_id) CHECK(length(writer_id)=32),
    sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 1024),
    event TEXT NOT NULL CHECK(length(CAST(event AS BLOB)) BETWEEN 1 AND 4096 AND json_valid(event)),
    previous_hash TEXT NOT NULL CHECK(length(previous_hash)=64 AND previous_hash NOT GLOB '*[^0-9a-f]*'),
    event_hash TEXT NOT NULL CHECK(length(event_hash)=64 AND event_hash NOT GLOB '*[^0-9a-f]*'),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0),
    PRIMARY KEY(writer_id,sequence),
    UNIQUE(writer_id,event_hash)
) STRICT;
INSERT INTO main.native_history_sources SELECT * FROM temp.migration073_native_history_sources;
INSERT INTO main.native_history_source_tables SELECT * FROM temp.migration073_native_history_source_tables;
INSERT INTO main.native_history_source_rows SELECT * FROM temp.migration073_native_history_source_rows;
INSERT INTO main.native_history_holds SELECT * FROM temp.migration073_native_history_holds;
INSERT INTO main.native_history_hold_rows SELECT * FROM temp.migration073_native_history_hold_rows;
INSERT INTO main.native_history_hold_objects SELECT * FROM temp.migration073_native_history_hold_objects;
INSERT INTO main.native_history_projection_rows SELECT * FROM temp.migration073_native_history_projection_rows;
INSERT INTO main.native_history_projection_root_columns SELECT * FROM temp.migration073_native_history_projection_root_columns;
INSERT INTO main.native_history_fresh_writers SELECT * FROM temp.migration073_native_history_fresh_writers;
INSERT INTO main.native_history_fresh_writer_events SELECT * FROM temp.migration073_native_history_fresh_writer_events;
DROP TABLE temp.migration073_native_history_fresh_writer_events;
DROP TABLE temp.migration073_native_history_fresh_writers;
DROP TABLE temp.migration073_native_history_projection_root_columns;
DROP TABLE temp.migration073_native_history_projection_rows;
DROP TABLE temp.migration073_native_history_hold_objects;
DROP TABLE temp.migration073_native_history_hold_rows;
DROP TABLE temp.migration073_native_history_holds;
DROP TABLE temp.migration073_native_history_source_rows;
DROP TABLE temp.migration073_native_history_source_tables;
DROP TABLE temp.migration073_native_history_sources;
CREATE INDEX native_history_hold_objects_content ON native_history_hold_objects(content_id);
CREATE INDEX native_history_holds_family ON native_history_holds(source_digest,family);
CREATE INDEX native_history_source_rows_table ON native_history_source_rows(source_digest,table_name);
CREATE INDEX native_history_fresh_writers_source ON native_history_fresh_writers(source_digest);

CREATE TRIGGER native_history_sources_immutable BEFORE UPDATE ON native_history_sources
BEGIN SELECT RAISE(ABORT,'inert native history source immutable'); END;
CREATE TRIGGER native_history_sources_no_delete BEFORE DELETE ON native_history_sources
BEGIN SELECT RAISE(ABORT,'inert native history source retained'); END;
CREATE TRIGGER native_history_source_tables_immutable BEFORE UPDATE ON native_history_source_tables
BEGIN SELECT RAISE(ABORT,'inert native history table inventory immutable'); END;
CREATE TRIGGER native_history_source_tables_no_delete BEFORE DELETE ON native_history_source_tables
BEGIN SELECT RAISE(ABORT,'inert native history table inventory retained'); END;
CREATE TRIGGER native_history_source_rows_immutable BEFORE UPDATE ON native_history_source_rows
BEGIN SELECT RAISE(ABORT,'inert native history original row immutable'); END;
CREATE TRIGGER native_history_source_rows_no_delete BEFORE DELETE ON native_history_source_rows
BEGIN SELECT RAISE(ABORT,'inert native history original row retained'); END;
CREATE TRIGGER native_history_holds_immutable BEFORE UPDATE ON native_history_holds
BEGIN SELECT RAISE(ABORT,'inert native history owner hold immutable'); END;
CREATE TRIGGER native_history_holds_no_release BEFORE DELETE ON native_history_holds
BEGIN SELECT RAISE(ABORT,'inert native history owner hold cannot be released'); END;
CREATE TRIGGER native_history_hold_rows_immutable BEFORE UPDATE ON native_history_hold_rows
BEGIN SELECT RAISE(ABORT,'inert native history hold row immutable'); END;
CREATE TRIGGER native_history_hold_rows_no_release BEFORE DELETE ON native_history_hold_rows
BEGIN SELECT RAISE(ABORT,'inert native history hold row cannot be released'); END;
CREATE TRIGGER native_history_hold_objects_immutable BEFORE UPDATE ON native_history_hold_objects
BEGIN SELECT RAISE(ABORT,'inert native history object hold immutable'); END;
CREATE TRIGGER native_history_hold_objects_no_release BEFORE DELETE ON native_history_hold_objects
BEGIN SELECT RAISE(ABORT,'inert native history object hold cannot be released'); END;
CREATE TRIGGER native_history_projection_rows_immutable BEFORE UPDATE ON native_history_projection_rows
BEGIN SELECT RAISE(ABORT,'native history projection immutable'); END;
CREATE TRIGGER native_history_projection_rows_no_delete BEFORE DELETE ON native_history_projection_rows
BEGIN SELECT RAISE(ABORT,'native history projection retained'); END;
CREATE TRIGGER native_history_projection_root_columns_immutable BEFORE UPDATE ON native_history_projection_root_columns
BEGIN SELECT RAISE(ABORT,'native history root projection immutable'); END;
CREATE TRIGGER native_history_projection_root_columns_no_delete BEFORE DELETE ON native_history_projection_root_columns
BEGIN SELECT RAISE(ABORT,'native history root projection retained'); END;
CREATE TRIGGER native_history_fresh_writer_insert BEFORE INSERT ON native_history_fresh_writers
WHEN NEW.state!='admitted' OR NEW.created_snapshot IS NOT NULL OR NEW.replaced_snapshot IS NOT NULL
    OR NEW.updated_at_ms!=NEW.admitted_at_ms
BEGIN SELECT RAISE(ABORT,'native history fresh writer requires new admission'); END;
CREATE TRIGGER native_history_fresh_writer_transition BEFORE UPDATE ON native_history_fresh_writers
WHEN NEW.writer_id!=OLD.writer_id OR NEW.source_digest!=OLD.source_digest
    OR NEW.projection_digest!=OLD.projection_digest OR NEW.image_digest!=OLD.image_digest
    OR NEW.space_id!=OLD.space_id OR NEW.device_id!=OLD.device_id
    OR NEW.worktree!=OLD.worktree OR NEW.creator_id!=OLD.creator_id
    OR NEW.nonce_hash!=OLD.nonce_hash OR NEW.admitted_at_ms!=OLD.admitted_at_ms
    OR NEW.updated_at_ms<OLD.updated_at_ms
    OR NOT (
        (OLD.state='admitted' AND NEW.state='created' AND NEW.created_snapshot IS NOT NULL AND NEW.replaced_snapshot IS NULL)
        OR (OLD.state='created' AND NEW.state='replaced' AND NEW.created_snapshot=OLD.created_snapshot AND NEW.replaced_snapshot IS NOT NULL)
        OR (OLD.state IN ('created','replaced','reopened') AND NEW.state='closed'
            AND NEW.created_snapshot=OLD.created_snapshot AND NEW.replaced_snapshot=OLD.replaced_snapshot)
        OR (OLD.state='closed' AND NEW.state='reopened'
            AND NEW.created_snapshot=OLD.created_snapshot AND NEW.replaced_snapshot=OLD.replaced_snapshot)
    )
BEGIN SELECT RAISE(ABORT,'native history fresh writer authority transition refused'); END;
CREATE TRIGGER native_history_fresh_writer_no_delete BEFORE DELETE ON native_history_fresh_writers
BEGIN SELECT RAISE(ABORT,'native history fresh writer retained'); END;
CREATE TRIGGER native_history_fresh_writer_event_insert BEFORE INSERT ON native_history_fresh_writer_events
WHEN NEW.sequence IS NOT (1+COALESCE((SELECT max(sequence) FROM native_history_fresh_writer_events WHERE writer_id=NEW.writer_id),0))
    OR NEW.previous_hash IS NOT COALESCE(
        (SELECT event_hash FROM native_history_fresh_writer_events WHERE writer_id=NEW.writer_id ORDER BY sequence DESC LIMIT 1),
        (SELECT nonce_hash FROM native_history_fresh_writers WHERE writer_id=NEW.writer_id))
BEGIN SELECT RAISE(ABORT,'native history fresh writer event chain refused'); END;
CREATE TRIGGER native_history_fresh_writer_event_immutable BEFORE UPDATE ON native_history_fresh_writer_events
BEGIN SELECT RAISE(ABORT,'native history fresh writer event immutable'); END;
CREATE TRIGGER native_history_fresh_writer_event_no_delete BEFORE DELETE ON native_history_fresh_writer_events
BEGIN SELECT RAISE(ABORT,'native history fresh writer event retained'); END;
PRAGMA user_version=73;
