-- Ready is the only newly executable phase; publishing/disposition stay closed.
DROP TRIGGER native_publication_phases_insert;
CREATE TRIGGER native_publication_phases_insert BEFORE INSERT ON native_publication_phases
WHEN NEW.phase!='ready' OR NEW.attempt!=0 OR
 sync_native_publication_issue('phases',NEW.transaction_id,NEW.generation,NEW.attempt,
 NEW.header_hash,NEW.phase,NEW.identity_hash,NEW.content_id,NEW.target_hash,NEW.observed_at_ms,
 NEW.source_parent_volume,NEW.source_parent_id,NEW.target_parent_volume,NEW.target_parent_id,NEW.target_path)!=1
BEGIN SELECT RAISE(ABORT,'native publication private ready issuer required'); END;
PRAGMA user_version=35;
