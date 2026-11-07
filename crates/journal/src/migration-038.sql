-- Exact original native disposition prefixes and terminal owner closure.
DROP TRIGGER native_publication_phases_insert;
CREATE TRIGGER native_publication_phases_insert BEFORE INSERT ON native_publication_phases
WHEN NEW.phase NOT IN ('ready','publishing','observed','final','cleanup') OR NEW.attempt!=0 OR
 sync_native_publication_issue('phases',NEW.transaction_id,NEW.generation,NEW.attempt,
 NEW.header_hash,NEW.phase,NEW.identity_hash,NEW.content_id,NEW.target_hash,NEW.observed_at_ms,
 NEW.source_parent_volume,NEW.source_parent_id,NEW.target_parent_volume,NEW.target_parent_id,NEW.target_path)!=1
BEGIN SELECT RAISE(ABORT,'native publication private cleanup issuer required'); END;
DROP TRIGGER native_publication_dispositions_insert;
CREATE TRIGGER native_publication_dispositions_insert BEFORE INSERT ON native_publication_dispositions
WHEN NEW.stage NOT IN ('intended','absent','terminal') OR
 sync_native_publication_issue('dispositions',NEW.transaction_id,NEW.generation,NEW.step,
 NEW.header_hash,NEW.stage,NEW.identity_hash,NEW.observed_at_ms)!=1
BEGIN SELECT RAISE(ABORT,'native disposition private exact issuer required'); END;
PRAGMA user_version=38;
