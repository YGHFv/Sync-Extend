CREATE TABLE rename_observations (
    space_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    observation TEXT NOT NULL,
    observation_hash TEXT NOT NULL,
    CHECK (length(CAST(observation AS BLOB)) BETWEEN 1 AND 16777216)
) STRICT;

CREATE TRIGGER rename_observation_admission BEFORE INSERT ON rename_observations
WHEN EXISTS (SELECT 1 FROM rename_observations WHERE space_id=NEW.space_id)
OR NOT EXISTS (
    SELECT 1 FROM current_manifests c JOIN snapshots s ON s.snapshot_id=c.snapshot_id
    WHERE c.space_id=NEW.space_id AND s.space_id=NEW.space_id
    AND c.snapshot_id=NEW.snapshot_id AND s.state='materialized'
    AND NOT EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=s.snapshot_id)
)
OR json_extract(NEW.observation,'$.scope.format_version') IS NOT 1
OR json_extract(NEW.observation,'$.scope.space_id') IS NOT NEW.space_id
OR json_extract(NEW.observation,'$.scope.prior_snapshot') IS NOT NEW.snapshot_id
BEGIN SELECT RAISE(ABORT,'invalid rename observation admission'); END;

CREATE TRIGGER rename_observation_immutable BEFORE UPDATE ON rename_observations
BEGIN SELECT RAISE(ABORT,'rename observation is immutable'); END;

CREATE TRIGGER rename_observation_current_insert AFTER INSERT ON current_manifests
BEGIN DELETE FROM rename_observations WHERE space_id=NEW.space_id; END;
CREATE TRIGGER rename_observation_current_update AFTER UPDATE ON current_manifests
BEGIN
    DELETE FROM rename_observations WHERE space_id=OLD.space_id OR space_id=NEW.space_id;
END;
CREATE TRIGGER rename_observation_current_delete AFTER DELETE ON current_manifests
BEGIN DELETE FROM rename_observations WHERE space_id=OLD.space_id; END;

PRAGMA user_version=18;
