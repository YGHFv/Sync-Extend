CREATE TABLE snapshot_prunings (
    snapshot_id TEXT PRIMARY KEY REFERENCES snapshots(snapshot_id),
    space_id TEXT NOT NULL,
    baseline_root TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    pruned_at_ms INTEGER NOT NULL CHECK (pruned_at_ms >= 0),
    CHECK (snapshot_id != baseline_root)
) STRICT;

CREATE TRIGGER snapshot_pruning_admission BEFORE INSERT ON snapshot_prunings
WHEN EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=NEW.snapshot_id)
OR NOT EXISTS (
    SELECT 1 FROM snapshots s JOIN current_manifests c ON c.space_id=s.space_id
    WHERE s.snapshot_id=NEW.snapshot_id AND s.space_id=NEW.space_id
        AND s.locked=0 AND s.state='materialized' AND c.snapshot_id=NEW.baseline_root
        AND c.snapshot_id!=s.snapshot_id
)
OR EXISTS (SELECT 1 FROM read_leases WHERE snapshot_id=NEW.snapshot_id)
OR EXISTS (SELECT 1 FROM mutations
    WHERE baseline_root=NEW.snapshot_id OR committed_snapshot=NEW.snapshot_id)
OR EXISTS (SELECT 1 FROM publications
    WHERE committed_snapshot=NEW.snapshot_id
        OR json_extract(intent,'$.baseline_root')=NEW.snapshot_id
        OR json_extract(intent,'$.source_snapshot')=NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT,'invalid snapshot pruning admission'); END;

CREATE TRIGGER snapshot_pruning_immutable BEFORE UPDATE ON snapshot_prunings
BEGIN SELECT RAISE(ABORT,'snapshot pruning record is immutable'); END;
CREATE TRIGGER snapshot_pruning_no_delete BEFORE DELETE ON snapshot_prunings
BEGIN SELECT RAISE(ABORT,'snapshot pruning record cannot be deleted'); END;
CREATE TRIGGER pruned_snapshot_immutable BEFORE UPDATE ON snapshots
WHEN EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=OLD.snapshot_id)
BEGIN SELECT RAISE(ABORT,'pruned snapshot metadata is immutable'); END;
CREATE TRIGGER pruned_snapshot_no_replace BEFORE INSERT ON snapshots
WHEN EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT,'pruned snapshot metadata cannot be replaced'); END;
CREATE TRIGGER pruned_snapshot_no_delete BEFORE DELETE ON snapshots
WHEN EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=OLD.snapshot_id)
BEGIN SELECT RAISE(ABORT,'pruned snapshot metadata cannot be deleted'); END;
CREATE TRIGGER pruned_snapshot_no_pin BEFORE INSERT ON snapshot_objects
WHEN EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT,'pruned snapshot cannot be pinned'); END;
CREATE TRIGGER pruned_snapshot_no_pin_update BEFORE UPDATE ON snapshot_objects
WHEN EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT,'pruned snapshot cannot be pinned'); END;
CREATE TRIGGER pruned_snapshot_no_current_insert BEFORE INSERT ON current_manifests
WHEN EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT,'pruned snapshot cannot become current'); END;
CREATE TRIGGER pruned_snapshot_no_current_update BEFORE UPDATE ON current_manifests
WHEN EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT,'pruned snapshot cannot become current'); END;
CREATE TRIGGER pruned_snapshot_no_lease BEFORE INSERT ON read_leases
WHEN EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT,'pruned snapshot cannot acquire a lease'); END;
CREATE TRIGGER pruned_snapshot_no_mutation BEFORE INSERT ON mutations
WHEN EXISTS (SELECT 1 FROM snapshot_prunings
    WHERE snapshot_id=NEW.baseline_root OR snapshot_id=NEW.committed_snapshot)
BEGIN SELECT RAISE(ABORT,'pruned snapshot cannot acquire a mutation'); END;
CREATE TRIGGER pruned_snapshot_no_mutation_update BEFORE UPDATE ON mutations
WHEN EXISTS (SELECT 1 FROM snapshot_prunings
    WHERE snapshot_id=NEW.baseline_root OR snapshot_id=NEW.committed_snapshot)
BEGIN SELECT RAISE(ABORT,'pruned snapshot cannot acquire a mutation'); END;
CREATE TRIGGER pruned_snapshot_no_publication BEFORE INSERT ON publications
WHEN EXISTS (SELECT 1 FROM snapshot_prunings
    WHERE snapshot_id=NEW.committed_snapshot
        OR snapshot_id=json_extract(NEW.intent,'$.baseline_root')
        OR snapshot_id=json_extract(NEW.intent,'$.source_snapshot'))
BEGIN SELECT RAISE(ABORT,'pruned snapshot cannot acquire a publication'); END;
CREATE TRIGGER pruned_snapshot_no_publication_update BEFORE UPDATE ON publications
WHEN EXISTS (SELECT 1 FROM snapshot_prunings
    WHERE snapshot_id=NEW.committed_snapshot
        OR snapshot_id=json_extract(NEW.intent,'$.baseline_root')
        OR snapshot_id=json_extract(NEW.intent,'$.source_snapshot'))
BEGIN SELECT RAISE(ABORT,'pruned snapshot cannot acquire a publication'); END;

PRAGMA user_version = 9;
