CREATE TABLE reference_snapshot_handoffs (
    owner_id TEXT PRIMARY KEY REFERENCES reference_reservations(owner_id),
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    owner_intent_hash TEXT NOT NULL
) STRICT;
CREATE TRIGGER reference_snapshot_handoff_admission BEFORE INSERT ON reference_snapshot_handoffs
WHEN EXISTS (SELECT 1 FROM reference_snapshot_handoffs WHERE owner_id=NEW.owner_id)
OR NOT EXISTS (
    SELECT 1 FROM reference_reservations o JOIN snapshots s ON s.snapshot_id=NEW.snapshot_id
    WHERE o.owner_id=NEW.owner_id AND o.space_id=s.space_id
    AND o.intent_hash=NEW.owner_intent_hash AND s.state='materialized'
    AND json_extract(o.intent,'$.scope.kind') IN ('download','restore')
    AND NOT EXISTS (SELECT 1 FROM snapshot_prunings WHERE snapshot_id=s.snapshot_id)
    AND NOT EXISTS (
        SELECT 1 FROM json_each(o.intent,'$.scope.files') f
        WHERE NOT EXISTS (SELECT 1 FROM json_each(s.manifest,'$.entries') e
            WHERE json_extract(e.value,'$.content')=json(f.value)))
    AND NOT EXISTS (
        SELECT 1 FROM json_each(o.intent,'$.scope.files') f,
            json_each(f.value,'$.chunks') c
        WHERE NOT EXISTS (SELECT 1 FROM reference_reservation_objects p
            WHERE p.owner_id=o.owner_id
            AND p.content_id=json_extract(c.value,'$.content_id'))
        OR NOT EXISTS (SELECT 1 FROM snapshot_objects p
            WHERE p.snapshot_id=s.snapshot_id
            AND p.content_id=json_extract(c.value,'$.content_id')))
)
BEGIN SELECT RAISE(ABORT,'invalid local snapshot handoff'); END;
CREATE TRIGGER reference_snapshot_handoff_immutable BEFORE UPDATE ON reference_snapshot_handoffs
BEGIN SELECT RAISE(ABORT,'snapshot handoff is immutable'); END;
CREATE TRIGGER reference_snapshot_handoff_no_delete BEFORE DELETE ON reference_snapshot_handoffs
BEGIN SELECT RAISE(ABORT,'snapshot handoff cannot be deleted'); END;
DROP TRIGGER reference_reservation_pin_no_delete;
CREATE TRIGGER reference_reservation_pin_no_delete BEFORE DELETE ON reference_reservation_objects
WHEN NOT EXISTS (SELECT 1 FROM reference_snapshot_handoffs WHERE owner_id=OLD.owner_id)
BEGIN SELECT RAISE(ABORT,'reference reservation release is unavailable'); END;
CREATE TRIGGER reference_snapshot_handoff_no_pin BEFORE INSERT ON reference_reservation_objects
WHEN EXISTS (SELECT 1 FROM reference_snapshot_handoffs WHERE owner_id=NEW.owner_id)
BEGIN SELECT RAISE(ABORT,'snapshot handoff is terminal'); END;
PRAGMA user_version=17;
