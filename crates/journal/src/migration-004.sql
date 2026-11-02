DROP TRIGGER publication_requires_no_mutation;
DROP TRIGGER mutation_requires_no_publication;

CREATE TABLE mutations_v4 (
    transaction_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    baseline_root TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'cancelled', 'executing', 'quarantined', 'committed')),
    execution TEXT,
    execution_hash TEXT,
    committed_snapshot TEXT REFERENCES snapshots(snapshot_id),
    CHECK (
        (state IN ('prepared','cancelled') AND execution IS NULL AND execution_hash IS NULL AND committed_snapshot IS NULL)
        OR (state IN ('executing','quarantined') AND execution IS NOT NULL AND execution_hash IS NOT NULL AND committed_snapshot IS NULL)
        OR (state = 'committed' AND execution IS NOT NULL AND execution_hash IS NOT NULL AND committed_snapshot IS NOT NULL)
    )
) STRICT;
INSERT INTO mutations_v4 SELECT *,NULL,NULL,NULL FROM mutations;
CREATE TABLE mutation_objects_v4 (
    transaction_id TEXT NOT NULL REFERENCES mutations_v4(transaction_id),
    content_id TEXT NOT NULL,
    PRIMARY KEY(transaction_id, content_id)
) STRICT;
INSERT INTO mutation_objects_v4 SELECT * FROM mutation_objects;
DROP TABLE mutation_objects;
DROP TABLE mutations;
ALTER TABLE mutations_v4 RENAME TO mutations;
ALTER TABLE mutation_objects_v4 RENAME TO mutation_objects;

CREATE UNIQUE INDEX one_active_mutation_per_space ON mutations(space_id)
WHERE state IN ('prepared','executing','quarantined');
CREATE TRIGGER publication_requires_no_mutation BEFORE INSERT ON publications
WHEN EXISTS (SELECT 1 FROM mutations WHERE space_id = NEW.space_id AND state IN ('prepared','executing','quarantined'))
BEGIN
    SELECT RAISE(ABORT, 'active mutation must be resolved first');
END;
CREATE TRIGGER mutation_requires_no_publication BEFORE INSERT ON mutations
WHEN EXISTS (
    SELECT 1 FROM publications WHERE space_id = NEW.space_id
    AND (state != 'committed' OR cleaned = 0)
)
BEGIN
    SELECT RAISE(ABORT, 'outstanding publication must be recovered first');
END;
PRAGMA user_version = 4;
