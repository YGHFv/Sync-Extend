CREATE TABLE mutations (
    transaction_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    baseline_root TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'cancelled'))
) STRICT;

CREATE UNIQUE INDEX one_active_mutation_per_space ON mutations(space_id)
WHERE state = 'prepared';

CREATE TABLE mutation_objects (
    transaction_id TEXT NOT NULL REFERENCES mutations(transaction_id),
    content_id TEXT NOT NULL,
    PRIMARY KEY(transaction_id, content_id)
) STRICT;

CREATE TRIGGER publication_requires_no_mutation BEFORE INSERT ON publications
WHEN EXISTS (SELECT 1 FROM mutations WHERE space_id = NEW.space_id AND state = 'prepared')
BEGIN
    SELECT RAISE(ABORT, 'prepared mutation must be resolved first');
END;

CREATE TRIGGER mutation_requires_no_publication BEFORE INSERT ON mutations
WHEN EXISTS (
    SELECT 1 FROM publications WHERE space_id = NEW.space_id
    AND (state != 'committed' OR cleaned = 0)
)
BEGIN
    SELECT RAISE(ABORT, 'outstanding publication must be recovered first');
END;

PRAGMA user_version = 3;
