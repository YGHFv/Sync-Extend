CREATE TABLE cleanup_plans (
    transaction_id TEXT PRIMARY KEY REFERENCES mutations(transaction_id),
    space_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'cancelled', 'executing', 'cleaned')),
    authorized_at_ms INTEGER CHECK (authorized_at_ms >= 0),
    cleaned_at_ms INTEGER CHECK (cleaned_at_ms >= authorized_at_ms),
    CHECK ((state IN ('executing', 'cleaned')) = (authorized_at_ms IS NOT NULL)),
    CHECK ((state = 'cleaned') = (cleaned_at_ms IS NOT NULL))
) STRICT;

CREATE TRIGGER cleanup_immutable BEFORE UPDATE OF transaction_id,space_id,intent,intent_hash
ON cleanup_plans BEGIN
    SELECT RAISE(ABORT, 'cleanup intent is immutable');
END;

CREATE TRIGGER cleanup_transition BEFORE UPDATE OF state ON cleanup_plans
WHEN NOT (
    (OLD.state = 'prepared' AND NEW.state IN ('cancelled','executing'))
    OR (OLD.state = 'executing' AND NEW.state = 'cleaned')
) BEGIN
    SELECT RAISE(ABORT, 'invalid cleanup transition');
END;

PRAGMA user_version = 7;
