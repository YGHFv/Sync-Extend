CREATE TABLE gc_authorizations (
    authorization_id TEXT PRIMARY KEY,
    mark_id TEXT NOT NULL UNIQUE REFERENCES gc_marks(mark_id),
    intent TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    authorized_at_ms INTEGER NOT NULL CHECK (authorized_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > authorized_at_ms)
) STRICT;
CREATE TABLE gc_revocations (
    authorization_id TEXT PRIMARY KEY REFERENCES gc_authorizations(authorization_id),
    revoked_at_ms INTEGER NOT NULL CHECK (revoked_at_ms >= 0)
) STRICT;

CREATE TRIGGER gc_authorization_admission BEFORE INSERT ON gc_authorizations
WHEN EXISTS (SELECT 1 FROM gc_authorizations
    WHERE authorization_id=NEW.authorization_id OR mark_id=NEW.mark_id)
OR NOT EXISTS (SELECT 1 FROM gc_marks m JOIN gc_clock c ON c.singleton=1
    WHERE m.mark_id=NEW.mark_id AND m.grace_until_ms<=NEW.authorized_at_ms
    AND c.observed_at_ms>=NEW.authorized_at_ms
    AND NOT EXISTS (SELECT 1 FROM gc_cancellations WHERE mark_id=m.mark_id)
    AND NOT EXISTS (SELECT 1 FROM gc_invalidations WHERE mark_id=m.mark_id)
    AND NOT EXISTS (SELECT 1 FROM snapshot_objects WHERE content_id=m.content_id)
    AND NOT EXISTS (SELECT 1 FROM publication_objects WHERE content_id=m.content_id)
    AND NOT EXISTS (SELECT 1 FROM mutation_objects WHERE content_id=m.content_id)
    AND NOT EXISTS (SELECT 1 FROM read_lease_objects WHERE content_id=m.content_id))
BEGIN SELECT RAISE(ABORT,'invalid GC authorization admission'); END;
CREATE TRIGGER gc_authorization_immutable BEFORE UPDATE ON gc_authorizations
BEGIN SELECT RAISE(ABORT,'GC authorization is immutable'); END;
CREATE TRIGGER gc_authorization_no_delete BEFORE DELETE ON gc_authorizations
BEGIN SELECT RAISE(ABORT,'GC authorization cannot be deleted'); END;
CREATE TRIGGER gc_revocation_admission BEFORE INSERT ON gc_revocations
WHEN EXISTS (SELECT 1 FROM gc_revocations WHERE authorization_id=NEW.authorization_id)
OR NOT EXISTS (SELECT 1 FROM gc_authorizations a JOIN gc_clock c ON c.singleton=1
    WHERE a.authorization_id=NEW.authorization_id
    AND a.authorized_at_ms<=NEW.revoked_at_ms AND NEW.revoked_at_ms<=c.observed_at_ms)
BEGIN SELECT RAISE(ABORT,'invalid GC revocation'); END;
CREATE TRIGGER gc_revocation_immutable BEFORE UPDATE ON gc_revocations
BEGIN SELECT RAISE(ABORT,'GC revocation is immutable'); END;
CREATE TRIGGER gc_revocation_no_delete BEFORE DELETE ON gc_revocations
BEGIN SELECT RAISE(ABORT,'GC revocation cannot be deleted'); END;
PRAGMA user_version = 11;
