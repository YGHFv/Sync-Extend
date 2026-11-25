-- Portable Entry metadata format admission. Signed operation rows are not
-- rewritten; their optional metadata is carried only in the original payload.
-- The schema bump itself is the old-reader rejection boundary.
PRAGMA user_version=71;
