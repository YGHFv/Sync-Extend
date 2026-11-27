-- Bind actual local metadata to the existing immutable-snapshot observation
-- JSON. No signed Entry, operation, signature or historical observation is
-- rewritten. Older readers must reject the new observation field at open.
PRAGMA user_version=72;
