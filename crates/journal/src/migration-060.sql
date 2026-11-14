-- Storage-only original quarantine-owner creation. No payload move or disposal.
CREATE TABLE storage_retirement_owner_activations (
    request_id TEXT PRIMARY KEY NOT NULL REFERENCES storage_retirement_requests(request_id),
    activation_id TEXT NOT NULL UNIQUE CHECK(length(activation_id)=32),
    tmp_key TEXT NOT NULL CHECK(length(CAST(tmp_key AS BLOB)) BETWEEN 1 AND 64),
    activated_at_ms INTEGER NOT NULL CHECK(activated_at_ms>=0)
) STRICT;
CREATE TABLE storage_retirement_owner_creations (
    request_id TEXT PRIMARY KEY NOT NULL REFERENCES storage_retirement_owner_activations(request_id),
    activation_id TEXT NOT NULL CHECK(length(activation_id)=32),
    owner_key TEXT NOT NULL CHECK(length(CAST(owner_key AS BLOB)) BETWEEN 1 AND 64),
    parent_key TEXT NOT NULL CHECK(length(CAST(parent_key AS BLOB)) BETWEEN 1 AND 64),
    component TEXT NOT NULL CHECK(length(CAST(component AS BLOB))=49),
    marker_hash TEXT NOT NULL CHECK(length(marker_hash)=64),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0)
) STRICT;
CREATE TRIGGER storage_retirement_owner_activation_insert
BEFORE INSERT ON storage_retirement_owner_activations
WHEN NOT sync_storage_retirement_owner_issue(NEW.activation_id,NEW.activated_at_ms)
OR NOT EXISTS(SELECT 1 FROM storage_retirement_requests r
    JOIN storage_retirement_clock c ON c.singleton=1
    WHERE r.request_id=NEW.request_id AND r.admitted_at_ms<=NEW.activated_at_ms
    AND r.grace_until_ms<=NEW.activated_at_ms AND NEW.activated_at_ms<r.expires_at_ms
    AND c.observed_at_ms=NEW.activated_at_ms)
OR EXISTS(SELECT 1 FROM storage_retirement_cancellations WHERE request_id=NEW.request_id)
BEGIN SELECT RAISE(ABORT,'invalid storage retirement owner activation'); END;
CREATE TRIGGER storage_retirement_owner_creation_insert
BEFORE INSERT ON storage_retirement_owner_creations
WHEN NOT sync_storage_retirement_owner_receipt(NEW.marker_hash,NEW.created_at_ms)
OR NOT EXISTS(SELECT 1 FROM storage_retirement_owner_activations a
    JOIN storage_retirement_clock c ON c.singleton=1
    WHERE a.request_id=NEW.request_id AND a.activation_id=NEW.activation_id
    AND a.tmp_key=NEW.parent_key AND a.activated_at_ms<=NEW.created_at_ms
    AND c.observed_at_ms=NEW.created_at_ms)
OR EXISTS(SELECT 1 FROM storage_retirement_cancellations WHERE request_id=NEW.request_id)
OR NEW.component IS NOT 'retirement-'||NEW.activation_id||'.owner'
OR NEW.owner_key=NEW.parent_key
BEGIN SELECT RAISE(ABORT,'invalid storage retirement original owner receipt'); END;
CREATE TRIGGER storage_retirement_owner_activation_immutable
BEFORE UPDATE ON storage_retirement_owner_activations
BEGIN SELECT RAISE(ABORT,'storage retirement owner activation immutable'); END;
CREATE TRIGGER storage_retirement_owner_activation_no_delete
BEFORE DELETE ON storage_retirement_owner_activations
BEGIN SELECT RAISE(ABORT,'storage retirement owner activation retained'); END;
CREATE TRIGGER storage_retirement_owner_creation_immutable
BEFORE UPDATE ON storage_retirement_owner_creations
BEGIN SELECT RAISE(ABORT,'storage retirement original owner receipt immutable'); END;
CREATE TRIGGER storage_retirement_owner_creation_no_delete
BEFORE DELETE ON storage_retirement_owner_creations
BEGIN SELECT RAISE(ABORT,'storage retirement original owner receipt retained'); END;
-- Once native CREATE may have occurred, only a future exact recovery protocol
-- can release the fence. Metadata-only cancellation must conservatively refuse.
CREATE TRIGGER storage_retirement_owner_cancel_refusal
BEFORE INSERT ON storage_retirement_cancellations
WHEN EXISTS(SELECT 1 FROM storage_retirement_owner_activations WHERE request_id=NEW.request_id)
BEGIN SELECT RAISE(ABORT,'storage retirement native owner recovery required'); END;
PRAGMA user_version=60;
