CREATE TRIGGER storage_retirement_fence_remote_replace_objects_insert BEFORE INSERT ON remote_replace_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;

CREATE TRIGGER storage_retirement_fence_remote_replace_objects_update BEFORE UPDATE ON remote_replace_objects
WHEN EXISTS(SELECT 1 FROM storage_retirement_requests r WHERE r.content_id=NEW.content_id
    AND NOT EXISTS(SELECT 1 FROM storage_retirement_cancellations c WHERE c.request_id=r.request_id))
BEGIN SELECT RAISE(ABORT,'object fenced by storage retirement'); END;
