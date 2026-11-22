-- Independent original Unix creator, disposition, closure and fence release.
-- The v1 request and every old fence remain immutable until this full terminal.
CREATE TABLE unix_storage_retirement_native_v1_activations (
    activation_id TEXT PRIMARY KEY NOT NULL CHECK(length(activation_id)=32),
    request_id TEXT UNIQUE NOT NULL REFERENCES unix_storage_retirement_v1_requests(request_id) CHECK(length(request_id)=32 AND request_id!=activation_id),
    binding_hash TEXT NOT NULL CHECK(length(binding_hash)=64),
    activation_hash TEXT NOT NULL CHECK(length(activation_hash)=64),
    activated_at_ms INTEGER NOT NULL CHECK(activated_at_ms>=0),
    activation TEXT NOT NULL CHECK(length(CAST(activation AS BLOB)) BETWEEN 1 AND 16384 AND json_valid(activation))
) STRICT;
CREATE TABLE unix_storage_retirement_native_v1_events (
    activation_id TEXT NOT NULL REFERENCES unix_storage_retirement_native_v1_activations(activation_id) CHECK(length(activation_id)=32),
    sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 12),
    kind TEXT NOT NULL CHECK(length(CAST(kind AS BLOB)) BETWEEN 1 AND 48),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0),
    previous_hash TEXT NOT NULL CHECK(length(previous_hash)=64),
    event_hash TEXT NOT NULL CHECK(length(event_hash)=64),
    evidence TEXT NOT NULL CHECK(length(CAST(evidence AS BLOB)) BETWEEN 1 AND 4096 AND json_valid(evidence)),
    PRIMARY KEY(activation_id,sequence)
) STRICT;
CREATE TABLE unix_storage_retirement_native_v1_clock (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0)
) STRICT;
CREATE TABLE unix_storage_retirement_native_v1_releases (
    activation_id TEXT PRIMARY KEY NOT NULL REFERENCES unix_storage_retirement_native_v1_activations(activation_id) CHECK(length(activation_id)=32),
    request_id TEXT UNIQUE NOT NULL REFERENCES unix_storage_retirement_v1_requests(request_id) CHECK(length(request_id)=32),
    terminal_hash TEXT NOT NULL CHECK(length(terminal_hash)=64),
    released_at_ms INTEGER NOT NULL CHECK(released_at_ms>=0),
    release_hash TEXT NOT NULL CHECK(length(release_hash)=64),
    release TEXT NOT NULL CHECK(length(CAST(release AS BLOB)) BETWEEN 1 AND 2048 AND json_valid(release))
) STRICT;

CREATE TRIGGER unix_storage_retirement_native_v1_activation_insert BEFORE INSERT ON unix_storage_retirement_native_v1_activations
WHEN NOT sync_unix_storage_retirement_native_activation(NEW.activation_hash,NEW.activated_at_ms)
OR NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_requests r
    JOIN main.unix_storage_retirement_native_v1_clock c ON c.singleton=1
    JOIN main.unix_storage_retirement_v1_clock v ON v.singleton=1
    WHERE r.request_id=NEW.request_id AND r.admitted_at_ms<=NEW.activated_at_ms
        AND NEW.activated_at_ms<r.expires_at_ms
        AND c.observed_at_ms=NEW.activated_at_ms AND v.observed_at_ms=NEW.activated_at_ms)
OR EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations WHERE request_id=NEW.request_id)
OR json_extract(NEW.activation,'$.format_version') IS NOT 1
OR json_extract(NEW.activation,'$.activation_id') IS NOT NEW.activation_id
OR json_extract(NEW.activation,'$.request_id') IS NOT NEW.request_id
OR json_extract(NEW.activation,'$.activated_at_ms') IS NOT NEW.activated_at_ms
BEGIN SELECT RAISE(ABORT,'original Unix native activation refused'); END;
CREATE TRIGGER unix_storage_retirement_native_v1_activation_immutable BEFORE UPDATE ON unix_storage_retirement_native_v1_activations
BEGIN SELECT RAISE(ABORT,'Unix native activation immutable'); END;
CREATE TRIGGER unix_storage_retirement_native_v1_activation_no_delete BEFORE DELETE ON unix_storage_retirement_native_v1_activations
BEGIN SELECT RAISE(ABORT,'Unix native activation retained'); END;

CREATE TRIGGER unix_storage_retirement_native_v1_event_insert BEFORE INSERT ON unix_storage_retirement_native_v1_events
WHEN NOT sync_unix_storage_retirement_native_event(NEW.event_hash,NEW.observed_at_ms)
OR NEW.sequence IS NOT (1+COALESCE((SELECT max(sequence) FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id),0))
OR NEW.previous_hash IS NOT COALESCE(
    (SELECT event_hash FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id ORDER BY sequence DESC LIMIT 1),
    (SELECT activation_hash FROM main.unix_storage_retirement_native_v1_activations WHERE activation_id=NEW.activation_id))
OR NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_clock c
    JOIN main.unix_storage_retirement_v1_clock v ON v.singleton=1
    JOIN main.unix_storage_retirement_native_v1_activations a
    JOIN main.unix_storage_retirement_v1_requests r ON r.request_id=a.request_id
    WHERE c.singleton=1 AND a.activation_id=NEW.activation_id
        AND c.observed_at_ms=NEW.observed_at_ms AND v.observed_at_ms=NEW.observed_at_ms
        AND a.activated_at_ms<=NEW.observed_at_ms
        AND (NEW.kind NOT IN ('quarantine_requested','delete_requested','restore_requested',
            'payload_close_requested','restored_close_requested','marker_unlink_requested','owner_close_requested')
            OR NEW.observed_at_ms<r.expires_at_ms))
OR EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c
    JOIN main.unix_storage_retirement_native_v1_activations a ON a.request_id=c.request_id
    WHERE a.activation_id=NEW.activation_id)
OR NOT (
    (NEW.sequence=1 AND NEW.kind='creator_receipted')
    OR (NEW.sequence=2 AND NEW.kind='quarantine_requested'
        AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=1 AND kind='creator_receipted'))
    OR (NEW.sequence=3 AND NEW.kind='quarantine_observed'
        AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=2 AND kind='quarantine_requested'))
    OR (NEW.sequence=4 AND NEW.kind IN ('delete_requested','restore_requested')
        AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=3 AND kind='quarantine_observed'))
    OR (NEW.sequence=5 AND (
        (NEW.kind='payload_unlinked' AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=4 AND kind='delete_requested'))
        OR (NEW.kind='restore_observed' AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=4 AND kind='restore_requested'))))
    OR (NEW.sequence=6 AND (
        (NEW.kind='payload_close_requested' AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=5 AND kind='payload_unlinked'))
        OR (NEW.kind='restored_close_requested' AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=5 AND kind='restore_observed'))))
    OR (NEW.sequence=7 AND (
        (NEW.kind='payload_closed' AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=6 AND kind='payload_close_requested'))
        OR (NEW.kind='restored_closed' AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=6 AND kind='restored_close_requested'))))
    OR (NEW.sequence=8 AND NEW.kind='marker_unlink_requested'
        AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=7 AND kind IN ('payload_closed','restored_closed')))
    OR (NEW.sequence=9 AND NEW.kind='marker_unlinked'
        AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=8 AND kind='marker_unlink_requested'))
    OR (NEW.sequence=10 AND NEW.kind='owner_close_requested'
        AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=9 AND kind='marker_unlinked'))
    OR (NEW.sequence=11 AND NEW.kind='owner_closed'
        AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=10 AND kind='owner_close_requested'))
    OR (NEW.sequence=12 AND (
        (NEW.kind='terminal_deleted' AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=4 AND kind='delete_requested'))
        OR (NEW.kind='terminal_restored_closed' AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=4 AND kind='restore_requested')))
        AND EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=NEW.activation_id AND sequence=11 AND kind='owner_closed'))
)
BEGIN SELECT RAISE(ABORT,'Unix native exact durable event prefix refused'); END;
CREATE TRIGGER unix_storage_retirement_native_v1_event_immutable BEFORE UPDATE ON unix_storage_retirement_native_v1_events
BEGIN SELECT RAISE(ABORT,'Unix native event immutable'); END;
CREATE TRIGGER unix_storage_retirement_native_v1_event_no_delete BEFORE DELETE ON unix_storage_retirement_native_v1_events
BEGIN SELECT RAISE(ABORT,'Unix native event retained'); END;

CREATE TRIGGER unix_storage_retirement_native_v1_clock_insert BEFORE INSERT ON unix_storage_retirement_native_v1_clock
WHEN NOT sync_unix_storage_retirement_native_clock('unix-retirement-native-clock-v1',NEW.observed_at_ms)
OR EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_clock)
BEGIN SELECT RAISE(ABORT,'Unix native clock issuance refused'); END;
CREATE TRIGGER unix_storage_retirement_native_v1_clock_update BEFORE UPDATE ON unix_storage_retirement_native_v1_clock
WHEN NOT sync_unix_storage_retirement_native_clock('unix-retirement-native-clock-v1',NEW.observed_at_ms)
OR NEW.singleton IS NOT OLD.singleton OR NEW.observed_at_ms<OLD.observed_at_ms
BEGIN SELECT RAISE(ABORT,'Unix native clock rollback or raw update'); END;
CREATE TRIGGER unix_storage_retirement_native_v1_clock_no_delete BEFORE DELETE ON unix_storage_retirement_native_v1_clock
BEGIN SELECT RAISE(ABORT,'Unix native clock retained'); END;

CREATE TRIGGER unix_storage_retirement_native_v1_release_insert BEFORE INSERT ON unix_storage_retirement_native_v1_releases
WHEN NOT sync_unix_storage_retirement_native_release(NEW.release_hash,NEW.released_at_ms)
OR NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_activations a
    JOIN main.unix_storage_retirement_native_v1_events e ON e.activation_id=a.activation_id AND e.sequence=12
    JOIN main.unix_storage_retirement_native_v1_clock c ON c.singleton=1
    JOIN main.unix_storage_retirement_v1_clock v ON v.singleton=1
    WHERE a.activation_id=NEW.activation_id AND a.request_id=NEW.request_id
        AND e.kind IN ('terminal_deleted','terminal_restored_closed') AND e.event_hash=NEW.terminal_hash
        AND e.observed_at_ms<=NEW.released_at_ms AND c.observed_at_ms=NEW.released_at_ms AND v.observed_at_ms=NEW.released_at_ms)
OR EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations WHERE request_id=NEW.request_id)
BEGIN SELECT RAISE(ABORT,'Unix native full terminal release refused'); END;
CREATE TRIGGER unix_storage_retirement_native_v1_release_immutable BEFORE UPDATE ON unix_storage_retirement_native_v1_releases
BEGIN SELECT RAISE(ABORT,'Unix native release immutable'); END;
CREATE TRIGGER unix_storage_retirement_native_v1_release_no_delete BEFORE DELETE ON unix_storage_retirement_native_v1_releases
BEGIN SELECT RAISE(ABORT,'Unix native release retained'); END;
CREATE TRIGGER unix_storage_retirement_native_v1_cancel_requires_terminal BEFORE INSERT ON unix_storage_retirement_v1_cancellations
WHEN EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_activations WHERE request_id=NEW.request_id)
AND NOT EXISTS(SELECT 1 FROM main.unix_storage_retirement_native_v1_releases r
    WHERE r.request_id=NEW.request_id AND r.released_at_ms=NEW.cancelled_at_ms)
BEGIN SELECT RAISE(ABORT,'active Unix native prefix cannot bypass terminal release'); END;
PRAGMA user_version=69;
