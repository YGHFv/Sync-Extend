#!/system/bin/sh

MODDIR=${0%/*}
. "$MODDIR/common.sh" || exit 1
# Never create a replacement identity while credential-encrypted storage is locked.
attempt=0
while [ "$(getprop sys.boot_completed)" != 1 ] ||
      [ "$(getprop sys.user.0.ce_available)" != true ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 180 ] || exit 1
    sleep 5
done
[ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ] || exit 0
private_state && load_config || exit 1
[ "$enabled" = true ] || exit 0
[ -x "$MODDIR/bin/syncd" ] && [ ! -L "$MODDIR/bin/syncd" ] || exit 1
attempt=0
while [ ! -d "$worktree" ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 180 ] || exit 1
    [ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ] || exit 0
    sleep 5
done
validate_worktree || exit 1

if [ ! -e "$DATA/journal.sqlite" ]; then
    "$MODDIR/bin/syncd" init --data-dir "$DATA" --root "$worktree" || exit 1
fi
# Reopening verifies the existing secret and worktree marker, never rotates identity.
"$MODDIR/bin/syncd" status --data-dir "$DATA" || exit 1
# The Rust daemon holds the data/worktree locks for its lifetime. A duplicate
# service invocation fails there; no stale shell PID file can kill another process.
# No unattended retry on a safety error. Reconfigure and reboot to retry.
if [ "$mode" = files ]; then
    # Pairing must already exist in the private data directory; no implicit trust.
    exec "$MODDIR/bin/syncd" serve-files --data-dir "$DATA" \
        --peer-device "$peer_device" --listen "$listen"
fi
exec "$MODDIR/bin/syncd" run --data-dir "$DATA" --scan-interval-secs "$scan_interval_secs"
