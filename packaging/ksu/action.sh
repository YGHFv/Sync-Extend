#!/system/bin/sh

MODDIR=${0%/*}
. "$MODDIR/common.sh" || exit 1
load_config || exit 1
printf 'SyncExtend local alpha: enabled=%s worktree=%s interval=%s\n' \
    "$enabled" "$worktree" "$scan_interval_secs"
printf 'A running daemon owns the database lock. No PID-based stop is attempted.\n'
printf 'Disable this module and reboot to stop it safely.\n'
printf 'Mode=%s; file mode only serves one explicitly paired device.\n' "$mode"
printf 'Automatic sync and Android destructive mutation are not available.\n'
