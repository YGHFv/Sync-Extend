#!/system/bin/sh

# KSU removes the module itself. Persistent device identity, history, user config
# and the configured worktree are deliberately left untouched.
MODDIR=${0%/*}
if [ -r "$MODDIR/common.sh" ]; then
    . "$MODDIR/common.sh"
    if [ -d "$CONTROL" ] && control stop >/dev/null 2>&1; then
        printf 'SyncExtend: requested a graceful stop of the authenticated owner.\n'
    fi
fi
printf 'SyncExtend: persistent /data/adb/sync-extend and all user files are preserved.\n'
