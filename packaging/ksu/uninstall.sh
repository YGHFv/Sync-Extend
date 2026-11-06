#!/system/bin/sh

# A reboot stops the daemon; never signal an unchecked or recycled process ID.
# KSU removes the module itself. Persistent device identity, history, user config
# and the configured worktree are deliberately left untouched.
printf 'SyncExtend: persistent /data/adb/sync-extend and all user files are preserved.\n'
printf 'Reboot to stop the existing daemon before manually changing its data.\n'
