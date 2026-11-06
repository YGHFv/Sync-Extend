#!/system/bin/sh

SKIPUNZIP=0
[ "$KSU" = true ] || abort 'KernelSU installation is required'
[ "$ARCH" = arm64 ] || abort 'Only Android arm64 is packaged'
[ "$API" -ge 26 ] || abort 'Android API 26 or newer is required'

. "$MODPATH/common.sh" || abort 'Cannot load module helpers'
private_state || abort 'Cannot create private persistent state'
if [ ! -e "$CONFIG" ]; then
    cp "$MODPATH/config.example" "$CONFIG" || abort 'Cannot initialize disabled config'
fi
chmod 600 "$CONFIG" || abort 'Cannot protect config'
[ -f "$MODPATH/bin/syncd" ] && [ ! -L "$MODPATH/bin/syncd" ] ||
    abort 'Locally built Android syncd is missing'
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/syncd" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
ui_print 'Installed disabled. Edit /data/adb/sync-extend/config before reboot.'
ui_print 'Local mode is default. File-server mode requires prior explicit pairing.'
ui_print 'This alpha does not provide automatic multiway synchronization.'
ui_print 'Uninstall preserves the worktree, history, config and device identity.'
