#!/system/bin/sh

# This entry point is invoked only with the module's fixed WebUI command.
[ "$#" -eq 0 ] || exit 2
MODDIR=${0%/webroot/gateway.sh}
[ "$MODDIR" = /data/adb/modules/sync_extend ] || exit 1
. "$MODDIR/common.sh" || exit 1

if ! module_enabled; then
    printf '%s\n' '{"format_version":1,"webdav":null}'
    exit 0
fi

load_config read-only || exit 1
if [ "$enabled" != true ] || [ "$mode" != deployment ]; then
    printf '%s\n' '{"format_version":1,"webdav":null}'
    exit 0
fi

validate_deployment read-only || exit 1
[ -x "$MODDIR/bin/syncd" ] && [ ! -L "$MODDIR/bin/syncd" ] || exit 1
exec "$MODDIR/bin/syncd" deployment-check --config "$deployment_config" --describe-webdav
