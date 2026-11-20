#!/system/bin/sh

MODDIR=${0%/*}
. "$MODDIR/common.sh" || exit 1

usage() {
    printf '%s\n' 'Usage: action.sh [status|stop|wait-stopped|run|config|probe-webdav EXPORT]' >&2
    exit 2
}

if [ "${1-}" = probe-webdav ]; then
    [ "$#" -eq 2 ] || usage
    case "$2" in ''|*[!A-Za-z0-9_-]*) usage ;; esac
    [ "${#2}" -le 64 ] || usage
    module_enabled || exit 1
    control probe-webdav "--export=$2"
    exit $?
fi
[ "$#" -le 1 ] || usage
case "${1-status}" in
    status|stop|wait-stopped) control "${1-status}" ;;
    run) exec /system/bin/sh "$MODDIR/service.sh" ;;
    config)
        load_config || exit 1
        printf 'enabled=%s mode=%s worktree=%s scan_interval_secs=%s\n' \
            "$enabled" "$mode" "$worktree" "$scan_interval_secs"
        if [ "$mode" = deployment ]; then
            printf 'deployment_config=%s\n' "$deployment_config"
        fi ;;
    *) usage ;;
esac
