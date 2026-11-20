#!/system/bin/sh

MODDIR=${0%/*}
. "$MODDIR/common.sh" || exit 1

usage() {
    printf '%s\n' 'Usage: action.sh [status|stop|wait-stopped|run|config]' >&2
    exit 2
}

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
