#!/system/bin/sh

# Only fixed operations and a bounded lowercase hexadecimal request are accepted.
operation=webdav
preview_hex=
preview_space=
case "$#" in
    0) ;;
    1) [ "$1" = preview-context ] || exit 2; operation=preview-context ;;
    2)
        case "$1" in
            preview)
                operation=preview
                preview_hex=$2
                case "$preview_hex" in ''|*[!0-9a-f]*) exit 2 ;; esac
                [ "${#preview_hex}" -le 131072 ] && [ "$((${#preview_hex} % 2))" -eq 0 ] || exit 2
                ;;
            preview-context)
                operation=preview-context
                preview_space=$2
                case "$preview_space" in ''|*[!0-9a-f]*) exit 2 ;; esac
                [ "${#preview_space}" -eq 32 ] || exit 2
                ;;
            *) exit 2 ;;
        esac
        ;;
    *) exit 2 ;;
esac
MODDIR=${0%/webroot/gateway.sh}
[ "$MODDIR" = /data/adb/modules/sync_extend ] || exit 1
. "$MODDIR/common.sh" || exit 1

unavailable() {
    if [ "$operation" = webdav ]; then
        printf '%s\n' '{"format_version":1,"webdav":null}'
    else
        printf '%s\n' '{"preview_context_format_version":2,"available":false,"reason":"configured_management_unavailable","restoration_performed":false,"native_authority":false,"cleanup_authority":false,"pending_resume_authority":false,"execution_available_from_preview":false}'
    fi
}

if ! module_enabled; then
    unavailable
    exit 0
fi

load_config read-only || exit 1
if [ "$enabled" != true ] || [ "$mode" != deployment ]; then
    unavailable
    exit 0
fi

validate_deployment read-only || exit 1
[ -x "$MODDIR/bin/syncd" ] && [ ! -L "$MODDIR/bin/syncd" ] || exit 1
case "$operation" in
    webdav) exec "$MODDIR/bin/syncd" deployment-check --config "$deployment_config" --describe-webdav ;;
    preview-context)
        if [ -n "$preview_space" ]; then
            exec "$MODDIR/bin/syncd" management-restore-preview --deployment "$deployment_config" --context --space-id "$preview_space"
        fi
        exec "$MODDIR/bin/syncd" management-restore-preview --deployment "$deployment_config" --context
        ;;
    preview) exec "$MODDIR/bin/syncd" management-restore-preview --deployment "$deployment_config" --request-hex "$preview_hex" ;;
esac
