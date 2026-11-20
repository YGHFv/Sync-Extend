#!/bin/sh
set -eu
umask 077
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'SyncExtend reads an explicit configuration under /config; extra arguments are refused' >&2
    exit 2
fi
case "${SYNCEXTEND_DEPLOYMENT_PROFILE-}" in
    '') config=/config/deployment.json ;;
    webdav) config=/config/deployment-webdav.json ;;
    *) printf '%s\n' 'Unknown SyncExtend deployment profile' >&2; exit 2 ;;
esac
if [ ! -f "$config" ] || [ -L "$config" ] || [ ! -r "$config" ]; then
    printf '%s\n' 'SyncExtend requires an existing readable deployment configuration' >&2
    exit 2
fi
exec /usr/local/bin/syncd deployment-run --config "$config"
