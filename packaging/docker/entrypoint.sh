#!/bin/sh
set -eu
umask 077
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'SyncExtend deployment uses /config/deployment.json; extra arguments are refused' >&2
    exit 2
fi
config=/config/deployment.json
if [ ! -f "$config" ] || [ -L "$config" ] || [ ! -r "$config" ]; then
    printf '%s\n' 'SyncExtend requires an existing readable deployment configuration' >&2
    exit 2
fi
exec /usr/local/bin/syncd deployment-run --config "$config"
