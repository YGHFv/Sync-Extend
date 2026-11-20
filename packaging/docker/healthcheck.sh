#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
    printf '%s\n' 'Health check uses /config/management.json' >&2
    exit 2
fi
exec /usr/local/bin/syncd management-health --config /config/management.json
