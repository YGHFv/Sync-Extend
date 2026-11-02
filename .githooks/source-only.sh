#!/bin/sh

check_paths() {
    failed=0
    while IFS= read -r path; do
        case "$path" in
            docs/*|tests/*|test/*|benches/*|fixtures/*|snapshots/*|.local-history/*|.local/*|\
            */docs/*|*/tests/*|*/test/*|*/benches/*|*/fixtures/*|*/snapshots/*|\
            *.md|*.docx|*.pdf|*.pptx|*.xlsx|*_test.*|*.test.*|*.spec.*|\
            *.sqlite*|*.db|*.db-*|*.log|*.tmp|*.pem|*.key|.env|.env.*|*/target/*|target/*)
                printf 'Source-only policy rejected: %s\n' "$path" >&2
                failed=1
                ;;
        esac
    done
    return "$failed"
}
