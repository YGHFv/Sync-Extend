#!/bin/sh

check_paths() {
    failed=0
    while IFS= read -r path; do
        normalized=$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')
        case "$normalized" in
            *.env.example|.env.example)
                ;;
            docs/*|tests/*|test/*|benches/*|fixtures/*|snapshots/*|.local-history/*|.local/*|\
            */docs/*|*/tests/*|*/test/*|*/benches/*|*/fixtures/*|*/snapshots/*|\
            *.md|*.docx|*.pdf|*.pptx|*.xlsx|*_test.*|*.test.*|*.spec.*|\
            *.sqlite*|*.db|*.db-*|*.log|*.tmp|*.pem|*.key|*.secret|.env|.env.*|*/target/*|target/*)
                printf 'Source-only policy rejected: %s\n' "$path" >&2
                failed=1
                ;;
        esac
    done
    return "$failed"
}

check_inline_tests() {
    revision=$1
    if git grep -n -E '#\[(test|cfg\(test\))\]|#\[tokio::test' "$revision" -- '*.rs'; then
        printf 'Source-only policy rejected inline Rust tests.\n' >&2
        return 1
    fi
}
