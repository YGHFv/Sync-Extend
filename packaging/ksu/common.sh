#!/system/bin/sh

STATE=/data/adb/sync-extend
DATA=$STATE/data
CONFIG=$STATE/config

fail() {
    printf 'SyncExtend: %s\n' "$*" >&2
    return 1
}

private_state() {
    [ ! -L "$STATE" ] && [ ! -L "$DATA" ] && [ ! -L "$CONFIG" ] ||
        { fail 'symlink in private state'; return 1; }
    umask 077
    mkdir -p "$DATA" || return 1
    chmod 700 "$STATE" "$DATA" || return 1
}

load_config() {
    [ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] ||
        { fail 'private config is missing'; return 1; }
    [ "$(wc -c < "$CONFIG")" -le 4096 ] ||
        { fail 'config exceeds 4096 bytes'; return 1; }
    chmod 600 "$CONFIG" || return 1
    enabled=
    worktree=
    scan_interval_secs=
    seen_enabled=false
    seen_worktree=false
    seen_interval=false
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*) continue ;;
            enabled=*)
                [ "$seen_enabled" = false ] || return 1
                enabled=${line#enabled=}
                seen_enabled=true ;;
            worktree=*)
                [ "$seen_worktree" = false ] || return 1
                worktree=${line#worktree=}
                seen_worktree=true ;;
            scan_interval_secs=*)
                [ "$seen_interval" = false ] || return 1
                scan_interval_secs=${line#scan_interval_secs=}
                seen_interval=true ;;
            *) fail 'unknown config key'; return 1 ;;
        esac
    done < "$CONFIG"
    case "$enabled" in true|false) ;; *) return 1 ;; esac
    case "$scan_interval_secs" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#scan_interval_secs}" -le 5 ] &&
        [ "$scan_interval_secs" -ge 1 ] &&
        [ "$scan_interval_secs" -le 86400 ] || return 1
    [ "$enabled" = true ] || return 0
    case "$worktree" in /*) ;; *) fail 'worktree must be absolute'; return 1 ;; esac
}

validate_worktree() {
    [ -d "$worktree" ] && [ ! -L "$worktree" ] ||
        { fail 'worktree is unavailable'; return 1; }
    worktree=$(realpath "$worktree") || return 1
    case "$worktree" in
        /|/data|/data/adb|/data/adb/*|/system|/system/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*)
            fail 'reserved worktree'; return 1 ;;
    esac
    # Scan supports shared storage, but publication on Android FUSE is not certified.
    [ "$worktree" != "$STATE" ] || return 1
    case "$STATE/" in "$worktree/"*) fail 'worktree contains private state'; return 1 ;; esac
}
