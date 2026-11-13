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
    mode=local
    peer_device=
    listen=
    address=
    metadata_rounds=16
    deployment_config=
    seen_enabled=false
    seen_worktree=false
    seen_interval=false
    seen_mode=false
    seen_peer=false
    seen_listen=false
    seen_address=false
    seen_rounds=false
    seen_deployment=false
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
            mode=*)
                [ "$seen_mode" = false ] || return 1
                mode=${line#mode=}
                seen_mode=true ;;
            peer_device=*)
                [ "$seen_peer" = false ] || return 1
                peer_device=${line#peer_device=}
                seen_peer=true ;;
            listen=*)
                [ "$seen_listen" = false ] || return 1
                listen=${line#listen=}
                seen_listen=true ;;
            address=*)
                [ "$seen_address" = false ] || return 1
                address=${line#address=}
                seen_address=true ;;
            metadata_rounds=*)
                [ "$seen_rounds" = false ] || return 1
                metadata_rounds=${line#metadata_rounds=}
                seen_rounds=true ;;
            deployment_config=*)
                [ "$seen_deployment" = false ] || return 1
                deployment_config=${line#deployment_config=}
                seen_deployment=true ;;
            *) fail 'unknown config key'; return 1 ;;
        esac
    done < "$CONFIG"
    case "$enabled" in true|false) ;; *) return 1 ;; esac
    case "$mode" in local|files|metadata-client|metadata-server|deployment) ;; *) return 1 ;; esac
    case "$metadata_rounds" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#metadata_rounds}" -le 2 ] &&
        [ "$metadata_rounds" -ge 1 ] &&
        [ "$metadata_rounds" -le 64 ] || return 1
    case "$scan_interval_secs" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#scan_interval_secs}" -le 5 ] &&
        [ "$scan_interval_secs" -ge 1 ] &&
        [ "$scan_interval_secs" -le 86400 ] || return 1
    if [ "$mode" = deployment ]; then
        case "$deployment_config" in
            "$STATE/"*) ;;
            *) fail 'deployment config must be inside private module state'; return 1 ;;
        esac
        case "$deployment_config" in
            *'/../'*|*'/./'*|*'//'*|*/..|*/.|*/)
                fail 'deployment config path must be exact'; return 1 ;;
        esac
    elif [ "$seen_deployment" = true ]; then
        fail 'deployment config requires explicit deployment mode'; return 1
    fi
    [ "$enabled" = true ] || return 0
    [ "$mode" != deployment ] || return 0
    if [ "$mode" != local ]; then
        [ "${#peer_device}" -eq 64 ] || return 1
        case "$peer_device" in *[!0-9a-f]*) return 1 ;; esac
        if [ "$mode" = metadata-client ]; then
            [ -n "$address" ] && [ "${#address}" -le 128 ] || return 1
            case "$address" in *[!0-9a-fA-F.:\[\]]*) return 1 ;; esac
        else
            [ -n "$listen" ] && [ "${#listen}" -le 128 ] || return 1
            case "$listen" in *[!0-9a-fA-F.:\[\]]*) return 1 ;; esac
        fi
    fi
    case "$worktree" in /*) ;; *) fail 'worktree must be absolute'; return 1 ;; esac
}

validate_deployment() {
    [ -f "$deployment_config" ] && [ ! -L "$deployment_config" ] ||
        { fail 'private deployment config is unavailable'; return 1; }
    [ "$(wc -c < "$deployment_config")" -le 65536 ] ||
        { fail 'deployment config exceeds 65536 bytes'; return 1; }
    deployment_config=$(realpath "$deployment_config") || return 1
    case "$deployment_config" in
        "$STATE/"*) ;;
        *) fail 'resolved deployment config left private state'; return 1 ;;
    esac
    chmod 600 "$deployment_config" || return 1
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
