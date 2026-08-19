#!/bin/sh
set -eu

a9_material_directory=/var/lib/notifications-server/a9
a9_material_mode=false
a9_material_cli_mode=false

entrypoint_fail() {
    if [ "${1:-$a9_material_cli_mode}" = true ]; then
        echo "a9_material=fail" >&2
    else
        echo "bridge_startup=fail" >&2
    fi
    exit 1
}

for argument in "$@"; do
    case "$argument" in
        --provision-a9-material|--provision-a9-material=*|--preflight-a9-runtime-files|--preflight-a9-runtime-files=*)
            a9_material_mode=true
            a9_material_cli_mode=true
            ;;
        --a9-enabled|--a9-enabled=''|--a9-enabled=1|--a9-enabled=t|--a9-enabled=T|--a9-enabled=true|--a9-enabled=TRUE|--a9-enabled=True)
            a9_material_mode=true
            ;;
        --)
            break
            ;;
    esac
done

if [ -n "${RAILWAY_PROJECT_ID:-}${RAILWAY_ENVIRONMENT_ID:-}${RAILWAY_SERVICE_ID:-}" ]; then
    if [ "${BRIDGE_A9_ENABLED+x}" = x ]; then
        case "$BRIDGE_A9_ENABLED" in
            ''|1|t|T|true|TRUE|True)
                a9_material_mode=true
                ;;
        esac
    fi
    if [ "$a9_material_mode" = true ] && \
        [ "${RAILWAY_VOLUME_MOUNT_PATH:-}" != "$a9_material_directory" ]; then
        entrypoint_fail
    fi
fi

# Railway mounts persistent volumes as root. RAILWAY_RUN_UID=0 lets this
# entrypoint repair only the dedicated mount root before permanently dropping
# to the image's unprivileged bridge account. Server code never runs as root.
if [ "$(id -u)" = "0" ]; then
    if [ ! -d "$a9_material_directory" ] || [ -L "$a9_material_directory" ]; then
        entrypoint_fail
    fi
    if ! chown bridge:bridge "$a9_material_directory" 2>/dev/null; then
        entrypoint_fail
    fi
    if ! chmod 0700 "$a9_material_directory" 2>/dev/null; then
        entrypoint_fail
    fi
    if [ "$a9_material_cli_mode" = true ]; then
        if su-exec bridge:bridge /usr/bin/notifications-server "$@" 2>/dev/null; then
            exit 0
        fi
        entrypoint_fail
    fi
    exec su-exec bridge:bridge /usr/bin/notifications-server "$@"
fi

if [ "$a9_material_cli_mode" = true ]; then
    if /usr/bin/notifications-server "$@" 2>/dev/null; then
        exit 0
    fi
    entrypoint_fail
fi

exec /usr/bin/notifications-server "$@"
