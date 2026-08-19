#!/bin/sh
set -eu

image=${1:-}
if [ -z "$image" ]; then
    echo "usage: $0 <candidate-image>" >&2
    exit 2
fi

material_directory=/var/lib/notifications-server/a9
scratch_directory=$(mktemp -d)
output_directory="$scratch_directory/output"
fixture_volume=''
mkdir -p "$output_directory"
cleanup() {
    if [ -n "$fixture_volume" ]; then
        docker volume rm --force "$fixture_volume" >/dev/null 2>&1 || :
    fi
    rm -rf "$scratch_directory"
}
trap cleanup EXIT HUP INT TERM
fixture_volume=$(docker volume create)

run_candidate() {
    docker run --rm -i \
        --user 0:0 \
        --env RAILWAY_PROJECT_ID=fixture-project \
        --env RAILWAY_ENVIRONMENT_ID=fixture-environment \
        --env RAILWAY_SERVICE_ID=fixture-service \
        --env RAILWAY_VOLUME_MOUNT_PATH="$material_directory" \
        --env BRIDGE_API_BEARER_TOKEN=fixture-audit-bearer \
        --volume "$fixture_volume:$material_directory" \
        "$image" "$@"
}

assert_exact_output() {
    expected=$1
    actual=$2
    if [ "$actual" != "$expected" ]; then
        echo "a9_entrypoint_container_test=fail" >&2
        exit 1
    fi
}

image_user=$(docker image inspect --format '{{.Config.User}}' "$image")
image_entrypoint=$(docker image inspect \
    --format '{{json .Config.Entrypoint}}' "$image")
assert_exact_output "10001:10001" "$image_user"
assert_exact_output '["/usr/local/bin/bridge-entrypoint"]' "$image_entrypoint"

wrong_stdout="$output_directory/wrong.stdout"
wrong_stderr="$output_directory/wrong.stderr"
if printf '%s' fixture-material | docker run --rm -i \
    --user 0:0 \
    --env RAILWAY_PROJECT_ID=fixture-project \
    --env RAILWAY_VOLUME_MOUNT_PATH=/wrong \
    --volume "$fixture_volume:$material_directory" \
    "$image" \
    --provision-a9-material=topic-commitment-keys \
    --a9-topic-commitment-keys-file-path="$material_directory/topic-commitment-keys.json" \
    >"$wrong_stdout" 2>"$wrong_stderr"; then
    echo "a9_entrypoint_container_test=fail" >&2
    exit 1
fi
assert_exact_output "" "$(cat "$wrong_stdout")"
assert_exact_output "a9_material=fail" "$(cat "$wrong_stderr")"

invalid_stdout="$output_directory/invalid.stdout"
invalid_stderr="$output_directory/invalid.stderr"
if printf '%s' fixture-material | docker run --rm -i \
    --user 0:0 \
    --env RAILWAY_PROJECT_ID=fixture-project \
    --env RAILWAY_VOLUME_MOUNT_PATH="$material_directory" \
    --volume "$fixture_volume:$material_directory" \
    "$image" \
    --provision-a9-material=unknown \
    >"$invalid_stdout" 2>"$invalid_stderr"; then
    echo "a9_entrypoint_container_test=fail" >&2
    exit 1
fi
assert_exact_output "" "$(cat "$invalid_stdout")"
assert_exact_output "a9_material=fail" "$(cat "$invalid_stderr")"

completion_stdout="$output_directory/completion.stdout"
completion_stderr="$output_directory/completion.stderr"
if printf '%s' fixture-material | docker run --rm -i \
    --user 0:0 \
    --env RAILWAY_PROJECT_ID=fixture-project \
    --env RAILWAY_VOLUME_MOUNT_PATH="$material_directory" \
    --env GO_FLAGS_COMPLETION=1 \
    --volume "$fixture_volume:$material_directory" \
    "$image" \
    --provision-a9-material=topic-commitment-keys \
    --a9-topic-commitment-keys-file-path="$material_directory/topic-commitment-keys.json" \
    >"$completion_stdout" 2>"$completion_stderr"; then
    echo "a9_entrypoint_container_test=fail" >&2
    exit 1
fi
assert_exact_output "" "$(cat "$completion_stdout")"
assert_exact_output "a9_material=fail" "$(cat "$completion_stderr")"

absent_stderr="$output_directory/absent.stderr"
docker run --rm \
    --env RAILWAY_PROJECT_ID=fixture-project \
    --env RAILWAY_VOLUME_MOUNT_PATH=/wrong \
    "$image" --help >/dev/null 2>"$absent_stderr"
assert_exact_output "" "$(cat "$absent_stderr")"

readonly_stdout="$output_directory/readonly.stdout"
readonly_stderr="$output_directory/readonly.stderr"
if printf '%s' fixture-material | docker run --rm -i \
    --user 0:0 \
    --env RAILWAY_PROJECT_ID=fixture-project \
    --env RAILWAY_VOLUME_MOUNT_PATH="$material_directory" \
    --volume "$fixture_volume:$material_directory:ro" \
    "$image" \
    --provision-a9-material=topic-commitment-keys \
    --a9-topic-commitment-keys-file-path="$material_directory/topic-commitment-keys.json" \
    >"$readonly_stdout" 2>"$readonly_stderr"; then
    echo "a9_entrypoint_container_test=fail" >&2
    exit 1
fi
assert_exact_output "" "$(cat "$readonly_stdout")"
assert_exact_output "a9_material=fail" "$(cat "$readonly_stderr")"

for enabled in '' 1 t T true TRUE True; do
    enabled_stdout="$output_directory/enabled.stdout"
    enabled_stderr="$output_directory/enabled.stderr"
    if docker run --rm \
        --env RAILWAY_PROJECT_ID=fixture-project \
        --env RAILWAY_VOLUME_MOUNT_PATH=/wrong \
        --env BRIDGE_A9_ENABLED="$enabled" \
        "$image" --help >"$enabled_stdout" 2>"$enabled_stderr"; then
        echo "a9_entrypoint_container_test=fail" >&2
        exit 1
    fi
    assert_exact_output "" "$(cat "$enabled_stdout")"
    assert_exact_output "bridge_startup=fail" "$(cat "$enabled_stderr")"
done

for disabled in false FALSE False 0 f F; do
    disabled_stderr="$output_directory/disabled.stderr"
    docker run --rm \
        --env RAILWAY_PROJECT_ID=fixture-project \
        --env RAILWAY_VOLUME_MOUNT_PATH=/wrong \
        --env BRIDGE_A9_ENABLED="$disabled" \
        "$image" --help >/dev/null 2>"$disabled_stderr"
    assert_exact_output "" "$(cat "$disabled_stderr")"
done

for enabled_argument in \
    --a9-enabled \
    --a9-enabled= \
    --a9-enabled=1 \
    --a9-enabled=t \
    --a9-enabled=T \
    --a9-enabled=true \
    --a9-enabled=TRUE \
    --a9-enabled=True; do
    cli_stderr="$output_directory/cli.stderr"
    if docker run --rm \
        --env RAILWAY_PROJECT_ID=fixture-project \
        --env RAILWAY_VOLUME_MOUNT_PATH=/wrong \
        --env BRIDGE_A9_ENABLED=false \
        "$image" "$enabled_argument" --help >/dev/null 2>"$cli_stderr"; then
        echo "a9_entrypoint_container_test=fail" >&2
        exit 1
    fi
    assert_exact_output "bridge_startup=fail" "$(cat "$cli_stderr")"
done

topic_output=$(printf '%s' topic-fixture | run_candidate \
    --provision-a9-material=topic-commitment-keys \
    --a9-topic-commitment-keys-file-path="$material_directory/topic-commitment-keys.json")
assert_exact_output "a9_material_provision=pass
BRIDGE_A9_TOPIC_COMMITMENT_KEYS_FILE_PATH" "$topic_output"

certificate_output=$(printf '%s' certificate-fixture | run_candidate \
    --provision-a9-material=tls-certificate \
    --a9-tls-certificate-file-path="$material_directory/tls-certificate.pem")
assert_exact_output "a9_material_provision=pass
BRIDGE_A9_TLS_CERTIFICATE_FILE_PATH" "$certificate_output"

private_key_output=$(printf '%s' private-key-fixture | run_candidate \
    --provision-a9-material=tls-private-key \
    --a9-tls-private-key-file-path="$material_directory/tls-private-key.pem")
assert_exact_output "a9_material_provision=pass
BRIDGE_A9_TLS_PRIVATE_KEY_FILE_PATH" "$private_key_output"

metadata=$(docker run --rm --user 0:0 \
    --entrypoint /bin/sh \
    --volume "$fixture_volume:$material_directory" \
    "$image" -c \
    "stat -c '%u:%g %a' '$material_directory/topic-commitment-keys.json' '$material_directory/tls-certificate.pem' '$material_directory/tls-private-key.pem'")
assert_exact_output "10001:10001 600
10001:10001 600
10001:10001 600" "$metadata"

preflight_output=$(run_candidate \
    --preflight-a9-runtime-files \
    --api \
    --xmtp-listener \
    --listener-type=v4 \
    --hytch-secure-vault \
    --bridge-api-bearer-token= \
    --a9-enabled \
    --a9-keyset-origin=https://modern-api.internal \
    --a9-pinned-root-public-key=fixture-public-key \
    --a9-pinned-root-key-id=fixture-key-id \
    --a9-topic-commitment-keys-file-path="$material_directory/topic-commitment-keys.json" \
    --a9-private-bind=127.0.0.1:9443 \
    --a9-tls-certificate-file-path="$material_directory/tls-certificate.pem" \
    --a9-tls-private-key-file-path="$material_directory/tls-private-key.pem")
assert_exact_output "a9_material_preflight=pass
BRIDGE_A9_TOPIC_COMMITMENT_KEYS_FILE_PATH
BRIDGE_A9_TLS_CERTIFICATE_FILE_PATH
BRIDGE_A9_TLS_PRIVATE_KEY_FILE_PATH" "$preflight_output"

echo "a9_entrypoint_container_test=pass"
