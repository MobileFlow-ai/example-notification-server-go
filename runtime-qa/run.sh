#!/bin/sh

set -eu

compose_project=xmtp-bridge-runtime-qa
compose_file=runtime-qa/docker-compose.yml
http_result_file="${TMPDIR:-/tmp}/xmtp-bridge-runtime-qa-http.$$.txt"
schema_result_file="${TMPDIR:-/tmp}/xmtp-bridge-runtime-qa-schema.$$.txt"
vector_result_file="${TMPDIR:-/tmp}/xmtp-bridge-runtime-qa-vectors.$$.jsonl"

opt_in_vault_integration=''
if [ "${RUNTIME_QA_INCLUDE_OPT_IN:-0}" = 1 ]; then
  opt_in_vault_integration=1
fi

compose() {
  if [ -n "$opt_in_vault_integration" ]; then
    docker compose \
      -f "$compose_file" \
      -p "$compose_project" \
      --profile pg18 \
      "$@"
  else
    docker compose -f "$compose_file" -p "$compose_project" "$@"
  fi
}

cleanup() {
  rm -f "$http_result_file" "$schema_result_file" "$vector_result_file"
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT HUP INT TERM

docker info >/dev/null
compose config --quiet
compose up --build --detach --wait

while IFS='|' read -r path expected_status expected_body; do
  case "$path" in
    ''|'#'*) continue ;;
  esac
  actual_status="$(
    curl --silent --show-error \
      --output "$http_result_file" \
      --write-out '%{http_code}' \
      "http://127.0.0.1:18080${path}"
  )"
  actual_body="$(sed -n '1p' "$http_result_file")"
  test "$actual_status" = "$expected_status"
  test "$actual_body" = "$expected_body"
done < runtime-qa/expected/http.txt

compose exec -T db psql \
  -U bridge_runtime_qa \
  -d bridge_runtime_qa \
  -Atc 'SELECT version::text || '"'"'|'"'"' || dirty::text FROM schema_migrations;' \
  > "$schema_result_file"
cmp runtime-qa/expected/schema_migrations.txt "$schema_result_file"

compose exec -T bridge sh -eu -c '
  test "$APNS_ENABLED" = false
  test "$BRIDGE_A9_ENABLED" = false
  test "$BRIDGE_A10_REGISTRATION_ENABLED" = false
  test "$BRIDGE_A3_ASSOCIATION_ENABLED" = false
  test "$BRIDGE_A3_WITNESS_ENABLED" = false
  test "$BRIDGE_WELCOME_ENABLED" = false
'

# The long-lived container remains dormant so runtime QA can never contact
# APNS, XMTP, or an authority service. This explicit probe separately turns on
# the complete A9/A10/APNS activation predicates, crosses the production A10
# initializer with a loopback TLS keyset peer, mounts the real API route, and
# proves encrypted persistence plus replay durability against the QA database.
runtime_qa_dsn='postgres://bridge_runtime_qa:xmtp_runtime_qa@127.0.0.1:15432/bridge_runtime_qa?sslmode=disable'
A10_RUNTIME_QA=1 \
  BRIDGE_TEST_DSN="$runtime_qa_dsn" \
  go test \
    -buildvcs=false \
    -mod=readonly \
    -p 1 \
    -count=1 \
    ./cmd/server \
    -run '^TestActivatedA10ServerAssemblyRuntimeQA$'

# This separately activates both A3 public handlers with injected in-process
# IdentityApi/ValidationApi seams, crosses the real ApiServer assembly and
# PostgreSQL witness store, then rebuilds the runtime to prove exact replay.
# No external client is constructed and all credentials are synthetic.
A3_RUNTIME_QA=1 \
  BRIDGE_TEST_DSN="$runtime_qa_dsn" \
  go test \
    -buildvcs=false \
    -mod=readonly \
    -p 1 \
    -count=1 \
    ./cmd/server \
    -run '^TestActivatedA3ServerAssemblyRuntimeQA$'

# RUNTIME_QA_INCLUDE_OPT_IN=1 additionally runs the VAULT_INTEGRATION_TESTS
# surface (the A9 CAS delivery/routing integration tests), the access-audit
# catalog barrier, and the A3 witness activation barrier against both supported
# PostgreSQL catalog families. The default run skips those matrix tests, so a
# default green does not prove either opt-in surface.

BRIDGE_TEST_DSN="$runtime_qa_dsn" \
  VAULT_INTEGRATION_TESTS="$opt_in_vault_integration" \
  go test -buildvcs=false -mod=readonly -p 1 -count=1 ./...

if [ -n "$opt_in_vault_integration" ]; then
  for matrix_entry in \
    'postgres13|postgres://bridge_runtime_qa:xmtp_runtime_qa@127.0.0.1:15432/bridge_runtime_qa?sslmode=disable' \
    'postgres18|postgres://bridge_runtime_qa:xmtp_runtime_qa@127.0.0.1:15433/bridge_runtime_qa?sslmode=disable'
  do
    matrix_name=${matrix_entry%%|*}
    matrix_dsn=${matrix_entry#*|}
    printf 'access-audit barrier matrix: %s\n' "$matrix_name"
    BRIDGE_TEST_DSN="$matrix_dsn" \
      VAULT_INTEGRATION_TESTS=1 \
      go test \
        -buildvcs=false \
        -mod=readonly \
        -p 1 \
        -count=1 \
        ./pkg/vault \
        -run '^TestAccessAuditBarrier'
    printf 'A3 witness barrier matrix: %s\n' "$matrix_name"
    BRIDGE_TEST_DSN="$matrix_dsn" \
      go test \
        -buildvcs=false \
        -mod=readonly \
        -p 1 \
        -count=1 \
        ./pkg/db \
        -run '^TestA3WitnessActivationBarrier'
  done
fi

go run ./runtime-qa/cmd/gate6check \
  -cases runtime-qa/vectors/gate6.json \
  > "$vector_result_file"
cmp runtime-qa/expected/gate6.jsonl "$vector_result_file"

compose ps
if [ -n "$opt_in_vault_integration" ]; then
    printf '%s\n' 'runtime QA passed (with opt-in vault integration): postgres=15432 bridge=18080 a10-assembly=activated-local a3-assembly=activated-local long-lived-a3=dark welcome=false'
else
  printf '%s\n' 'runtime QA passed: postgres=15432 bridge=18080 a10-assembly=activated-local a3-assembly=activated-local long-lived-a3=dark welcome=false'
fi
