#!/bin/sh

set -eu

compose_project=xmtp-bridge-runtime-qa
compose_file=runtime-qa/docker-compose.yml
http_result_file="${TMPDIR:-/tmp}/xmtp-bridge-runtime-qa-http.$$.txt"
schema_result_file="${TMPDIR:-/tmp}/xmtp-bridge-runtime-qa-schema.$$.txt"
vector_result_file="${TMPDIR:-/tmp}/xmtp-bridge-runtime-qa-vectors.$$.jsonl"

compose() {
  docker compose -f "$compose_file" -p "$compose_project" "$@"
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
  test "$BRIDGE_WELCOME_ENABLED" = false
'

# RUNTIME_QA_INCLUDE_OPT_IN=1 additionally runs the VAULT_INTEGRATION_TESTS
# surface (the A9 CAS delivery/routing integration tests). The default run
# skips those tests, so a default green does not prove the A9 CAS layer —
# that gap is how an always-red A9 surface went unnoticed until 2026-08-06.
opt_in_vault_integration=''
if [ "${RUNTIME_QA_INCLUDE_OPT_IN:-0}" = 1 ]; then
  opt_in_vault_integration=1
fi

BRIDGE_TEST_DSN='postgres://bridge_runtime_qa:xmtp_runtime_qa@127.0.0.1:15432/bridge_runtime_qa?sslmode=disable' \
  VAULT_INTEGRATION_TESTS="$opt_in_vault_integration" \
  go test -buildvcs=false -mod=readonly -p 1 -count=1 ./...

go run ./runtime-qa/cmd/gate6check \
  -cases runtime-qa/vectors/gate6.json \
  > "$vector_result_file"
cmp runtime-qa/expected/gate6.jsonl "$vector_result_file"

compose ps
if [ -n "$opt_in_vault_integration" ]; then
  printf '%s\n' 'runtime QA passed (with opt-in vault integration): postgres=15432 bridge=18080 welcome=false'
else
  printf '%s\n' 'runtime QA passed: postgres=15432 bridge=18080 welcome=false'
fi
