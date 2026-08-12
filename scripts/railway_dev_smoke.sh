#!/bin/sh
# Read-only Railway dev smoke test for the Hytch XMTP push bridge.
#
# Usage:
#   BRIDGE_BASE_URL=https://<railway-service-host> ./scripts/railway_dev_smoke.sh
#
# Optional:
#   BRIDGE_SMOKE_DSN  restricted read-only Postgres DSN; when set, the script
#                     additionally asserts schema_migrations reads exactly
#                     "14|false". Requires psql on PATH.
#
# The script sends no authenticated request, carries no bearer token, and
# never prints a secret. It exits nonzero on the first contract violation.

set -eu

: "${BRIDGE_BASE_URL:?set BRIDGE_BASE_URL to the bridge service origin}"

case "$BRIDGE_BASE_URL" in
  *\?*|*\#*) echo "BRIDGE_BASE_URL must be a bare origin" >&2; exit 2 ;;
esac

fail() {
  echo "SMOKE FAIL: $1" >&2
  exit 1
}

probe() {
  path="$1"
  expected_status="$2"
  expected_body="$3"

  body_file="$(mktemp)"
  status="$(
    curl --silent --show-error --max-time 15 \
      --output "$body_file" \
      --write-out '%{http_code}' \
      "${BRIDGE_BASE_URL}${path}"
  )" || { rm -f "$body_file"; fail "curl ${path} did not complete"; }
  body="$(sed -n '1p' "$body_file")"
  rm -f "$body_file"

  [ "$status" = "$expected_status" ] || \
    fail "${path}: status ${status}, expected ${expected_status}"
  [ "$body" = "$expected_body" ] || \
    fail "${path}: body '${body}', expected '${expected_body}'"
  echo "ok ${path} ${status} ${body}"
}

probe /livez 200 ok
probe /readyz 200 ok

# /health/xmtp is 200 when XMTP dev is reachable. A 503 with livez/readyz
# green means the bridge is healthy but XMTP dev is not; report it distinctly
# rather than passing or hard-failing ambiguously.
xmtp_body_file="$(mktemp)"
xmtp_status="$(
  curl --silent --show-error --max-time 15 \
    --output "$xmtp_body_file" \
    --write-out '%{http_code}' \
    "${BRIDGE_BASE_URL}/health/xmtp"
)" || { rm -f "$xmtp_body_file"; fail "curl /health/xmtp did not complete"; }
xmtp_body="$(sed -n '1p' "$xmtp_body_file")"
rm -f "$xmtp_body_file"

case "${xmtp_status}|${xmtp_body}" in
  "200|ok")
    echo "ok /health/xmtp 200 ok"
    ;;
  "503|xmtp_unavailable")
    echo "WARN /health/xmtp 503 xmtp_unavailable — bridge healthy, XMTP dev unreachable" >&2
    ;;
  *)
    fail "/health/xmtp: unexpected ${xmtp_status} '${xmtp_body}'"
    ;;
esac

if [ -n "${BRIDGE_SMOKE_DSN:-}" ]; then
  command -v psql >/dev/null 2>&1 || fail "BRIDGE_SMOKE_DSN set but psql not on PATH"
  schema="$(
    psql "$BRIDGE_SMOKE_DSN" -Atc \
      "SELECT version::text || '|' || dirty::text FROM schema_migrations;"
  )" || fail "schema_migrations query did not complete"
  [ "$schema" = "14|false" ] || \
    fail "schema_migrations '${schema}', expected '14|false'"
  echo "ok schema_migrations 14|false"
fi

echo "smoke passed: ${BRIDGE_BASE_URL}"
