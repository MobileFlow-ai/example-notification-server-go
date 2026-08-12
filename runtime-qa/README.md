# Bridge runtime QA

This harness builds the current bridge image, applies all embedded migrations
to an isolated Postgres container, starts the API-only dormant runtime, checks
exact health and Gate 6 outcomes, and runs an activated A10 assembly probe.

## Ports

- Postgres host port: `15432`
- Bridge API host port: `18080`

Both bind to `127.0.0.1` and avoid the default Postgres and bridge ports used
by other XMTP lanes.

## Run

Prerequisites are Go 1.26, Docker, Docker Compose v2, and `curl`.

```sh
make runtime-qa
```

`make runtime-qa-full` runs the same harness with
`VAULT_INTEGRATION_TESTS=1`, adding the opt-in A9 CAS delivery/routing
integration tests to the serial suite. The default target skips those tests,
so a default green does not prove the A9 CAS layer; use the full target for
any A9-related claim or merge gate.

Both targets run `TestActivatedA10ServerAssemblyRuntimeQA` against the isolated
Postgres service. The probe turns on the exact A9, A10, APNS, secure-vault,
API, and V4-listener activation predicates, then crosses the production A10
initializer, durable keyset/replay stores, encrypted vault sink, and public API
mount. Its trust peer and HTTP server bind only to loopback and use synthetic
test keys. It deliberately does not construct APNS or XMTP clients, so the
positive assembly check cannot create external egress or consume deployment
secrets.

Both targets always remove their containers and volume on exit. For
interactive inspection, use `make runtime-qa-up` and finish with
`make runtime-qa-down`.

## Expected evidence

The harness verifies:

- `/livez` returns `200 ok`;
- `/readyz` returns `200 ok` after migration 00013 is applied;
- `/health/xmtp` returns `503 xmtp_unavailable` because the QA bridge is
  intentionally API-only and does not activate an XMTP listener;
- `schema_migrations` records version 13 with `dirty=false`;
- `APNS_ENABLED`, `BRIDGE_A9_ENABLED`,
  `BRIDGE_A10_REGISTRATION_ENABLED`, and `BRIDGE_WELCOME_ENABLED` are all
  exactly `false` inside the long-lived bridge container;
- the separate loopback-only A10 probe enables the full activation predicate,
  serves one successful registration through the assembled API, observes
  encrypted persistence, rebuilds the runtime, and rejects the same credential
  from the durable replay store;
- the full serial Go suite runs against the isolated Postgres service through
  `BRIDGE_TEST_DSN`; and
- the seeded Gate 6 cases reproduce
  [`expected/gate6.jsonl`](expected/gate6.jsonl) exactly.

The Gate 6 checker calls the bridge-owned `pkg/pushpolicy` package. It records
one eligible non-self conversation and fail-closed outcomes for control,
ephemeral, missing `shouldPush`, self-originated, stale-period, missing-HMAC,
Welcome, and unknown-message cases. This keeps `shouldPush` interpretation on
the server side and does not introduce a client-side policy seam.
