# XMTP dev-loop acceptance evidence — August 2026

**Status: NOT ACCEPTED — deployment remains blocked.**

This is the Phase 3 local evidence packet for the XMTP development loop. It
records what ran on 2026-08-04 and, just as importantly, the boundaries that
prevent a claim of a complete modern-api → A9 → bridge → APNS delivery loop.
No Railway service, variable, deployment, database, or environment was
changed for this packet.

## Tested revisions and isolation

| Surface | Revision / isolation | Result |
| --- | --- | --- |
| Bridge runtime QA | `c1ea4f1` (`feat/xmtp-bridge-a9-runtime-wiring-20260801`) | PASS at the checked-in 15432/18080 harness scope |
| Modern-api L4 test branch | `feat/xmtp-dev-e2e-20260804` from `origin/dev` `8ee2d4f1` | New files are limited to `tests/xmtp_e2e/` |
| Historical modern-api diagnostic | `rechain/985` / `bd7f30aa` over then-current `origin/dev` | Multiple-head migration failure; retained below as historical evidence |
| Current modern-api preview | Exact detached draft #987 tip `fc91e067` | One head and `upgrade head` PASS; composed lane is 3 PASS / 1 FAIL |
| Bridge database | Compose-owned `bridge_runtime_qa` on `127.0.0.1:15432` | Dedicated and torn down after QA |
| Modern-api database | `test_modern_api_dev_e2e` on a dedicated disposable local Postgres at `127.0.0.1:15433` | Lane-unique scratch database; the opt-in harness connects and asserts this exact name before service/API checks, never a shared `modern_api` database |

## Per-scenario acceptance record

| Scenario | Evidence | Result | Scope and limitation |
| --- | --- | --- | --- |
| A9 authority | Two scripted clients create, activate, deduplicate, list, and reject stale lineage in `tests/xmtp_scenarios/test_authority_scenarios.py` | PASS | Service-level SQLite harness with fake binding/product/deadline providers; not authenticated HTTP or a live product-authority integration |
| Directory binding outage recovery | Same idempotency key fails with no authority state while bindings are unavailable, then creates exactly one authority after recovery | PASS | Service-level fake binding provider; no fixed-HTTPS association/witness adapter |
| Directory challenge recovery | Owner resets a failed challenge; a different session/incarnation is rejected and leaves state unchanged | PASS | Service-level fake DB/adapter; `requeue_failed_challenge` has no HTTP route |
| Receipt issuance | HSM-shaped receipt issue and same-principal replay produce one persisted operation; conflicting session/signature is rejected | PASS | Service-level SQLite/fake-trust test; no live remote HSM or mounted HTTP router |
| Bridge push policy | `livez`, `readyz`, migration `12|false`, serial `go test -p 1 ./...`, and payload-free Gate-6 verifier | PASS | API-only V4 bridge. Explicit-true non-self conversation is admitted once; control, ephemeral, self, stale, missing-HMAC, Welcome, and unknown cases deny. No XMTP listener, A9 private ingress, APNS, or device delivery |
| Historical migration diagnostic | `rechain/985` reported `245_web_analytics_counters` and `250_xmtp_receipt_issuance_operations`; `alembic upgrade head` rejected multiple heads | FAIL (historical) | The later candidate below replaces this as the current migration evidence, not as an E2E acceptance |
| Modern-api migration gate | Detached `fc91e067`: `alembic heads` and `alembic current` both report `253_xmtp_recovery_capsule_authority`; `alembic upgrade head` succeeds | PASS | Applied only to the disposable L4 Postgres; no Railway or shared database was touched |
| Modern-api HTTP surface | Loopback Uvicorn at detached `fc91e067` fails the opt-in OpenAPI test on directory challenge and provenance receipt routes | FAIL | `app.main` mounts only the authority router; directory and provenance are present but not registered |
| Positive A9 HTTP authority | Not runnable | BLOCKED | Router uses `UnavailableXMTPProductConversationAuthorizer`, returning fail-closed `xmtp_product_authority_unavailable` |
| Positive receipt HTTP issuance | Not runnable | BLOCKED | Provenance router is unmounted and its default trust dependency is unavailable |
| Positive bridge A9 → push → APNS loop | Not runnable | BLOCKED | No checked-in compose combines secure vault, private TLS/JWS ingress, V4 listener, A9, and a permitted observable delivery boundary; APNS is hard-disabled |

### Commands run locally

```sh
# Bridge, isolated to the dedicated runtime-QA Compose project
make runtime-qa-up
BRIDGE_TEST_DSN='<local bridge_runtime_qa DSN>' \
  go test -buildvcs=false -mod=readonly -p 1 -count=1 ./...

# Scripted authority/directory/challenge/receipt service lane. The harness
# fails before running if this is not the fixed L4 scratch database.
RUN_XMTP_DEV_E2E=1 \
  XMTP_DEV_E2E_DATABASE_URL='<test_modern_api_dev_e2e asyncpg DSN>' \
  XMTP_DEV_E2E_STACK_ROOT='<detached L2 merge-preview worktree>' \
  poetry run pytest -q \
    tests/xmtp_e2e/test_dev_loop.py::test_scripted_clients_exercise_core_service_contracts

# L4 harness checks the loopback bridge health contract and Gate-6 output.
RUN_XMTP_DEV_E2E=1 \
  XMTP_DEV_E2E_BRIDGE_URL=http://127.0.0.1:18080 \
  XMTP_DEV_E2E_BRIDGE_ROOT='<bridge worktree>' \
  poetry run pytest -q \
    tests/xmtp_e2e/test_dev_loop.py::test_bridge_runtime_proves_health_and_fail_closed_push_policy

# Current stack diagnostic against the L4-only scratch database
DATABASE_URL='<test_modern_api_dev_e2e asyncpg DSN>' poetry run alembic heads
DATABASE_URL='<test_modern_api_dev_e2e asyncpg DSN>' poetry run alembic upgrade head

# Fully composed local lane: detached preview + scratch DB + bridge + loopback API.
# At `fc91e067` this intentionally finishes 3 PASS / 1 FAIL on the missing routes.
RUN_XMTP_DEV_E2E=1 \
  XMTP_DEV_E2E_DATABASE_URL='<test_modern_api_dev_e2e asyncpg DSN>' \
  XMTP_DEV_E2E_STACK_ROOT='<detached L2 merge-preview worktree>' \
  XMTP_DEV_E2E_BRIDGE_URL=http://127.0.0.1:18080 \
  XMTP_DEV_E2E_BRIDGE_ROOT='<bridge worktree>' \
  XMTP_DEV_E2E_API_URL=http://127.0.0.1:18081 \
  poetry run pytest -q tests/xmtp_e2e/test_dev_loop.py
```

The L4 test directory is skipped unless `RUN_XMTP_DEV_E2E=1`, so ordinary
`pytest tests/ -q` remains network- and compose-free. With the opt-in set,
missing runtime capability is a failure, not a skip. The service/API checks
also require `XMTP_DEV_E2E_DATABASE_URL` and verify it is loopback-only and
connects to the fixed lane-only `test_modern_api_dev_e2e` database; that guard
does not turn the service-level SQLite scenario evidence into a PostgreSQL HTTP
acceptance claim. The scripted service test additionally uses
`XMTP_DEV_E2E_STACK_ROOT` to execute the target preview's scenarios without
copying any test files into the stack worktree.

### Stable L2 preview rerun (still not accepted)

After a 30-minute quiet claim window, L4 created a detached preview of exact
remote draft #987 tip `fc91e067`. The real lane database migrated to
`253_xmtp_recovery_capsule_authority`, then the fully composed opt-in suite
completed **3 passed, 1 failed**: scratch-DB isolation, scripted
authority/directory/challenge/receipt service scenarios, and bridge health /
Gate-6 passed. The running loopback API failed only because the three required
directory/provenance paths are still absent. This is stronger local evidence,
but it does not prove positive authenticated A9, receipt HTTP issuance, A9 →
bridge delivery, XMTP consumption, or APNS.

## Required handoff to XMTP-LANDING-TRAIN

L4 did not modify a stack branch. Before this packet can be rerun as a true
end-to-end acceptance, L2 must publish a stable merge-preview that:

1. retains the verified single Alembic head when it publishes the next stable
   candidate;
2. mounts the directory and provenance routers, then proves the six required
   OpenAPI paths from the running stack;
3. wires a real product authority and directory/provenance runtime adapters,
   the corresponding HTTP routers under their explicit dark-by-default gates.

The known #988 `.claude/scratch/` contamination must also be removed from its
history before the train can be accepted. The detached `fc91e067` rerun did
not inspect those artifacts; it must not be treated as their clearance.

## Railway dev deploy preparation

### Dockerfile and configuration audit

| Item | Current verified state | Human action before any deploy |
| --- | --- | --- |
| Dockerfile | Pinned Go/alpine bases; non-root runtime user; build args default to `unknown` | Produce an image with recorded commit/version provenance. Do not treat `unknown` as release provenance |
| Secret material | Dockerfile has no provisioned restricted TOPIC/TLS files | Establish a Railway-supported, audited restricted-file mount plan; do not move any secret into an environment string or this repository |
| `railway.toml` | Blocked audit mode: V3 listener, secure vault, public API, `/readyz` | It does **not** enable A9. Do not edit/deploy it as though it did |
| Runtime QA compose | API-only V4, `HYTCH_SECURE_VAULT=false`, A9/APNS/Welcome false | Useful offline regression harness only; not a secure deployment template |
| Schema deployment | Secure runtime verifies but never migrates | A separate owner-only migration job and its preflight are required after explicit human authorization; runtime never receives `MIGRATION_DB_CONNECTION_STRING` |

### Environment matrix — names and presence only

| Category | Current audit mode | Future A9 private-listener candidate |
| --- | --- | --- |
| Listener | V3; public API + listener as checked in | V4 plus XMTP listener; private TLS listener required |
| Authentication | `BRIDGE_API_BEARER_TOKEN` is the audit-mode mechanism | `BRIDGE_API_BEARER_TOKEN` absent; one-use root-keyset-verified service JWS only |
| Vault | `HYTCH_SECURE_VAULT=true`, `BRIDGE_VAULT_MASTER_KEYS_JSON`, `BRIDGE_VAULT_LOOKUP_KEY` | Same vault material plus a restricted non-owner runtime DB credential |
| A9 | Disabled | `BRIDGE_A9_ENABLED=true`, `BRIDGE_A9_KEYSET_ORIGIN`, root public key/key ID, private numeric bind, and bounded timeouts |
| File-only secrets | Not used by audit mode | Absolute restricted TOPIC key, TLS certificate, and TLS private-key files; no symlinks or inline JSON secret replacement |
| Delivery | `APNS_ENABLED=false`; Welcome false | Still `APNS_ENABLED=false` until a reviewed Gate-8 observer and sandbox proof exist; Welcome remains false |
| Migration owner | Absent from runtime | Present only in a separate private migration job; never runtime |

### Cost and human go/no-go

The last recorded workspace fact in `STATE.md` was **$29.77 of the $30 hard
usage cap**, with an observed workspace burn near **$2/day**. At that observed
rate, the workspace run-rate is about **$60.80/month**, or **$30.80/month above
the cap**. This is a workspace-level observation, **not** a measured marginal
cost for this bridge. The historical note says the cap reset then likely
reached its ceiling again around Aug. 22; a human must re-check the current
usage and billing period read-only immediately before any deploy decision.

No agent may raise the cap, change a Railway variable, create a service, or
press Deploy. The human-only go/no-go is: either explicitly fund/raise the
cap for the measured budget, or keep the bridge deployment paused.

### One-click human deploy runbook

The single click is intentionally the final action, not an automated command.
It is unavailable until every prerequisite below is checked by a human:

1. L2 has published a clean single-head modern-api merge-preview and the full
   local acceptance table above is green at its actual HTTP/secure scopes.
2. The migration freeze is lifted by a human-recorded off-platform backup
   acknowledgement; no migration-carrying PR has merely been marked ready.
3. The dedicated Railway dev bridge database, restricted runtime role,
   owner-only migration job, legacy-retirement preflight, and schema marker
   are independently verified. Do not combine this with production or any
   shared database.
4. The audit-mode or A9-mode environment matrix is complete as the mutually
   exclusive configuration it is. For A9, private networking and restricted
   TOPIC/TLS file mounts are independently proven. APNS and Welcome remain
   false.
5. The human has rechecked cost/cap status, selected one replica, recorded the
   exact image commit/digest, and reviewed the required local QA evidence.
6. In the Railway **dev bridge service UI**, the human presses **Deploy** for
   that exact image and records the deployment ID. Then require `/livez=200`,
   `/readyz=200`, and `/health/xmtp=200` before considering an A9 test.

### Rollback / stop runbook

1. Keep `APNS_ENABLED=false`; do not add credentials or bypass the hard-close.
2. Do not use a blind "previous deployment" rollback. Migrations are
   monotonic and an older image may fail the current schema attestation.
3. If a deploy fails, stop egress and deploy a pre-tested, current-schema-
   compatible **roll-forward revert image** only after repeating its local
   gate. Keep one replica and secure-vault/legacy-retirement protections.
4. Never down-migrate, resurrect legacy plaintext routing, or point a restore
   at a listener/APNS-enabled service. Follow the detailed restore procedure
   in `docs/railway-dev-runbook.md` for a separately authorized isolated
   recovery.
5. Recheck health, current A9 trust state, explicit-true conversation policy,
   negative control/ephemeral/self-message cases, and the Welcome hard-close.

## What this packet does not claim

It does not claim a Railway deploy, cap availability, A9 private-ingress
success, modern-api producer-to-bridge delivery, XMTP consumption, APNS
provider invocation, client receipt, decryption, rendering, or multi-replica
behavior. Each remains unconfirmed until a secure, approved, synthetic
environment proves it at the stated scope.
