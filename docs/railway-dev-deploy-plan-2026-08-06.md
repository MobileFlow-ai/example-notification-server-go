# Railway dev deployment plan — Hytch XMTP push bridge (2026-08-06)

**Status: PLAN ONLY. Nothing here is a deploy authorization.** The deploy
button, Railway service creation, every Railway variable write, APNs key
provisioning, and all merges remain human actions. This plan operationalizes
[railway-dev-runbook.md](railway-dev-runbook.md) (normative for runtime
behavior and variable semantics) and
[xmtp-dev-e2e-acceptance-2026-08.md](xmtp-dev-e2e-acceptance-2026-08.md)
(normative for acceptance state). Where this plan and those documents
disagree, they win.

The deployable configuration is the **blocked audit mode**: API + V4 listener,
secure vault, A9 disabled, `APNS_ENABLED=false` (the binary rejects `true`),
Welcome hard-closed. It observes XMTP dev and proves runtime health; it
delivers nothing. A9/APNs activation is a separate, later, human-authorized
change with its own gates. V4 is pinned early only to remove a live-command
edit from that later ceremony; it does not activate A9.

## 1. Service definition

| Item | Value |
| --- | --- |
| Railway project / environment | existing Hytch workspace, `dev` environment (same environment as `dev-modern-api`) |
| Service name | `dev-xmtp-bridge` |
| Source | GitHub `MobileFlow-ai/example-notification-server-go`, branch: the post-merge `main` (after #2 → #4 → #3 → #5 land; never a draft head) |
| Build | repository `Dockerfile` (pinned Go/alpine, non-root). Set build args so image provenance records the exact commit; do not ship `unknown` provenance |
| Config as code | `railway.toml` at repo root (audit mode). Do not hand-edit it in the UI to enable A9 or APNS; both are startup-rejected anyway |
| Replicas | exactly 1 |
| Region | same as `dev-modern-api` (private-network adjacency for the future A9 keyset origin) |
| Public networking | none required for audit mode. If Railway assigns a domain, it exposes only `/livez`, `/readyz`, `/health/xmtp`, and the bearer-gated API; prefer no public domain and private networking only |
| Healthcheck | `GET /readyz` (Railway evaluates at deploy time; process-exit restart policy applies afterward) |

## 2. Ports and health

- `API_PORT` — the single public-API listen port; Railway injects `PORT`, so
  set `API_PORT` to the same value the service exposes (see the port note in
  mf-brain `docs/infrastructure.md`: prod once 502'd on a PORT mismatch).
- `GET /livez` → `200 ok` — process liveness only; stays 200 during an XMTP
  outage.
- `GET /readyz` → `200 ok` / `503 not_ready` — aggregate readiness; used by
  Railway's deploy healthcheck; continuous monitoring must be external.
- `GET /health/xmtp` → `200 ok` / `503 xmtp_unavailable` — XMTP dependency
  only; modern-api consumes this.
- All three bodies are fixed and content-free.

## 3. Environment-variable contract (audit mode, names only)

Never print, copy, or log values. Set in the Railway service UI only.

| Variable | Value posture | Source of the value |
| --- | --- | --- |
| `DB_CONNECTION_STRING` | restricted runtime role DSN | from §4's provisioning step; the restricted role, never the owner |
| `HYTCH_SECURE_VAULT` | `true` | literal |
| `BRIDGE_ENVIRONMENT` | `dev` | literal (signed wire value; internal vault namespace stays `development` by design) |
| `BRIDGE_VAULT_MASTER_KEYS_JSON` | secret JSON | generated at provisioning per runbook key-shape rules; human generates and pastes |
| `BRIDGE_VAULT_LOOKUP_KEY` | secret | same |
| `BRIDGE_AUTHORITY_PUBLIC_KEYS_JSON` | public keys JSON | exported from modern-api dev authority material (public halves only) |
| `BRIDGE_API_BEARER_TOKEN` | secret | generated at provisioning; shared only with modern-api dev service config |
| `BRIDGE_VAULT_LEASE_TTL_HOURS` | `168` | literal |
| `BRIDGE_WELCOME_ENABLED` | `false` | literal; startup rejects `true` |
| `BRIDGE_TEEN_CONVERSATION_MODE` | `disabled` | literal |
| `APNS_ENABLED` | `false` | literal; startup rejects `true` in this build |
| `XMTP_GRPC_ADDRESS` | `grpc.dev.xmtp.network:443` | literal |
| `LISTENER_TYPE` | `v4` | literal; A9 remains disabled until its separate reviewed ceremony |
| `API_PORT` | service port | Railway |
| `LOG_ENCODING` / `LOG_LEVEL` | `json` / `info` | literal |

Forbidden in this service: `MIGRATION_DB_CONNECTION_STRING` (runtime startup
fails if present), any `BRIDGE_A9_*`, `BRIDGE_A3_*`, any `APNS_*` credential,
and incident-access variables (separate, later, reviewed change).

## 4. Database and persistence

- Create a **dedicated** Railway Postgres in `dev` for the bridge (working
  name `dev-xmtp-bridge-db`). Never share the modern-api database or any
  production database.
- Two credentials:
  - **owner/migration** credential — used only by a separate, private,
    manually-run migration job (`MIGRATION_DB_CONNECTION_STRING` there and
    only there). Applies `pkg/db/migrations` through `00014` and the marker
    contract, then is removed from any long-lived service.
  - **restricted runtime** role — `DB_CONNECTION_STRING` for the bridge
    service. Owns no schema/table/trigger/function, no `CREATE`, not a member
    of the owner, cannot execute the retirement function (runbook §Required
    Railway variables has the full posture; secure startup verifies and
    refuses on violations).
- Schema acceptance: `schema_migrations` must read exactly `14|false` before
  first runtime start (the secure runtime verifies and never migrates).
- Backups: Railway's default snapshot posture is acceptable for dev; the
  vault holds only encrypted route material and keyed lookups by design.

## 5. APNs credentials — by reference only

**No APNs credential is needed, or permitted, for this deploy.**
`APNS_ENABLED=false` and the binary rejects `true`; maintenance modes cannot
initialize APNS. Nothing below happens now.

For the future, separately reviewed APNs sandbox activation, the provisioning
is recorded here by reference only:

- The credential is an App Store Connect **APNs auth key (`.p8`)** for the
  Hytch team, the same key family the existing dev push path already uses:
  the modern-api dev service on Railway holds APNs variables today
  (dev/TestFlight pushes go through it — see mf-brain infrastructure notes
  and the modern-api dev service's variable names in the Railway UI).
- A human with App Store Connect **Admin** access (Demetre) either reuses
  that key's `.p8` (Key ID + Team ID as already recorded in the modern-api
  dev service's APNs variables) or issues a new APNs key scoped for the
  bridge in App Store Connect → Users and Access → Integrations → Keys.
- The human base64-encodes the `.p8` locally and pastes it into the bridge
  service's `APNS_P8_CERTIFICATE_BASE64` in the Railway UI, with
  `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_TOPIC` (the iOS bundle id), and
  `APNS_MODE=development`.
- Agents never read, move, copy, echo, or commit the key material; it exists
  only in App Store Connect and the Railway variable store. If the `.p8`
  file must transit a laptop, it is deleted after paste, not archived.

## 6. Deploy procedure (human)

1. Merge gate: #2 → #4 → #3 → #5 (+ any stacked follow-ups) land on `main`
   via the recorded merge order; the bridge repo is outside the
   `dev-batch-merge` cron, so these are manual merges after cross-agent
   review. Re-run `make runtime-qa` on the merge result and keep the log.
2. Provision §4 (database, two roles, migration job run, `14|false`
   verified read-only).
3. Create the service per §1, set §3 variables in the Railway UI.
4. Re-check the cost gate (§8) the same day.
5. Press **Deploy** in the Railway dev bridge service UI for the exact
   audited image; record the deployment ID and image digest.
6. Run the smoke script (§7) against the service URL; attach output to the
   deploy record. `/livez` and `/readyz` must be `200`; `/health/xmtp` should
   be `200` when XMTP dev is reachable (a `503 xmtp_unavailable` with
   `/livez=200` means the bridge is up but XMTP dev is not — investigate
   before calling the deploy good).

## 7. Dev smoke test

`scripts/railway_dev_smoke.sh` (added alongside this plan) is read-only,
secret-free, and safe to run repeatedly:

```sh
BRIDGE_BASE_URL=https://<railway-service-host> ./scripts/railway_dev_smoke.sh
```

It asserts the three health endpoints' exact status/body contract and, when
`BRIDGE_SMOKE_DSN` (the restricted read-only role) is provided, that
`schema_migrations` reads `14|false`. It never sends authenticated API
requests and carries no bearer token.

## 8. Cost gate

- The Railway workspace hit its **$30 hard usage cap** on 2026-08-02 (full
  outage) and burns ≈ **$2/day**; on that trajectory the cap re-bricks the
  workspace around **Aug 22** (STATE.md / cap-outage record).
  **ed@gocybered.com owns the cap raise.**
- A new always-on service (bridge container + dedicated Postgres) **adds
  burn** — order-of-magnitude a few dollars/month at one replica, but the
  binding constraint is the cap, not the marginal cost: any addition pulls
  the re-brick date earlier for *everything* on the workspace, including
  dev-modern-api and TestFlight-adjacent staging.
- **Demetre must approve the spend explicitly** (and sequence it with the cap
  raise) before service creation — creating the service is itself a cost
  action, prior to any deploy.

## 9. Rollback / stop story

Runbook §Rollback is normative; summary:

1. Stop = scale to zero / remove the service; `APNS_ENABLED` stays `false`.
2. Never blind-rollback to a previous deployment: migrations are monotonic
   and an older image can fail the schema attestation. Roll **forward** with
   a re-gated, current-schema-compatible image.
3. Never down-migrate; never point a restore at a listener/APNS-enabled
   service; isolated recovery follows the runbook's restore procedure under
   separate authorization.
4. Deleting the service loses nothing of record: the vault holds re-derivable
   encrypted route material for dev, and acceptance evidence lives in the
   repo/mf-brain, not the container.

## 10. What blocks A9-mode (not this deploy)

Recorded so the next lane doesn't rediscover it: the A9 private-listener mode
additionally requires the A9 activation checklist in
`contracts/xmtp_push/a9_adapter/v1/README.md` ("Activation requires all of the
following", items 1–7) — including the landed modern-api producer (none
exists; the producer side has no owner in the fleet), key ceremonies (root
pin, TOPIC file mounts, signing-key rotation) exercised in the target
environment, and a separately authorized end-to-end gate.

**2026-08-06 finding — the opt-in A9 CAS integration surface has never been
green.** With `VAULT_INTEGRATION_TESTS=1` against the checked-in runtime-QA
Postgres, eight `pkg/vault` tests fail identically at every recorded head:
the current #3 head `c1ea4f1`, the green-QA head `4df115d`, #4's own head
`bc81ddf` (where the tests were introduced), and the pre-slicing rescue
commit `f401b42`:

- `TestA9DeliveryEnqueueClaimAndPreEgressRoundTrip`
- `TestA9DeliveryFinalDatabaseTimeRejectsExpiredGate6Route`
- `TestA9DeliveryAttemptGuardBlocksRevocationUntilRelease`
- `TestA9DeliveryRevocationBeforePreEgressSpendsNoAttempt`
- `TestA9DeliveryClaimRejectsEncryptedSnapshotMismatch`
- `TestA9RoutingWithLeaseReturnsExactSnapshot` (the one failure
  [xmtp-dev-e2e-acceptance-2026-08.md](xmtp-dev-e2e-acceptance-2026-08.md)
  already records, with its source-backed assertion/Gate-6 lease-identity
  diagnosis)
- `TestA9RoutingGetSubscriptionsUsesOneCurrentTrustLease`
- `TestAdvancePolicyFailsClosedOnStoredEnvironmentOrIdentityMismatch`
  (a distinct class: migration 00012's
  `subscription_leases_a9_installation_identity_fk` now breaks a
  pre-existing `installation_states` update path)

The default runtime QA (`make runtime-qa`) never runs these — that is why
every recorded "suite green" is true and yet the A9 delivery path is
unproven. None of this affects the blocked-audit-mode deploy this plan
covers (A9 disabled; these code paths are unreachable).

**2026-08-07 update — repair delivered as draft PR #7** (one commit on top
of #3's head; cross-agent review required before merge). Root causes, per
an instrumented three-way investigation and a four-lens adversarial
verification pass (0 refuted, 0 blocking findings):

1. Production defect: `loadA9CurrentAssertionTx` constrained
   `a9_assertions.lease_id` (the assertion's modern-api roster-lease
   reference) to equal the route's bridge-generated Gate-6 lease — disjoint
   namespaces, unsatisfiable by construction; in A9 mode this denies 100%
   of egress. This confirms and sharpens the lease-identity diagnosis in
   [xmtp-dev-e2e-acceptance-2026-08.md](xmtp-dev-e2e-acceptance-2026-08.md):
   the join was a genuine code defect to repair, not a fail-closed check to
   preserve — no contract sentence ties the two leases, and the
   route→assertion linkage is enforced by `assertion_hash`, ten identity
   predicates, and migration 00012's 11-column composite FK.
2. Fixture defect: `topic_key_epoch` pinned to `7` (the Aug-1970 period)
   against the live DB clock; the store's contract-aligned wall-clock epoch
   gates correctly rejected the data.
3. Test-tamper defect: the stable-identity tamper rewrote the identity
   parent-only — a state production cannot produce; migration 00012's FK
   correctly blocks it as tamper resistance.

With PR #7, the full `pkg/vault` suite is green under
`VAULT_INTEGRATION_TESTS=1` for the first time at any recorded head, the
whole-repo opt-in suite is green, and `make runtime-qa` passes end-to-end
at the fix head. A9-mode activation remains blocked on the checklist items
above (landed producer, key ceremonies, authorized E2E gate) — but no
longer on a red bridge CAS surface once #7 lands with cross-agent review.
