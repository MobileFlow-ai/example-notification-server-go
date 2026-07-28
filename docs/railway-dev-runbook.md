# Hytch XMTP Push Bridge — Railway Dev Runbook

This runbook is internal and applies only to Railway `dev`, XMTP dev, and the
APNS sandbox. It does not authorize a production or public-cohort deployment.
All numeric limits below are provisional defaults pending measurement.

## Safety contract

The bridge sees encrypted XMTP outer envelopes. It cannot decrypt a content
type or identify a sender.

- Conversation delivery requires an explicit outer `shouldPush=true`, a fresh
  signed receive capability, a fresh policy control, and a valid HMAC for the
  exact 30-day key period.
- The shared contract requires control and ephemeral codecs to produce
  `shouldPush=false`. Bridge-owned serialized V3 and V4 fixtures pass through
  the real listener, dispatcher, and `ApnsDelivery` provider boundary and prove
  that a false authenticated outer bit makes zero provider calls in both V4
  payload formats. Official codec-produced V3 and V4 conformance fixtures
  remain **UNCONFIRMED**. Classification of plaintext content remains outside
  the bridge's tested scope.
- The HMAC check suppresses a message originated by the same installation. It
  is not sender identification, blocking, or sender-level filtering. Blocking
  remains client-side decrypt-then-hide.
- Missing, false, malformed, stale, unknown, or ambiguous authority fails
  closed.
- Adult receive and policy authority is capped at 60 seconds; teen authority is
  capped at 30 seconds. Exact Welcome preauthorization rejects teen state.
- A conversation APNS alert is always generic and contains no name or content.
  This permits the client's amended expired-projection behavior without
  leaking a sender or message.

The bridge's primary tested scope is the authenticated outer `shouldPush` bit.
Whether every current and future Hytch codec sets that bit correctly is a
cross-repository conformance claim and remains **UNCONFIRMED** until the
corresponding modern-api/iOS vector suite passes.

## Runtime shape and probes

- Run one listener replica in Railway dev unless a duplicate-delivery exercise
  is intentional. PostgreSQL queue claims are lease-protected across rolling
  replicas, but APNS is still at-least-once across a crash after Apple accepts a
  notification and before the success deletion commits.
- Use the checked-in `railway.toml`. It runs API plus V3 listener against XMTP
  dev, enables the secure vault, and uses `APNS_ENABLED` as the delivery kill
  switch.
- Railway's deployment healthcheck is `GET /readyz`; Railway evaluates it while
  bringing up a deployment, not as a continuous restart probe. The checked-in
  restart policy responds to process exit. Continuous `/readyz` monitoring must
  be supplied externally.
- `GET /livez` is operator-visible process liveness and stays `200 ok` during
  an XMTP outage, avoiding an operator-induced restart loop.
- `GET /readyz` is aggregate readiness. It is `503 not_ready` when XMTP is
  disconnected, retention is unsafe, APNS egress has stopped, or the
  deletion-only invalid-token worker is unavailable. When the private
  incident-access listener is enabled, its failure also removes readiness and
  terminates the runtime.
- `GET /health/xmtp` reports only the XMTP dependency: `200 ok` or
  `503 xmtp_unavailable`. modern-api consumes this endpoint.
- All three responses are content-free. Liveness does not authorize delivery.

When XMTP is unreachable, the process stays live, readiness and the XMTP probe
fail, no new route resolution occurs, and the listener continues its bounded
reconnect behavior. Existing authorized APNS jobs remain subject to their
original expiry; an outage never extends authority.

## Required Railway variables

Inspect names and presence only. Never print or copy values into commands,
logs, screenshots, tickets, Mattermost, this repository, or evidence files.

Required secure bridge variables:

- `DB_CONNECTION_STRING`
- `HYTCH_SECURE_VAULT=true`
- `BRIDGE_ENVIRONMENT=development`
- `BRIDGE_VAULT_MASTER_KEYS_JSON`
- `BRIDGE_VAULT_LOOKUP_KEY`
- `BRIDGE_AUTHORITY_PUBLIC_KEYS_JSON`
- `BRIDGE_API_BEARER_TOKEN`
- `BRIDGE_VAULT_LEASE_TTL_HOURS=168`
- `BRIDGE_WELCOME_ENABLED=false`
- `BRIDGE_TEEN_CONVERSATION_MODE=disabled`

`DB_CONNECTION_STRING` must authenticate as a restricted runtime role. That
role owns no schema, table, trigger, or function; is not a member of the
migration owner; has no `CREATE`, superuser, replication, or bypass-RLS
authority; and cannot execute the retirement function. The bridge refuses
secure startup if the schema is stale, a retired relation exists, the marker
contract is missing or redirected, logical replication is configured, or the
runtime role is privileged enough to change protected state.

`MIGRATION_DB_CONNECTION_STRING` is allowed only in a separate, private
migration job. Never add it to the bridge runtime service. Runtime startup
fails if that owner credential is present, and secure runtime startup never
applies migrations.

Welcome authorization is independently fail-closed. Keep
`BRIDGE_WELCOME_ENABLED=false` until the A9 issuer contract, fixed commitment
vector, and secure handoff have been acknowledged and exercised end to end.
Turning off Welcome does not weaken conversation policy checks or
invalid-token deletion.

Teen XMTP conversations and inbound Welcomes remain disabled pending the
required safety review. The 30-second teen authority ceiling is implemented
for the future reviewed conversation enablement; it is not permission to turn
the mode on in this dev deployment.

Required APNS sandbox variables:

- `APNS_ENABLED=true`
- `APNS_MODE=development`
- `APNS_P8_CERTIFICATE_BASE64`
- `APNS_KEY_ID`
- `APNS_TEAM_ID`
- `APNS_TOPIC`

Required listener/runtime variables:

- `XMTP_GRPC_ADDRESS=grpc.dev.xmtp.network:443`
- `LISTENER_TYPE=v3`
- `API_PORT`
- `LOG_ENCODING`
- `LOG_LEVEL`

Provisional APNS controls and their defaults:

- `APNS_RATE_PER_SECOND=50`
- `APNS_RATE_BURST=50`
- `APNS_MAX_CONCURRENCY=8`
- `APNS_QUEUE_CAPACITY=5000`
- `APNS_QUEUE_POLL_INTERVAL_MS=500`
- `APNS_REQUEST_TIMEOUT_SECONDS=10`
- `APNS_INITIAL_RETRY_DELAY_MS=500`
- `APNS_MAX_RETRY_DELAY_MS=30000`
- `APNS_SHUTDOWN_TIMEOUT_SECONDS=15`

Use only `APNS_P8_CERTIFICATE_BASE64` on Railway. Do not also configure raw
`.p8` text or a file path. Secure mode rejects FCM and HTTP delivery.

Private incident access is disabled unless explicitly configured. Enabling it
requires all of the following:

- `BRIDGE_INCIDENT_ACCESS_ENABLED=true`
- `BRIDGE_INCIDENT_ACCESS_BIND=127.0.0.1:9091`
- `BRIDGE_INCIDENT_ACTOR_CREDENTIALS_JSON`
- `BRIDGE_INCIDENT_OVERSIGHT_WEBHOOK_URL`
- `BRIDGE_INCIDENT_OVERSIGHT_WEBHOOK_BEARER`
- `BRIDGE_INCIDENT_ROLE_TTL_MINUTES=30`
- `BRIDGE_INCIDENT_REQUEST_TIMEOUT_SECONDS=10`
- `BRIDGE_INCIDENT_OVERSIGHT_TIMEOUT_SECONDS=5`

The actor JSON contains only canonical base64url SHA-256 digests of
independently delivered bearer secrets, one fixed `requester` or `approver`
role per actor, and opaque actor labels. It must contain at least one of each
role; duplicate actors or digests are rejected. Never put raw actor bearer
values in Railway, the database, or the bridge configuration. The oversight
webhook must be HTTPS, redirect-free, and authenticated; its notification
contains only fixed purpose/data-class enums and a UTC-hour bucket.

The incident listener accepts only a numeric loopback bind. Do not attach a
Railway public domain or expose its port. Reach it only through an
authenticated, audited operator tunnel on the exact service. Partial
configuration, a non-loopback bind, or missing database barriers fails closed
before APNS or XMTP starts. Startup validates the oversight destination's
syntax but does not claim that the remote endpoint is reachable. A broadcaster
failure during approval denies that approval without exposing vault data.

## Internal API contracts

All three endpoints require
`Authorization: Bearer <BRIDGE_API_BEARER_TOKEN>`, reject unknown JSON fields,
bound request sizes, return fixed errors, and set `Cache-Control: no-store`.

### Atomic subscription replacement

`PUT /internal/v1/xmtp-push/subscriptions:replace`

```text
{
  schema_version: 1,
  environment,
  installation_id,
  account_incarnation_id,
  generation,
  idempotency_key,
  apns_token_b64,
  payload_schema: "hytch_push_wrapper_v1",
  policy_control: PolicyControlV1,
  subscriptions: [{
    topic_b64,
    route_key_b64,
    route_key_epoch,
    hmac_keys: [{
      thirty_day_periods_since_epoch,
      key_b64
    }],
    receive_capability: ReceiveCapabilityV1
  }]
}
```

The list is a full atomic replacement, not a one-topic mutation. One logical DM
may span multiple topics. A suppressed Welcome topic is required. Route-key or
APNS-token rotation cancels queued work bound to the old key/token; an ordinary
fresh-control refresh preserves valid retries.

### Policy advancement

`POST /internal/v1/xmtp-push/policy:advance`

The body is one signed `PolicyControlV1`. A newer revoke disables lookup first,
cancels leases/jobs through the vault transaction, and cannot be reversed by a
stale generation or a same-epoch active replay.

### Exact Welcome preauthorization

`POST /internal/v1/xmtp-push/welcomes:authorize`

```text
{
  schema_version: 1,
  topic_b64,
  authorization: WelcomeAuthorizationV1
}
```

`WelcomeAuthorizationV1` contains `schema_version`, `environment`,
`installation_id`, `account_incarnation_id`, `policy_epoch`, `topic_digest`,
`outer_envelope_digest`, `expected_conversation_commitment`, `grant_version`,
`nonce`, `issued_at`, `expires_at`, `signing_key_id`, `algorithm`, and
`signature`.

The Ed25519 signature domain is the exact byte string
`Hytch safety welcome authorization v1\x00`. The listener digests are:

```text
V3: SHA-256("Hytch exact Welcome outer envelope v3\x00" ||
           topic.Bytes() || env.Message)
V4: SHA-256("Hytch exact Welcome outer envelope v4\x00" ||
           topic.Bytes() || origEnv.Bytes())
```

The trusted modern-api issuer must validate the publisher/conversation
association before signing. An `expected_conversation_id` echoed by the caller
is insufficient authority. After that validation, modern-api and iOS compute:

```text
SHA-256("Hytch expected conversation commitment v1\x00" ||
       u64be(len(environment)) || environment ||
       u64be(len(installation_id)) || installation_id ||
       u64be(len(account_incarnation_id)) || account_incarnation_id ||
       u64be(len(canonical_expected_conversation_id)) ||
       canonical_expected_conversation_id)
```

Each length counts exact bounded-ASCII bytes. The result is lower-case hex in
both signed objects. It is mandatory in the encrypted Welcome-path
`ReceiveCapabilityV1`, optional for ordinary conversation capabilities, and
must exactly match the Welcome authorization. The raw conversation identifier
is not sent to the bridge. The fixed commitment vector for
`development`, `installation`, `incarnation`, `conversation` is
`5c98d79b0069383245a2fe22c161c922c244d3a9557340ff8ce2c88e542287bc`.

The authorization is encrypted and exact-envelope bound. Route resolution
allocates a nonce but does not consume the grant. The grant and budget are
finalized in the same PostgreSQL transaction that inserts the encrypted durable
APNS job, so enqueue failure/backpressure rolls them back; a budget denial
intentionally consumes the one-use grant with no job. Destination limits are
database-shared at 1/minute and 5/hour. A breach opens one global 30-minute
circuit observed by all replicas. Destination pseudonyms rotate on UTC-hour
boundaries and budget rows expire within one hour. Unmatched, duplicate,
expired, teen, ambiguous, or exhausted cases produce no egress.

## Private incident-access contract

The private listener is a distinct loopback-only HTTP server, not a route on
the public API mux. Every operation is `POST`, requires
`Authorization: Bearer <out-of-band actor secret>`, authenticates before
reading the bounded JSON body, rejects unknown fields, and returns fixed
errors with `Cache-Control: no-store`.

- `/private/v1/incident-access/requests:create` requires the requester
  credential plus an opaque ticket, fixed hypothesis enum, and bounded
  RFC3339 window. Actor, purpose, and data class are derived by the server.
- `/private/v1/incident-access/requests:approve` requires the independent
  approver credential and an opaque request ID. Approval commits only after
  the content-free oversight webhook succeeds.
- `/private/v1/incident-access/vault:query` requires the original requester
  credential, an approved unexpired request, and one typed lookup: installation
  keyed digest, lease ID, or delivery-job ID. It never accepts SQL or a
  mutation callback and returns at most one encrypted snapshot.
- `/private/v1/incident-access/requests:revoke` accepts only the request's
  requester or approver credential and closes the role immediately.

The response body is privileged incident data and must never be copied to
general logs, a ticket, Mattermost, or release evidence. A private tunnel does
not weaken the independent-actor, expiry, environment, read-only transaction,
oversight, or append-only audit checks.

## APNS wrapper and retry behavior

The outer APNS JSON contains only `aps` and `hytch_wrapper`. The authenticated
header exposes only the fixed schema/environment, UTC alias day, daily route
alias, route-key epoch, nonce prefix, and delivery sequence. Capability,
delivery mode, XMTP ciphertext, and randomized padding are AES-GCM encrypted.
Raw topic, topic digest, installation ID, APNS token, exact content type, exact
size, and sender/content are absent.

- Conversation: generic `New message` alert, mutable content, alert priority.
- Matched Welcome: silent background wakeup, background priority.
- If the complete inline wrapper would exceed 4096 bytes, mode selection occurs
  before encryption and the bridge emits a foreground-sync wrapper with no XMTP
  envelope. The 8192-byte Welcome regression covers the former APNS 413.
- Alias, AEAD, environment, day, route-key epoch, nonce, sequence, replay, or
  key-state failure is deny, never plaintext fallback.
- The Go reference opener requires an injected atomic compare-and-advance replay
  protector. Its in-memory window supports validated state transfer for tests
  but deliberately is not crash-safe. A durable client implementation and
  restart proof belong to the client track and remain **UNCONFIRMED** here.
- Durable jobs are encrypted, capped by lease/control expiry and 15 minutes,
  and have at most three APNS attempts. Only network errors, 429, and 5xx retry.
  Exact serialized wrapper bytes are reused.
- Queue claim alone does not spend an APNS attempt. After rate capacity is
  available, a bounded database guard revalidates authority and holds shared
  retention/lease/installation locks plus the job lock across the Apple call.
  The attempt is committed only after the APNS client has been invoked.
  Shutdown before invocation releases the claim with its count unchanged. A
  process or database crash after Apple receives the request but before the
  attempt/result transaction commits remains inherently ambiguous because
  APNS cannot participate in PostgreSQL. That bounded at-least-once window may
  duplicate a notification.
- A committed APNS success deletes the encrypted job directly and does not
  write a success aggregate. A normal non-success terminal path first commits a
  non-sendable final marker: the serialized APNS job is replaced by a one-byte
  tombstone, authority foreign keys are removed, and only the row identity,
  environment, fixed traffic/final-reason enums, bounded attempt count, and
  retention timestamps remain. The fixed reasons are terminal rejection,
  retry exhausted, TTL expired, safety invalidated, and material invalid. This
  is a payload-free recovery marker, not a payload-bearing DLQ.
- A second transaction writes the fixed terminal observation and deletes its
  final marker atomically. If that write fails, the marker remains
  non-sendable; claim recovery retries completion, and the affected delivery
  path fails closed rather than deleting its only recovery evidence. The
  aggregate contains only UTC day/hour, environment, fixed traffic/outcome
  enums, a coarse attempt/lifetime band, and a saturating approximate count.
- Queue accepted/backpressure and local rate-delay/cancellation observations
  use the same allowlisted aggregate dimensions but are best effort; their
  absence is not delivery evidence. No aggregate distinguishes transient
  network failure from APNS 429 or 5xx, and the invalid-token path does not emit
  an invalid-token outcome. Those provider classes must not be inferred from
  retry-exhausted or TTL-expired cells. Crash/restart recovery of a stranded
  final marker and live Railway visibility of these cells remain
  **UNCONFIRMED** until exercised and recorded in sanitized evidence.
- An invalid-token response verifies that the failed token is still current,
  then disables the installation and deletes its live routes. If erasure
  temporarily fails, notification content is removed before a content-free
  erasure control retry. The same live process never resubmits that token after
  Apple classifies it invalid. A process crash before the conversion commits
  can lose that in-memory fact and replay the original job; this is part of the
  documented bounded at-least-once ambiguity.
- Invalid-token erasure runs in a deletion-only worker with no APNS client or
  credential dependency. It synchronously recovers available markers before
  retention readiness, continues while retention is unsafe, and remains active
  when `APNS_ENABLED=false`; the kill switch disables egress, not deletion
  authority. Its retry exponent is persisted independently from the three-call
  APNS ceiling and reaches the configured 30-second capped backoff.
- Queue capacity rejects new delivery with fixed backpressure. It never spills
  plaintext to another queue.
- Process, listener, APNS, retention, and erasure goroutine boundaries recover
  without serializing panic values. They emit only rate-limited fixed messages;
  affected readiness fails closed and egress stops.

## Retention and access controls

The bridge owns schema `hytch_push_vault` and its Go migrations. It never uses
modern-api Alembic.

- Active encrypted lease: at most 7 days from authenticated refresh.
- Encrypted delivery job: at most 15 minutes and three APNS attempts.
- Welcome authorization/budget: short-lived; hourly rotating destination
  pseudonym and at most one-hour budget retention; the 30-minute circuit is
  shared by all replicas in one environment but isolated between development
  and production; no payload log or payload-bearing DLQ.
- Raw provider IP: the application stores none. Railway/provider enforcement of
  the 24-hour ceiling must be verified separately.
- Encrypted backup: at most 7 days.
- Operational aggregate cells: at most 30 days; event volume uses a
  saturating Morris-style randomized count bucket, never an exact counter.
- Raw-vault access audit: at most 180 days.
- Deletion tombstone: 8 days.

Before starting any worker, secure startup read-only verifies an exact, clean
migration relation and version; the database-wide legacy-retirement marker;
the irreversible absence of all four legacy plaintext routing relations; the
exact marker trigger shapes and function bodies; hardened function
ACL/search-path state; no logical subscription for this database; and a
non-owner runtime role. Missing, stale, redirected, owner-run, replicated, or
contaminated state fails closed. Startup never applies migrations or deletes
legacy rows. It then enables only the deletion-only invalid-token worker,
establishes a safe retention deadline for the configured environment, reapplies
that environment's typed installation/route tombstones, and rechecks
retention. Only then does it start recurring retention, APNS workers, XMTP
listeners, and the API.

Within an activated secure vault, trusted delivery, retention, tombstone, and
incident-access queries are explicitly keyed to the configured environment,
and the audit purge entry point is literal-bound to one environment. The
runtime role still has base-table DML required by the bridge; those grants are
not PostgreSQL row-level isolation against a compromised credential or
arbitrary SQL. Never share one bridge database between development and
production. Physical environment separation is an activation prerequisite,
not an inference from the `environment` columns. The recurring sweep marks only
its configured environment's readiness unsafe before deletion work. While
unsafe, registration, route resolution, and new durable job creation fail
closed; revocation remains available.

### One-time legacy routing retirement

The first secure deployment requires a separately authorized, destructive
one-shot retirement. Do not run it as a startup hook and do not run it against
a database used by production, another environment, a legacy bridge, or any
unknown replica.

1. Read-only verify the exact Railway project, environment, service, PostgreSQL
   service, database identity, and active replica set. The target must be a
   dedicated dev bridge database with no legacy writer.
2. Disable API, listener, and every delivery mechanism. Drain and terminate
   every legacy database session, remove the legacy credential, prove this
   database has no logical-replication subscription, and verify
   `pg_event_trigger` contains no row whose `evtenabled` is not `D`. This
   event-trigger check must happen before migration DDL; the migration command
   repeats it read-only and aborts before reconciliation if it fails. Revoke
   every non-owner `CREATE` grant on `public`; the retirement function revokes
   the default public grant and rejects any remaining one. Take and verify a
   recoverable backup. Obtain explicit operator confirmation for this exact
   database and the four-relation deletion scope.
3. From the exact candidate image, run a separate private job with only
   `MIGRATION_DB_CONNECTION_STRING` and
   `/usr/bin/notifications-server --migrate-only`. This applies migrations and
   exits without starting an API, listener, worker, or delivery client. Do not
   configure this owner DSN on the bridge service.
4. Through the migration-owner connection, call
   `hytch_push_vault.activate_legacy_routing_retirement` with the exact literal
   `RETIRE LEGACY PLAINTEXT ROUTING FROM <verified-database-name>`. Do not
   compute or copy the database name from an unverified deployment context.
   The one-shot function validates the literal, rejects logical subscriptions
   and enabled event triggers, checks exact ordinary/permanent ownership, takes
   parent-first `ACCESS EXCLUSIVE` locks, and drops child-first without
   `CASCADE`. It verifies all four relations are absent, writes the immutable
   marker, and revokes public `CREATE` on `public`. A dependent object, owner
   mismatch, catalog anomaly, or any other error rolls back every drop and the
   marker transition together.
5. Create a distinct non-owner runtime credential. Grant it `CONNECT`,
   `USAGE` on `hytch_push_vault`, required DML on secure-vault tables, and
   read-only access to `schema_migrations` and the marker. On
   `access_audit`, grant only `SELECT, INSERT`; explicitly revoke
   `UPDATE, DELETE, TRUNCATE`, grant execution only on
   `purge_expired_access_audit_development()` for this dev runtime, explicitly
   revoke `purge_expired_access_audit_production()`, and do not grant direct
   execution on the trigger guard. The production runtime uses the inverse
   literal-bound grants. The retired legacy relations must remain absent.
   Explicitly revoke marker mutation, schema creation, retirement-function
   execution, role membership in the owner, replication, bypass-RLS, and
   ownership. Store only this restricted DSN as `DB_CONNECTION_STRING` on the
   bridge service.
6. Start the secure service and require the fixed schema and legacy-routing
   gates plus the exact append-only audit function/trigger/ACL gate to pass
   before proceeding. Once activated, migration 00008 refuses its own down path
   even if the marker has been tampered with, because any missing legacy
   relation proves the irreversible transition. Recovery requires a separately
   approved break-glass plan, not a routine rollback.

Never replace the one-shot function with an unconditional startup `TRUNCATE`,
`DELETE`, or `DROP`,
and never infer database isolation from the logical `BRIDGE_ENVIRONMENT`
value. If legacy and secure workloads must coexist, use separate
databases/schemas or first migrate an environment discriminator under a
separately reviewed plan.

Raw vault querying is disabled by default. When fully configured, the bridge
mounts the G8.7 path on its separate loopback-only listener: one independently
authenticated approver, a successful immediate content-free oversight
broadcast, an expiring role, a read-only transaction, and a coarse append-only
audit. Approval fails closed when the broadcaster is unavailable. The gate
requires an opaque ticket, a fixed hypothesis, and a bounded time window, and
exposes one typed target lookup rather than arbitrary SQL. Every request,
approval, audit, and typed raw lookup is restricted to the gate's configured
environment. Query parameters, raw values, and results never enter general
logs or tickets.

The database enforces audit append-only behavior: direct update and truncate
always fail, direct delete is unavailable to the runtime, and an exact
security-definer purge can delete only rows already outside the 180-day
window for its fixed environment. Secure startup attests the permanent table,
function bodies, trigger shapes, ownership, search paths, ACLs, and restricted
runtime grants. An owner can still alter DDL, so the owner credential remains
separate break-glass authority.

Code availability is not configuration evidence. Until the dev service has
the two independent digest-only actors, a working oversight destination, the
runtime grants above, and a successful private-tunnel exercise recorded in the
sanitized evidence file, operational incident access remains
**UNCONFIRMED**.

Railway documents daily volume backups retained for six days, which is within
the seven-day ceiling, but configuration evidence for this database is
**UNCONFIRMED**. Provider raw-IP behavior, external tombstone export/import,
and a destructive restore rehearsal are also **UNCONFIRMED** until the evidence
file records them. They block production, not this dev-only deployment.

### Restore procedure

Never point the bridge at a restored snapshot and enable the listener/APNS.

1. Restore into an isolated dev database with listener and APNS disabled.
2. Using the lookup root bound to that database and environment, import every
   typed installation/route tombstone newer than the snapshot from the controlled
   append-only record.
3. Run the mandatory tombstone reapplication gate. Then destroy or ignore every
   restored active-route data key and delete restored delivery jobs, Welcome
   authorizations, nonce state, route-key history, leases, and installation
   token ciphertext.
4. Rotate the active vault root-key version. Lookup-root replacement is
   deliberately rejected while the database remains bound: turn off all
   egress, prove every lookup-derived route/installation/history row is gone,
   and rebind only through a separately reviewed empty-vault maintenance
   procedure. Replacing the secret in place is a startup failure, not rotation.
5. Run migrations from the isolated owner job, reapply tombstones again, and
   run the retention sweep. Independently verify the immutable activation
   marker, exact marker trigger/function contract, absence of every retired
   relation, and absence of logical subscriptions. A snapshot with recreated
   legacy relations or a missing, redirected, or nonexact marker guard is
   contaminated: discard and re-restore it or use a separately approved
   break-glass retirement. Never down-migrate as routine recovery.
6. Start API-only under the restricted runtime role and require every device to
   foreground-register a fresh route
   key, nonce prefix, and monotonic route-key epoch.
7. Enable listener/APNS only after no restored route can resolve and the
   restore test is recorded.

The in-process reapplication gate is implemented; the external append-only
export/import and destructive restore rehearsal remain manual and
**UNCONFIRMED**. A normal process restart is not a restore.

## Deploy to Railway dev

1. Confirm the selected Railway project, environment, and service are exactly
   the dev bridge. Confirm the PostgreSQL service is the dedicated,
   legacy-retired dev database, APNS mode is `development`, and replica count is
   one.
2. Confirm all required variable names are present without displaying values.
3. Run every QA gate locally. GitHub-hosted Actions are not QA:

   ```bash
   ./dev/gen-sqlc
   VAULT_INTEGRATION_TESTS=1 go test -p 1 -count=1 ./...
   go vet ./...
   ./dev/build
   golangci-lint run --timeout=5m --config dev/.golangci.yaml
   ./dev/lint-shellcheck
   buf lint proto
   buf breaking proto \
     --against 'https://github.com/xmtp/example-notification-server-go.git#branch=main,subdir=proto'
   ./dev/integration v3-direct
   ./dev/integration v4-with-migrator
   docker build --platform linux/amd64 .
   docker build --platform linux/arm64 .
   ```

4. For the first secure deployment only, complete the separately authorized
   one-time legacy routing retirement above. Routine redeploys only verify its
   marker and the absence of all retired relations; they never delete data.
5. Deploy the exact committed source state. Record its commit and Railway
   deployment ID.
6. Require `/livez=200`, `/readyz=200`, and `/health/xmtp=200`.
7. Run the APNS sandbox proof below before directing another dev installation
   to the service.

## APNS sandbox proof

Use a dedicated dev installation and sanitized identifiers. Do not store the
device token, topic, route key, HMAC key, signed capability, or ciphertext in
the evidence file. Welcome steps remain blocked while
`BRIDGE_WELCOME_ENABLED=false`; enable them only after signed cross-repository
vectors and the A9 contract are acknowledged.

1. Submit one atomic replacement with at least two stitched DM topics and one
   suppressed Welcome topic. Record only HTTP status, lease count bucket, and
   UTC-hour bucket.
2. Preauthorize one exact Welcome, publish that exact envelope, and prove one
   silent APNS acceptance plus client sync/decryption.
3. Replay the same Welcome and prove zero additional APNS calls.
4. Publish a visible conversation from another installation with
   `shouldPush=true`; prove one APNS acceptance and one client decryption.
5. Publish a self-originated conversation with the exact-period HMAC; prove zero
   APNS calls.
6. Publish the control and ephemeral outer fixtures with `shouldPush=false`;
   prove zero APNS calls.
7. Exercise an 8192-byte Welcome and record that the serialized APNS payload is
   below 4096 bytes and accepted without 413.
8. Capture `/livez`, `/readyz`, and `/health/xmtp`.
9. Scan logs for denylisted raw values using ephemeral local needles; commit
   only pass/fail and fixed outcome classes.

State each result at its tested scope. Any device Notification Center,
decrypt/render, backup, provider-retention, crash-duplicate, V4, or multi-replica
behavior not exercised in this run is **UNCONFIRMED**, with the missing test
named.

Bridge-owned relabeled negative fixtures do not settle official codec
conformance. Capture official V3/V4 control and ephemeral envelopes from the
owning client/server tracks and rerun step 6 before claiming that scope.

## Diagnose a missing notification

Do not start by querying raw vault data.

1. Check `/livez`, `/readyz`, and `/health/xmtp`. XMTP `503` with liveness `200`
   is a dependency outage, not a process crash.
2. Confirm `APNS_ENABLED=true`, APNS sandbox mode/topic, listener type, and
   required secure variable presence. Inspect names only.
3. Confirm the atomic refresh returned success and included every stitched DM
   topic plus the suppressed Welcome topic.
4. Confirm policy/capability freshness and policy epoch. Adult state older than
   60 seconds and teen state older than 30 seconds is intentionally denied.
5. For a conversation, verify explicit `shouldPush=true`, a well-formed
   sender_hmac input, and an HMAC key for the envelope's exact 30-day period.
6. For a Welcome, verify exact preauthorization arrived before the stream,
   digest domain/version, one-use state, age policy, and circuit budget.
7. Inspect only the allowlisted aggregate outcomes: queue accepted or
   backpressure; local rate delayed or cancelled; and terminal rejected, retry
   exhausted, TTL expired, safety invalidated, or material invalid. Queue/rate
   observations are best effort, success has no aggregate, and invalid-token
   erasure has no invalid-token outcome. These cells cannot distinguish a
   transient network error from APNS 429 or 5xx. Use health/readiness plus
   deletion-only worker status; never copy or infer APNS identifiers or
   provider reasons.
8. Verify the job had not reached three attempts, 15 minutes, or its earlier
   lease/control expiry.
9. Use the single-approved, oversight-broadcast raw access path only when a
   specific hypothesis cannot be tested with safe aggregates—and only after
   the production blockers in the retention/access section are closed.

Expected missing notifications include false/unknown `shouldPush`, self-origin,
stale key period, expired authority, revoked/blocked state, duplicate Welcome,
teen Welcome, circuit-open Welcome, oversized foreground-sync requiring client
fetch, invalid token, and queue backpressure.

## Diagnose a spurious notification

A spurious push is a safety defect.

1. Set `APNS_ENABLED=false` on the dev bridge and redeploy the same revision.
   Confirm the listener remains available but APNS has zero calls.
2. Preserve only sanitized deployment ID, UTC-hour bucket, wrapper schema,
   fixed traffic class, and fixed outcome. Never capture payload, token, topic,
   digest, exact type/size/time, or identity.
3. Determine whether the outer `shouldPush` decision was explicit true or a
   bridge bypass occurred. The bridge cannot determine plaintext content or a
   sender.
4. Check for stale/same-epoch revoke replay, route-key/token rotation, duplicate
   queue claim, one-use Welcome consumption, and authorization fingerprint
   mutation.
5. Reproduce with a synthetic fixture and add a zero-APNS-call regression
   before re-enabling delivery.
6. If Apple accepted a job immediately before a crash, classify possible
   duplicate delivery as the documented at-least-once window; do not call it
   exactly-once.

## Rollback

1. Set `APNS_ENABLED=false` first if the rollback is caused by spurious egress.
2. Redeploy the immediately preceding known-good dev deployment. Do not roll
   back database migrations destructively; the down path is tested only for
   development migration verification. The append-only audit-barrier down
   migration refuses to run while any audit history exists.
3. Keep one replica and secure-vault mode. Never re-enable legacy plaintext
   registration or delivery.
4. Verify `/livez`, `/readyz`, `/health/xmtp`, atomic refresh, conversation
   positive, control/ephemeral negative, self-message negative, and Welcome
   single-use/size regressions.
5. Re-enable `APNS_ENABLED` only after the safe revision and negative fixtures
   are green.

## Secret and key rotation

- **APNS `.p8`:** create the replacement in Apple, update the Railway
  certificate/key ID together, deploy and prove sandbox acceptance, then revoke
  the old Apple key. Never log either key.
- **Authority Ed25519:** add the new public key ID alongside the old one in
  `BRIDGE_AUTHORITY_PUBLIC_KEYS_JSON`; deploy; switch the signer; wait for all
  old 60-second grants to expire; then remove the old public key.
- **Vault root key:** add a new version to
  `BRIDGE_VAULT_MASTER_KEYS_JSON`, set it active, and deploy while retaining old
  versions for reads. Client refresh writes current ciphertext under the new
  version. Do not remove an old root until no live row references it and the
  seven-day backup horizon plus tombstone window has elapsed.
- **Lookup root:** each environment has an independent database-bound lookup
  root commitment. An in-place secret replacement within an environment is
  deliberately rejected at startup because it would hide live history and
  tombstones. Turn off that environment's egress, drain and erase all of its
  lookup-derived installation, route, job, nonce, and history state, verify the
  environment is empty, then rebind under a separately reviewed maintenance
  procedure.
  Clients must return with a higher route-key epoch and a new route key. Never
  copy raw values to migrate them.
- **Route key:** the device increments `route_key_epoch` in an authenticated
  full replacement. The bridge resets nonce state only for the higher epoch and
  cancels queued ciphertext bound to the prior key.
- **API Bearer token:** the current bridge accepts one token, so rotation
  requires an ordered, brief fail-closed cutover with modern-api. Do not send
  the token through Mattermost or a ticket. A zero-downtime overlapping token
  ring is **UNCONFIRMED** and would require a versioned contract change.

Every rotation ends with the negative policy fixtures, sanitized log scan, and
health checks. Never rotate credentials as an unrecorded side effect of a
routine rollback.
