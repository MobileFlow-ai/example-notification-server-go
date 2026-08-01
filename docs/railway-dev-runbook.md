# Hytch XMTP Push Bridge — Railway Dev Runbook

This runbook is internal and applies only to Railway `dev`, XMTP dev, and the
APNS sandbox. It does not authorize a production or public-cohort deployment.
All numeric limits below are provisional defaults pending measurement.

## Current deployment gate

This revision is **not yet authorized for A9 activation, APNS egress,
deployment, or database retirement**. The repository contains the mirrored A9
v1 conformance contract and dormant bridge runtime source, but local formatting,
compile, test, database, and integration QA for that source is
**UNCONFIRMED**. Source availability is not runtime, modern-api rollout,
migration, client-vector, or end-to-end evidence.

Welcome remains compiled hard-closed. The exact zero/one live provider-call
proof also requires the versioned Gate 8 amendment and recorded Security and
Privacy approval; current Gate 8 has no debug or internal-cohort exception.

Do not enable A9, activate any migration or the legacy-retirement function,
deploy this candidate, set `APNS_ENABLED=true`, or claim end-to-end readiness
until those blockers are closed and this section is updated in the same
reviewed change. Read-only Railway and database audits remain permitted.

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
  capped at 30 seconds. Welcome delivery is unavailable in this build.
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
  dev and enables the secure vault. This blocked audit configuration does not
  activate A9; dormant A9 mode requires a V4 listener and rejects V3. The
  configuration supplies no delivery service: `APNS_ENABLED` must remain
  false, and startup rejects true. The listener may consume XMTP for
  health/audit behavior with zero delivery services.
- Railway's deployment healthcheck is `GET /readyz`; Railway evaluates it while
  bringing up a deployment, not as a continuous restart probe. The checked-in
  restart policy responds to process exit. Continuous `/readyz` monitoring must
  be supplied externally.
- `GET /livez` is operator-visible process liveness and stays `200 ok` during
  an XMTP outage, avoiding an operator-induced restart loop.
- `GET /readyz` is aggregate readiness. It is `503 not_ready` when XMTP is
  disconnected, retention is unsafe, a configured APNS worker has stopped, or
  the deletion-only invalid-token worker is unavailable. This hard-closed build
  has no APNS worker to evaluate. When separately configured, private
  incident-access failure removes readiness and terminates the runtime. The
  dormant A9 path would additionally require its private listener plus a
  bounded durable-current keyset/TOPIC join; either failure is non-ready and
  fail-stop.
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

Required secure bridge variables for the checked-in, non-A9 blocked audit
configuration:

- `DB_CONNECTION_STRING`
- `HYTCH_SECURE_VAULT=true`
- `BRIDGE_ENVIRONMENT=dev`
- `BRIDGE_VAULT_MASTER_KEYS_JSON`
- `BRIDGE_VAULT_LOOKUP_KEY`
- `BRIDGE_AUTHORITY_PUBLIC_KEYS_JSON`
- `BRIDGE_API_BEARER_TOKEN`
- `BRIDGE_VAULT_LEASE_TTL_HOURS=168`
- `BRIDGE_WELCOME_ENABLED=false`
- `BRIDGE_TEEN_CONVERSATION_MODE=disabled`

`dev` is the signed A9/Gate 8 wire value. For upgrade continuity, the vault
continues to derive lookup identities, route-key history, and deletion
tombstones under its original internal `development` namespace while APNS
wrappers and signed authority use `dev`. This is deliberate and regression
tested: changing the internal namespace requires a separately reviewed
live-row and tombstone migration, not a configuration rename.

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

Welcome is hard-closed at four boundaries: startup rejects
`BRIDGE_WELCOME_ENABLED=true`, the production store constructor rejects an
enabled Welcome path, atomic refresh rejects every Welcome topic before
retention lookup or persistence, and the registration handler never attaches a
Welcome authorizer. The authenticated compatibility endpoint returns a fixed
unavailable response before reading its body. Dormant types and unit fixtures
are not a deployment contract. Turning off Welcome does not weaken conversation
policy checks or invalid-token deletion.

Teen XMTP conversations and inbound Welcomes remain disabled pending the
required safety review. The 30-second teen authority ceiling is implemented
for the future reviewed conversation enablement; it is not permission to turn
the mode on in this dev deployment.

Current blocked-state APNS setting:

- `APNS_ENABLED=false`

Do not load or use APNS provider credentials until A9 activation evidence and
the G8 amendment are approved in a reviewed change. The current binary also
rejects `APNS_ENABLED=true` at runtime startup, so a stale Railway variable
fails closed rather than enabling provider egress. Maintenance-only migration
and preflight modes cannot initialize APNS.

Post-gate APNS sandbox variables, after that startup rejection is removed in
the same reviewed implementation:

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

The dormant A9 configuration instead requires `LISTENER_TYPE=v4`, forbids
`BRIDGE_API_BEARER_TOKEN`, and adds the A9 names and restricted file mounts
listed below. Do not mix the two configuration sets.

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

## Dormant A9 v1 private authority runtime

The bridge contains a dormant source path for the mirrored A9 v1 contract. It
is not enabled by the checked-in Railway configuration and has not completed
local QA, migration activation, Railway deployment, client-vector, or
end-to-end proof. This section records the source-level configuration and
fail-closed behavior only.

### Required configuration

A future separately approved A9 exercise would require these exact names:

- `BRIDGE_A9_ENABLED=true`
- `BRIDGE_A9_KEYSET_ORIGIN`
- `BRIDGE_A9_PINNED_ROOT_PUBLIC_KEY`
- `BRIDGE_A9_PINNED_ROOT_KEY_ID`
- `BRIDGE_A9_TOPIC_COMMITMENT_KEYS_FILE_PATH`
- `BRIDGE_A9_PRIVATE_BIND=127.0.0.1:9443`
- `BRIDGE_A9_ALLOW_WILDCARD_PRIVATE_BIND=false`
- `BRIDGE_A9_TLS_CERTIFICATE_FILE_PATH`
- `BRIDGE_A9_TLS_PRIVATE_KEY_FILE_PATH`
- `BRIDGE_A9_KEYSET_REQUEST_TIMEOUT_SECONDS=10`
- `BRIDGE_A9_READ_HEADER_TIMEOUT_SECONDS=5`
- `BRIDGE_A9_READ_TIMEOUT_SECONDS=15`
- `BRIDGE_A9_WRITE_TIMEOUT_SECONDS=15`
- `BRIDGE_A9_IDLE_TIMEOUT_SECONDS=30`
- `BRIDGE_A9_MAX_HEADER_BYTES=16384`

It also requires secure-vault mode, the public API, and the XMTP V4 listener.
`BRIDGE_API_BEARER_TOKEN` must be absent. The deprecated
`BRIDGE_A9_TOPIC_COMMITMENT_KEYS_JSON` must be absent; inline TOPIC secrets are
rejected. When `BRIDGE_A9_ENABLED` is false, no A9 trust material or wildcard
opt-in may remain configured. Partial A9 configuration fails startup.

`BRIDGE_A9_KEYSET_ORIGIN` is an exact private HTTPS modern-api origin used only
for root-pinned keyset discovery. The root public key and its derived key ID
are out-of-band pins; they are not fetched from that origin.

The TOPIC key path must be absolute and identify one nonempty, stable regular
file no larger than 64 KiB. Symlinks, executable bits, special mode bits, and
all group/other permissions are rejected; use an owner-readable restricted
file such as mode `0400` or `0600`. The bridge checks identity and size across
open/read, consumes the file once during initialization, and clears the input
buffer. It does not accept the secret through an environment string.

The certificate and private-key paths must also be absolute, stable regular
files, each nonempty and no larger than 1 MiB. Both reject symlinks, executable
bits, and special mode bits. The certificate must be owner-readable and not
group/other-writable; the private key must be owner-readable with no
group/other permissions. Their input buffers are cleared after loading.

### Private transport and one-use service authentication

The A9 listener is a separate numeric-IP bind. It serves TLS 1.3 only, with
HTTP/1.1 and HTTP/2 over TLS; it has no plaintext or h2c path and discards
forwarding/proxy headers. This is server-certificate TLS, **not mTLS**. Client
authentication is the compact signed `SERVICE_AUTH` JWT/JWS in
`Authorization: Bearer ...`.

The one-use JWS binds the environment, uppercase HTTP method, exact path, and
request-body digest. Its signing key comes from the current root-pinned
keyset. The bridge durably consumes `(environment, jti)` before dispatch, so a
proved replay is rejected and replay-store unavailability or commit ambiguity
returns a fixed unavailable response. Unknown paths, wrong methods, non-TLS
requests, malformed authentication, non-JSON content, oversized bodies,
unknown JSON fields, and unavailable trust all fail closed with fixed,
non-secret responses.

The only private A9 routes are:

- `POST /internal/v1/xmtp-push/a9-authority:apply`
- `POST /internal/v1/xmtp-push/a9-watermarks:apply`
- `PUT /internal/v1/xmtp-push/subscriptions:replace`

Control is contiguous and revoke-wins; uncertainty and gaps are non-passing.
The watermark path records signed uncertainty rather than manufacturing a
passing zero. Subscription replacement is a full atomic replacement bound to
the exact root-verified keyset receipt and current TOPIC binding. Its vault CAS
and final route/pre-egress checks bind installation, topic epoch, topic
commitment, authority, watermark, and Gate 6 state. Raw `roster_digest` is not
a bridge persistence field. These statements describe the dormant source
contract, not activated adapter or delivery evidence.

There is no A9 Welcome route. Welcome remains rejected at its existing
boundaries, and every public Connect installation/subscription mutation
returns `failed_precondition` while A9 mode is selected. No replacement
authority handler is mounted on the public API mux; all A9 ingress belongs to
the dedicated private TLS listener.

### Bind isolation, readiness, and shutdown

The default bind is loopback. A numeric private, loopback, or link-local
address is accepted only with
`BRIDGE_A9_ALLOW_WILDCARD_PRIVATE_BIND=false`. An unspecified bind such as
`0.0.0.0:9443` is accepted only with the exact wildcard opt-in set true. That
opt-in is forbidden until independent Railway evidence proves the port has no
public domain or public TCP proxy, is reachable only through Railway's private
network, and remains protected by the one-use JWS boundary. The application
does not infer private-only ingress from a Railway variable or forwarded
header.

Initialization loads the TOPIC file, constructs the root-pinned trust manager,
and completes an initial remote/durable keyset refresh before exposing the
private listener, XMTP listener, or public API. A fetch, validation, durable
join, certificate, bind, or listener failure aborts startup. Aggregate
`/readyz` then performs a one-second read-only durable-current trust join and
requires the exact current-epoch TOPIC secret as well as private-listener
readiness.

The refresh worker starts before XMTP and the public API. It refreshes ahead of
the hard deadline and retries transient failures without extending authority.
A retained snapshot may be retryable only until its original deadline;
readiness, routing, and final pre-egress checks independently deny expired,
gapped, uncertain, or epoch-mismatched state. Loss of a usable refresh
deadline, private-listener failure, or a recovered private-handler panic
cancels the runtime. `/livez` remains process liveness and does not authorize
A9 or delivery.

On shutdown, refresh attempts are cancelled and private A9 ingress closes
first. The public API, XMTP listener, APNS worker if one is ever separately
authorized, and deletion-only erasure worker stop before the trust manager is
closed and its TOPIC material is released. Incomplete private-listener or
trust-manager shutdown is a runtime failure. None of this dormant wiring
authorizes migration activation, deployment, APNS, Welcome, or E2E claims;
local QA remains **UNCONFIRMED**.

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
- If the complete inline wrapper would exceed 4096 bytes, mode selection occurs
  before encryption and the bridge emits a foreground-sync wrapper with no XMTP
  envelope. A dormant 8192-byte Welcome unit regression preserves the former
  APNS 413 fix, but Welcome is not a runnable deployment path.
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
  while `APNS_ENABLED=false`; the current startup hard-close disables egress,
  not deletion authority. Its retry exponent is persisted independently from
  the three-call APNS ceiling and reaches the configured 30-second capped
  backoff.
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
- Dormant Welcome authorization/budget tables remain retention-bounded for
  migration compatibility; no runtime path can create Welcome authority in
  this build. The 30-minute circuit state is isolated between `dev` and
  `production`; no payload log or payload-bearing DLQ exists.
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
4. After migration and before activation, run the exact candidate binary's
   checked-in, read-only database preflight from the private job where
   `MIGRATION_DB_CONNECTION_STRING` is already loaded:

   ```bash
   /usr/bin/notifications-server --preflight-legacy-retirement
   ```

   For a local candidate built at `dist/server`, the equivalent guarded wrapper
   is `./dev/railway-legacy-retirement-preflight`. Set
   `BRIDGE_SERVER_BINARY` only to an explicitly verified candidate path. The
   connection string remains in the process environment and is never passed as
   an argument or printed.

   Require `preflight=pass` and record its safe boolean statuses plus the
   JSON-escaped current database name. The preflight requires migration 11
   clean, only its own client session, no logical subscription, no enabled
   event trigger, all four exact owner-held legacy tables, an empty activation
   marker with exactly the non-null `singleton BOOLEAN` and
   `activated_at TIMESTAMPTZ` columns, the exact activation/rejection function
   bodies and security flags, all three `ENABLE ALWAYS` marker triggers, and no
   named non-owner `CREATE` grant on `public`. The Go driver opens a
   `SERIALIZABLE READ ONLY` transaction; the mode never migrates, invokes the
   activation function, or starts a runtime surface. Any connection, query,
   catalog, close, or check failure emits only the fixed `preflight=fail`.

   This result is necessary but not sufficient for retirement. Railway UI
   evidence must separately prove the dev-only physical service and volume
   topology, a verified recoverable backup, no copied external DSNs or
   production contamination, and zero bridge replicas before activation.
5. Through the migration-owner connection, call
   `hytch_push_vault.activate_legacy_routing_retirement` with the exact literal
   `RETIRE LEGACY PLAINTEXT ROUTING FROM <verified-database-name>`. Do not
   compute or copy the database name from an unverified deployment context.
   The one-shot function validates the literal, rejects logical subscriptions
   and enabled event triggers, checks exact ordinary/permanent ownership, takes
   parent-first `ACCESS EXCLUSIVE` locks, rechecks the exact two-column marker
   shape, and drops child-first without `CASCADE`. It verifies all four
   relations are absent, writes the immutable marker, and revokes public
   `CREATE` on `public`. A dependent object, owner mismatch, catalog anomaly,
   or any other error rolls back every drop and the marker transition together.
6. Create a distinct non-owner runtime credential. Grant it `CONNECT`,
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
7. Start the secure service and require the fixed schema and legacy-routing
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

1. Require the exact A9 v1 mirror and dormant bridge source to pass the complete
   local QA matrix, then require separately reviewed modern-api authority
   rollout and cross-repository evidence for control watermarks, subscription
   binding, revoke ordering, and the final pre-egress check. The current bridge
   QA and all runtime/deployment evidence are **UNCONFIRMED**, so this step is
   not satisfied.
2. Confirm the selected Railway project, environment, and service are exactly
   the dev bridge. Confirm the PostgreSQL service is the dedicated,
   legacy-retired dev database, logical bridge environment is `dev`, APNS mode
   is `development`, and replica count is one.
3. Confirm all required variable names are present without displaying values.
4. Run every QA gate locally. GitHub-hosted Actions are not QA:

   Go database tests expect PostgreSQL on `localhost:25432` with the repository
   test credential. Either verify that compatible isolated test service is
   already ready or run `./dev/up` after reviewing its local Docker and Nix
   side effects. `./dev/up` can install or replace the pinned `xnet-cli` in the
   user's Nix profile. Do not point these tests at a shared or non-test
   database.

   ```bash
   git diff --check
   test -z "$(git ls-files -z '*.go' | xargs -0 gofmt -l)"
   ./dev/gen-sqlc
   git diff --exit-code -- pkg/db/queries
   VAULT_INTEGRATION_TESTS=1 go test -p 1 -count=1 ./...
   go vet ./...
   ./dev/build
   golangci-lint version | rg -q 'version 2\.9\.0([[:space:]]|$)'
   golangci-lint run --timeout=5m --config dev/.golangci.yaml
   ./dev/lint-shellcheck
   buf lint proto
   buf breaking proto \
     --against 'https://github.com/xmtp/example-notification-server-go.git#branch=main,subdir=proto'
   docker buildx inspect --bootstrap
   ./dev/integration v3-direct
   ./dev/integration v4-with-migrator
   docker build --platform linux/amd64 .
   docker build --platform linux/arm64 .
   ```

   Use exactly `golangci-lint` v2.9.0, matching the checked-in workflow.
   `./dev/lint-shellcheck` discovers tracked shell files, including
   `dev/railway-legacy-retirement-preflight`.
   Confirm the active Buildx builder reports both `linux/amd64` and
   `linux/arm64`; cross-platform builds require working QEMU/binfmt support
   where the Docker runtime does not provide it.

   The integration scripts tear down and recreate local Docker test state,
   including volumes, and their xnet setup can modify the user's Nix profile.
   Confirm those exact local resources are disposable before running either
   integration command.

   Before deployment, require
   `git status --porcelain=v1 --untracked-files=all` to be empty and rerun the
   gates against that committed state. If interim QA intentionally exercises a
   dirty tree, record the commit plus a digest of its full tracked patch and an
   explicit untracked-file manifest; that evidence is not deployable-source
   provenance and does not replace the clean committed rerun.

5. For the first secure deployment only, complete the separately authorized
   one-time legacy routing retirement above. Routine redeploys only verify its
   marker and the absence of all retired relations; they never delete data.
6. Deploy the exact committed source state. Record its commit and Railway
   deployment ID.
7. Require `/livez=200`, `/readyz=200`, and `/health/xmtp=200`.
8. Run the APNS sandbox proof below before directing another dev installation
   to the service. Current Gate 8 blocks that proof until the exact-purpose
   amendment is approved.

## APNS sandbox proof

This proof is currently **BLOCKED**. Gate 8 treats exact delivery frequency as
sensitive and has no debug exception; a renamed boolean still reveals whether
the provider was called zero or one time. Existing aggregates deliberately
cannot prove exact counts, and APNS acceptance does not prove client receipt,
sync, decryption, or rendering.

The proposed `G8-DP01` amendment must receive recorded Security and Privacy
approval before any live observer exists. It must be dev/APNS-sandbox only,
single-replica, volatile, short-lived, authenticated, default-off, and
purpose-bound to fixed synthetic scenarios. Its terminal result must
distinguish `VALID_ZERO`, `VALID_ONE`, and `INCONCLUSIVE`; restart, replica
ambiguity, `MULTIPLE`, retry, unmatched or unrelated provider traffic,
overflow, lost state, and every other observer failure are
`INCONCLUSIVE`—never a passing zero or one.

After that approval and the separately satisfied A9 activation gate, use a
dedicated synthetic dev installation and never persist the device token,
topic, route key, HMAC key, signed authority, ciphertext, observer handle, or
provider identifier:

1. Verify the exact deployment, one ready replica, autoscaling off, APNS
   sandbox, and an independently fresh A9 control watermark.
2. Submit one atomic replacement with at least two stitched DM topics and no
   Welcome topic.
3. Publish a visible conversation from another installation with
   `shouldPush=true`; require `VALID_ONE` provider acceptance and pair it with
   client-track sync/decryption evidence.
4. Publish a self-originated conversation with the exact-period HMAC; require
   `VALID_ZERO`.
5. Publish official control and ephemeral outer fixtures with
   `shouldPush=false`; require `VALID_ZERO` for each.
6. Capture `/livez`, `/readyz`, and `/health/xmtp`, then scan logs with
   ephemeral local needles and retain only approved fixed verdicts and coarse
   evidence fields.

Welcome positive, replay, and 8192-byte live steps are excluded. The compact
wakeup size regression remains unit-tested, but live Welcome proof is
impossible while the product-authority adapter and exact pre-import correlator
are unavailable.

State each result at its tested scope. Any device Notification Center,
decrypt/render, backup, provider-retention, crash-duplicate, V4, or multi-replica
behavior not exercised in this run is **UNCONFIRMED**, with the missing test
named.

Bridge-owned relabeled negative fixtures do not settle official codec
conformance. Capture official V3/V4 control and ephemeral envelopes from the
owning client/server tracks and rerun step 5 before claiming that scope.

## Diagnose a missing notification

In this hard-closed build, a missing APNS notification is the expected result.
`APNS_ENABLED=true` is rejected before runtime initialization, so diagnosis
ends by confirming the exact deployed revision and that startup rejection. Do
not add credentials, bypass the guard, or query raw vault data. The audit-only
checks that remain meaningful are `/livez`, `/readyz`, `/health/xmtp`, and
sanitized fixed logs.

The following procedure is reserved for a later reviewed post-gate revision
that removes the startup rejection and implements A9/Gate 8. It does not
authorize those actions on this revision:

1. Check `/livez`, `/readyz`, and `/health/xmtp`. XMTP `503` with liveness `200`
   is a dependency outage, not a process crash.
2. Confirm `APNS_ENABLED=true`, APNS sandbox mode/topic, listener type, and
   required secure variable presence. Inspect names only.
3. Confirm the atomic refresh returned success and included every stitched DM
   topic with no Welcome topic.
4. Confirm policy/capability freshness and policy epoch. Adult state older than
   60 seconds and teen state older than 30 seconds is intentionally denied.
5. For a conversation, verify explicit `shouldPush=true`, a well-formed
   sender_hmac input, and an HMAC key for the envelope's exact 30-day period.
6. A missing Welcome notification is expected in this build. Do not attempt to
   enable or bypass the hard-close to diagnose it.
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
stale key period, expired authority, revoked/blocked state, every Welcome,
oversized foreground-sync requiring client fetch, invalid token, and queue
backpressure.

## Diagnose a spurious notification

A spurious push attributed to this exact hard-closed build is first a deployment
provenance or configuration-integrity defect: the binary rejects APNS
activation and has no provider client. Preserve only sanitized revision and
deployment identifiers, set/keep `APNS_ENABLED=false`, and verify the running
image digest before any other diagnosis.

The following response procedure applies only to a later reviewed post-gate
revision that permits APNS egress:

1. Set `APNS_ENABLED=false` on the dev bridge and redeploy the same revision.
   Confirm the listener remains available but APNS has zero calls.
2. Preserve only sanitized deployment ID, UTC-hour bucket, wrapper schema,
   fixed traffic class, and fixed outcome. Never capture payload, token, topic,
   digest, exact type/size/time, or identity.
3. Determine whether the outer `shouldPush` decision was explicit true or a
   bridge bypass occurred. The bridge cannot determine plaintext content or a
   sender.
4. Check for stale/same-epoch revoke replay, route-key/token rotation, duplicate
   queue claim, and authorization fingerprint mutation.
5. Reproduce with a synthetic fixture and add a zero-APNS-call regression
   before re-enabling delivery.
6. If Apple accepted a job immediately before a crash, classify possible
   duplicate delivery as the documented at-least-once window; do not call it
   exactly-once.

## Rollback

1. Keep `APNS_ENABLED=false`. This revision already rejects true; a running
   provider client indicates that a different or modified revision is deployed.
2. Treat database migrations as monotonic. Do not blindly redeploy the
   immediately preceding binary: migration 11 advances the exact schema
   version and hardened activation-function hash, so the version-10 binary
   cannot start against it. Migration 11's security-monotonic down file also
   cannot make that binary compatible; it moves the version boundary without
   restoring the weaker function. Keep migration 11 applied and build a
   roll-forward application revert on the current schema/attestation contract,
   then run the full local QA matrix before deployment. If no tested
   schema-compatible build exists, keep the dev service and APNS egress off.
   Never use a destructive database down migration as incident rollback; the
   append-only audit-barrier down migration also refuses to run while any audit
   history exists.
3. Keep one replica and secure-vault mode. Never re-enable legacy plaintext
   registration or delivery.
4. Verify `/livez`, `/readyz`, `/health/xmtp`, atomic refresh, conversation
   positive, control/ephemeral negative, self-message negative, and the Welcome
   configuration hard-close.
5. Only a later reviewed revision that removes the startup hard-close may
   re-enable `APNS_ENABLED`, after its A9/Gate 8 activation and negative
   fixtures are green.

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
- **Legacy API bearer token:** this applies only to the non-A9 blocked audit
  configuration. It accepts one token, so rotation requires an ordered, brief
  fail-closed cutover with modern-api. Do not send the token through Mattermost
  or a ticket. A9 mode rejects this variable and uses one-use
  root-keyset-verified service JWS authentication instead.

Every rotation ends with the negative policy fixtures, sanitized log scan, and
health checks. Never rotate credentials as an unrecorded side effect of a
routine rollback.
