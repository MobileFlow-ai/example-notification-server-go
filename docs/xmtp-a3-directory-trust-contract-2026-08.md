# A3 XMTP directory trust contract

This document pins the default-off bridge implementation consumed by
modern-api. It is a source and local-QA candidate only: it authorizes no
deployment, Railway variable, database migration, grant, or secret ceremony.

## Runtime boundary

Both routes are fixed children of the existing public `ApiServer`. Railway's
managed HTTPS is the future transport boundary; neither route belongs on the
A9 private listener. A route is absent unless its own enable flag is true, and
disabled configuration rejects dormant endpoint, bearer, or key material.
Association and witness use different canonical unpadded Base64url Bearer
values carrying 32 through 64 CSPRNG bytes. The parser rejects obvious
low-diversity fixtures, but only an audited secret-generation ceremony can
establish randomness; generated values go directly to the secret manager and
must not pass through shell history, logs, chat, or deployment evidence.

Every enabled request must be an exact `POST` target with no query, fragment,
or forced query, exact `Content-Type: application/json`, exact
`Accept: application/json`, unique JSON object keys, only the documented
fields, and a bounded body. Authentication, malformed requests, unknown
environments, overloaded bounds, and upstream ambiguity return only a fixed
non-enumerating error. Logs contain no identifiers, bodies, tokens, keys, or
signatures.

## Association reader

`POST /internal/v1/xmtp-directory/installation-associations:read` accepts
exactly `environment`, `inbox_id`, and `installation_id`. Both IDs are
lowercase 32-byte hex and the request environment must equal the bridge's
configured environment.

The production reader starts `IdentityApi.GetIdentityUpdates` at cursor zero,
requires exactly one inbox echo on every non-empty page, then advances to the
last strictly increasing sequence ID. The pinned API's zero-response result,
or one correctly echoed response with no updates, proves terminal completion.
Page, round, total-update, per-update protobuf, aggregate-history protobuf,
cumulative-validation-work, gRPC send/receive, and request-time caps turn
partial, oversized, or truncated history into unavailability. The only
reviewed production IdentityApi binding is the DEV environment at
`grpc.dev.xmtp.network:443` over TLS. Production association activation is
refused until its own endpoint is reviewed and pinned. ValidationApi remains
separately configurable; TLS is mandatory except for an explicit numeric
loopback ValidationApi target used in disposable local QA.
The gRPC dials disable environment proxy routing and retries; HTTP redirects
do not apply to these fixed gRPC clients.

Each update is independently authorized by calling
`ValidationApi.GetAssociationState` with the already-validated prefix as
`old_updates` and exactly one update as `new_updates`. This is deliberate:
validating the full history with an empty old prefix does not expose historical
removals in `StateDiff`. Every returned state must have unique, internally
consistent member mappings, and each returned diff must exactly equal the
member-set transition from the prior validated state. `revoked=true` only
when the target installation is absent from the final validated state and at
least one such incremental diff removed it. Current membership takes
precedence, so `associated` and `revoked` can never both be true.

The response contract is exactly:

```text
installation_id, associated_inbox_id, associated, revoked, fresh,
state_digest, position, observed_at_ms
```

`position` is the decimal final IdentityApi sequence ID.
`observed_at_ms` is the bridge time at which the complete IdentityApi read and
incremental ValidationApi pass finished, and `fresh` is true for that
successful bounded read. Identity-update timestamps are still required,
bounded, and nondecreasing, but they describe mutations rather than the age of
the authoritative observation; using them as freshness would permanently
break stable old associations. An empty history cannot currently produce a ValidationApi-backed
digest and timestamp, so it fails closed rather than inventing negative state.

### Association state digest v1

Raw AssociationState protobuf bytes are not stable because the producing
libxmtp implementation serializes hash collections in nondeterministic order.
The bridge therefore clones the validated final proto, rejects unknown proto
fields, verifies each `MemberMap.key` equals `MemberMap.value.identifier`,
rejects duplicate member keys and duplicate seen signatures, sorts members by
deterministic protobuf encoding of the key, and sorts seen signatures
lexicographically. It then deterministically marshals the canonical proto and
computes:

```text
SHA-256(
  "hytch.xmtp-association-state-digest.v1\0" ||
  uint64_be(canonical_proto_length) ||
  canonical_proto
)
```

The cross-language vector at
`contracts/xmtp_directory/a3_trust_v1_vectors.json` and the Go golden test pin
the exact result
`1c42de751b8ecf205152cbd92678c64e63aa3bb91a9e2a1101801361ab2082fb`
for its documented two-installation vector, invariant across reversed member
and signature order.

## Independent witness

`POST /internal/v1/xmtp-directory/tree-heads:cosign` accepts the strict flat
modern-api proposal:

```text
head, signature_payload_base64, sequencer_key_id,
sequencer_signature_base64, consistency_proof
```

There is no enabled-mode legacy fallback. The bridge reconstructs the exact
modern canonical head bytes as
`"hytch-directory-tree-head-v1\0" || uint32_be(json_length) || json`, where
JSON is compact, ASCII, and key-sorted. It requires byte equality with the
canonical Base64-decoded `signature_payload_base64`, selects a configured
Ed25519 sequencer key by `sequencer_key_id`, and verifies the sequencer
signature over those exact bytes. This closes the original proposal-auth gap;
TLS plus the dedicated bearer is still required.

The head is fixed to domain `hytch.directory.tree-head/v1`, protocol version
1, the configured environment, safe JSON integers, lowercase SHA-256 hashes,
and bounded age/skew. The consistency proof is checked with RFC 6962 node
hashing. The first head requires prior size zero, the SHA-256 empty root, and
an empty proof.

Migration 00014 stores the canonical head, exact proof, predecessor, root,
timestamp, witness key ID, and deterministic Ed25519 signature. A
transaction-scoped advisory lock serializes each environment. Exact replay
returns the original stored receipt; same-position conflicts, rollback, and
advances that do not name the exact accepted predecessor are rejected. Rows
are immutable, downgrade takes `ACCESS EXCLUSIVE` before checking emptiness,
and any durable witness state refuses downgrade. A witness seed change is not
an implicit key rotation: replay or advance fails closed unless the stored
witness key ID equals the current key. New proposals are checked for freshness
again after taking the per-environment database lock; exact stored replay
remains idempotent after the freshness window.

Before mounting the route, the bridge runs a read-only activation barrier. It
pins the PostgreSQL 13 and 18 constraint shapes and exact check expressions,
the table, primary key, columns/default, PUBLIC ACL, mutation-function source,
full shape of all three `ENABLE ALWAYS` statement triggers, absence of
policies/rules/event hooks, schema/table/function ownership relationship, and
exact authenticated-role privileges. The connection must authenticate as the
restricted LOGIN directly: an owner session using `SET ROLE` (including a
DSN `options=-c role=...`) is rejected. Changing `SESSION AUTHORIZATION` to
impersonate the runtime LOGIN is also rejected: the backend's immutable
authenticated-user OID and name must match the runtime role, so a session able
to reset to its owner identity is never accepted. Owner, superuser, database/schema/
migration-owner members (including set-only membership), grant-option
holders, roles with mutation privileges, and catalog drift all fail closed.

## Witness restricted-runtime grant ceremony

Migration 00014 grants nothing to a deployment-specific role and revokes
PUBLIC access. If witness activation is separately authorized, perform this
ceremony only from the owner-only migration job while every bridge replica is
stopped, after verifying the exact dedicated database, clean `14|false`
schema, candidate image, and non-owner runtime LOGIN. The deployed DSN must
authenticate as that LOGIN directly; it must not authenticate as an owner and
select this role through `SET ROLE`, a connection option, or `SET SESSION
AUTHORIZATION`:

```sql
\set ON_ERROR_STOP on
\set runtime_role bridge_runtime_dev

BEGIN;

-- The runtime role inherits PUBLIC privileges. Remove ambient object-creation
-- authority before granting its exact A3 reads and append-only insert.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

REVOKE ALL ON SCHEMA hytch_push_vault FROM :"runtime_role";
REVOKE ALL ON TABLE
    hytch_push_vault.a3_directory_witness_heads
FROM :"runtime_role";
REVOKE ALL ON FUNCTION
    hytch_push_vault.reject_a3_witness_mutation()
FROM :"runtime_role";
REVOKE ALL ON TABLE public.schema_migrations FROM :"runtime_role";

GRANT USAGE ON SCHEMA hytch_push_vault TO :"runtime_role";
GRANT SELECT, INSERT ON TABLE
    hytch_push_vault.a3_directory_witness_heads
TO :"runtime_role";
GRANT SELECT ON TABLE public.schema_migrations TO :"runtime_role";

WITH assumable_roles AS (
    SELECT assumable_role.oid
      FROM pg_catalog.pg_roles AS assumable_role
     WHERE pg_catalog.pg_has_role(
               :'runtime_role', assumable_role.oid, 'MEMBER'
           )
),
runtime_role_record AS (
    SELECT role.oid, role.rolname
      FROM pg_catalog.pg_roles AS role
     WHERE role.rolname = :'runtime_role'
),
schema_migrations_relation AS (
    SELECT relation.*
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relname = 'schema_migrations'
)
SELECT
    pg_catalog.has_schema_privilege(
        :'runtime_role', 'hytch_push_vault', 'USAGE'
    ) AND pg_catalog.has_table_privilege(
        :'runtime_role',
        'hytch_push_vault.a3_directory_witness_heads',
        'SELECT'
    ) AND pg_catalog.has_table_privilege(
        :'runtime_role',
        'hytch_push_vault.a3_directory_witness_heads',
        'INSERT'
    ) AND pg_catalog.has_table_privilege(
        :'runtime_role', 'public.schema_migrations', 'SELECT'
    ) AND (
        SELECT pg_catalog.count(*) = 1 AND
               COALESCE(pg_catalog.bool_and(
                   migrations.relkind = 'r' AND
                   migrations.relpersistence = 'p' AND
                   NOT migrations.relispartition AND
                   NOT migrations.relhassubclass AND
                   NOT migrations.relhastriggers AND
                   NOT migrations.relhasrules AND
                   NOT migrations.relrowsecurity AND
                   NOT migrations.relforcerowsecurity AND
                   NOT EXISTS (
                       SELECT 1
                         FROM pg_catalog.pg_inherits AS inheritance
                        WHERE inheritance.inhrelid = migrations.oid OR
                              inheritance.inhparent = migrations.oid
                   ) AND
                   (
                       SELECT (
                                  (
                                      pg_catalog.current_setting(
                                          'server_version_num'
                                      )::pg_catalog.int4 >= 130000 AND
                                      pg_catalog.current_setting(
                                          'server_version_num'
                                      )::pg_catalog.int4 < 140000 AND
                                      pg_catalog.count(*) = 1 AND
                                      pg_catalog.count(*) FILTER (
                                          WHERE constraint_record.contype = 'n'
                                      ) = 0
                                  ) OR (
                                      pg_catalog.current_setting(
                                          'server_version_num'
                                      )::pg_catalog.int4 >= 180000 AND
                                      pg_catalog.current_setting(
                                          'server_version_num'
                                      )::pg_catalog.int4 < 190000 AND
                                      pg_catalog.count(*) = 3 AND
                                      pg_catalog.count(*) FILTER (
                                          WHERE constraint_record.contype = 'n'
                                      ) = 2
                                  )
                              ) AND
                              pg_catalog.count(*) FILTER (
                                  WHERE constraint_record.contype <> 'n'
                              ) = 1 AND
                              pg_catalog.count(*) FILTER (
                                  WHERE constraint_record.contype = 'p' AND
                                        constraint_record.conkey =
                                            ARRAY[1]::pg_catalog.int2[] AND
                                        constraint_record.convalidated AND
                                        NOT constraint_record.condeferrable AND
                                        NOT constraint_record.condeferred AND
                                        constraint_record.conislocal AND
                                        constraint_record.coninhcount = 0 AND
                                        constraint_record.connoinherit
                              ) = 1
                         FROM pg_catalog.pg_constraint AS constraint_record
                        WHERE constraint_record.conrelid = migrations.oid
                   ) AND
                   NOT EXISTS (
                       SELECT 1
                         FROM pg_catalog.pg_trigger AS trigger
                        WHERE trigger.tgrelid = migrations.oid
                   ) AND
                   NOT EXISTS (
                       SELECT 1
                         FROM pg_catalog.pg_policy AS policy
                        WHERE policy.polrelid = migrations.oid
                   ) AND
                   NOT EXISTS (
                       SELECT 1
                         FROM pg_catalog.pg_rewrite AS rewrite_rule
                        WHERE rewrite_rule.ev_class = migrations.oid
                   ) AND
                   (
                       SELECT pg_catalog.count(*) = 2 AND
                              COALESCE(pg_catalog.bool_and(
                                  attribute.attnotnull AND
                                  attribute.attidentity = '' AND
                                  attribute.attgenerated = '' AND
                                  NOT attribute.atthasdef AND
                                  attribute.attacl IS NULL AND
                                  attribute.attoptions IS NULL AND
                                  attribute.attcollation = 0 AND
                                  (
                                      (
                                          attribute.attnum = 1 AND
                                          attribute.attname = 'version' AND
                                          attribute.atttypid =
                                              'pg_catalog.int8'
                                                  ::pg_catalog.regtype
                                      ) OR (
                                          attribute.attnum = 2 AND
                                          attribute.attname = 'dirty' AND
                                          attribute.atttypid =
                                              'pg_catalog.bool'
                                                  ::pg_catalog.regtype
                                      )
                                  )
                              ), FALSE)
                         FROM pg_catalog.pg_attribute AS attribute
                        WHERE attribute.attrelid = migrations.oid
                          AND attribute.attnum > 0
                          AND NOT attribute.attisdropped
                   ) AND
                   NOT EXISTS (
                       SELECT 1
                         FROM pg_catalog.aclexplode(
                             COALESCE(
                                 migrations.relacl,
                                 pg_catalog.acldefault(
                                     'r', migrations.relowner
                                 )
                             )
                         ) AS privilege
                        WHERE privilege.grantee <> migrations.relowner
                          AND (
                              privilege.grantee <> runtime_role.oid OR
                              privilege.privilege_type <> 'SELECT' OR
                              privilege.is_grantable
                          )
                   )
               ), FALSE)
          FROM schema_migrations_relation AS migrations
          CROSS JOIN runtime_role_record AS runtime_role
    ) AND NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_subscription AS subscription
         WHERE subscription.subdbid = (
             SELECT database_record.oid
               FROM pg_catalog.pg_database AS database_record
              WHERE database_record.datname =
                    pg_catalog.current_database()
         )
    ) AND NOT EXISTS (
        SELECT 1
          FROM assumable_roles AS assumable_role
         WHERE pg_catalog.has_schema_privilege(
                   assumable_role.oid, 'public', 'CREATE'
               ) OR
               pg_catalog.has_schema_privilege(
                   assumable_role.oid,
                   'hytch_push_vault',
                   'CREATE'
               ) OR
               pg_catalog.has_schema_privilege(
                   assumable_role.oid,
                   'hytch_push_vault',
                   'USAGE WITH GRANT OPTION'
               ) OR
               pg_catalog.has_table_privilege(
                   assumable_role.oid,
                   'hytch_push_vault.a3_directory_witness_heads',
                   'SELECT WITH GRANT OPTION'
               ) OR
               pg_catalog.has_table_privilege(
                   assumable_role.oid,
                   'hytch_push_vault.a3_directory_witness_heads',
                   'INSERT WITH GRANT OPTION'
               ) OR
               pg_catalog.has_table_privilege(
                   assumable_role.oid,
                   'hytch_push_vault.a3_directory_witness_heads',
                   'UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
               ) OR
               pg_catalog.has_function_privilege(
                   assumable_role.oid,
                   'hytch_push_vault.reject_a3_witness_mutation()',
                   'EXECUTE'
               )
    ) AS a3_witness_runtime_acl_exact
\gset

WITH protected_owners AS (
    SELECT relation.relowner AS owner
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'hytch_push_vault'
       AND relation.relname = 'a3_directory_witness_heads'
    UNION
    SELECT routine.proowner
      FROM pg_catalog.pg_proc AS routine
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = routine.pronamespace
     WHERE namespace.nspname = 'hytch_push_vault'
       AND routine.proname = 'reject_a3_witness_mutation'
       AND routine.pronargs = 0
    UNION
    SELECT namespace.nspowner
      FROM pg_catalog.pg_namespace AS namespace
     WHERE namespace.nspname = 'hytch_push_vault'
    UNION
    SELECT relation.relowner
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relname = 'schema_migrations'
    UNION
    SELECT database_record.datdba
      FROM pg_catalog.pg_database AS database_record
     WHERE database_record.datname = pg_catalog.current_database()
)
SELECT
    role.rolcanlogin AND
    NOT role.rolsuper AND
    NOT role.rolreplication AND
    NOT role.rolbypassrls AND
    NOT role.rolcreatedb AND
    NOT role.rolcreaterole AND
    NOT EXISTS (
        SELECT 1
          FROM protected_owners
         WHERE pg_catalog.pg_has_role(
             :'runtime_role', protected_owners.owner, 'MEMBER'
         )
    ) AND NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_roles AS powerful_role
         WHERE (
                   powerful_role.rolsuper OR
                   powerful_role.rolreplication OR
                   powerful_role.rolbypassrls OR
                   powerful_role.rolcreatedb OR
                   powerful_role.rolcreaterole OR
                   powerful_role.rolname LIKE 'pg\_%' ESCAPE '\'
               )
           AND pg_catalog.pg_has_role(
               :'runtime_role', powerful_role.oid, 'MEMBER'
           )
    ) AS a3_witness_runtime_role_restricted
FROM pg_catalog.pg_roles AS role
WHERE role.rolname = :'runtime_role'
\gset

\if :a3_witness_runtime_acl_exact
    \if :a3_witness_runtime_role_restricted
        COMMIT;
    \else
        ROLLBACK;
        \echo 'A3 witness runtime role restriction attestation failed'
        \quit 1
    \endif
\else
    ROLLBACK;
    \echo 'A3 witness runtime ACL attestation failed'
    \quit 1
\endif
```

The witness seed is distinct from A9, A10, sequencer, and vault material. It
must be exactly 32 bytes in an absolute, stable, owner-readable regular file
with no group/world permissions or execute bits. The bridge refuses symlinks,
symlinked ancestors, writable direct parent directories, file or parent inode
replacement, size changes, and noncanonical sequencer key JSON. Runtime
activation independently reruns the catalog/role barrier above; the ceremony
query is not a substitute for that enforcement. In particular, the owner-side
ceremony cannot prove the runtime DSN's authenticated identity. The first
runtime startup must connect with the actual restricted LOGIN and pass the
source barrier's immutable `pg_stat_activity.usesysid`/name check; an owner
session impersonating it will fail. Bearer,
seed, public-key configuration, and signatures must never be pasted into
Mattermost, logs, QA output, or deployment evidence.
