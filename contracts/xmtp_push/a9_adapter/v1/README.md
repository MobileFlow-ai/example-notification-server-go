# Hytch A9 modern-api to XMTP push-bridge conformance contract v1

Status: **normative contract artifact; implementation and activation are
blocked**.

This directory fixes the cross-repository A9 wire contract between
`modern-api`, which owns Hytch conversation and roster authority, and the XMTP
push bridge, which may route an opaque wake only while that authority is
current. Normative keywords **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
used as described by RFC 2119.

This contract does not authorize or claim any of the following:

- a modern-api A9 adapter implementation;
- a bridge A9 adapter implementation;
- bridge, APNS, or Railway deployment;
- database migration creation or activation;
- positive Welcome routing, subscription, correlation, or egress;
- client vectors or end-to-end proof.

Welcome remains hard-closed. Only XMTP MLS group-message topics are in scope.

## Repository state and activation hold

The modern-api A9 roster-authority work in PR #878 is an unlanded reference at
commit `4c88119bcf07b6c991734cb7cf29a64b7b89effa`. The `origin/dev` baseline used
to publish this contract is `b50d90b`; that baseline does not contain the PR
#878 A9 implementation. The bridge candidate is likewise fail-closed and must
not claim A9 implementation merely because it mirrors these artifacts. Its
reviewed provenance head is
`65f5c931815b49b1fe4365587a8eb3ec80d08377`; APNS and Welcome remain
hard-closed there.

Activation requires all of the following:

1. byte-identical copies of this directory committed in modern-api and the
   bridge repository;
2. both repositories validating every positive and negative vector;
3. a landed server implementation that derives each assertion from the
   serializably current A9 tuple and emits a durable, contiguous outbox stream;
4. a landed bridge implementation with the serializable vault CAS and
   pre-egress checks defined below;
5. root key pinning, online signing-key rotation, HMAC-key provisioning, and
   service-auth replay storage exercised in the target environment;
6. local lint, formatting, type-check, test, build, and migration-safety gates
   passing in both repositories; and
7. a separately authorized deployment and end-to-end gate.

Any missing item is an activation blocker, not permission to fall back to the
legacy static bearer or to infer authority from a subscription.

## Normative artifacts

The machine-readable schemas are normative for shape and scalar domains:

- `schemas/assertion.schema.json`
- `schemas/control_event.schema.json`
- `schemas/watermark.schema.json`
- `schemas/keyset.schema.json`
- `schemas/subscriptions_replace_request.schema.json`
- `schemas/result.schema.json`

`generate_vectors.py`, `vectors/positive.json`, `vectors/negative.json`,
`vectors/manifest.json`, and `SHA256SUMS` are normative for bytes and semantic
verdicts.

JSON Schema cannot prove decoded byte lengths, duplicate-key rejection,
canonical ordering, timestamp arithmetic, array ordering, signature validity,
commitment derivation, or cross-object equality. Implementations MUST perform
all semantic checks in this document in addition to schema validation.

If prose and a schema appear to disagree, the implementation MUST fail closed
and the contract must be versioned; it must not choose the more permissive
interpretation.

## Common scalar and JSON rules

All request and signed-object bodies use `application/json`, UTF-8 without a
BOM, and no trailing bytes. Parsers MUST reject:

- duplicate object member names at every depth;
- malformed or non-shortest UTF-8;
- unpaired Unicode surrogate code points;
- non-integer JSON numbers, negative zero, and integers outside the field's
  stated range;
- unknown fields;
- padded or non-canonical Base64url;
- timestamps that do not round-trip to the exact required spelling; and
- multiple JSON values or non-whitespace after the one allowed value.

The schemas close every object with `additionalProperties: false`.

The following lexical forms are exact:

| Name | Domain |
| --- | --- |
| `environment` | `dev` or `production` |
| canonical UUID | lowercase RFC 4122 hyphenated text |
| `b64u16` | unpadded Base64url of exactly 16 bytes; exactly 22 characters |
| `b64u32` | unpadded Base64url of exactly 32 bytes; exactly 43 characters |
| Ed25519 signature | unpadded Base64url of exactly 64 bytes; exactly 86 characters |
| Ed25519 key ID | `ed25519-sha256:` plus 64 lowercase hex characters |
| HMAC key ID | `hmac-sha256:` plus 64 lowercase hex characters |
| millisecond timestamp | valid UTC RFC 3339 `YYYY-MM-DDTHH:MM:SS.mmmZ`; exactly 24 ASCII characters |
| safe integer | JSON integer from 0 through `9007199254740991` |

An Ed25519 key ID is
`"ed25519-sha256:" || lowerhex(SHA-256(raw_public_key_32))`. An HMAC key ID is
`"hmac-sha256:" || lowerhex(SHA-256(key_32))`. A digest or commitment exposed
as `b64u32` is `base64url_no_pad(raw_32)`.

UUIDs enter binary framing as the 16 RFC 4122 network-order bytes represented
by their canonical text. Integers enter binary framing as unsigned big-endian
values of the stated width. `u8len(x)` is one length octet followed by `x`;
`u16len(x)` is a two-octet unsigned big-endian length followed by `x`. A frame
whose payload exceeds its length type is invalid.

## Canonical bytes and signatures

Signed objects are flat JSON objects. The signature input is not the received
wire spelling. A verifier:

1. parses with the strict rules above;
2. validates the corresponding schema and semantic rules;
3. removes only `signature_base64url` (or
   `root_signature_base64url` for a keyset);
4. serializes the remaining object with RFC 8785 JSON Canonicalization Scheme
   (JCS); and
5. verifies Ed25519 over the exact domain bytes followed immediately by those
   JCS bytes.

The domains, including their final NUL octet, are:

| Object | Signature domain |
| --- | --- |
| assertion | `Hytch A9 bridge assertion v1\x00` |
| control | `Hytch A9 bridge control v1\x00` |
| watermark | `Hytch A9 bridge control watermark v1\x00` |
| keyset | `Hytch A9 bridge keyset v1\x00` |

The assertion digest carried as `assertion_hash` is
`base64url_no_pad(SHA-256(JCS(complete_signed_assertion)))`; the complete
object includes `signature_base64url`.

All current v1 signed strings are ASCII and all numbers are integers, but an
implementation MUST use an RFC 8785 implementation rather than assuming that
ordinary sorted JSON is equivalent for future versions.

## Signed A9 assertion

`schemas/assertion.schema.json` defines the exact flat object. Its fixed
protocol is `hytch.a9-bridge-assertion`, `schema_version` is `1`, `audience` is
`hytch.xmtp-push-bridge.a9-control`, and `purpose` is
`conversation_message_push`.

The authority fields are:

- `environment`;
- `binding_id`, `installation_binding_id`, and `lease_id` as `b64u16`;
- `binding_version` and `stream_sequence` from 1 through the safe-integer
  maximum;
- `tuple_commitment`, `roster_commitment`, and `topic_binding` as `b64u32`;
- `tuple_commitment_key_id` and `roster_commitment_key_id` as HMAC key IDs;
- `conversation_generation` and `roster_version` from 1 through
  `2147483647`;
- `state`, fixed to `ACTIVE`;
- `topic_key_epoch` from 1 through `4294967295`;
- `issued_at` and `expires_at` in exact millisecond form; and
- `signature_algorithm`, fixed to `Ed25519`, `signing_key_id`, and
  `signature_base64url`.

`expires_at` MUST be later than `issued_at`, no more than 30 seconds after it,
and no later than the source `hytch.roster-lease` expiry. The lease and the
serializable source read MUST cover the same account incarnation, Hytch
conversation, generation, roster version, roster digest, and `ACTIVE` state
used in the commitments. Publication is forbidden if any member lineage,
generation, roster, transport claim, installation binding, key, clock, or
outbox prerequisite is unavailable or uncertain.

The assertion intentionally does not expose the account-incarnation UUID,
Hytch conversation UUID, raw roster digest, or raw XMTP transport identifier.
Those values remain modern-api authority inputs.

## XMTP group-topic resolver

Version 1 is pinned to the `xmtpd` topic representation at commit
`6ae509c61de37d000184b46106326139d85ef255`. For this contract, the modern-api
`transport_conversation_id` MUST be exactly 64 lowercase hex characters
representing a 32-byte XMTP MLS group ID:

```text
group_id_32 = lowerhex_decode(transport_conversation_id)
topic_bytes_33 = 0x00 || group_id_32
```

The `0x00` kind byte is the pinned `TopicKindGroupMessagesV1` representation.
The `topic_base64url` field in a subscription MUST decode to those exact
33 bytes and therefore has 44 unpadded Base64url characters. The schema
narrows `transport_conversation_id` to the exact 64-lowercase-hex group
identifier. The semantic verifier MUST additionally reject non-canonical
Base64url or any resolved-byte mismatch.

No V3 string parsing, slash trimming, Unicode normalization, case folding,
Welcome kind, or alternate xmtpd topic encoding is permitted. A future xmtpd
representation change requires a new version and vectors.

## Keyed commitments

Every production commitment key is an independently random 32-byte secret.
Keys for roster, tuple, and topic purposes MUST be distinct. Raw keys never
appear in a signed object, response, log, metric, trace, analytics event, or
general application table.

### Roster commitment

Modern-api retains the exact 43-character Base64url roster digest from its A9
authority. Let `roster_digest_32` be its strict decoded bytes and `env` the
ASCII environment:

```text
roster_commitment =
  base64url_no_pad(
    HMAC-SHA256(
      K_roster,
      "Hytch A9 bridge roster v1\x00"
      || u8len(env)
      || roster_digest_32
    )
  )
```

`roster_commitment_key_id` identifies `K_roster`. The bridge receives the
commitment, never the digest. The raw digest may exist only in modern-api's
serializable authority transaction and in its authority-owned storage.

### Topic binding

Let `topic_bytes_33` be the exact resolver output:

```text
topic_binding =
  base64url_no_pad(
    HMAC-SHA256(
      K_topic[environment, topic_key_epoch],
      "Hytch A9 bridge topic v1\x00"
      || u32be(33)
      || topic_bytes_33
    )
  )
```

The bridge computes this value from the provider topic bytes before lookup and
compares it in constant time. It MUST first require exactly 33 bytes and kind
byte `0x00`. No lookup on raw topic text is allowed.

### Tuple commitment

Let `account_uuid_16` and `conversation_uuid_16` be the modern UUIDs, not the
legacy 64-lowercase-hex E2EE fence. Let `transport_id` be the exact 64-byte
lowercase ASCII identifier and let `roster_commitment_32` be the decoded
commitment:

```text
tuple_commitment =
  base64url_no_pad(
    HMAC-SHA256(
      K_tuple,
      "Hytch A9 push tuple v1\x00"
      || u8len(env)
      || account_uuid_16
      || conversation_uuid_16
      || u32be(conversation_generation)
      || u32be(roster_version)
      || roster_commitment_32
      || u8len("ACTIVE")
      || u16len(transport_id)
    )
  )
```

`tuple_commitment_key_id` identifies `K_tuple`. The bridge treats this as an
opaque equality value. It does not receive or reconstruct the raw tuple.

### Thirty-day topic-key periods and overlap

The topic-key period is
`floor(unix_seconds(issued_at) / 2592000)`, where `2592000` is exactly 30
24-hour days from the Unix epoch. `topic_key_epoch` MUST equal that period.
Modern-api MUST stop issuing with the previous period at the exact boundary.

The bridge may hold the current and immediately previous topic-binding keys.
The previous key may be used only to verify an already accepted, unexpired
assertion and MUST be erased 60 seconds after the boundary. A future-period,
older-period, missing, duplicated, or rollback key fails closed. The separate
`hmac_keys` inside vault route material use their explicit
`thirty_day_periods_since_epoch` and are not interchangeable with the A9 topic
binding key.

## Signer discovery, keyset, and rotation

Modern-api owns:

```text
GET /.well-known/hytch-xmtp-push-a9-keyset-v1.json
```

The bridge fetches only that configured private service-network HTTPS origin,
follows no redirect, and accepts only a body matching
`schemas/keyset.schema.json`. This discovery request intentionally does not
require the per-request service JWT: it bootstraps the `SERVICE_AUTH` public
key needed to verify that JWT. The out-of-band pinned root public key and the
keyset's valid root signature remain the trust anchor. The keyset is flat,
root-signed, and has protocol `hytch.a9-bridge-keyset`. It carries a monotonic
`keyset_sequence`, exact validity timestamps, online `keys`, and
`commitment_keys`.

Each online key has:

- `key_id`;
- `use`, either `A9_CONTROL` or `SERVICE_AUTH`;
- `public_key_base64url`, decoding to exactly 32 bytes;
- `not_before` and `not_after`; and
- `state`, either `SIGN` or `VERIFY_ONLY`.

Each commitment-key descriptor has `purpose` (`ROSTER`, `TUPLE`, or `TOPIC`),
`key_id`, `topic_key_epoch`, `not_before`, and `not_after`. For `TOPIC`,
`topic_key_epoch` is an integer from 1 through `4294967295`; for `ROSTER` and
`TUPLE`, it is JSON `null`. The descriptor publishes identity and validity,
not secret key material. `root_signing_key_id`,
`root_signature_algorithm=Ed25519`, and `root_signature_base64url` complete
the keyset.

Secret commitment keys are provisioned out of band as records containing
`(environment, purpose, key_id, topic_key_epoch, key_32, not_before,
not_after)`, using the same integer-or-null rule. Each consumer recomputes
`key_id` from `key_32`, requires an equal root-signed metadata entry and
validity window, and rejects duplicate mappings. The discovery response alone
can never provision or recover a secret.

`keys` contains from two through four entries and exactly one `SIGN` entry for
each online use. `commitment_keys` contains from three through six entries and
from one through two entries for each purpose. `keys` MUST be ordered by
ASCII `(use, state, key_id)`. `commitment_keys` MUST be ordered by ASCII
`purpose`, then `topic_key_epoch` for `TOPIC`, then `not_before`, then
`key_id`. Array order is part of the signed bytes and JSON Schema does not
enforce these orderings.

The root public key and its key ID MUST be provisioned out of band and pinned
in the bridge. Root replacement is an explicit operational ceremony and is
not learned from this endpoint.

The bridge stores the greatest accepted `(environment, keyset_sequence)` and
its complete signed-object hash. A lower sequence, equal sequence with
different bytes, bad root signature, wrong environment, expired keyset,
an artifact that references an unknown key or uses a key outside that key's
validity window, or two `SIGN` keys for the same use is a hard uncertainty
state. It MUST stop egress. A future `VERIFY_ONLY` descriptor is allowed only
as the staged rotation described next; it cannot verify an artifact before
its `not_before`.

A new online key MUST appear as `VERIFY_ONLY` at least 24 hours before its
`not_before`, then become the sole `SIGN` key in a higher keyset. The old key
remains `VERIFY_ONLY` until 60 seconds after the last artifact it signed could
expire. Keysets MUST be refreshed at least every six hours and MUST have no
more than 24 hours of remaining validity when issued. An implementation may
refresh sooner but may not extend trust locally after keyset expiry.

## Service authentication and request binding

All modern-api to bridge endpoints use private TLS plus a one-use compact JWS
in `Authorization: Bearer <jwt>`. Static bearer authentication is not
conforming.

The JWT protected header is JCS:

```json
{"alg":"EdDSA","kid":"ed25519-sha256:<64-lowerhex>","typ":"JWT"}
```

The claims object contains exactly:

| Claim | Value |
| --- | --- |
| `iss` | `hytch-modern-api` |
| `sub` | `xmtp-push-a9-adapter` |
| `aud` | `hytch.xmtp-push-bridge.a9-control` |
| `environment` | request environment |
| `iat`, `nbf`, `exp` | integer Unix seconds |
| `jti` | canonical UUID |
| `method` | exact uppercase HTTP method |
| `path` | exact path, with no query |
| `request_sha256` | 64-character lowercase-hex SHA-256 of the exact request-body bytes |

The header and claims are independently JCS-serialized before normal compact
JWS Base64url encoding. The signing key must be a currently valid
`SERVICE_AUTH` key from the root-signed keyset. `exp - iat` MUST be from 1
through 60 seconds, `nbf` MUST be no earlier than `iat - 5` and no later than
`iat`, and permitted clock skew is at most five seconds. The positive vector
fixes `nbf = iat - 1`. The bridge atomically consumes `(environment, jti)`
until `exp + 5 seconds`. A replay, method/path/body mismatch, query string,
unknown key, or unavailable replay store is rejected before schema
processing.

Requests MUST send the JCS spelling of the complete request object so
`request_sha256` is deterministic.

## Signed control stream

Modern-api sends a signed `schemas/control_event.schema.json` object to the
bridge-owned endpoint:

```text
POST /internal/v1/xmtp-push/a9-authority:apply
```

The object has protocol `hytch.a9-bridge-control` and contains:

- the fixed control audience and environment;
- a canonical UUID `idempotency_key`;
- `installation_binding_id` and `sequencer_epoch` as `b64u16`;
- `stream_sequence` and `expected_previous_sequence`;
- `binding_id`, `binding_version`, and `expected_binding_version`;
- `action`, `UPSERT` or `REVOKE`;
- `assertion`, a signed assertion or `null`;
- `assertion_hash` as `b64u32`;
- `reason_code`; exact timestamps; and
- its Ed25519 signature fields.

`stream_sequence` and `binding_version` are positive safe integers.
`expected_previous_sequence` and `expected_binding_version` are nonnegative
safe integers. Exactly
`stream_sequence = expected_previous_sequence + 1` and
`binding_version = expected_binding_version + 1`. First creation therefore
uses expected values zero and versions one. `expires_at` MUST be later than
`issued_at` and no more than 30 seconds after it. The bridge MUST reject a
control at or after `expires_at`; an already committed revoke tombstone does
not expire with its transport object.

For `UPSERT`, `assertion` is required and `reason_code` is `null`. The embedded
assertion hash, environment, installation binding, binding ID/version, and
stream sequence MUST exactly match the control. For `REVOKE`, `assertion` is
`null` and `reason_code` is exactly one of `authority_revoked`,
`authority_expired`, or `authority_replaced`; `assertion_hash` identifies the
exact prior assertion being tombstoned while the control advances the binding
version.

Per `(environment, installation_binding_id, sequencer_epoch)`, the first event
has `stream_sequence=1` and `expected_previous_sequence=0`. Every later event
MUST increment by one and name the bridge's last accepted sequence. Events are
linearized in a serializable transaction.

The same idempotency key and identical signed bytes return `REPLAY`. Reuse
with different bytes is `CONFLICT` and marks the installation uncertain.
Ahead-of-stream input is `GAP`; stale non-identical input is `CONFLICT`. An
`UPSERT` across a gap MUST NOT mutate positive authority or advance the last
contiguous positive cursor; it atomically latches uncertainty. A
signature-valid, unexpired `REVOKE` whose binding version is higher than the
stored positive version MUST still win across a gap: in one transaction the
bridge persists the tombstone, cancels queued work, keeps the last contiguous
positive cursor unchanged, and latches uncertainty. It MUST NOT treat the
revoke as filling missing positive events or advance the positive cursor
through them. Denial wins. Missing storage, ambiguous commit, retry ambiguity,
overflow, or signer uncertainty is `INCONCLUSIVE`, never a successful
absence.

`REVOKE` wins over refresh and `UPSERT` at equal or older binding version,
even if it arrives concurrently. The bridge persists a terminal tombstone for
the revoked `(installation_binding_id, binding_id, binding_version,
assertion_hash)`, cancels queued work atomically, and will not resurrect it.
A replacement requires a new server-authorized binding/version and a new
assertion.

## Signed watermarks, gaps, and uncertainty

Modern-api sends `schemas/watermark.schema.json` to:

```text
POST /internal/v1/xmtp-push/a9-watermarks:apply
```

Its protocol is `hytch.a9-control-watermark`. It binds the environment,
installation binding, sequencer epoch, monotonic `watermark_sequence`,
`committed_through_stream_sequence`, `status`, `uncertainty_reason`, exact
timestamps, and signature.

`watermark_sequence` is a positive safe integer and
`committed_through_stream_sequence` is a nonnegative safe integer.

Modern-api emits a `CURRENT` watermark at least every ten seconds only while
one sequencer owns the stream, the durable outbox is contiguous through the
claimed sequence, all authority reads and writes are healthy, and the clock
and signing key are usable. Its `uncertainty_reason` is `NONE`; `expires_at`
MUST be later than `issued_at` and no more than 30 seconds after it. The
positive vector fixes the full 30-second interval.

On known uncertainty, modern-api SHOULD emit one signed `UNCERTAIN` watermark
when signing remains safe and then MUST stop `CURRENT` cadence. Its
`uncertainty_reason` is exactly one of `SOURCE_UNAVAILABLE`, `OUTBOX_GAP`,
`REPLICA_AMBIGUITY`, `OVERFLOW`, or `CLOCK_UNCERTAIN`. Silence also becomes
uncertainty when the last `CURRENT` watermark expires.

The bridge accepts a `CURRENT` watermark only if its sequence is monotonic,
its epoch matches, and it has accepted every control event from 1 through
`committed_through_stream_sequence`. A watermark cannot paper over a missing
event. After bootstrap, a new watermark sequence MUST equal the prior accepted
sequence plus one; an identical signed replay is harmless, while a jump
creates uncertainty. A claimed committed stream sequence ahead of local
contiguous state creates `GAP` and stops egress until the missing signed
controls are replayed in order. Epoch change, rollback, equal watermark
sequence with different bytes, expired watermark, or any `UNCERTAIN` status
stops egress.

Recovery from a sequencer-epoch change or any state whose continuity cannot
be proved requires a new unpredictable `sequencer_epoch`, fresh assertions
carried by controls in that epoch, and a full atomic subscription replacement.
The bridge MUST NOT infer continuity from an old assertion, binding ID,
generation, cursor, watermark, key overlap, or partially matching replacement.
Until the new-epoch controls and complete replacement commit together under
the vault CAS rules, the installation remains uncertain and egress stays
closed.

Restart, replica ambiguity, loss, overflow, unmatched provider traffic, and
retry ambiguity never map to a proved zero. Gate-8 proof observers expose only
`VALID_ZERO`, `VALID_ONE`, or `INCONCLUSIVE`; MULTIPLE and all uncertainty are
failure or `INCONCLUSIVE`, never `VALID_ZERO`.

## Subscription replacement and vault CAS

Modern-api sends `schemas/subscriptions_replace_request.schema.json` to the
bridge-owned endpoint:

```text
PUT /internal/v1/xmtp-push/subscriptions:replace
```

The request binds:

- protocol `hytch.a9-subscription-replace`, schema version, and environment;
- `installation_binding_id` and `sequencer_epoch`;
- `subscription_generation` and `expected_subscription_generation`;
- canonical UUID `idempotency_key`;
- the exact 64-lowercase-hex `legacy_installation_id`;
- the modern `account_incarnation_id` UUID;
- `apns_token_base64url`, decoding to exactly 32 bytes;
- `payload_schema`, fixed to `hytch_push_wrapper_v1`;
- `policy_control_base64url`, a canonical unpadded Base64url string of 2
  through 4096 characters whose decoded bytes must independently validate as
  the exact Gate-6 policy-control contract; and
- zero through 2048 complete subscription entries.

`subscription_generation` is a positive safe integer and
`expected_subscription_generation` is a nonnegative safe integer.

Each subscription binds:

- `binding_id`, `binding_version`, and `assertion_hash`;
- `topic_binding` and `topic_key_epoch`;
- `route_key_epoch`;
- `topic_base64url` and `transport_conversation_id`;
- `route_key_base64url`, decoding to exactly 32 bytes;
- one through three route HMAC keys, each with
  `thirty_day_periods_since_epoch` and a 32-byte `key_base64url`; and
- `receive_capability_base64url`, a canonical unpadded Base64url string of 2
  through 4096 characters whose decoded bytes must independently validate as
  the exact Gate-6 receive-capability contract.

The array is a complete replacement, not a patch. Before signing or sending,
modern-api sorts entries by the decoded 32-byte `topic_binding`, then decoded
`binding_id`; duplicate route CAS keys or binding IDs are invalid. JSON Schema
cannot enforce this order. Each entry's `hmac_keys` array is strictly
increasing by `thirty_day_periods_since_epoch`; duplicate periods are invalid.

The bridge linearizes the request in one serializable vault transaction locked
by `(environment, installation_binding_id)`. The route CAS key is:

```text
(installation_binding_id, topic_key_epoch, topic_binding)
```

The transaction performs these checks before mutation:

1. service JWT and request-body binding are valid and the `jti` is consumed;
2. schema, canonical encodings, topic resolver, ordering, and bounds are
   valid;
3. `expected_subscription_generation` equals the vault's current generation
   and `subscription_generation` equals it plus one;
4. the sequencer epoch is current and a non-expired `CURRENT` watermark covers
   every referenced assertion's stream sequence;
5. every `assertion_hash` resolves to an accepted, signature-valid,
   untombstoned, unexpired `ACTIVE` assertion for the same installation,
   binding, binding version, topic binding, and topic-key epoch;
6. no revoke, gap, uncertainty, expiry, key rollback, or queued stale work
   conflicts with the replacement; and
7. the Gate-6 policy and receive capability independently validate.

If all checks pass, the bridge encrypts raw ingress material, replaces the
installation's complete active subscription set, persists the new generation
and keyed authority references, tombstones/removes superseded rows, and
cancels superseded queued work in the same transaction. No assertion can be
paired with another installation or topic between validation and commit.

`schemas/result.schema.json` is the only response shape. It reports protocol
`hytch.a9-vault-cas-result`, environment, installation binding, sequencer
epoch, subscription generation, state (`ACTIVE`, `REVOKED`, or `UNCERTAIN`),
outcome (`APPLIED`, `REPLAY`, `STALE`, `GAP`, `CONFLICT`, or
`INCONCLUSIVE`), accepted stream sequence, and `idempotent_replay`.

`subscription_generation` and `accepted_stream_sequence` in the result are
nonnegative safe integers. `idempotent_replay` is true if and only if
`outcome` is `REPLAY`. `APPLIED` and `REPLAY` use HTTP 200; `STALE`, `GAP`,
and `CONFLICT` use HTTP 409; `INCONCLUSIVE` uses HTTP 503. A request rejected
before service authentication or strict parsing MUST use a fixed
content-free error and MUST NOT synthesize identifiers into a CAS result.

An identical replay returns `REPLAY` without mutation. Reusing an idempotency
key with different JCS bytes returns `CONFLICT`. A generation mismatch returns
`STALE`; a missing control returns `GAP`. Unavailable or ambiguous storage,
commit, clock, key, or authority returns `INCONCLUSIVE`. No negative outcome
advances the generation or creates a route.

`APPLIED` reports the committed state: `ACTIVE` for an accepted upsert or
replacement, `REVOKED` for a revoke, and `UNCERTAIN` for a committed
uncertainty latch. `REPLAY` reports the original result state. `STALE` reports
the unchanged current state. `GAP`, idempotency `CONFLICT`, and
`INCONCLUSIVE` report `UNCERTAIN`; they never report a proved absence.

## Privacy and persistence boundary

Raw roster digest, account/conversation tuple, XMTP topic, transport ID,
legacy installation ID, APNS token, route key, route HMAC keys, and receive
capability are sensitive.

Modern-api may use the raw roster tuple only in the serializable derivation
transaction. The bridge may hold the raw subscription ingress fields only in
request-scoped memory and inside the serializable vault call. At rest, the
bridge encrypts route material under the vault key hierarchy and persists only
keyed lookup values or encrypted ciphertext as already required by Gate 8.

General application storage, logs, metrics, traces, analytics, panic text,
dead-letter payloads, and fixed responses MUST contain none of the raw values.
Durable general-state references are limited to keyed commitments,
`assertion_hash`, binding/version identifiers, key epochs/IDs, monotonic
generations/sequences, fixed states/outcomes, and encrypted vault ciphertext.
Raw input must be zeroed or released promptly after the transaction.

## Pre-egress decision

For every provider envelope, the bridge recomputes the topic binding from the
exact provider topic bytes and evaluates:

```text
egress_allowed = gate6_allowed AND a9_current
```

`a9_current` is true only when all of these hold at one vault snapshot:

- the exact route CAS row is `ACTIVE`;
- the current installation and topic bindings match;
- the referenced assertion hash resolves to a valid signed `ACTIVE` assertion;
- assertion environment, installation, binding ID/version, topic binding,
  topic epoch, and route reference match;
- the assertion is not expired or tombstoned;
- every control through its stream sequence is contiguous;
- a non-expired `CURRENT` watermark in the same sequencer epoch covers it;
- the keyset and every referenced signing/commitment key are current;
- route ciphertext decrypts and the independent Gate-6 policy and receive
  capability allow this exact envelope; and
- no revoke, gap, uncertainty, expiry, or superseding generation is visible.

The check occurs immediately before durable enqueue and is repeated in the
same transaction that reserves or finalizes the egress job. Any false,
missing, stale, ambiguous, or unavailable input denies egress. A prior
subscription, successful refresh, cached assertion, or stale watermark is
never sufficient.

The emitted push remains a generic opaque wake. This contract grants no
Welcome path and no content-bearing notification.

## Vector obligations

The committed vector set fixes:

- all fixture UUIDs, identifiers, timestamps, Ed25519 seeds/public keys, HMAC
  keys, topic group ID, resolved 33-byte topic, and request bodies;
- exact JCS unsigned bytes and signature-input bytes for assertion, control,
  watermark, and keyset;
- exact signatures, key IDs, commitments, assertion hash, JWT protected
  header/claims/signing input/signature, and request-body hash for each of the
  three bridge-owned request endpoints;
- a positive ordered control plus watermark plus vault-CAS replacement; and
- root-signed online-signer transition/cutover keysets and old/new
  topic-key-epoch boundary assertions; and
- negative single-fault mutations or adversarial state contexts with fixed
  failure codes.

At minimum, negatives cover duplicate JSON keys; unknown fields; padded and
wrong-length Base64url; non-canonical UUID/timestamp; `development` instead of
`dev`; wrong signature domain; unknown, future, expired, and rollback keys;
roster/topic/tuple commitment mismatch; raw roster digest injection; wrong
topic kind/length/case; transport/topic mismatch; expired assertion;
UPSERT/REVOKE shape mismatch; idempotency-key reuse with different bytes;
stream gap/regression/overflow; watermark gap/rollback/expiry/uncertainty;
wrong installation/topic assertion pairing; subscription CAS staleness;
duplicate or unsorted subscriptions; revoke-versus-refresh race; service-JWT
replay/path/body mismatch; and unavailable/ambiguous vault commit.

Both implementations MUST reproduce the positive bytes exactly and reject
every negative with the stated fixed verdict. A vector pass proves only
contract-byte conformance. It is not deployment, APNS, Welcome, client, or
end-to-end evidence. In particular, the positive vector's decoded
`policy_control_base64url`, `receive_capability_base64url`, and
`gate6_independent_fixture_verdict` values are explicitly fixture-only slots.
They are not valid Gate-6 artifacts and do not prove Gate-6 or end-to-end
behavior.
