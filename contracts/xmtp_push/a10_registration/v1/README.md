# Hytch authenticated push registration contract v1

Status: **dormant handler implemented; durable runtime wiring and activation are blocked**.

This artifact specifies the public client-to-bridge registration exchange for
one XMTP installation. It does not change any byte in
`contracts/xmtp_push/a9_adapter/v1/`, does not remove the APNS hard-close, and
does not enable a runtime route.

## Required keyset extension

The current root-signed A9 keyset cannot safely authorize this credential. Its
validator admits only `A9_CONTROL` and `SERVICE_AUTH`, and `SERVICE_AUTH` is a
private modern-api-to-bridge request credential. Reusing that key for a public
client credential would collapse two trust domains.

The smallest safe extension is a separate, root-signed discovery document at
`/.well-known/hytch-xmtp-push-registration-keyset-v1.json` with protocol
`hytch.xmtp-push.registration-keyset`, schema version 1, and exactly one active
online use named `A10_REGISTRATION`. It uses the already provisioned root pin,
but has an independent online key and rotation history. The existing A9
keyset endpoint, schema, vectors, validator, and signed bytes stay unchanged.

The bridge must not mount the registration route until it has a durable,
root-verified, current A10 keyset manager. Keyset uncertainty, rollback,
equal-sequence/different-bytes, missing key, wrong use, or expiry fails closed.

## Route and authentication

The only route is:

```text
PUT /v1/xmtp-push/installations:register
```

It is default-off and separate from the private A9 TLS listener. The body is
the exact JCS encoding of:

```json
{"apns_token_base64url":"<1..256 opaque bytes>","apns_topic":"com.mobileflow.hytchdev","environment":"dev","installation_binding_id":"<16 bytes>","installation_id_base64url":"<32 bytes>","owner_binding":"<32 bytes>","payload_schema":"xmtp.encrypted.v4","protocol":"hytch.xmtp-push.registration-request","schema_version":1}
```

The APNS token is required for provider registration. Modern-api intentionally
returns the exact body only to the authenticated originating client so that it
can send those signed bytes to the independently configured bridge origin. The
bridge never echoes or logs the token or topic, and never persists plaintext
outside its encrypted vault. `owner_binding` is an opaque modern-api-derived
binding, not a raw account identifier.

`Authorization` carries `Bearer <compact JWS>`. The protected header contains
exactly `alg=EdDSA`, `kid`, and `typ=JWT`. Claims contain exactly:

- `iss=hytch-modern-api`
- `sub=xmtp-push-registration`
- `aud=hytch.xmtp-push-bridge.registration.v1`
- `environment`
- `installation_id_base64url`
- `installation_binding_id`
- `owner_binding`
- `apns_token_sha256` as 64 lowercase hex characters
- `apns_topic`
- integer Unix-second `iat`, `nbf`, and `exp`
- canonical lowercase RFC 4122 `jti`
- `method=PUT`
- `path=/v1/xmtp-push/installations:register`
- `request_sha256`, the lowercase SHA-256 of the exact request-body bytes

The signing key must be current for `A10_REGISTRATION`. `exp-iat` is 1 through
60 seconds. `nbf` is within five seconds before `iat` and no later than `iat`.
Clock skew is at most five seconds. The bridge verifies the complete token and
all request bindings before atomically consuming `(environment,jti)` until
`exp+5s`. Replay-store unavailability or commit ambiguity is unavailable, not
replay and not success.

The bridge then requires exact equality among the credential, body, configured
runtime environment, actual XMTP installation ID/binding, opaque owner binding,
APNS token digest, and an allowlisted environment-specific APNS topic. No
caller-supplied topic is trusted merely because it is signed.

## Fixed responses and privacy

Failures are content-free and `Cache-Control: no-store`:

| Condition | Status | Body |
| --- | --- | --- |
| malformed, bad signature, wrong binding/topic/environment, expired | 401 | `unauthorized` |
| proved replay | 409 | `replay` |
| keyset/replay/vault uncertainty | 503 | `unavailable` |
| success | 204 | empty |

Logs and metrics may contain only fixed verdict names and counts. They must not
contain the compact token, JTI, installation identifiers, owner binding, APNS
token or hash, APNS topic, request body, or signing key ID.

## Activation hold and implementation seam

The bridge now contains a strict default-off handler and sink interface. The
positive fixture reaches that handler, and every case in
`fixtures/negative.json` executes against its production guards. The handler
validates the separate A10 keyset against the existing out-of-band root pin;
it does not relax `ValidateKeyset` or reuse `SERVICE_AUTH`.

The route is not mounted by `main`, no APNS dependency is reachable, and the
durable A10 replay store remains an explicit wiring prerequisite. Activation
starts only after modern-api publishes the separately reviewed A10 keyset
contract, both repositories carry byte-identical fixtures, and a distinct
append-only A10 keyset/replay namespace plus encrypted-vault sink have passed
their database gates. It must not share an A9 replay namespace or remove the
APNS hard-close.
