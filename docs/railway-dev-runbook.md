# Hytch XMTP Push Bridge — Railway Dev Runbook

This runbook is for the Hytch **development environment only**. It does not
authorize a production deployment.

## Runtime shape

- Run exactly **one Railway replica**. The process subscribes to the XMTP
  network-wide stream, so multiple listener replicas can duplicate delivery.
- Use the checked-in `railway.toml` start command. It runs the API and the V3
  listener against XMTP dev and enables APNS.
- Keep the health check on `/readyz`. Readiness is false until the listener is
  connected.
- Keep APNS in development mode and use the development app topic.

## Railway variable names

Configure secrets only in Railway's variable store. Never paste values into
source, this runbook, deployment output, screenshots, or tickets.

Required:

- `DB_CONNECTION_STRING`
- `APNS_P8_CERTIFICATE_BASE64`
- `APNS_KEY_ID`
- `APNS_TEAM_ID`
- `APNS_TOPIC`
- `APNS_MODE`

Operational:

- `LOG_ENCODING`
- `LOG_LEVEL`

Optional overrides:

- `API_PORT`
- `XMTP_GRPC_ADDRESS`
- `LISTENER_TYPE`
- `APNS_ENABLED`
- `HTTP_MAX_ATTEMPTS`
- `HTTP_INITIAL_RETRY_DELAY_MS`

Use only one APNS certificate input. Railway should use
`APNS_P8_CERTIFICATE_BASE64`; do not also set `APNS_P8_CERTIFICATE` or
`APNS_P8_CERTIFICATE_FILE_PATH`.

## Push policy and OFF semantics

The bridge reads XMTP's outer envelope metadata. It cannot inspect an encrypted
Hytch content type.

- Conversation delivery requires the outer XMTP `shouldPush` Boolean to be
  present and exactly `true`. Missing, malformed, false, and unknown inputs fail
  closed.
- Hytch sender codecs must set `shouldPush=false` on every control or ephemeral
  type. The bridge cannot decrypt the subtype and cannot correct a modified
  sender that lies with `shouldPush=true`; codec conformance and rollout kill
  switches are the supported controls.
- Visible SOS, location-share, and initial location-pulse messages remain
  eligible when their outer bit is exactly true. Gate 8's rare-cohort
  suppression applies to telemetry, not delivery.
- Welcome delivery is closed. The supported XMTP outer data does not provide
  the exact pre-decryption binding required by Gate 6.2, so this bridge exposes
  no correlator hook and sends no Welcome push. Link-enabled crews remain on the
  legacy path until a reviewed SDK or protocol change passes the positive
  correlator suite.
- To turn APNS delivery OFF for the whole dev bridge, remove the
  `--apns-enabled` start flag (and any equivalent enablement) and redeploy.
  Registration and subscriptions can remain intact. Verify OFF with the
  configured service state and a zero-attempt APNS smoke fixture; the bridge
  intentionally does not emit event-level delivery logs.

## Compact welcomes

Welcome payload builders intentionally omit the encrypted welcome envelope
across APNS, FCM (including its APNS projection), and HTTP. This preserves the
compact wakeup shape for a future protocol-supported correlator without
enabling Welcome egress today. Conversation payloads retain their encrypted
envelope for Notification Service Extension processing.

## Deploy to Railway dev

1. Confirm the selected revision contains the compact-welcome behavior and the
   no-push egress tests.
2. Confirm the service is the Railway **dev** service and replica count is one.
3. Confirm the variable names above are present in Railway. Inspect presence,
   not values.
4. Deploy the selected revision through Railway.
5. Wait for `/readyz` to return success and confirm the listener reports ready.
6. Run the verification checks below before directing a Hytch dev build to the
   bridge.

## Verification

- `go test -p 1 ./...` passes for the deployed revision.
- `/readyz` is successful after the listener connects.
- A visible conversation envelope with explicit `shouldPush=true` produces one
  dev APNS attempt for one subscribed test installation.
- Control and ephemeral fixtures with explicit `shouldPush=false` produce zero
  APNS attempts. Missing, malformed, and unknown outer policy inputs also
  produce zero attempts.
- Welcome fixtures produce zero egress attempts. Unit tests separately pin that
  the dormant APNS, FCM, and HTTP payload builders omit the encrypted Welcome.
- No event-level push outcomes, raw topics, device tokens, identifiers, message
  sizes, exact content types, or exact activity timing are written to logs or
  analytics. This tranche intentionally exposes no telemetry counters: the
  bridge lacks a trustworthy non-rare eligibility bit, and process-local
  unexported counters would not satisfy Gate 8.5.
- No production bundle topic, production APNS mode, or production XMTP endpoint
  is configured.

## Rollback

1. In Railway dev, redeploy the immediately preceding known-good deployment.
2. Keep the replica count at one.
3. Re-run `/readyz`, normal-message, no-push, and compact-welcome verification.
4. If rollback cannot restore a trustworthy state, turn APNS delivery OFF as
   described above and leave the API available for registration maintenance.

Never delete subscriptions or rotate credentials as part of a routine rollback.
Treat credential rotation as a separate incident procedure.
