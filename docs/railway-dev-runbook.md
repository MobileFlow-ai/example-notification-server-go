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

- An explicit `shouldPush=false` is a hard no-push decision. The dispatcher
  blocks every delivery service before egress, and APNS repeats the check as a
  defense in depth.
- Hytch must set `shouldPush=false` before publishing every control or ephemeral
  message. The bridge does not infer this from encrypted content.
- A missing `shouldPush` keeps the legacy behavior and is eligible for push.
- To turn APNS delivery OFF for the whole dev bridge, remove the
  `--apns-enabled` start flag (and any equivalent enablement) and redeploy.
  Registration and subscriptions can remain intact. Confirm the bridge reports
  no matching APNS delivery service before considering OFF verified.

## Compact welcomes

Welcome pushes intentionally omit the encrypted welcome envelope. The topic and
message kind wake the Notification Service Extension, which then synchronizes
the welcome from XMTP. This keeps the APNS payload below the 4 KiB limit.
Conversation pushes retain their encrypted envelope for Notification Service
Extension processing.

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
- A normal conversation envelope with `shouldPush=true` produces one dev APNS
  attempt for one subscribed test installation.
- A control or ephemeral fixture published with `shouldPush=false` produces
  zero APNS attempts. Verify with aggregate delivery counters or the focused
  test; logs intentionally omit device tokens, HMAC material, raw topics,
  message context, and APNS identifiers.
- A welcome for a subscribed test installation produces a payload below 4 KiB
  without an inline encrypted welcome.
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
