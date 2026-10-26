-- name: EnqueueNotificationEnvelope :exec
INSERT INTO notification_queue.notification_envelopes(listener, message_key, payload)
VALUES (sqlc.arg(listener), sqlc.arg(message_key), sqlc.arg(payload))
ON CONFLICT (listener, message_key) DO NOTHING;

-- name: RecordRejectedNotificationEnvelope :exec
INSERT INTO notification_queue.notification_envelopes(listener, message_key, payload, status, failure_class)
VALUES (sqlc.arg(listener), sqlc.arg(message_key), ''::bytea, 'dead', sqlc.arg(failure_class))
ON CONFLICT (listener, message_key) DO NOTHING;

-- name: ExpireNotificationEnvelopes :exec
UPDATE notification_queue.notification_envelopes
SET status = 'dead', payload = ''::bytea, failure_class = 'expired', lease_id = '', lease_until = '-infinity'
WHERE status = 'pending' AND lease_until < clock_timestamp()
  AND (created_at < clock_timestamp() - INTERVAL '24 hours' OR attempts >= 12);

-- name: ClaimNotificationEnvelope :one
UPDATE notification_queue.notification_envelopes AS e
SET attempts = e.attempts + 1, lease_id = sqlc.arg(lease_id), lease_until = clock_timestamp() + INTERVAL '90 seconds'
FROM (
    SELECT pending.id FROM notification_queue.notification_envelopes AS pending
    WHERE pending.listener = sqlc.arg(listener) AND pending.status = 'pending'
      AND pending.attempts < 12 AND pending.created_at >= clock_timestamp() - INTERVAL '24 hours'
      AND pending.next_attempt_at <= clock_timestamp() AND pending.lease_until < clock_timestamp()
    ORDER BY pending.next_attempt_at, pending.id
    FOR UPDATE SKIP LOCKED LIMIT 1
) candidate
WHERE e.id = candidate.id
RETURNING e.id, e.listener, e.message_key, e.payload, e.attempts, e.lease_id, e.recipients_prepared;

-- name: RenewNotificationLease :execrows
UPDATE notification_queue.notification_envelopes SET lease_until = clock_timestamp() + INTERVAL '90 seconds'
WHERE id = sqlc.arg(id) AND lease_id = sqlc.arg(lease_id) AND status = 'pending'
  AND lease_until > clock_timestamp();

-- name: FinishNotificationEnvelope :execrows
UPDATE notification_queue.notification_envelopes
SET status = sqlc.arg(status),
    payload = CASE WHEN sqlc.arg(status)::text = 'pending' THEN payload ELSE ''::bytea END,
    next_attempt_at = clock_timestamp() + sqlc.arg(delay_seconds)::integer * INTERVAL '1 second',
    failure_class = sqlc.arg(failure_class), lease_id = '', lease_until = '-infinity'
WHERE id = sqlc.arg(id) AND lease_id = sqlc.arg(lease_id) AND status = 'pending'
  AND lease_until > clock_timestamp();

-- name: PrepareNotificationRecipients :exec
WITH prepared AS (
    UPDATE notification_queue.notification_envelopes AS prepared_envelope
    SET recipients_prepared = TRUE
    WHERE prepared_envelope.id = sqlc.arg(envelope_id) AND prepared_envelope.lease_id = sqlc.arg(expected_envelope_lease)
      AND prepared_envelope.status = 'pending' AND prepared_envelope.lease_until > clock_timestamp() AND NOT prepared_envelope.recipients_prepared
    RETURNING prepared_envelope.id
)
INSERT INTO notification_queue.notification_recipient_receipts(envelope_id, installation_id, lease_id, lease_until)
SELECT prepared.id, recipients.installation_id, '', '-infinity'::timestamptz
FROM prepared CROSS JOIN (SELECT DISTINCT unnest(sqlc.arg(installation_ids)::text[]) AS installation_id) recipients
ON CONFLICT (envelope_id, installation_id) DO NOTHING;

-- name: ClaimNotificationRecipient :one
UPDATE notification_queue.notification_recipient_receipts
SET lease_id = sqlc.arg(lease_id), lease_until = clock_timestamp() + INTERVAL '30 seconds'
WHERE envelope_id = sqlc.arg(envelope_id) AND installation_id = sqlc.arg(installation_id)
  AND status = 'pending' AND lease_until < clock_timestamp()
  AND EXISTS (SELECT 1 FROM notification_queue.notification_envelopes e WHERE e.id = sqlc.arg(envelope_id)
              AND e.lease_id = sqlc.arg(expected_envelope_lease)
              AND e.status = 'pending' AND e.lease_until > clock_timestamp())
RETURNING lease_id;

-- name: GetNotificationRecipientStatus :one
SELECT status FROM notification_queue.notification_recipient_receipts
WHERE envelope_id = sqlc.arg(envelope_id) AND installation_id = sqlc.arg(installation_id);

-- name: FinishNotificationRecipient :execrows
UPDATE notification_queue.notification_recipient_receipts AS receipt
SET status = sqlc.arg(status), failure_class = sqlc.arg(failure_class), lease_until = '-infinity'
WHERE receipt.envelope_id = sqlc.arg(envelope_id) AND receipt.installation_id = sqlc.arg(installation_id)
  AND receipt.lease_id = sqlc.arg(lease_id) AND receipt.status = 'pending' AND receipt.lease_until > clock_timestamp()
  AND EXISTS (SELECT 1 FROM notification_queue.notification_envelopes e WHERE e.id = sqlc.arg(envelope_id)
              AND e.lease_id = sqlc.arg(expected_envelope_lease)
              AND e.status = 'pending' AND e.lease_until > clock_timestamp());

-- name: PurgeNotificationReceipts :exec
DELETE FROM notification_queue.notification_envelopes
WHERE status != 'pending' AND created_at < clock_timestamp() - INTERVAL '7 days';

-- name: NotificationQueueHealth :many
SELECT listener, status, count(*)::bigint AS count, min(created_at)::timestamptz AS oldest_at
FROM notification_queue.notification_envelopes GROUP BY listener, status
UNION ALL
SELECT e.listener, ('recipient_' || r.status)::text AS status, count(*)::bigint AS count, min(e.created_at)::timestamptz AS oldest_at
FROM notification_queue.notification_recipient_receipts r JOIN notification_queue.notification_envelopes e ON e.id = r.envelope_id
GROUP BY e.listener, r.status
ORDER BY listener, status;

-- name: LockNotificationAdmission :exec
SELECT pg_advisory_xact_lock(830178462);

-- name: NotificationEnvelopeExists :one
SELECT EXISTS (SELECT 1 FROM notification_queue.notification_envelopes WHERE listener = sqlc.arg(listener) AND message_key = sqlc.arg(message_key));

-- name: NotificationPendingCapacity :one
SELECT count(*)::bigint AS count, COALESCE(sum(octet_length(payload)),0)::bigint AS bytes
FROM notification_queue.notification_envelopes WHERE status = 'pending';
