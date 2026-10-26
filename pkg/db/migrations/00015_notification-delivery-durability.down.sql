DROP TABLE notification_queue.notification_recipient_receipts;
DROP TABLE notification_queue.notification_envelopes;
DROP SCHEMA notification_queue;
ALTER TABLE IF EXISTS device_delivery_mechanisms
    DROP COLUMN invalidated_at,
    DROP COLUMN registration_version;
