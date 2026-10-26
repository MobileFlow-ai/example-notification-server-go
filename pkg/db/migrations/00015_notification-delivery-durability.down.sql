DROP TABLE notification_recipient_receipts;
DROP TABLE notification_envelopes;
ALTER TABLE IF EXISTS device_delivery_mechanisms
    DROP COLUMN invalidated_at,
    DROP COLUMN registration_version;
