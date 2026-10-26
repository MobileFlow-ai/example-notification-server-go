-- Durable notification admission for the plaintext (non-vault) listener path.
-- A secure-vault database has retired the four legacy routing relations, so
-- the token version columns are added only where device_delivery_mechanisms
-- still exists. The queue tables are additive; secure vault mode never wires
-- them, and this migration grants nothing to any runtime role.
ALTER TABLE IF EXISTS device_delivery_mechanisms
    ADD COLUMN invalidated_at TIMESTAMPTZ,
    ADD COLUMN registration_version BIGINT NOT NULL DEFAULT 1;

CREATE TABLE notification_envelopes (
    id BIGSERIAL PRIMARY KEY,
    listener TEXT NOT NULL CHECK (listener IN ('v3', 'v4')),
    message_key TEXT NOT NULL CHECK (length(message_key) BETWEEN 1 AND 128),
    payload BYTEA NOT NULL CHECK (octet_length(payload) <= 2097152),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'complete', 'dead')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 12),
    lease_id TEXT NOT NULL DEFAULT '',
    lease_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
    failure_class TEXT NOT NULL DEFAULT '',
    recipients_prepared BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(listener, message_key)
);
CREATE INDEX notification_envelopes_pending_idx ON notification_envelopes(next_attempt_at, id) WHERE status = 'pending';
CREATE INDEX notification_envelopes_terminal_created_idx ON notification_envelopes(created_at) WHERE status <> 'pending';

CREATE TABLE notification_recipient_receipts (
    envelope_id BIGINT NOT NULL REFERENCES notification_envelopes(id) ON DELETE CASCADE,
    installation_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
    lease_id TEXT NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL,
    failure_class TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(envelope_id, installation_id)
);
