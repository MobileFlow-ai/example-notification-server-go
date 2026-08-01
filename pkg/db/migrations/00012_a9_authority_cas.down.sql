-- Downgrade is permitted only while v12 is completely dormant. A9 authority
-- and queued A9 work are security state and must never be discarded by a
-- schema-version change.
LOCK TABLE
    hytch_push_vault.a9_accepted_keysets,
    hytch_push_vault.a9_online_key_descriptors,
    hytch_push_vault.a9_commitment_key_descriptors,
    hytch_push_vault.a9_keyset_state,
    hytch_push_vault.a9_service_jti_receipts,
    hytch_push_vault.a9_idempotency_receipts,
    hytch_push_vault.a9_installation_authority,
    hytch_push_vault.a9_watermarks,
    hytch_push_vault.a9_installation_gate6_bindings,
    hytch_push_vault.a9_control_events,
    hytch_push_vault.a9_assertions,
    hytch_push_vault.a9_bindings,
    hytch_push_vault.a9_binding_tombstones,
    hytch_push_vault.a9_subscription_routes,
    hytch_push_vault.subscription_leases,
    hytch_push_vault.delivery_jobs
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_accepted_keysets
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_online_key_descriptors
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_commitment_key_descriptors
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_keyset_state
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_service_jti_receipts
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_idempotency_receipts
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_installation_authority
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_watermarks
    ) OR EXISTS (
        SELECT 1
          FROM hytch_push_vault.a9_installation_gate6_bindings
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_control_events
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_assertions
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_bindings
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_binding_tombstones
    ) OR EXISTS (
        SELECT 1 FROM hytch_push_vault.a9_subscription_routes
    ) OR EXISTS (
        SELECT 1
          FROM hytch_push_vault.delivery_jobs
         WHERE a9_installation_binding_id IS NOT NULL
            OR a9_sequencer_epoch IS NOT NULL
            OR a9_subscription_generation IS NOT NULL
            OR a9_binding_id IS NOT NULL
            OR a9_binding_version IS NOT NULL
            OR a9_assertion_hash IS NOT NULL
            OR a9_assertion_stream_sequence IS NOT NULL
            OR a9_topic_key_epoch IS NOT NULL
            OR a9_topic_binding IS NOT NULL
            OR a9_route_key_epoch IS NOT NULL
            OR a9_keyset_sequence IS NOT NULL
            OR a9_keyset_hash IS NOT NULL
            OR a9_watermark_sequence IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot remove A9 authority CAS while A9 state exists';
    END IF;
END
$$;

DROP INDEX hytch_push_vault.delivery_jobs_a9_cancellation_idx;

ALTER TABLE hytch_push_vault.delivery_jobs
    DROP CONSTRAINT delivery_jobs_a9_route_fk,
    DROP CONSTRAINT delivery_jobs_a9_snapshot_shape_check,
    DROP COLUMN a9_watermark_sequence,
    DROP COLUMN a9_keyset_hash,
    DROP COLUMN a9_keyset_sequence,
    DROP COLUMN a9_route_key_epoch,
    DROP COLUMN a9_topic_binding,
    DROP COLUMN a9_topic_key_epoch,
    DROP COLUMN a9_assertion_stream_sequence,
    DROP COLUMN a9_assertion_hash,
    DROP COLUMN a9_binding_version,
    DROP COLUMN a9_binding_id,
    DROP COLUMN a9_subscription_generation,
    DROP COLUMN a9_sequencer_epoch,
    DROP COLUMN a9_installation_binding_id;

DROP TABLE hytch_push_vault.a9_subscription_routes;
DROP TABLE hytch_push_vault.a9_installation_gate6_bindings;
ALTER TABLE hytch_push_vault.subscription_leases
    DROP CONSTRAINT subscription_leases_a9_installation_pair_key,
    DROP CONSTRAINT subscription_leases_a9_installation_identity_fk,
    DROP CONSTRAINT subscription_leases_a9_identity_length_check,
    DROP COLUMN installation_identity;
DROP TABLE hytch_push_vault.a9_binding_tombstones;
DROP TABLE hytch_push_vault.a9_bindings;
DROP TABLE hytch_push_vault.a9_assertions;
DROP TABLE hytch_push_vault.a9_control_events;
DROP TABLE hytch_push_vault.a9_installation_authority;
DROP TABLE hytch_push_vault.a9_watermarks;
DROP TABLE hytch_push_vault.a9_idempotency_receipts;
DROP TABLE hytch_push_vault.a9_service_jti_receipts;
DROP TABLE hytch_push_vault.a9_keyset_state;
DROP TABLE hytch_push_vault.a9_commitment_key_descriptors;
DROP TABLE hytch_push_vault.a9_online_key_descriptors;
DROP TABLE hytch_push_vault.a9_accepted_keysets;

DROP FUNCTION hytch_push_vault.reject_unexpired_a9_jti_delete();
DROP FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
