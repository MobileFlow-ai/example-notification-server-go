-- A9 remains fail-closed after this migration. In particular, this migration
-- does not backfill legacy rows, synthesize authority, or activate APNS.
--
-- Runtime serializable transactions must acquire locks in this order:
-- keyset state, installation authority, bindings (sorted by binding_id),
-- subscription routes (sorted by topic epoch/binding), then delivery jobs
-- (sorted by job_id). PostgreSQL constraints protect identity pairing, but
-- lock ordering is deliberately enforced by the application.

LOCK TABLE hytch_push_vault.delivery_jobs
IN ACCESS EXCLUSIVE MODE;

CREATE FUNCTION hytch_push_vault.reject_a9_immutable_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'A9 authority history is append-only';
END;
$function$;

REVOKE ALL
    ON FUNCTION hytch_push_vault.reject_a9_immutable_mutation()
    FROM PUBLIC;

CREATE FUNCTION hytch_push_vault.reject_unexpired_a9_jti_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF OLD.delete_after >= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'A9 service JWT replay receipt is still active';
    END IF;
    RETURN OLD;
END;
$function$;

REVOKE ALL
    ON FUNCTION hytch_push_vault.reject_unexpired_a9_jti_delete()
    FROM PUBLIC;

CREATE TABLE hytch_push_vault.a9_accepted_keysets (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    keyset_sequence BIGINT NOT NULL
        CHECK (keyset_sequence BETWEEN 1 AND 9007199254740991),
    signed_keyset_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(signed_keyset_hash) = 32),
    -- The complete signed JCS keyset is public verification material. No
    -- commitment secret or other raw authority input is stored here.
    signed_keyset_jcs BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(signed_keyset_jcs)
                BETWEEN 1 AND 262144
        ),
    root_signing_key_id BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(root_signing_key_id) = 32),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (environment, keyset_sequence),
    UNIQUE (environment, signed_keyset_hash),
    UNIQUE (
        environment,
        keyset_sequence,
        signed_keyset_hash
    ),
    CHECK (expires_at > issued_at),
    CHECK (expires_at <= issued_at + INTERVAL '24 hours')
);

CREATE TABLE hytch_push_vault.a9_online_key_descriptors (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    keyset_sequence BIGINT NOT NULL
        CHECK (keyset_sequence BETWEEN 1 AND 9007199254740991),
    key_use SMALLINT NOT NULL CHECK (key_use IN (1, 2)),
    key_state SMALLINT NOT NULL CHECK (key_state IN (1, 2)),
    key_id BYTEA NOT NULL CHECK (pg_catalog.octet_length(key_id) = 32),
    public_key BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(public_key) = 32),
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (
        environment,
        keyset_sequence,
        key_use,
        key_id
    ),
    UNIQUE (environment, keyset_sequence, key_id),
    FOREIGN KEY (environment, keyset_sequence)
        REFERENCES hytch_push_vault.a9_accepted_keysets(
            environment,
            keyset_sequence
        ),
    CHECK (not_after > not_before)
);

-- key_use: 1=A9_CONTROL, 2=SERVICE_AUTH.
-- key_state: 1=SIGN, 2=VERIFY_ONLY.
CREATE UNIQUE INDEX a9_online_keys_sole_sign_idx
    ON hytch_push_vault.a9_online_key_descriptors (
        environment,
        keyset_sequence,
        key_use
    )
    WHERE key_state = 1;

CREATE INDEX a9_online_keys_lookup_idx
    ON hytch_push_vault.a9_online_key_descriptors (
        environment,
        key_id,
        not_before,
        not_after
    );

CREATE TABLE hytch_push_vault.a9_commitment_key_descriptors (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    keyset_sequence BIGINT NOT NULL
        CHECK (keyset_sequence BETWEEN 1 AND 9007199254740991),
    purpose SMALLINT NOT NULL CHECK (purpose IN (1, 2, 3)),
    key_id BYTEA NOT NULL CHECK (pg_catalog.octet_length(key_id) = 32),
    topic_key_epoch BIGINT,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (
        environment,
        keyset_sequence,
        purpose,
        key_id
    ),
    UNIQUE (environment, keyset_sequence, key_id),
    UNIQUE (
        environment,
        keyset_sequence,
        purpose,
        key_id,
        topic_key_epoch
    ),
    FOREIGN KEY (environment, keyset_sequence)
        REFERENCES hytch_push_vault.a9_accepted_keysets(
            environment,
            keyset_sequence
        ),
    CHECK (not_after > not_before),
    CHECK (
        (
            purpose IN (1, 2) AND
            topic_key_epoch IS NULL
        ) OR (
            purpose = 3 AND
            topic_key_epoch IS NOT NULL AND
            topic_key_epoch BETWEEN 1 AND 4294967295
        )
    )
);

-- purpose: 1=ROSTER, 2=TUPLE, 3=TOPIC.
CREATE INDEX a9_commitment_keys_lookup_idx
    ON hytch_push_vault.a9_commitment_key_descriptors (
        environment,
        purpose,
        topic_key_epoch,
        key_id
    );

CREATE TABLE hytch_push_vault.a9_keyset_state (
    environment SMALLINT PRIMARY KEY CHECK (environment IN (1, 2)),
    keyset_sequence BIGINT NOT NULL
        CHECK (keyset_sequence BETWEEN 0 AND 9007199254740991),
    signed_keyset_hash BYTEA,
    state SMALLINT NOT NULL CHECK (state IN (1, 2)),
    uncertainty_reason SMALLINT NOT NULL
        CHECK (uncertainty_reason BETWEEN 0 AND 16),
    expires_at TIMESTAMPTZ,
    refreshed_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (
        environment,
        keyset_sequence,
        signed_keyset_hash
    )
        REFERENCES hytch_push_vault.a9_accepted_keysets(
            environment,
            keyset_sequence,
            signed_keyset_hash
        ),
    CHECK (
        (
            state = 1 AND
            keyset_sequence BETWEEN 1 AND 9007199254740991 AND
            signed_keyset_hash IS NOT NULL AND
            pg_catalog.octet_length(signed_keyset_hash) = 32 AND
            expires_at IS NOT NULL AND
            uncertainty_reason = 0
        ) OR (
            state = 2 AND
            uncertainty_reason BETWEEN 1 AND 16 AND
            (
                (
                    keyset_sequence = 0 AND
                    signed_keyset_hash IS NULL AND
                    expires_at IS NULL
                ) OR (
                    keyset_sequence
                        BETWEEN 1 AND 9007199254740991 AND
                    signed_keyset_hash IS NOT NULL AND
                    pg_catalog.octet_length(signed_keyset_hash) = 32 AND
                    expires_at IS NOT NULL
                )
            )
        )
    )
);

-- state: 1=CURRENT, 2=UNCERTAIN. No row is also fail-closed.

CREATE TABLE hytch_push_vault.a9_service_jti_receipts (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    jti UUID NOT NULL,
    jwt_expires_at TIMESTAMPTZ NOT NULL,
    delete_after TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (environment, jti),
    CHECK (delete_after = jwt_expires_at + INTERVAL '5 seconds'),
    CHECK (consumed_at <= delete_after)
);

CREATE INDEX a9_service_jti_delete_idx
    ON hytch_push_vault.a9_service_jti_receipts (
        environment,
        delete_after
    );

CREATE TABLE hytch_push_vault.a9_idempotency_receipts (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    idempotency_key UUID NOT NULL,
    operation_kind SMALLINT NOT NULL CHECK (operation_kind IN (1, 2)),
    installation_binding_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(installation_binding_id) = 16
        ),
    sequencer_epoch BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(sequencer_epoch) = 16),
    signed_request_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(signed_request_hash) = 32),
    result_outcome SMALLINT NOT NULL
        CHECK (result_outcome BETWEEN 1 AND 6),
    result_state SMALLINT NOT NULL CHECK (result_state IN (1, 2, 3)),
    subscription_generation BIGINT NOT NULL
        CHECK (
            subscription_generation BETWEEN 0 AND 9007199254740991
        ),
    accepted_stream_sequence BIGINT NOT NULL
        CHECK (
            accepted_stream_sequence BETWEEN 0 AND 9007199254740991
        ),
    created_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (environment, idempotency_key),
    UNIQUE (
        environment,
        idempotency_key,
        installation_binding_id,
        sequencer_epoch,
        operation_kind,
        signed_request_hash
    ),
    UNIQUE (
        environment,
        idempotency_key,
        installation_binding_id,
        sequencer_epoch,
        operation_kind,
        result_outcome,
        result_state,
        subscription_generation
    )
);

-- operation_kind: 1=CONTROL, 2=SUBSCRIPTION_REPLACE.
-- result_outcome: 1=APPLIED, 2=REPLAY, 3=STALE, 4=GAP,
-- 5=CONFLICT, 6=INCONCLUSIVE.
-- result_state: 1=ACTIVE, 2=REVOKED, 3=UNCERTAIN.

CREATE TABLE hytch_push_vault.a9_installation_authority (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    installation_binding_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(installation_binding_id) = 16
        ),
    sequencer_epoch BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(sequencer_epoch) = 16),
    contiguous_stream_sequence BIGINT NOT NULL
        CHECK (
            contiguous_stream_sequence
                BETWEEN 0 AND 9007199254740991
        ),
    subscription_generation BIGINT NOT NULL
        CHECK (
            subscription_generation BETWEEN 0 AND 9007199254740991
        ),
    state SMALLINT NOT NULL CHECK (state IN (1, 2, 3)),
    uncertainty_reason SMALLINT NOT NULL
        CHECK (uncertainty_reason BETWEEN 0 AND 32),
    watermark_sequence BIGINT,
    watermark_signed_hash BYTEA,
    watermark_committed_through BIGINT,
    watermark_status SMALLINT,
    watermark_uncertainty_reason SMALLINT,
    watermark_issued_at TIMESTAMPTZ,
    watermark_expires_at TIMESTAMPTZ,
    watermark_signing_key_id BYTEA,
    watermark_signing_key_use SMALLINT
        GENERATED ALWAYS AS (1::SMALLINT) STORED,
    watermark_keyset_sequence BIGINT,
    watermark_keyset_hash BYTEA,
    created_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (environment, installation_binding_id),
    FOREIGN KEY (
        environment,
        watermark_keyset_sequence,
        watermark_keyset_hash
    )
        REFERENCES hytch_push_vault.a9_accepted_keysets(
            environment,
            keyset_sequence,
            signed_keyset_hash
        ),
    FOREIGN KEY (
        environment,
        watermark_keyset_sequence,
        watermark_signing_key_use,
        watermark_signing_key_id
    )
        REFERENCES hytch_push_vault.a9_online_key_descriptors(
            environment,
            keyset_sequence,
            key_use,
            key_id
        ),
    CHECK (
        (
            state IN (1, 2) AND
            uncertainty_reason = 0
        ) OR (
            state = 3 AND
            uncertainty_reason BETWEEN 1 AND 32
        )
    ),
    CHECK (
        (
            watermark_sequence IS NULL AND
            watermark_signed_hash IS NULL AND
            watermark_committed_through IS NULL AND
            watermark_status IS NULL AND
            watermark_uncertainty_reason IS NULL AND
            watermark_issued_at IS NULL AND
            watermark_expires_at IS NULL AND
            watermark_signing_key_id IS NULL AND
            watermark_keyset_sequence IS NULL AND
            watermark_keyset_hash IS NULL
        ) OR (
            watermark_sequence IS NOT NULL AND
            watermark_sequence BETWEEN 1 AND 9007199254740991 AND
            watermark_signed_hash IS NOT NULL AND
            pg_catalog.octet_length(watermark_signed_hash) = 32 AND
            watermark_committed_through IS NOT NULL AND
            watermark_committed_through
                BETWEEN 0 AND 9007199254740991 AND
            watermark_status IS NOT NULL AND
            watermark_status IN (1, 2) AND
            watermark_uncertainty_reason IS NOT NULL AND
            watermark_uncertainty_reason BETWEEN 0 AND 5 AND
            watermark_issued_at IS NOT NULL AND
            watermark_expires_at IS NOT NULL AND
            watermark_expires_at > watermark_issued_at AND
            watermark_expires_at <=
                watermark_issued_at + INTERVAL '30 seconds' AND
            watermark_signing_key_id IS NOT NULL AND
            pg_catalog.octet_length(watermark_signing_key_id) = 32 AND
            watermark_keyset_sequence IS NOT NULL AND
            watermark_keyset_sequence
                BETWEEN 1 AND 9007199254740991 AND
            watermark_keyset_hash IS NOT NULL AND
            pg_catalog.octet_length(watermark_keyset_hash) = 32 AND
            (
                (
                    watermark_status = 1 AND
                    watermark_uncertainty_reason = 0 AND
                    watermark_committed_through <=
                        contiguous_stream_sequence
                ) OR (
                    watermark_status = 2 AND
                    watermark_uncertainty_reason BETWEEN 1 AND 5
                )
            )
        )
    ),
    CHECK (updated_at >= created_at)
);

-- installation state: 1=ACTIVE, 2=REVOKED, 3=UNCERTAIN.
-- watermark status: 1=CURRENT, 2=UNCERTAIN.

CREATE INDEX a9_installation_watermark_expiry_idx
    ON hytch_push_vault.a9_installation_authority (
        environment,
        watermark_expires_at
    )
    WHERE watermark_status = 1;

CREATE TABLE hytch_push_vault.a9_watermarks (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    installation_binding_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(installation_binding_id) = 16
        ),
    sequencer_epoch BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(sequencer_epoch) = 16),
    watermark_sequence BIGINT NOT NULL
        CHECK (watermark_sequence BETWEEN 1 AND 9007199254740991),
    signed_watermark_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(signed_watermark_hash) = 32),
    committed_through_stream_sequence BIGINT NOT NULL
        CHECK (
            committed_through_stream_sequence
                BETWEEN 0 AND 9007199254740991
        ),
    status SMALLINT NOT NULL CHECK (status IN (1, 2)),
    uncertainty_reason SMALLINT NOT NULL
        CHECK (uncertainty_reason BETWEEN 0 AND 5),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    signing_key_id BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(signing_key_id) = 32),
    signing_key_use SMALLINT
        GENERATED ALWAYS AS (1::SMALLINT) STORED,
    keyset_sequence BIGINT NOT NULL
        CHECK (keyset_sequence BETWEEN 1 AND 9007199254740991),
    keyset_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(keyset_hash) = 32),
    accepted_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (
        environment,
        installation_binding_id,
        sequencer_epoch,
        watermark_sequence
    ),
    UNIQUE (environment, signed_watermark_hash),
    UNIQUE (
        environment,
        installation_binding_id,
        sequencer_epoch,
        watermark_sequence,
        signed_watermark_hash,
        committed_through_stream_sequence,
        status,
        uncertainty_reason,
        issued_at,
        expires_at,
        signing_key_id,
        signing_key_use,
        keyset_sequence,
        keyset_hash
    ),
    FOREIGN KEY (environment, keyset_sequence, keyset_hash)
        REFERENCES hytch_push_vault.a9_accepted_keysets(
            environment,
            keyset_sequence,
            signed_keyset_hash
        ),
    FOREIGN KEY (
        environment,
        keyset_sequence,
        signing_key_use,
        signing_key_id
    )
        REFERENCES hytch_push_vault.a9_online_key_descriptors(
            environment,
            keyset_sequence,
            key_use,
            key_id
        ),
    CHECK (expires_at > issued_at),
    CHECK (expires_at <= issued_at + INTERVAL '30 seconds'),
    CHECK (
        (
            status = 1 AND
            uncertainty_reason = 0
        ) OR (
            status = 2 AND
            uncertainty_reason BETWEEN 1 AND 5
        )
    )
);

ALTER TABLE hytch_push_vault.a9_installation_authority
    ADD CONSTRAINT a9_installation_current_watermark_fk
    FOREIGN KEY (
        environment,
        installation_binding_id,
        sequencer_epoch,
        watermark_sequence,
        watermark_signed_hash,
        watermark_committed_through,
        watermark_status,
        watermark_uncertainty_reason,
        watermark_issued_at,
        watermark_expires_at,
        watermark_signing_key_id,
        watermark_signing_key_use,
        watermark_keyset_sequence,
        watermark_keyset_hash
    )
    REFERENCES hytch_push_vault.a9_watermarks(
        environment,
        installation_binding_id,
        sequencer_epoch,
        watermark_sequence,
        signed_watermark_hash,
        committed_through_stream_sequence,
        status,
        uncertainty_reason,
        issued_at,
        expires_at,
        signing_key_id,
        signing_key_use,
        keyset_sequence,
        keyset_hash
    );

ALTER TABLE hytch_push_vault.subscription_leases
    ADD COLUMN installation_identity BYTEA;

UPDATE hytch_push_vault.subscription_leases AS lease
   SET installation_identity = installation.installation_identity
  FROM hytch_push_vault.installation_states AS installation
 WHERE installation.installation_lookup = lease.installation_lookup
   AND installation.environment = lease.environment;

ALTER TABLE hytch_push_vault.subscription_leases
    ALTER COLUMN installation_identity SET NOT NULL,
    ADD CONSTRAINT subscription_leases_a9_identity_length_check
        CHECK (
            pg_catalog.octet_length(installation_identity) = 32
        ),
    ADD CONSTRAINT subscription_leases_a9_installation_identity_fk
        FOREIGN KEY (installation_identity)
        REFERENCES hytch_push_vault.installation_states(
            installation_identity
        )
        ON DELETE CASCADE,
    ADD CONSTRAINT subscription_leases_a9_installation_pair_key
        UNIQUE (lease_id, environment, installation_identity);

CREATE TABLE hytch_push_vault.a9_installation_gate6_bindings (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    installation_binding_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(installation_binding_id) = 16
        ),
    installation_identity BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(installation_identity) = 32),
    created_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (environment, installation_binding_id),
    UNIQUE (environment, installation_identity),
    UNIQUE (
        environment,
        installation_binding_id,
        installation_identity
    ),
    FOREIGN KEY (environment, installation_binding_id)
        REFERENCES hytch_push_vault.a9_installation_authority(
            environment,
            installation_binding_id
        )
);

-- This append-only table is the only durable bridge between A9's opaque
-- installation binding and Gate 6's stable keyed installation identity.
-- It deliberately has no FK to the mutable/deletable installation row:
-- retaining the keyed reverse-unique fence prevents a deleted identity from
-- being rebound to a different A9 installation. Neither side contains a raw
-- installation identifier.

CREATE TABLE hytch_push_vault.a9_control_events (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    installation_binding_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(installation_binding_id) = 16
        ),
    sequencer_epoch BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(sequencer_epoch) = 16),
    stream_sequence BIGINT NOT NULL
        CHECK (stream_sequence BETWEEN 1 AND 9007199254740991),
    expected_previous_sequence BIGINT NOT NULL
        CHECK (
            expected_previous_sequence
                BETWEEN 0 AND 9007199254740991
        ),
    binding_id BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(binding_id) = 16),
    binding_version BIGINT NOT NULL
        CHECK (binding_version BETWEEN 1 AND 9007199254740991),
    expected_binding_version BIGINT NOT NULL
        CHECK (
            expected_binding_version BETWEEN 0 AND 9007199254740991
        ),
    action SMALLINT NOT NULL CHECK (action IN (1, 2)),
    assertion_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(assertion_hash) = 32),
    reason_code SMALLINT NOT NULL CHECK (reason_code BETWEEN 0 AND 3),
    idempotency_key UUID NOT NULL,
    idempotency_operation SMALLINT NOT NULL
        DEFAULT 1
        CHECK (idempotency_operation = 1),
    signed_event_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(signed_event_hash) = 32),
    stream_is_contiguous BOOLEAN NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    signing_key_id BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(signing_key_id) = 32),
    signing_key_use SMALLINT
        GENERATED ALWAYS AS (1::SMALLINT) STORED,
    keyset_sequence BIGINT NOT NULL
        CHECK (keyset_sequence BETWEEN 1 AND 9007199254740991),
    keyset_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(keyset_hash) = 32),
    accepted_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (
        environment,
        installation_binding_id,
        sequencer_epoch,
        stream_sequence
    ),
    UNIQUE (environment, signed_event_hash),
    UNIQUE (
        environment,
        installation_binding_id,
        sequencer_epoch,
        stream_sequence,
        binding_id,
        binding_version,
        assertion_hash,
        action,
        reason_code
    ),
    FOREIGN KEY (environment, installation_binding_id)
        REFERENCES hytch_push_vault.a9_installation_authority(
            environment,
            installation_binding_id
        ),
    FOREIGN KEY (
        environment,
        idempotency_key,
        installation_binding_id,
        sequencer_epoch,
        idempotency_operation,
        signed_event_hash
    )
        REFERENCES hytch_push_vault.a9_idempotency_receipts(
            environment,
            idempotency_key,
            installation_binding_id,
            sequencer_epoch,
            operation_kind,
            signed_request_hash
        ),
    FOREIGN KEY (environment, keyset_sequence, keyset_hash)
        REFERENCES hytch_push_vault.a9_accepted_keysets(
            environment,
            keyset_sequence,
            signed_keyset_hash
        ),
    FOREIGN KEY (
        environment,
        keyset_sequence,
        signing_key_use,
        signing_key_id
    )
        REFERENCES hytch_push_vault.a9_online_key_descriptors(
            environment,
            keyset_sequence,
            key_use,
            key_id
        ),
    CHECK (stream_sequence = expected_previous_sequence + 1),
    CHECK (binding_version = expected_binding_version + 1),
    CHECK (expires_at > issued_at),
    CHECK (expires_at <= issued_at + INTERVAL '30 seconds'),
    CHECK (
        (
            action = 1 AND
            reason_code = 0
        ) OR (
            action = 2 AND
            reason_code BETWEEN 1 AND 3
        )
    ),
    -- A denial-winning gap record is valid only for REVOKE. It never advances
    -- the installation's contiguous positive cursor.
    CHECK (stream_is_contiguous OR action = 2)
);

-- action: 1=UPSERT, 2=REVOKE.
-- reason_code: 0=NONE, 1=AUTHORITY_REVOKED, 2=AUTHORITY_EXPIRED,
-- 3=AUTHORITY_REPLACED.

CREATE INDEX a9_control_binding_version_idx
    ON hytch_push_vault.a9_control_events (
        environment,
        installation_binding_id,
        binding_id,
        binding_version
    );

CREATE TABLE hytch_push_vault.a9_assertions (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    assertion_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(assertion_hash) = 32),
    installation_binding_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(installation_binding_id) = 16
        ),
    sequencer_epoch BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(sequencer_epoch) = 16),
    assertion_stream_sequence BIGINT NOT NULL
        CHECK (
            assertion_stream_sequence
                BETWEEN 1 AND 9007199254740991
        ),
    binding_id BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(binding_id) = 16),
    binding_version BIGINT NOT NULL
        CHECK (binding_version BETWEEN 1 AND 9007199254740991),
    lease_id BYTEA NOT NULL CHECK (pg_catalog.octet_length(lease_id) = 16),
    tuple_commitment BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(tuple_commitment) = 32),
    tuple_commitment_key_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(tuple_commitment_key_id) = 32
        ),
    tuple_commitment_purpose SMALLINT
        GENERATED ALWAYS AS (2::SMALLINT) STORED,
    roster_commitment BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(roster_commitment) = 32),
    roster_commitment_key_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(roster_commitment_key_id) = 32
        ),
    roster_commitment_purpose SMALLINT
        GENERATED ALWAYS AS (1::SMALLINT) STORED,
    topic_binding BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(topic_binding) = 32),
    topic_key_epoch BIGINT NOT NULL
        CHECK (topic_key_epoch BETWEEN 1 AND 4294967295),
    topic_commitment_key_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(topic_commitment_key_id) = 32
        ),
    topic_commitment_purpose SMALLINT
        GENERATED ALWAYS AS (3::SMALLINT) STORED,
    conversation_generation INTEGER NOT NULL
        CHECK (conversation_generation BETWEEN 1 AND 2147483647),
    roster_version INTEGER NOT NULL
        CHECK (roster_version BETWEEN 1 AND 2147483647),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    signing_key_id BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(signing_key_id) = 32),
    signing_key_use SMALLINT
        GENERATED ALWAYS AS (1::SMALLINT) STORED,
    keyset_sequence BIGINT NOT NULL
        CHECK (keyset_sequence BETWEEN 1 AND 9007199254740991),
    keyset_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(keyset_hash) = 32),
    control_action SMALLINT
        GENERATED ALWAYS AS (1::SMALLINT) STORED,
    control_reason_code SMALLINT
        GENERATED ALWAYS AS (0::SMALLINT) STORED,
    accepted_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (environment, assertion_hash),
    UNIQUE (
        environment,
        installation_binding_id,
        sequencer_epoch,
        assertion_stream_sequence,
        binding_id,
        binding_version,
        assertion_hash,
        control_action,
        control_reason_code
    ),
    UNIQUE (
        environment,
        installation_binding_id,
        sequencer_epoch,
        binding_id,
        binding_version,
        assertion_hash,
        assertion_stream_sequence,
        topic_key_epoch,
        topic_binding,
        keyset_sequence,
        keyset_hash
    ),
    FOREIGN KEY (
        environment,
        installation_binding_id,
        sequencer_epoch,
        assertion_stream_sequence,
        binding_id,
        binding_version,
        assertion_hash,
        control_action,
        control_reason_code
    )
        REFERENCES hytch_push_vault.a9_control_events(
            environment,
            installation_binding_id,
            sequencer_epoch,
            stream_sequence,
            binding_id,
            binding_version,
            assertion_hash,
            action,
            reason_code
        ),
    FOREIGN KEY (environment, keyset_sequence, keyset_hash)
        REFERENCES hytch_push_vault.a9_accepted_keysets(
            environment,
            keyset_sequence,
            signed_keyset_hash
        ),
    FOREIGN KEY (
        environment,
        keyset_sequence,
        signing_key_use,
        signing_key_id
    )
        REFERENCES hytch_push_vault.a9_online_key_descriptors(
            environment,
            keyset_sequence,
            key_use,
            key_id
        ),
    FOREIGN KEY (
        environment,
        keyset_sequence,
        tuple_commitment_purpose,
        tuple_commitment_key_id
    )
        REFERENCES hytch_push_vault.a9_commitment_key_descriptors(
            environment,
            keyset_sequence,
            purpose,
            key_id
        ),
    FOREIGN KEY (
        environment,
        keyset_sequence,
        roster_commitment_purpose,
        roster_commitment_key_id
    )
        REFERENCES hytch_push_vault.a9_commitment_key_descriptors(
            environment,
            keyset_sequence,
            purpose,
            key_id
        ),
    FOREIGN KEY (
        environment,
        keyset_sequence,
        topic_commitment_purpose,
        topic_commitment_key_id,
        topic_key_epoch
    )
        REFERENCES hytch_push_vault.a9_commitment_key_descriptors(
            environment,
            keyset_sequence,
            purpose,
            key_id,
            topic_key_epoch
        ),
    CHECK (expires_at > issued_at),
    CHECK (expires_at <= issued_at + INTERVAL '30 seconds')
);

-- Only keyed commitments and fixed authority metadata are retained. The
-- complete signed assertion, signature, raw roster digest, tuple, transport
-- identifier, and provider topic are intentionally absent.
CREATE INDEX a9_assertions_expiry_idx
    ON hytch_push_vault.a9_assertions (
        environment,
        expires_at
    );

CREATE INDEX a9_assertions_topic_idx
    ON hytch_push_vault.a9_assertions (
        environment,
        topic_key_epoch,
        topic_binding
    );

CREATE TABLE hytch_push_vault.a9_bindings (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    installation_binding_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(installation_binding_id) = 16
        ),
    binding_id BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(binding_id) = 16),
    sequencer_epoch BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(sequencer_epoch) = 16),
    binding_version BIGINT NOT NULL
        CHECK (binding_version BETWEEN 1 AND 9007199254740991),
    state SMALLINT NOT NULL CHECK (state IN (1, 2)),
    active_assertion_hash BYTEA,
    active_assertion_stream_sequence BIGINT,
    active_topic_key_epoch BIGINT,
    active_topic_binding BYTEA,
    active_keyset_sequence BIGINT,
    active_keyset_hash BYTEA,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (
        environment,
        installation_binding_id,
        binding_id
    ),
    UNIQUE (
        environment,
        installation_binding_id,
        sequencer_epoch,
        binding_id,
        binding_version,
        active_assertion_hash,
        active_assertion_stream_sequence,
        active_topic_key_epoch,
        active_topic_binding,
        active_keyset_sequence,
        active_keyset_hash
    ),
    FOREIGN KEY (environment, installation_binding_id)
        REFERENCES hytch_push_vault.a9_installation_authority(
            environment,
            installation_binding_id
        ),
    FOREIGN KEY (
        environment,
        installation_binding_id,
        sequencer_epoch,
        binding_id,
        binding_version,
        active_assertion_hash,
        active_assertion_stream_sequence,
        active_topic_key_epoch,
        active_topic_binding,
        active_keyset_sequence,
        active_keyset_hash
    )
        REFERENCES hytch_push_vault.a9_assertions(
            environment,
            installation_binding_id,
            sequencer_epoch,
            binding_id,
            binding_version,
            assertion_hash,
            assertion_stream_sequence,
            topic_key_epoch,
            topic_binding,
            keyset_sequence,
            keyset_hash
        ),
    CHECK (
        (
            state = 1 AND
            active_assertion_hash IS NOT NULL AND
            pg_catalog.octet_length(active_assertion_hash) = 32 AND
            active_assertion_stream_sequence IS NOT NULL AND
            active_assertion_stream_sequence
                BETWEEN 1 AND 9007199254740991 AND
            active_topic_key_epoch IS NOT NULL AND
            active_topic_key_epoch BETWEEN 1 AND 4294967295 AND
            active_topic_binding IS NOT NULL AND
            pg_catalog.octet_length(active_topic_binding) = 32 AND
            active_keyset_sequence IS NOT NULL AND
            active_keyset_sequence
                BETWEEN 1 AND 9007199254740991 AND
            active_keyset_hash IS NOT NULL AND
            pg_catalog.octet_length(active_keyset_hash) = 32
        ) OR (
            state = 2 AND
            active_assertion_hash IS NULL AND
            active_assertion_stream_sequence IS NULL AND
            active_topic_key_epoch IS NULL AND
            active_topic_binding IS NULL AND
            active_keyset_sequence IS NULL AND
            active_keyset_hash IS NULL
        )
    )
);

-- binding state: 1=ACTIVE, 2=REVOKED. Installation-level uncertainty is kept
-- only in a9_installation_authority and cannot be mistaken for a binding.

CREATE TABLE hytch_push_vault.a9_binding_tombstones (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    installation_binding_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(installation_binding_id) = 16
        ),
    binding_id BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(binding_id) = 16),
    binding_version BIGINT NOT NULL
        CHECK (binding_version BETWEEN 1 AND 9007199254740991),
    assertion_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(assertion_hash) = 32),
    sequencer_epoch BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(sequencer_epoch) = 16),
    control_stream_sequence BIGINT NOT NULL
        CHECK (
            control_stream_sequence BETWEEN 1 AND 9007199254740991
        ),
    control_action SMALLINT
        GENERATED ALWAYS AS (2::SMALLINT) STORED,
    reason_code SMALLINT NOT NULL CHECK (reason_code BETWEEN 1 AND 3),
    revoked_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (
        environment,
        installation_binding_id,
        binding_id,
        binding_version
    ),
    FOREIGN KEY (
        environment,
        installation_binding_id,
        sequencer_epoch,
        control_stream_sequence,
        binding_id,
        binding_version,
        assertion_hash,
        control_action,
        reason_code
    )
        REFERENCES hytch_push_vault.a9_control_events(
            environment,
            installation_binding_id,
            sequencer_epoch,
            stream_sequence,
            binding_id,
            binding_version,
            assertion_hash,
            action,
            reason_code
        )
);

-- Tombstones intentionally have no expires_at column. Once a binding version
-- is denied, v12 never resurrects it.

CREATE TABLE hytch_push_vault.a9_subscription_routes (
    lease_id BYTEA NOT NULL CHECK (pg_catalog.octet_length(lease_id) = 16),
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    installation_binding_id BYTEA NOT NULL
        CHECK (
            pg_catalog.octet_length(installation_binding_id) = 16
        ),
    installation_identity BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(installation_identity) = 32),
    sequencer_epoch BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(sequencer_epoch) = 16),
    subscription_generation BIGINT NOT NULL
        CHECK (
            subscription_generation BETWEEN 1 AND 9007199254740991
        ),
    replacement_idempotency_key UUID NOT NULL,
    replacement_operation SMALLINT
        GENERATED ALWAYS AS (2::SMALLINT) STORED,
    replacement_outcome SMALLINT
        GENERATED ALWAYS AS (1::SMALLINT) STORED,
    replacement_state SMALLINT
        GENERATED ALWAYS AS (1::SMALLINT) STORED,
    binding_id BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(binding_id) = 16),
    binding_version BIGINT NOT NULL
        CHECK (binding_version BETWEEN 1 AND 9007199254740991),
    assertion_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(assertion_hash) = 32),
    assertion_stream_sequence BIGINT NOT NULL
        CHECK (
            assertion_stream_sequence
                BETWEEN 1 AND 9007199254740991
        ),
    topic_key_epoch BIGINT NOT NULL
        CHECK (topic_key_epoch BETWEEN 1 AND 4294967295),
    topic_binding BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(topic_binding) = 32),
    route_key_epoch BIGINT NOT NULL
        CHECK (route_key_epoch BETWEEN 1 AND 4294967295),
    keyset_sequence BIGINT NOT NULL
        CHECK (keyset_sequence BETWEEN 1 AND 9007199254740991),
    keyset_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(keyset_hash) = 32),
    watermark_sequence BIGINT NOT NULL
        CHECK (watermark_sequence BETWEEN 1 AND 9007199254740991),
    created_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    refreshed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (lease_id, environment),
    UNIQUE (lease_id),
    UNIQUE (
        environment,
        installation_binding_id,
        topic_key_epoch,
        topic_binding
    ),
    -- Every row in this table is an ACTIVE route. Superseded routes are
    -- removed in the same serializable replacement transaction.
    UNIQUE (
        environment,
        installation_binding_id,
        binding_id
    ),
    UNIQUE (
        lease_id,
        environment,
        installation_binding_id,
        sequencer_epoch,
        subscription_generation,
        binding_id,
        binding_version,
        assertion_hash,
        assertion_stream_sequence,
        topic_key_epoch,
        topic_binding,
        route_key_epoch,
        keyset_sequence,
        keyset_hash,
        watermark_sequence
    ),
    FOREIGN KEY (lease_id, environment, installation_identity)
        REFERENCES hytch_push_vault.subscription_leases(
            lease_id,
            environment,
            installation_identity
        ),
    FOREIGN KEY (
        environment,
        installation_binding_id,
        installation_identity
    )
        REFERENCES hytch_push_vault.a9_installation_gate6_bindings(
            environment,
            installation_binding_id,
            installation_identity
        ),
    FOREIGN KEY (environment, installation_binding_id)
        REFERENCES hytch_push_vault.a9_installation_authority(
            environment,
            installation_binding_id
        ),
    FOREIGN KEY (
        environment,
        replacement_idempotency_key,
        installation_binding_id,
        sequencer_epoch,
        replacement_operation,
        replacement_outcome,
        replacement_state,
        subscription_generation
    )
        REFERENCES hytch_push_vault.a9_idempotency_receipts(
            environment,
            idempotency_key,
            installation_binding_id,
            sequencer_epoch,
            operation_kind,
            result_outcome,
            result_state,
            subscription_generation
        ),
    FOREIGN KEY (
        environment,
        installation_binding_id,
        sequencer_epoch,
        binding_id,
        binding_version,
        assertion_hash,
        assertion_stream_sequence,
        topic_key_epoch,
        topic_binding,
        keyset_sequence,
        keyset_hash
    )
        REFERENCES hytch_push_vault.a9_assertions(
            environment,
            installation_binding_id,
            sequencer_epoch,
            binding_id,
            binding_version,
            assertion_hash,
            assertion_stream_sequence,
            topic_key_epoch,
            topic_binding,
            keyset_sequence,
            keyset_hash
        ),
    FOREIGN KEY (
        environment,
        installation_binding_id,
        sequencer_epoch,
        binding_id,
        binding_version,
        assertion_hash,
        assertion_stream_sequence,
        topic_key_epoch,
        topic_binding,
        keyset_sequence,
        keyset_hash
    )
        REFERENCES hytch_push_vault.a9_bindings(
            environment,
            installation_binding_id,
            sequencer_epoch,
            binding_id,
            binding_version,
            active_assertion_hash,
            active_assertion_stream_sequence,
            active_topic_key_epoch,
            active_topic_binding,
            active_keyset_sequence,
            active_keyset_hash
        ),
    CHECK (refreshed_at >= created_at)
);

CREATE INDEX a9_subscription_routes_topic_idx
    ON hytch_push_vault.a9_subscription_routes (
        environment,
        topic_key_epoch,
        topic_binding
    );

ALTER TABLE hytch_push_vault.delivery_jobs
    ADD COLUMN a9_installation_binding_id BYTEA,
    ADD COLUMN a9_sequencer_epoch BYTEA,
    ADD COLUMN a9_subscription_generation BIGINT,
    ADD COLUMN a9_binding_id BYTEA,
    ADD COLUMN a9_binding_version BIGINT,
    ADD COLUMN a9_assertion_hash BYTEA,
    ADD COLUMN a9_assertion_stream_sequence BIGINT,
    ADD COLUMN a9_topic_key_epoch BIGINT,
    ADD COLUMN a9_topic_binding BYTEA,
    ADD COLUMN a9_route_key_epoch BIGINT,
    ADD COLUMN a9_keyset_sequence BIGINT,
    ADD COLUMN a9_keyset_hash BYTEA,
    ADD COLUMN a9_watermark_sequence BIGINT,
    ADD CONSTRAINT delivery_jobs_a9_snapshot_shape_check
        CHECK (
            (
                a9_installation_binding_id IS NULL AND
                a9_sequencer_epoch IS NULL AND
                a9_subscription_generation IS NULL AND
                a9_binding_id IS NULL AND
                a9_binding_version IS NULL AND
                a9_assertion_hash IS NULL AND
                a9_assertion_stream_sequence IS NULL AND
                a9_topic_key_epoch IS NULL AND
                a9_topic_binding IS NULL AND
                a9_route_key_epoch IS NULL AND
                a9_keyset_sequence IS NULL AND
                a9_keyset_hash IS NULL AND
                a9_watermark_sequence IS NULL
            ) OR (
                state IN (1, 2) AND
                lease_id IS NOT NULL AND
                a9_installation_binding_id IS NOT NULL AND
                pg_catalog.octet_length(
                    a9_installation_binding_id
                ) = 16 AND
                a9_sequencer_epoch IS NOT NULL AND
                pg_catalog.octet_length(a9_sequencer_epoch) = 16 AND
                a9_subscription_generation IS NOT NULL AND
                a9_subscription_generation
                    BETWEEN 1 AND 9007199254740991 AND
                a9_binding_id IS NOT NULL AND
                pg_catalog.octet_length(a9_binding_id) = 16 AND
                a9_binding_version IS NOT NULL AND
                a9_binding_version
                    BETWEEN 1 AND 9007199254740991 AND
                a9_assertion_hash IS NOT NULL AND
                pg_catalog.octet_length(a9_assertion_hash) = 32 AND
                a9_assertion_stream_sequence IS NOT NULL AND
                a9_assertion_stream_sequence
                    BETWEEN 1 AND 9007199254740991 AND
                a9_topic_key_epoch IS NOT NULL AND
                a9_topic_key_epoch BETWEEN 1 AND 4294967295 AND
                a9_topic_binding IS NOT NULL AND
                pg_catalog.octet_length(a9_topic_binding) = 32 AND
                a9_route_key_epoch IS NOT NULL AND
                a9_route_key_epoch BETWEEN 1 AND 4294967295 AND
                a9_keyset_sequence IS NOT NULL AND
                a9_keyset_sequence
                    BETWEEN 1 AND 9007199254740991 AND
                a9_keyset_hash IS NOT NULL AND
                pg_catalog.octet_length(a9_keyset_hash) = 32 AND
                a9_watermark_sequence IS NOT NULL AND
                a9_watermark_sequence
                    BETWEEN 1 AND 9007199254740991
            )
        ),
    ADD CONSTRAINT delivery_jobs_a9_route_fk
        FOREIGN KEY (
            lease_id,
            environment,
            a9_installation_binding_id,
            a9_sequencer_epoch,
            a9_subscription_generation,
            a9_binding_id,
            a9_binding_version,
            a9_assertion_hash,
            a9_assertion_stream_sequence,
            a9_topic_key_epoch,
            a9_topic_binding,
            a9_route_key_epoch,
            a9_keyset_sequence,
            a9_keyset_hash,
            a9_watermark_sequence
        )
        REFERENCES hytch_push_vault.a9_subscription_routes(
            lease_id,
            environment,
            installation_binding_id,
            sequencer_epoch,
            subscription_generation,
            binding_id,
            binding_version,
            assertion_hash,
            assertion_stream_sequence,
            topic_key_epoch,
            topic_binding,
            route_key_epoch,
            keyset_sequence,
            keyset_hash,
            watermark_sequence
        );

-- This index supports revoke/replacement cancellation before a route is
-- removed. Terminal/finalization updates must clear every A9 snapshot column.
CREATE INDEX delivery_jobs_a9_cancellation_idx
    ON hytch_push_vault.delivery_jobs (
        environment,
        a9_installation_binding_id,
        a9_binding_id,
        a9_binding_version
    )
    WHERE state IN (1, 2)
      AND a9_installation_binding_id IS NOT NULL;

-- Append-only tables reject UPDATE, DELETE, and TRUNCATE, including owner
-- sessions and replication-role sessions.
CREATE TRIGGER hytch_a9_keysets_update_guard
BEFORE UPDATE ON hytch_push_vault.a9_accepted_keysets
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_accepted_keysets
    ENABLE ALWAYS TRIGGER hytch_a9_keysets_update_guard;
CREATE TRIGGER hytch_a9_keysets_delete_guard
BEFORE DELETE ON hytch_push_vault.a9_accepted_keysets
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_accepted_keysets
    ENABLE ALWAYS TRIGGER hytch_a9_keysets_delete_guard;
CREATE TRIGGER hytch_a9_keysets_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a9_accepted_keysets
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_accepted_keysets
    ENABLE ALWAYS TRIGGER hytch_a9_keysets_truncate_guard;

CREATE TRIGGER hytch_a9_online_keys_update_guard
BEFORE UPDATE ON hytch_push_vault.a9_online_key_descriptors
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_online_key_descriptors
    ENABLE ALWAYS TRIGGER hytch_a9_online_keys_update_guard;
CREATE TRIGGER hytch_a9_online_keys_delete_guard
BEFORE DELETE ON hytch_push_vault.a9_online_key_descriptors
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_online_key_descriptors
    ENABLE ALWAYS TRIGGER hytch_a9_online_keys_delete_guard;
CREATE TRIGGER hytch_a9_online_keys_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a9_online_key_descriptors
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_online_key_descriptors
    ENABLE ALWAYS TRIGGER hytch_a9_online_keys_truncate_guard;

CREATE TRIGGER hytch_a9_commitment_keys_update_guard
BEFORE UPDATE ON hytch_push_vault.a9_commitment_key_descriptors
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_commitment_key_descriptors
    ENABLE ALWAYS TRIGGER hytch_a9_commitment_keys_update_guard;
CREATE TRIGGER hytch_a9_commitment_keys_delete_guard
BEFORE DELETE ON hytch_push_vault.a9_commitment_key_descriptors
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_commitment_key_descriptors
    ENABLE ALWAYS TRIGGER hytch_a9_commitment_keys_delete_guard;
CREATE TRIGGER hytch_a9_commitment_keys_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a9_commitment_key_descriptors
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_commitment_key_descriptors
    ENABLE ALWAYS TRIGGER hytch_a9_commitment_keys_truncate_guard;

CREATE TRIGGER hytch_a9_watermarks_update_guard
BEFORE UPDATE ON hytch_push_vault.a9_watermarks
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_watermarks
    ENABLE ALWAYS TRIGGER hytch_a9_watermarks_update_guard;
CREATE TRIGGER hytch_a9_watermarks_delete_guard
BEFORE DELETE ON hytch_push_vault.a9_watermarks
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_watermarks
    ENABLE ALWAYS TRIGGER hytch_a9_watermarks_delete_guard;
CREATE TRIGGER hytch_a9_watermarks_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a9_watermarks
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_watermarks
    ENABLE ALWAYS TRIGGER hytch_a9_watermarks_truncate_guard;

CREATE TRIGGER hytch_a9_gate6_bindings_update_guard
BEFORE UPDATE ON hytch_push_vault.a9_installation_gate6_bindings
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_installation_gate6_bindings
    ENABLE ALWAYS TRIGGER hytch_a9_gate6_bindings_update_guard;
CREATE TRIGGER hytch_a9_gate6_bindings_delete_guard
BEFORE DELETE ON hytch_push_vault.a9_installation_gate6_bindings
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_installation_gate6_bindings
    ENABLE ALWAYS TRIGGER hytch_a9_gate6_bindings_delete_guard;
CREATE TRIGGER hytch_a9_gate6_bindings_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a9_installation_gate6_bindings
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_installation_gate6_bindings
    ENABLE ALWAYS TRIGGER hytch_a9_gate6_bindings_truncate_guard;

CREATE TRIGGER hytch_a9_idempotency_update_guard
BEFORE UPDATE ON hytch_push_vault.a9_idempotency_receipts
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_idempotency_receipts
    ENABLE ALWAYS TRIGGER hytch_a9_idempotency_update_guard;
CREATE TRIGGER hytch_a9_idempotency_delete_guard
BEFORE DELETE ON hytch_push_vault.a9_idempotency_receipts
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_idempotency_receipts
    ENABLE ALWAYS TRIGGER hytch_a9_idempotency_delete_guard;
CREATE TRIGGER hytch_a9_idempotency_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a9_idempotency_receipts
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_idempotency_receipts
    ENABLE ALWAYS TRIGGER hytch_a9_idempotency_truncate_guard;

CREATE TRIGGER hytch_a9_control_update_guard
BEFORE UPDATE ON hytch_push_vault.a9_control_events
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_control_events
    ENABLE ALWAYS TRIGGER hytch_a9_control_update_guard;
CREATE TRIGGER hytch_a9_control_delete_guard
BEFORE DELETE ON hytch_push_vault.a9_control_events
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_control_events
    ENABLE ALWAYS TRIGGER hytch_a9_control_delete_guard;
CREATE TRIGGER hytch_a9_control_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a9_control_events
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_control_events
    ENABLE ALWAYS TRIGGER hytch_a9_control_truncate_guard;

CREATE TRIGGER hytch_a9_assertions_update_guard
BEFORE UPDATE ON hytch_push_vault.a9_assertions
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_assertions
    ENABLE ALWAYS TRIGGER hytch_a9_assertions_update_guard;
CREATE TRIGGER hytch_a9_assertions_delete_guard
BEFORE DELETE ON hytch_push_vault.a9_assertions
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_assertions
    ENABLE ALWAYS TRIGGER hytch_a9_assertions_delete_guard;
CREATE TRIGGER hytch_a9_assertions_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a9_assertions
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_assertions
    ENABLE ALWAYS TRIGGER hytch_a9_assertions_truncate_guard;

CREATE TRIGGER hytch_a9_tombstones_update_guard
BEFORE UPDATE ON hytch_push_vault.a9_binding_tombstones
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_binding_tombstones
    ENABLE ALWAYS TRIGGER hytch_a9_tombstones_update_guard;
CREATE TRIGGER hytch_a9_tombstones_delete_guard
BEFORE DELETE ON hytch_push_vault.a9_binding_tombstones
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_binding_tombstones
    ENABLE ALWAYS TRIGGER hytch_a9_tombstones_delete_guard;
CREATE TRIGGER hytch_a9_tombstones_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a9_binding_tombstones
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_binding_tombstones
    ENABLE ALWAYS TRIGGER hytch_a9_tombstones_truncate_guard;

CREATE TRIGGER hytch_a9_jti_update_guard
BEFORE UPDATE ON hytch_push_vault.a9_service_jti_receipts
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_service_jti_receipts
    ENABLE ALWAYS TRIGGER hytch_a9_jti_update_guard;
CREATE TRIGGER hytch_a9_jti_delete_guard
BEFORE DELETE ON hytch_push_vault.a9_service_jti_receipts
FOR EACH ROW
EXECUTE FUNCTION hytch_push_vault.reject_unexpired_a9_jti_delete();
ALTER TABLE hytch_push_vault.a9_service_jti_receipts
    ENABLE ALWAYS TRIGGER hytch_a9_jti_delete_guard;
CREATE TRIGGER hytch_a9_jti_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a9_service_jti_receipts
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a9_immutable_mutation();
ALTER TABLE hytch_push_vault.a9_service_jti_receipts
    ENABLE ALWAYS TRIGGER hytch_a9_jti_truncate_guard;

REVOKE ALL
    ON ALL TABLES IN SCHEMA hytch_push_vault
    FROM PUBLIC;
REVOKE ALL
    ON ALL FUNCTIONS IN SCHEMA hytch_push_vault
    FROM PUBLIC;
