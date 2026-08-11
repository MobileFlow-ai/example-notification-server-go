CREATE TABLE hytch_push_vault.a10_accepted_keysets (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    keyset_sequence BIGINT NOT NULL
        CHECK (keyset_sequence BETWEEN 1 AND 9007199254740991),
    signed_keyset_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(signed_keyset_hash) = 32),
    signed_keyset_jcs BYTEA NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (environment, keyset_sequence),
    UNIQUE (environment, signed_keyset_hash),
    UNIQUE (environment, keyset_sequence, signed_keyset_hash),
    CHECK (expires_at > issued_at)
);

CREATE TABLE hytch_push_vault.a10_keyset_state (
    environment SMALLINT PRIMARY KEY CHECK (environment IN (1, 2)),
    keyset_sequence BIGINT NOT NULL
        CHECK (keyset_sequence BETWEEN 1 AND 9007199254740991),
    signed_keyset_hash BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(signed_keyset_hash) = 32),
    state SMALLINT NOT NULL CHECK (state IN (1, 2)),
    uncertainty_reason SMALLINT NOT NULL CHECK (uncertainty_reason IN (0, 1)),
    expires_at TIMESTAMPTZ NOT NULL,
    refreshed_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (environment, keyset_sequence, signed_keyset_hash)
        REFERENCES hytch_push_vault.a10_accepted_keysets (
            environment,
            keyset_sequence,
            signed_keyset_hash
        ),
    CHECK (
        (state = 1 AND uncertainty_reason = 0) OR
        (state = 2 AND uncertainty_reason = 1)
    )
);

CREATE TABLE hytch_push_vault.a10_registration_replays (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    jti UUID NOT NULL,
    jwt_expires_at TIMESTAMPTZ NOT NULL,
    delete_after TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (environment, jti),
    CHECK (delete_after = jwt_expires_at + INTERVAL '5 seconds'),
    CHECK (consumed_at <= delete_after)
);

CREATE INDEX a10_registration_replays_expiry_idx
    ON hytch_push_vault.a10_registration_replays (delete_after);

CREATE TABLE hytch_push_vault.a10_registration_bindings (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    installation_binding_id BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(installation_binding_id) = 16),
    installation_identity BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(installation_identity) = 32),
    owner_binding BYTEA NOT NULL
        CHECK (pg_catalog.octet_length(owner_binding) = 32),
    created_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (environment, installation_binding_id),
    UNIQUE (environment, installation_identity),
    FOREIGN KEY (
        environment,
        installation_binding_id,
        installation_identity
    ) REFERENCES hytch_push_vault.a9_installation_gate6_bindings (
        environment,
        installation_binding_id,
        installation_identity
    )
);

CREATE FUNCTION hytch_push_vault.reject_a10_immutable_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION 'A10 immutable state cannot be modified'
        USING ERRCODE = '55000';
END;
$function$;

CREATE TRIGGER hytch_a10_keysets_update_guard
BEFORE UPDATE ON hytch_push_vault.a10_accepted_keysets
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a10_immutable_mutation();
ALTER TABLE hytch_push_vault.a10_accepted_keysets
    ENABLE ALWAYS TRIGGER hytch_a10_keysets_update_guard;
CREATE TRIGGER hytch_a10_keysets_delete_guard
BEFORE DELETE ON hytch_push_vault.a10_accepted_keysets
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a10_immutable_mutation();
ALTER TABLE hytch_push_vault.a10_accepted_keysets
    ENABLE ALWAYS TRIGGER hytch_a10_keysets_delete_guard;
CREATE TRIGGER hytch_a10_keysets_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a10_accepted_keysets
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a10_immutable_mutation();
ALTER TABLE hytch_push_vault.a10_accepted_keysets
    ENABLE ALWAYS TRIGGER hytch_a10_keysets_truncate_guard;

CREATE TRIGGER hytch_a10_bindings_update_guard
BEFORE UPDATE ON hytch_push_vault.a10_registration_bindings
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a10_immutable_mutation();
ALTER TABLE hytch_push_vault.a10_registration_bindings
    ENABLE ALWAYS TRIGGER hytch_a10_bindings_update_guard;
CREATE TRIGGER hytch_a10_bindings_delete_guard
BEFORE DELETE ON hytch_push_vault.a10_registration_bindings
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a10_immutable_mutation();
ALTER TABLE hytch_push_vault.a10_registration_bindings
    ENABLE ALWAYS TRIGGER hytch_a10_bindings_delete_guard;
CREATE TRIGGER hytch_a10_bindings_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a10_registration_bindings
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a10_immutable_mutation();
ALTER TABLE hytch_push_vault.a10_registration_bindings
    ENABLE ALWAYS TRIGGER hytch_a10_bindings_truncate_guard;

CREATE FUNCTION hytch_push_vault.guard_a10_replay_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF OLD.delete_after >= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION 'live A10 replay receipt cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
END;
$function$;

CREATE TRIGGER hytch_a10_replays_update_guard
BEFORE UPDATE ON hytch_push_vault.a10_registration_replays
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a10_immutable_mutation();
ALTER TABLE hytch_push_vault.a10_registration_replays
    ENABLE ALWAYS TRIGGER hytch_a10_replays_update_guard;
CREATE TRIGGER hytch_a10_replays_delete_guard
BEFORE DELETE ON hytch_push_vault.a10_registration_replays
FOR EACH ROW
EXECUTE FUNCTION hytch_push_vault.guard_a10_replay_delete();
ALTER TABLE hytch_push_vault.a10_registration_replays
    ENABLE ALWAYS TRIGGER hytch_a10_replays_delete_guard;
CREATE TRIGGER hytch_a10_replays_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a10_registration_replays
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a10_immutable_mutation();
ALTER TABLE hytch_push_vault.a10_registration_replays
    ENABLE ALWAYS TRIGGER hytch_a10_replays_truncate_guard;

REVOKE ALL ON hytch_push_vault.a10_accepted_keysets FROM PUBLIC;
REVOKE ALL ON hytch_push_vault.a10_keyset_state FROM PUBLIC;
REVOKE ALL ON hytch_push_vault.a10_registration_replays FROM PUBLIC;
REVOKE ALL ON hytch_push_vault.a10_registration_bindings FROM PUBLIC;
