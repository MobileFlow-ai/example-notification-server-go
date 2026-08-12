CREATE TABLE hytch_push_vault.a3_directory_witness_heads (
    environment SMALLINT NOT NULL
        CONSTRAINT a3_witness_environment_check
        CHECK (environment IN (1, 2)),
    tree_size BIGINT NOT NULL
        CONSTRAINT a3_witness_tree_size_check
        CHECK (tree_size BETWEEN 1 AND 9007199254740991),
    root_hash BYTEA NOT NULL
        CONSTRAINT a3_witness_root_hash_check
        CHECK (pg_catalog.octet_length(root_hash) = 32),
    prior_tree_size BIGINT NOT NULL
        CONSTRAINT a3_witness_prior_tree_size_check
        CHECK (prior_tree_size BETWEEN 0 AND 9007199254740991),
    prior_root_hash BYTEA NOT NULL
        CONSTRAINT a3_witness_prior_root_hash_check
        CHECK (pg_catalog.octet_length(prior_root_hash) = 32),
    timestamp_ms BIGINT NOT NULL
        CONSTRAINT a3_witness_timestamp_ms_check
        CHECK (timestamp_ms BETWEEN 0 AND 9007199254740991),
    canonical_head BYTEA NOT NULL
        CONSTRAINT a3_witness_canonical_head_check
        CHECK (pg_catalog.octet_length(canonical_head) BETWEEN 1 AND 4096),
    consistency_proof BYTEA NOT NULL
        CONSTRAINT a3_witness_consistency_proof_check
        CHECK (
            pg_catalog.octet_length(consistency_proof) <= 2048 AND
            pg_catalog.octet_length(consistency_proof) % 32 = 0
        ),
    witness_key_id TEXT NOT NULL
        CONSTRAINT a3_witness_key_id_check
        CHECK (
            pg_catalog.length(witness_key_id) = 79 AND
            witness_key_id ~ '^ed25519-sha256:[0-9a-f]{64}$'
        ),
    witness_signature BYTEA NOT NULL
        CONSTRAINT a3_witness_signature_check
        CHECK (pg_catalog.octet_length(witness_signature) = 64),
    accepted_at TIMESTAMPTZ NOT NULL
        DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT a3_directory_witness_heads_pkey
        PRIMARY KEY (environment, tree_size),
    CONSTRAINT a3_witness_predecessor_check
        CHECK (prior_tree_size < tree_size)
);

CREATE FUNCTION hytch_push_vault.reject_a3_witness_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION 'A3 witness state cannot be modified'
        USING ERRCODE = '55000';
END;
$function$;

REVOKE ALL
    ON FUNCTION hytch_push_vault.reject_a3_witness_mutation()
    FROM PUBLIC;

CREATE TRIGGER hytch_a3_witness_update_guard
BEFORE UPDATE ON hytch_push_vault.a3_directory_witness_heads
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a3_witness_mutation();
ALTER TABLE hytch_push_vault.a3_directory_witness_heads
    ENABLE ALWAYS TRIGGER hytch_a3_witness_update_guard;

CREATE TRIGGER hytch_a3_witness_delete_guard
BEFORE DELETE ON hytch_push_vault.a3_directory_witness_heads
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a3_witness_mutation();
ALTER TABLE hytch_push_vault.a3_directory_witness_heads
    ENABLE ALWAYS TRIGGER hytch_a3_witness_delete_guard;

CREATE TRIGGER hytch_a3_witness_truncate_guard
BEFORE TRUNCATE ON hytch_push_vault.a3_directory_witness_heads
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_a3_witness_mutation();
ALTER TABLE hytch_push_vault.a3_directory_witness_heads
    ENABLE ALWAYS TRIGGER hytch_a3_witness_truncate_guard;

REVOKE ALL ON hytch_push_vault.a3_directory_witness_heads FROM PUBLIC;
