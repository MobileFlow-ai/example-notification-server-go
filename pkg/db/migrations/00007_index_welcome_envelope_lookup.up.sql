CREATE INDEX welcome_authorizations_envelope_lookup_idx
    ON hytch_push_vault.welcome_authorizations (
        environment,
        envelope_lookup
    );
