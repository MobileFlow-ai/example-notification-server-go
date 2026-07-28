CREATE SCHEMA IF NOT EXISTS hytch_push_vault;
REVOKE ALL ON SCHEMA hytch_push_vault FROM PUBLIC;

CREATE TABLE hytch_push_vault.vault_key_bindings (
    environment SMALLINT PRIMARY KEY CHECK (environment IN (1, 2)),
    lookup_root_commitment BYTEA NOT NULL
        CHECK (octet_length(lookup_root_commitment) = 32),
    bound_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE hytch_push_vault.installation_states (
    installation_lookup BYTEA PRIMARY KEY,
    installation_identity BYTEA NOT NULL UNIQUE
        CHECK (octet_length(installation_identity) = 32),
    incarnation_lookup BYTEA NOT NULL,
    lookup_key_epoch BIGINT NOT NULL CHECK (lookup_key_epoch >= 0),
    -- Generation zero is reserved for a pre-registration revocation fence.
    generation BIGINT NOT NULL CHECK (generation >= 0),
    idempotency_digest BYTEA NOT NULL CHECK (octet_length(idempotency_digest) = 32),
    control_event_digest BYTEA NOT NULL CHECK (octet_length(control_event_digest) = 32),
    encrypted_apns_token BYTEA,
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    payload_schema SMALLINT NOT NULL CHECK (payload_schema = 1),
    age_policy SMALLINT NOT NULL CHECK (age_policy IN (1, 2)),
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch > 0),
    state SMALLINT NOT NULL CHECK (state IN (1, 2, 3, 4, 5, 6, 7, 8, 9)),
    encryption_key_version INTEGER NOT NULL CHECK (encryption_key_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    refreshed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    control_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    UNIQUE (installation_lookup, environment),
    CHECK (expires_at <= refreshed_at + INTERVAL '7 days'),
    CHECK (control_expires_at <= refreshed_at + INTERVAL '60 seconds')
);

CREATE INDEX installation_states_expiry_idx
    ON hytch_push_vault.installation_states (environment, expires_at);

-- This pseudonymous, append-only fence survives lease and installation
-- deletion so a removed route cannot restart an AES-GCM nonce lineage with a
-- previously used route key. All values are keyed commitments; no raw route
-- metadata or key material is stored.
CREATE TABLE hytch_push_vault.route_key_history (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    route_identity BYTEA NOT NULL CHECK (octet_length(route_identity) = 32),
    route_key_epoch BIGINT NOT NULL
        CHECK (route_key_epoch BETWEEN 1 AND 4294967295),
    route_key_commitment BYTEA NOT NULL
        CHECK (octet_length(route_key_commitment) = 32),
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (environment, route_identity, route_key_epoch),
    UNIQUE (environment, route_key_commitment),
    CHECK (expires_at >= updated_at),
    CHECK (expires_at <= updated_at + INTERVAL '15 days')
);

CREATE INDEX route_key_history_expiry_idx
    ON hytch_push_vault.route_key_history (environment, expires_at);

CREATE TABLE hytch_push_vault.subscription_leases (
    lease_id BYTEA PRIMARY KEY CHECK (octet_length(lease_id) = 16),
    installation_lookup BYTEA NOT NULL,
    route_identity BYTEA NOT NULL CHECK (octet_length(route_identity) = 32),
    topic_lookup BYTEA NOT NULL CHECK (octet_length(topic_lookup) = 32),
    lookup_key_epoch BIGINT NOT NULL CHECK (lookup_key_epoch >= 0),
    encrypted_topic BYTEA NOT NULL,
    encrypted_route_key BYTEA NOT NULL,
    encrypted_hmac_keys BYTEA NOT NULL,
    encrypted_receive_capability BYTEA NOT NULL,
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    payload_schema SMALLINT NOT NULL CHECK (payload_schema = 1),
    topic_kind SMALLINT NOT NULL CHECK (topic_kind IN (1, 2)),
    push_mode SMALLINT NOT NULL CHECK (push_mode IN (1, 2)),
    state SMALLINT NOT NULL CHECK (state IN (1, 2, 3, 4, 5, 6, 7, 8, 9)),
    generation BIGINT NOT NULL CHECK (generation > 0),
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch > 0),
    route_key_epoch BIGINT NOT NULL
        CHECK (route_key_epoch BETWEEN 1 AND 4294967295),
    encrypted_nonce_state BYTEA NOT NULL,
    encryption_key_version INTEGER NOT NULL CHECK (encryption_key_version > 0),
    issued_at TIMESTAMPTZ NOT NULL,
    refreshed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    control_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (installation_lookup, environment)
        REFERENCES hytch_push_vault.installation_states(
            installation_lookup,
            environment
        )
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    UNIQUE (lease_id, environment),
    UNIQUE (installation_lookup, topic_lookup, environment),
    CHECK (expires_at <= refreshed_at + INTERVAL '7 days'),
    CHECK (control_expires_at <= refreshed_at + INTERVAL '60 seconds')
);

CREATE INDEX subscription_leases_topic_active_idx
    ON hytch_push_vault.subscription_leases (
        environment,
        topic_lookup,
        lookup_key_epoch
    )
    WHERE state = 2;

CREATE INDEX subscription_leases_expiry_idx
    ON hytch_push_vault.subscription_leases (environment, expires_at);

CREATE TABLE hytch_push_vault.welcome_authorizations (
    authorization_id BYTEA PRIMARY KEY CHECK (octet_length(authorization_id) = 16),
    lease_id BYTEA NOT NULL,
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    envelope_lookup BYTEA NOT NULL CHECK (octet_length(envelope_lookup) = 32),
    encrypted_authorization BYTEA NOT NULL,
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch > 0),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (lease_id, environment)
        REFERENCES hytch_push_vault.subscription_leases(
            lease_id,
            environment
        )
        ON DELETE CASCADE,
    UNIQUE (environment, lease_id, envelope_lookup)
);

CREATE INDEX welcome_authorizations_expiry_idx
    ON hytch_push_vault.welcome_authorizations (environment, expires_at);

CREATE TABLE hytch_push_vault.welcome_budgets (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    destination_lookup BYTEA NOT NULL
        CHECK (octet_length(destination_lookup) = 32),
    minute_window_start TIMESTAMPTZ NOT NULL,
    minute_count SMALLINT NOT NULL CHECK (minute_count >= 0),
    hour_window_start TIMESTAMPTZ NOT NULL,
    hour_count SMALLINT NOT NULL CHECK (hour_count >= 0),
    circuit_open_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (environment, destination_lookup),
    CHECK (expires_at >= updated_at),
    CHECK (expires_at <= updated_at + INTERVAL '1 hour'),
    CHECK (
        circuit_open_until IS NULL OR
        circuit_open_until <= updated_at + INTERVAL '30 minutes'
    )
);

CREATE INDEX welcome_budgets_expiry_idx
    ON hytch_push_vault.welcome_budgets (environment, expires_at);

CREATE TABLE hytch_push_vault.welcome_global_circuit (
    environment SMALLINT PRIMARY KEY CHECK (environment IN (1, 2)),
    circuit_open_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        circuit_open_until IS NULL OR
        circuit_open_until <= updated_at + INTERVAL '30 minutes'
    )
);

INSERT INTO hytch_push_vault.welcome_global_circuit (environment)
VALUES (1), (2)
ON CONFLICT (environment) DO NOTHING;

CREATE TABLE hytch_push_vault.delivery_jobs (
    job_id BYTEA PRIMARY KEY CHECK (octet_length(job_id) = 16),
    lease_id BYTEA,
    installation_lookup BYTEA,
    encrypted_job BYTEA NOT NULL,
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    state SMALLINT NOT NULL CHECK (state IN (1, 2, 3, 4)),
    attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    retry_exponent SMALLINT NOT NULL DEFAULT 0
        CHECK (retry_exponent BETWEEN 0 AND 16),
    available_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (lease_id, environment)
        REFERENCES hytch_push_vault.subscription_leases(
            lease_id,
            environment
        )
        ON DELETE CASCADE,
    FOREIGN KEY (installation_lookup, environment)
        REFERENCES hytch_push_vault.installation_states(
            installation_lookup,
            environment
        )
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CHECK (expires_at <= created_at + INTERVAL '15 minutes'),
    CHECK (
        (
            state IN (1, 2) AND
            lease_id IS NOT NULL AND
            installation_lookup IS NULL AND
            retry_exponent = 0
        ) OR (
            state IN (3, 4) AND
            lease_id IS NULL AND
            installation_lookup IS NOT NULL
        )
    )
);

CREATE INDEX delivery_jobs_available_idx
    ON hytch_push_vault.delivery_jobs (environment, available_at)
    WHERE state IN (1, 3);

CREATE TABLE hytch_push_vault.delivery_dedupes (
    lease_id BYTEA NOT NULL,
    source_event_lookup BYTEA NOT NULL
        CHECK (octet_length(source_event_lookup) = 32),
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    traffic_class SMALLINT NOT NULL CHECK (traffic_class IN (1, 2)),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (lease_id, environment)
        REFERENCES hytch_push_vault.subscription_leases(
            lease_id,
            environment
        )
        ON DELETE CASCADE,
    PRIMARY KEY (
        environment,
        lease_id,
        source_event_lookup,
        traffic_class
    ),
    CHECK (expires_at <= created_at + INTERVAL '15 minutes')
);

CREATE INDEX delivery_dedupes_expiry_idx
    ON hytch_push_vault.delivery_dedupes (environment, expires_at);

CREATE TABLE hytch_push_vault.deletion_tombstones (
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    target_kind SMALLINT NOT NULL CHECK (target_kind IN (1, 2)),
    target_identity BYTEA NOT NULL
        CHECK (octet_length(target_identity) = 32),
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    fence_epoch BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (environment, target_kind, target_identity),
    CHECK (
        (target_kind = 1 AND fence_epoch BETWEEN 1 AND 9007199254740991) OR
        (target_kind = 2 AND fence_epoch BETWEEN 1 AND 4294967295)
    ),
    CHECK (expires_at <= created_at + INTERVAL '8 days')
);

CREATE INDEX deletion_tombstones_expiry_idx
    ON hytch_push_vault.deletion_tombstones (environment, expires_at);

CREATE TABLE hytch_push_vault.operational_aggregates (
    bucket_day DATE NOT NULL,
    bucket_hour SMALLINT CHECK (bucket_hour BETWEEN 0 AND 23),
    event_name SMALLINT NOT NULL,
    component SMALLINT NOT NULL,
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    traffic_class SMALLINT,
    outcome SMALLINT NOT NULL,
    count_bucket SMALLINT NOT NULL CHECK (count_bucket BETWEEN 1 AND 7),
    size_bucket SMALLINT,
    latency_bucket SMALLINT CHECK (latency_bucket BETWEEN 0 AND 4),
    privacy_version SMALLINT NOT NULL,
    expires_on DATE NOT NULL,
    PRIMARY KEY (
        bucket_day,
        bucket_hour,
        event_name,
        component,
        environment,
        traffic_class,
        outcome,
        privacy_version
    ),
    CHECK (expires_on <= bucket_day + 30)
);

CREATE INDEX operational_aggregates_expiry_idx
    ON hytch_push_vault.operational_aggregates (environment, expires_on);

CREATE TABLE hytch_push_vault.access_requests (
    request_id BYTEA PRIMARY KEY CHECK (octet_length(request_id) = 16),
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    purpose SMALLINT NOT NULL,
    data_class SMALLINT NOT NULL,
    requester_actor TEXT NOT NULL,
    ticket_reference TEXT NOT NULL,
    hypothesis SMALLINT NOT NULL CHECK (hypothesis IN (1, 2, 3)),
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    approver_actor TEXT,
    oversight_broadcast_hour TIMESTAMPTZ,
    coarse_created_hour TIMESTAMPTZ NOT NULL,
    role_expires_at TIMESTAMPTZ,
    state SMALLINT NOT NULL CHECK (state IN (1, 2, 3, 4)),
    UNIQUE (request_id, environment),
    CHECK (
        date_trunc('hour', coarse_created_hour AT TIME ZONE 'UTC') =
            coarse_created_hour AT TIME ZONE 'UTC'
    ),
    CHECK (window_end > window_start),
    CHECK (window_end <= window_start + INTERVAL '2 hours'),
    CHECK (
        oversight_broadcast_hour IS NULL OR
        date_trunc(
            'hour',
            oversight_broadcast_hour AT TIME ZONE 'UTC'
        ) = oversight_broadcast_hour AT TIME ZONE 'UTC'
    ),
    CHECK (
        role_expires_at IS NULL OR
        role_expires_at <= coarse_created_hour + INTERVAL '2 hours'
    ),
    CHECK (
        (
            state = 1 AND
            approver_actor IS NULL AND
            oversight_broadcast_hour IS NULL AND
            role_expires_at IS NULL
        ) OR (
            state = 2 AND
            approver_actor IS NOT NULL AND
            oversight_broadcast_hour IS NOT NULL AND
            role_expires_at IS NOT NULL
        ) OR (
            state IN (3, 4) AND
            role_expires_at IS NULL AND
            (
                (
                    approver_actor IS NULL AND
                    oversight_broadcast_hour IS NULL
                ) OR (
                    approver_actor IS NOT NULL AND
                    oversight_broadcast_hour IS NOT NULL
                )
            )
        )
    )
);

CREATE INDEX access_requests_retention_idx
    ON hytch_push_vault.access_requests (
        environment,
        coarse_created_hour
    );

CREATE TABLE hytch_push_vault.access_audit (
    event_id BYTEA PRIMARY KEY CHECK (octet_length(event_id) = 16),
    request_id BYTEA NOT NULL,
    environment SMALLINT NOT NULL CHECK (environment IN (1, 2)),
    actor TEXT NOT NULL,
    purpose SMALLINT NOT NULL,
    data_class SMALLINT NOT NULL,
    coarse_event_hour TIMESTAMPTZ NOT NULL,
    action SMALLINT NOT NULL,
    result_count_bucket SMALLINT NOT NULL,
    expires_on DATE NOT NULL,
    FOREIGN KEY (request_id, environment)
        REFERENCES hytch_push_vault.access_requests(
            request_id,
            environment
        ),
    CHECK (
        date_trunc('hour', coarse_event_hour AT TIME ZONE 'UTC') =
            coarse_event_hour AT TIME ZONE 'UTC'
    ),
    CHECK (
        expires_on <=
            (coarse_event_hour AT TIME ZONE 'UTC')::date + 180
    )
);

CREATE INDEX access_audit_expiry_idx
    ON hytch_push_vault.access_audit (environment, expires_on);

CREATE TABLE hytch_push_vault.retention_state (
    environment SMALLINT PRIMARY KEY CHECK (environment IN (1, 2)),
    last_started_at TIMESTAMPTZ,
    last_completed_at TIMESTAMPTZ,
    next_deadline_at TIMESTAMPTZ,
    is_safe BOOLEAN NOT NULL DEFAULT FALSE,
    fixed_outcome SMALLINT NOT NULL DEFAULT 1
);

INSERT INTO hytch_push_vault.retention_state (environment)
VALUES (1), (2)
ON CONFLICT (environment) DO NOTHING;

REVOKE ALL ON ALL TABLES IN SCHEMA hytch_push_vault FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA hytch_push_vault FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA hytch_push_vault FROM PUBLIC;
