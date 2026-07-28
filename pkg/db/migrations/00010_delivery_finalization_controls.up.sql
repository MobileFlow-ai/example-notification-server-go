ALTER TABLE hytch_push_vault.delivery_jobs
    DROP CONSTRAINT delivery_jobs_state_check,
    DROP CONSTRAINT delivery_jobs_check1,
    ADD COLUMN traffic_class SMALLINT,
    ADD COLUMN final_reason SMALLINT,
    ADD CONSTRAINT delivery_jobs_state_check
        CHECK (state IN (1, 2, 3, 4, 5)),
    ADD CONSTRAINT delivery_jobs_traffic_class_check
        CHECK (
            traffic_class IS NULL OR
            traffic_class IN (0, 1, 2)
        ),
    ADD CONSTRAINT delivery_jobs_final_reason_check
        CHECK (
            final_reason IS NULL OR
            final_reason IN (1, 2, 3, 4, 5)
        ),
    ADD CONSTRAINT delivery_jobs_shape_check
        CHECK (
            (
                state IN (1, 2) AND
                lease_id IS NOT NULL AND
                installation_lookup IS NULL AND
                retry_exponent = 0 AND
                (
                    traffic_class IS NULL OR
                    traffic_class IN (1, 2)
                ) AND
                final_reason IS NULL
            ) OR (
                state IN (3, 4) AND
                lease_id IS NULL AND
                installation_lookup IS NOT NULL AND
                (
                    traffic_class IS NULL OR
                    traffic_class IN (1, 2)
                ) AND
                final_reason IS NULL
            ) OR (
                state = 5 AND
                lease_id IS NULL AND
                installation_lookup IS NULL AND
                encrypted_job = decode('00', 'hex') AND
                retry_exponent = 0 AND
                traffic_class IS NOT NULL AND
                final_reason IS NOT NULL AND
                (
                    (
                        final_reason IN (1, 2, 3) AND
                        traffic_class IN (1, 2)
                    ) OR (
                        final_reason IN (4, 5) AND
                        traffic_class IN (0, 1, 2)
                    )
                )
            )
        );

CREATE INDEX delivery_jobs_finalization_idx
    ON hytch_push_vault.delivery_jobs (environment, created_at)
    WHERE state = 5;

ALTER TABLE hytch_push_vault.operational_aggregates
    ADD CONSTRAINT operational_aggregates_component_allowlist
        CHECK (component = 1) NOT VALID,
    ADD CONSTRAINT operational_aggregates_privacy_version_allowlist
        CHECK (privacy_version IN (1, 2)) NOT VALID,
    ADD CONSTRAINT operational_aggregates_fixed_dimensions
        CHECK (
            bucket_hour IS NOT NULL AND
            traffic_class IS NOT NULL AND
            latency_bucket IS NOT NULL AND
            (
                (
                    event_name IN (1, 2) AND
                    traffic_class = 0 AND
                    outcome IN (1, 2) AND
                    size_bucket IS NULL
                ) OR (
                    event_name = 3 AND
                    traffic_class IN (0, 1, 2) AND
                    (
                        (
                            traffic_class IN (1, 2) AND
                            outcome IN (1, 2, 3)
                        ) OR
                        outcome IN (8, 9)
                    ) AND
                    size_bucket IS NOT NULL AND
                    size_bucket BETWEEN 1 AND 3
                ) OR (
                    event_name = 4 AND
                    traffic_class IN (1, 2) AND
                    outcome IN (4, 5) AND
                    size_bucket IS NOT NULL AND
                    size_bucket BETWEEN 0 AND 4 AND
                    latency_bucket = 0
                ) OR (
                    event_name = 5 AND
                    traffic_class IN (1, 2) AND
                    outcome IN (6, 7) AND
                    size_bucket IS NOT NULL AND
                    size_bucket = 0
                )
            )
        ) NOT VALID;

ALTER TABLE hytch_push_vault.operational_aggregates
    VALIDATE CONSTRAINT operational_aggregates_component_allowlist,
    VALIDATE CONSTRAINT operational_aggregates_privacy_version_allowlist,
    VALIDATE CONSTRAINT operational_aggregates_fixed_dimensions;
