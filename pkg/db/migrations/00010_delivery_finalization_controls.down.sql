DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM hytch_push_vault.delivery_jobs
         WHERE state = 5
    ) THEN
        RAISE EXCEPTION
            'cannot remove delivery finalization controls while final markers exist';
    END IF;
END
$$;

DROP INDEX hytch_push_vault.delivery_jobs_finalization_idx;

ALTER TABLE hytch_push_vault.delivery_jobs
    DROP CONSTRAINT delivery_jobs_shape_check,
    DROP CONSTRAINT delivery_jobs_final_reason_check,
    DROP CONSTRAINT delivery_jobs_traffic_class_check,
    DROP CONSTRAINT delivery_jobs_state_check,
    DROP COLUMN final_reason,
    DROP COLUMN traffic_class,
    ADD CONSTRAINT delivery_jobs_state_check
        CHECK (state IN (1, 2, 3, 4)),
    ADD CONSTRAINT delivery_jobs_check1
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
        );

ALTER TABLE hytch_push_vault.operational_aggregates
    DROP CONSTRAINT operational_aggregates_fixed_dimensions,
    DROP CONSTRAINT operational_aggregates_privacy_version_allowlist,
    DROP CONSTRAINT operational_aggregates_component_allowlist;
