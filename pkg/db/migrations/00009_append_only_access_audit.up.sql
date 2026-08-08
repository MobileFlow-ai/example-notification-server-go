LOCK TABLE hytch_push_vault.access_audit
IN ACCESS EXCLUSIVE MODE;

REVOKE ALL
    ON TABLE hytch_push_vault.access_audit
    FROM PUBLIC;

CREATE FUNCTION hytch_push_vault.reject_access_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'access audit is append-only';
END;
$function$;

REVOKE ALL
    ON FUNCTION hytch_push_vault.reject_access_audit_mutation()
    FROM PUBLIC;

CREATE TRIGGER hytch_access_audit_update_guard
BEFORE UPDATE
ON hytch_push_vault.access_audit
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_access_audit_mutation();

ALTER TABLE hytch_push_vault.access_audit
    ENABLE ALWAYS TRIGGER hytch_access_audit_update_guard;

CREATE TRIGGER hytch_access_audit_delete_guard
BEFORE DELETE
ON hytch_push_vault.access_audit
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_access_audit_mutation();

ALTER TABLE hytch_push_vault.access_audit
    ENABLE ALWAYS TRIGGER hytch_access_audit_delete_guard;

CREATE TRIGGER hytch_access_audit_truncate_guard
BEFORE TRUNCATE
ON hytch_push_vault.access_audit
FOR EACH STATEMENT
EXECUTE FUNCTION hytch_push_vault.reject_access_audit_mutation();

ALTER TABLE hytch_push_vault.access_audit
    ENABLE ALWAYS TRIGGER hytch_access_audit_truncate_guard;

CREATE FUNCTION
    hytch_push_vault.purge_expired_access_audit_development()
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    cutoff_date DATE;
    deleted_count BIGINT;
BEGIN
    cutoff_date :=
        (pg_catalog.clock_timestamp() AT TIME ZONE 'UTC')::DATE;

    ALTER TABLE hytch_push_vault.access_audit
        DISABLE TRIGGER hytch_access_audit_delete_guard;

    DELETE FROM hytch_push_vault.access_audit AS audit
     WHERE audit.environment = 1
       AND audit.expires_on <= cutoff_date;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    ALTER TABLE hytch_push_vault.access_audit
        ENABLE ALWAYS TRIGGER hytch_access_audit_delete_guard;

    RETURN deleted_count;
END;
$function$;

REVOKE ALL
    ON FUNCTION
        hytch_push_vault.purge_expired_access_audit_development()
    FROM PUBLIC;

CREATE FUNCTION
    hytch_push_vault.purge_expired_access_audit_production()
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    cutoff_date DATE;
    deleted_count BIGINT;
BEGIN
    cutoff_date :=
        (pg_catalog.clock_timestamp() AT TIME ZONE 'UTC')::DATE;

    ALTER TABLE hytch_push_vault.access_audit
        DISABLE TRIGGER hytch_access_audit_delete_guard;

    DELETE FROM hytch_push_vault.access_audit AS audit
     WHERE audit.environment = 2
       AND audit.expires_on <= cutoff_date;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    ALTER TABLE hytch_push_vault.access_audit
        ENABLE ALWAYS TRIGGER hytch_access_audit_delete_guard;

    RETURN deleted_count;
END;
$function$;

REVOKE ALL
    ON FUNCTION
        hytch_push_vault.purge_expired_access_audit_production()
    FROM PUBLIC;
