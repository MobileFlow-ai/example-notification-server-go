LOCK TABLE hytch_push_vault.access_audit
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM hytch_push_vault.access_audit
    ) THEN
        RAISE EXCEPTION
            'cannot remove access audit barrier while audit history exists';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS hytch_access_audit_truncate_guard
    ON hytch_push_vault.access_audit;
DROP TRIGGER IF EXISTS hytch_access_audit_delete_guard
    ON hytch_push_vault.access_audit;
DROP TRIGGER IF EXISTS hytch_access_audit_update_guard
    ON hytch_push_vault.access_audit;

DROP FUNCTION IF EXISTS
    hytch_push_vault.purge_expired_access_audit_production();
DROP FUNCTION IF EXISTS
    hytch_push_vault.purge_expired_access_audit_development();
DROP FUNCTION IF EXISTS
    hytch_push_vault.reject_access_audit_mutation();
