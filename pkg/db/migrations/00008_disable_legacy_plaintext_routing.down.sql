DO $guard$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM hytch_push_vault.legacy_routing_activation
    ) OR pg_catalog.to_regclass('public.installations') IS NULL
       OR pg_catalog.to_regclass(
           'public.device_delivery_mechanisms'
       ) IS NULL
       OR pg_catalog.to_regclass('public.subscriptions') IS NULL
       OR pg_catalog.to_regclass(
           'public.subscription_hmac_keys'
       ) IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'activated legacy routing retirement is irreversible';
    END IF;
END;
$guard$;

LOCK TABLE
    public.installations,
    public.device_delivery_mechanisms,
    public.subscriptions,
    public.subscription_hmac_keys
IN ACCESS EXCLUSIVE MODE;
LOCK TABLE hytch_push_vault.legacy_routing_activation
IN ACCESS EXCLUSIVE MODE;

DROP TRIGGER IF EXISTS hytch_legacy_activation_truncate_guard
    ON hytch_push_vault.legacy_routing_activation;
DROP TRIGGER IF EXISTS hytch_legacy_activation_dml_guard
    ON hytch_push_vault.legacy_routing_activation;
DROP TRIGGER IF EXISTS hytch_legacy_activation_insert_guard
    ON hytch_push_vault.legacy_routing_activation;

DROP FUNCTION IF EXISTS
    hytch_push_vault.activate_legacy_routing_retirement(TEXT);
DROP FUNCTION IF EXISTS
    hytch_push_vault.reject_legacy_routing_mutation();
DROP TABLE IF EXISTS hytch_push_vault.legacy_routing_activation;
