DO $block$
BEGIN
    IF EXISTS (
        SELECT 1 FROM hytch_push_vault.a10_accepted_keysets
        UNION ALL
        SELECT 1 FROM hytch_push_vault.a10_keyset_state
        UNION ALL
        SELECT 1 FROM hytch_push_vault.a10_registration_replays
        UNION ALL
        SELECT 1 FROM hytch_push_vault.a10_registration_bindings
    ) THEN
        RAISE EXCEPTION 'A10 registration state exists; downgrade refused'
            USING ERRCODE = '55000';
    END IF;
END;
$block$;

DROP TRIGGER IF EXISTS hytch_a10_replays_truncate_guard
    ON hytch_push_vault.a10_registration_replays;
DROP TRIGGER IF EXISTS hytch_a10_replays_delete_guard
    ON hytch_push_vault.a10_registration_replays;
DROP TRIGGER IF EXISTS hytch_a10_replays_update_guard
    ON hytch_push_vault.a10_registration_replays;
DROP TRIGGER IF EXISTS hytch_a10_bindings_truncate_guard
    ON hytch_push_vault.a10_registration_bindings;
DROP TRIGGER IF EXISTS hytch_a10_bindings_delete_guard
    ON hytch_push_vault.a10_registration_bindings;
DROP TRIGGER IF EXISTS hytch_a10_bindings_update_guard
    ON hytch_push_vault.a10_registration_bindings;
DROP TRIGGER IF EXISTS hytch_a10_keysets_truncate_guard
    ON hytch_push_vault.a10_accepted_keysets;
DROP TRIGGER IF EXISTS hytch_a10_keysets_delete_guard
    ON hytch_push_vault.a10_accepted_keysets;
DROP TRIGGER IF EXISTS hytch_a10_keysets_update_guard
    ON hytch_push_vault.a10_accepted_keysets;

DROP FUNCTION IF EXISTS hytch_push_vault.guard_a10_replay_delete();
DROP FUNCTION IF EXISTS hytch_push_vault.reject_a10_immutable_mutation();

DROP TABLE IF EXISTS hytch_push_vault.a10_registration_bindings;
DROP TABLE IF EXISTS hytch_push_vault.a10_registration_replays;
DROP TABLE IF EXISTS hytch_push_vault.a10_keyset_state;
DROP TABLE IF EXISTS hytch_push_vault.a10_accepted_keysets;
