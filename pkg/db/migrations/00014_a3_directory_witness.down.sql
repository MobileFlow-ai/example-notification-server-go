-- Hold the table against all writers before proving it is dormant. This
-- prevents a state-bearing witness deployment from being silently downgraded.
LOCK TABLE hytch_push_vault.a3_directory_witness_heads
IN ACCESS EXCLUSIVE MODE;

DO $block$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM hytch_push_vault.a3_directory_witness_heads
    ) THEN
        RAISE EXCEPTION 'A3 witness state exists; downgrade refused'
            USING ERRCODE = '55000';
    END IF;
END;
$block$;

DROP TRIGGER IF EXISTS hytch_a3_witness_truncate_guard
    ON hytch_push_vault.a3_directory_witness_heads;
DROP TRIGGER IF EXISTS hytch_a3_witness_delete_guard
    ON hytch_push_vault.a3_directory_witness_heads;
DROP TRIGGER IF EXISTS hytch_a3_witness_update_guard
    ON hytch_push_vault.a3_directory_witness_heads;

DROP FUNCTION IF EXISTS hytch_push_vault.reject_a3_witness_mutation();
DROP TABLE IF EXISTS hytch_push_vault.a3_directory_witness_heads;
