-- This security hardening is intentionally monotonic. A down migration moves
-- the schema version boundary without restoring the weaker destructive
-- function; migration 00008 removes the function if the entire secure-routing
-- feature is later rolled back under its own pre-activation safety checks.
SELECT TRUE;
