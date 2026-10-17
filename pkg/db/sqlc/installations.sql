-- name: UpsertInstallation :exec
INSERT INTO installations (id, payload_format)
VALUES (sqlc.arg(id), sqlc.arg(payload_format))
ON CONFLICT (id) DO UPDATE
SET deleted_at = NULL,
    payload_format = EXCLUDED.payload_format;

-- name: UpsertDeviceDeliveryMechanism :exec
INSERT INTO device_delivery_mechanisms (
    installation_id,
    kind,
    token,
    updated_at
)
VALUES (
    sqlc.arg(installation_id),
    sqlc.arg(kind),
    sqlc.arg(token),
    COALESCE(sqlc.narg(updated_at), clock_timestamp())
)
ON CONFLICT (installation_id, kind, token) DO UPDATE
SET updated_at = EXCLUDED.updated_at, invalidated_at = NULL,
    registration_version = device_delivery_mechanisms.registration_version + 1;

-- name: SoftDeleteInstallation :exec
UPDATE installations
SET deleted_at = sqlc.arg(deleted_at)
WHERE id = sqlc.arg(id);

-- name: GetLatestInstallations :many
SELECT ddm.id, ddm.installation_id, ddm.kind, ddm.token, ddm.created_at, ddm.updated_at, ddm.registration_version, i.payload_format
FROM installations i
JOIN LATERAL (
    SELECT d.id, d.installation_id, d.kind, d.token, d.created_at, d.updated_at, d.invalidated_at, d.registration_version
    FROM device_delivery_mechanisms d
    WHERE d.installation_id = i.id
    ORDER BY d.updated_at DESC, d.id DESC
    LIMIT 1
) ddm ON TRUE
WHERE i.id = ANY(sqlc.arg(installation_ids)::text[])
  AND i.deleted_at IS NULL
  AND ddm.invalidated_at IS NULL
ORDER BY i.id DESC;

-- name: InvalidateDeliveryToken :exec
UPDATE device_delivery_mechanisms
SET invalidated_at = clock_timestamp()
WHERE installation_id = sqlc.arg(installation_id)
  AND kind = sqlc.arg(kind)
  AND token = sqlc.arg(token)
  AND updated_at = sqlc.arg(expected_updated_at)
  AND registration_version = sqlc.arg(expected_registration_version)
  AND (sqlc.narg(invalid_before)::timestamptz IS NULL
       OR updated_at <= sqlc.narg(invalid_before)::timestamptz);
