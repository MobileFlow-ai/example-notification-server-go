package vault

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	maxInstallationTombstoneFenceEpoch = uint64(1<<53 - 1)
	maxDeletionTombstoneKeyVersion     = uint32(1<<31 - 1)
)

func upsertDeletionTombstone(
	ctx context.Context,
	tx *sql.Tx,
	environmentID int16,
	targetKind int16,
	targetIdentity []byte,
	keyVersion uint32,
	fenceEpoch uint64,
	now time.Time,
) error {
	if tx == nil ||
		(environmentID != environmentDevelopment &&
			environmentID != environmentProduction) ||
		len(targetIdentity) != 32 ||
		keyVersion == 0 ||
		keyVersion > maxDeletionTombstoneKeyVersion ||
		!validDeletionTombstoneFence(targetKind, fenceEpoch) {
		return ErrStoreUnavailable
	}
	now = now.UTC()
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.deletion_tombstones AS tombstone (
			     environment, target_kind, target_identity,
			     key_version, fence_epoch,
			     created_at, expires_at
			 ) VALUES ($1,$2,$3,$4,$5,$6,$7)
			 ON CONFLICT (
			   environment, target_kind, target_identity
			 ) DO UPDATE SET
		     key_version = CASE
		         WHEN EXCLUDED.fence_epoch >= tombstone.fence_epoch
		         THEN EXCLUDED.key_version
		         ELSE tombstone.key_version
		     END,
		     fence_epoch = GREATEST(
		         tombstone.fence_epoch,
		         EXCLUDED.fence_epoch
		     ),
		     created_at = CASE
		         WHEN EXCLUDED.fence_epoch >= tombstone.fence_epoch
		         THEN EXCLUDED.created_at
		         ELSE tombstone.created_at
		     END,
		     expires_at = CASE
		         WHEN EXCLUDED.fence_epoch >= tombstone.fence_epoch
		         THEN EXCLUDED.expires_at
		         ELSE tombstone.expires_at
		     END`,
		environmentID,
		targetKind,
		targetIdentity,
		int32(keyVersion),
		int64(fenceEpoch),
		now,
		now.Add(8*24*time.Hour),
	); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

// requireTombstoneAdvance rejects resurrection at or below an active deletion
// fence. Callers must hold the same transaction through the subsequent
// installation or lease upsert so the row lock closes the check/write race.
func requireTombstoneAdvance(
	ctx context.Context,
	tx *sql.Tx,
	environmentID int16,
	targetKind int16,
	targetIdentity []byte,
	proposedEpoch uint64,
	now time.Time,
) error {
	if tx == nil ||
		(environmentID != environmentDevelopment &&
			environmentID != environmentProduction) ||
		len(targetIdentity) != 32 ||
		!validDeletionTombstoneFence(targetKind, proposedEpoch) {
		return ErrStoreUnavailable
	}
	var fenceEpoch int64
	err := tx.QueryRowContext(
		ctx,
		`SELECT fence_epoch
			   FROM hytch_push_vault.deletion_tombstones
			  WHERE environment = $1
			    AND target_kind = $2
			    AND target_identity = $3
			    AND expires_at > $4
			  FOR UPDATE`,
		environmentID,
		targetKind,
		targetIdentity,
		now.UTC(),
	).Scan(&fenceEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil ||
		fenceEpoch <= 0 ||
		!validDeletionTombstoneFence(targetKind, uint64(fenceEpoch)) {
		return ErrStoreUnavailable
	}
	if proposedEpoch <= uint64(fenceEpoch) {
		return ErrRefreshConflict
	}
	return nil
}

func validDeletionTombstoneFence(
	targetKind int16,
	fenceEpoch uint64,
) bool {
	switch targetKind {
	case deletionTargetInstallation:
		return fenceEpoch > 0 &&
			fenceEpoch <= maxInstallationTombstoneFenceEpoch
	case deletionTargetRoute:
		return fenceEpoch > 0 &&
			fenceEpoch <= uint64(maxRouteKeyEpoch)
	default:
		return false
	}
}

// ReapplyDeletionTombstones is the mandatory pre-egress restore gate. Operators
// import the controlled append-only tombstone export into this table first;
// this transaction then removes restored installation or route versions that
// are at or below their stable, typed deletion fence before routing or APNS
// workers are started. A later, explicitly authorized higher policy or route
// epoch with the same stable identity is not erased by an older marker.
func (s *Store) ReapplyDeletionTombstones(ctx context.Context) error {
	if s == nil || s.db == nil || s.lookup == nil {
		return ErrStoreUnavailable
	}
	tx, err := s.db.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelSerializable},
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if err = requireLookupKeyBoundTx(
		ctx,
		tx,
		s.lookup,
		s.environmentID,
	); err != nil {
		return ErrStoreUnavailable
	}
	now := s.now().UTC()
	if _, err = tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.deletion_tombstones
			  WHERE expires_at <= $1
			    AND environment = $2`,
		now,
		s.environmentID,
	); err != nil {
		return ErrStoreUnavailable
	}
	if err = s.markTombstonedDeliveryJobsTx(ctx, tx, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.subscription_leases AS lease
			  USING hytch_push_vault.deletion_tombstones AS tombstone
			  WHERE tombstone.environment = $1
			    AND lease.environment = $1
			    AND tombstone.target_kind = $2
			    AND tombstone.target_identity = lease.route_identity
			    AND tombstone.expires_at > $3
			    AND lease.route_key_epoch <= tombstone.fence_epoch`,
		s.environmentID,
		deletionTargetRoute,
		now,
	); err != nil {
		return ErrStoreUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.installation_states AS installation
			  USING hytch_push_vault.deletion_tombstones AS tombstone
			  WHERE tombstone.environment = $1
			    AND installation.environment = $1
			    AND tombstone.target_kind = $2
			    AND tombstone.target_identity =
			        installation.installation_identity
			    AND tombstone.expires_at > $3
			    AND installation.policy_epoch <= tombstone.fence_epoch`,
		s.environmentID,
		deletionTargetInstallation,
		now,
	); err != nil {
		return ErrStoreUnavailable
	}
	if err = tx.Commit(); err != nil {
		return ErrStoreUnavailable
	}
	if err = s.finalizeDeliveryMarkers(ctx); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *Store) markTombstonedDeliveryJobsTx(
	ctx context.Context,
	tx *sql.Tx,
	now time.Time,
) error {
	rows, err := tx.QueryContext(
		ctx,
		`SELECT lease.lease_id
		   FROM hytch_push_vault.subscription_leases AS lease
		   JOIN hytch_push_vault.deletion_tombstones AS tombstone
		     ON tombstone.target_identity = lease.route_identity
		  WHERE tombstone.environment = $1
		    AND lease.environment = $1
		    AND tombstone.target_kind = $2
		    AND tombstone.expires_at > $3
		    AND lease.route_key_epoch <= tombstone.fence_epoch
		  FOR UPDATE OF lease`,
		s.environmentID,
		deletionTargetRoute,
		now,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	var leaseIDs [][]byte
	for rows.Next() {
		var leaseID []byte
		if err = rows.Scan(&leaseID); err != nil {
			_ = rows.Close()
			return ErrStoreUnavailable
		}
		leaseIDs = append(leaseIDs, leaseID)
	}
	if err = rows.Close(); err != nil {
		return ErrStoreUnavailable
	}
	if err = rows.Err(); err != nil {
		return ErrStoreUnavailable
	}
	for _, leaseID := range leaseIDs {
		if err = s.markDeliveryJobsSafetyForLeaseTx(
			ctx,
			tx,
			leaseID,
		); err != nil {
			return ErrStoreUnavailable
		}
	}

	rows, err = tx.QueryContext(
		ctx,
		`SELECT installation.installation_lookup
		   FROM hytch_push_vault.installation_states AS installation
		   JOIN hytch_push_vault.deletion_tombstones AS tombstone
		     ON tombstone.target_identity =
		        installation.installation_identity
		  WHERE tombstone.environment = $1
		    AND installation.environment = $1
		    AND tombstone.target_kind = $2
		    AND tombstone.expires_at > $3
		    AND installation.policy_epoch <= tombstone.fence_epoch
		  FOR UPDATE OF installation`,
		s.environmentID,
		deletionTargetInstallation,
		now,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	var installationLookups [][]byte
	for rows.Next() {
		var installationLookup []byte
		if err = rows.Scan(&installationLookup); err != nil {
			_ = rows.Close()
			return ErrStoreUnavailable
		}
		installationLookups = append(
			installationLookups,
			installationLookup,
		)
	}
	if err = rows.Close(); err != nil {
		return ErrStoreUnavailable
	}
	if err = rows.Err(); err != nil {
		return ErrStoreUnavailable
	}
	for _, installationLookup := range installationLookups {
		if err = s.markDeliveryJobsSafetyForInstallationTx(
			ctx,
			tx,
			installationLookup,
			nil,
		); err != nil {
			return ErrStoreUnavailable
		}
	}
	return nil
}
