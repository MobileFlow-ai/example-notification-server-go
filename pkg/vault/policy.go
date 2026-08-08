package vault

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/authority"
)

type PolicyAdvanceRequest struct {
	Control authority.PolicyControlV1
}

func (s *Store) AdvancePolicy(
	ctx context.Context,
	request PolicyAdvanceRequest,
) error {
	now := s.now().UTC()
	if err := authority.VerifyPolicyControl(
		request.Control,
		s.authorityKeys,
		authority.PolicyVerifyOptions{
			Now:                          now,
			ExpectedEnvironment:          s.environment,
			ExpectedInstallationID:       request.Control.InstallationID,
			ExpectedAccountIncarnationID: request.Control.AccountIncarnationID,
		},
	); err != nil {
		return ErrRefreshInvalid
	}
	if request.Control.State == authority.PolicyStateActive &&
		request.Control.AgePolicy == authority.AgePolicyTeen &&
		!s.teenConversationEnabled {
		return ErrRefreshInvalid
	}
	if request.Control.State == authority.PolicyStateActive {
		if err := s.RequireRetentionSafe(ctx); err != nil {
			return ErrStoreUnavailable
		}
	}
	eventDigest, err := controlDigest(request.Control)
	if err != nil {
		return err
	}
	controlExpiresAt, err := time.Parse(
		time.RFC3339Nano,
		request.Control.ExpiresAt,
	)
	if err != nil {
		return ErrRefreshInvalid
	}
	controlTTL := time.Minute
	if request.Control.AgePolicy == authority.AgePolicyTeen {
		controlTTL = 30 * time.Second
	}
	if maximum := now.Add(controlTTL); controlExpiresAt.After(maximum) {
		controlExpiresAt = maximum
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ErrStoreUnavailable
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if request.Control.State == authority.PolicyStateActive {
		if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
			return ErrStoreUnavailable
		}
	} else if err = requireLookupKeyBoundTx(
		ctx,
		tx,
		s.lookup,
		s.environmentID,
	); err != nil {
		return ErrStoreUnavailable
	}

	existing, err := s.findInstallation(
		ctx,
		tx,
		request.Control.InstallationID,
		now,
	)
	if err != nil {
		return err
	}
	// An active event cannot create a route by itself. A revoke that wins a race
	// with first registration must persist its policy epoch, though, or a
	// still-fresh lower-epoch active control could create a route afterward.
	if existing == nil {
		if request.Control.State == authority.PolicyStateActive {
			return tx.Commit()
		}
		lookupEpoch := LookupEpoch(now)
		installationLookup, lookupErr := s.environmentLookupDigest(
			"installation",
			lookupEpoch,
			[]byte(request.Control.InstallationID),
		)
		if lookupErr != nil {
			return ErrStoreUnavailable
		}
		incarnationLookup, lookupErr := s.environmentLookupDigest(
			"incarnation",
			lookupEpoch,
			[]byte(request.Control.AccountIncarnationID),
		)
		if lookupErr != nil {
			return ErrStoreUnavailable
		}
		installationIdentity, lookupErr :=
			s.installationDeletionIdentity(
				request.Control.InstallationID,
			)
		if lookupErr != nil {
			return ErrStoreUnavailable
		}
		ageID := ageAdult
		if request.Control.AgePolicy == authority.AgePolicyTeen {
			ageID = ageTeen
		}
		if _, err = tx.ExecContext(
			ctx,
			`INSERT INTO hytch_push_vault.installation_states (
			     installation_lookup, installation_identity,
			     incarnation_lookup, lookup_key_epoch,
			     generation, idempotency_digest, control_event_digest,
			     encrypted_apns_token, environment, payload_schema,
			     age_policy, policy_epoch, state, encryption_key_version,
			     created_at, refreshed_at, expires_at, control_expires_at,
			     revoked_at
			 ) VALUES (
			     $1,$2,$3,$4,0,$5,$5,NULL,$6,1,$7,$8,$9,$10,
			     $11,$11,$12,$13,$11
			 )`,
			installationLookup,
			installationIdentity,
			incarnationLookup,
			int64(lookupEpoch),
			eventDigest[:],
			s.environmentID,
			ageID,
			int64(request.Control.PolicyEpoch),
			stateRevoking,
			int32(s.encryption.ActiveVersion()),
			now,
			now.Add(s.leaseTTL),
			controlExpiresAt.UTC(),
		); err != nil {
			return ErrStoreUnavailable
		}
		if err = upsertDeletionTombstone(
			ctx,
			tx,
			s.environmentID,
			deletionTargetInstallation,
			installationIdentity,
			s.encryption.ActiveVersion(),
			request.Control.PolicyEpoch,
			now,
		); err != nil {
			return err
		}
		return tx.Commit()
	}
	controlIncarnationLookup, err := s.environmentLookupDigest(
		"incarnation",
		existing.lookupKeyEpoch,
		[]byte(request.Control.AccountIncarnationID),
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !equalBytes(controlIncarnationLookup, existing.incarnationLookup) {
		return ErrRefreshConflict
	}

	var currentState int16
	var currentDigest []byte
	if err = tx.QueryRowContext(
		ctx,
		`SELECT state, control_event_digest
			 FROM hytch_push_vault.installation_states
			 WHERE installation_lookup = $1
			   AND environment = $2
			 FOR UPDATE`,
		existing.lookup,
		s.environmentID,
	).Scan(&currentState, &currentDigest); err != nil {
		return ErrStoreUnavailable
	}
	if request.Control.PolicyEpoch < existing.policyEpoch {
		return ErrRefreshConflict
	}
	if request.Control.PolicyEpoch == existing.policyEpoch {
		if !equalDigest(currentDigest, eventDigest[:]) {
			return ErrRefreshConflict
		}
		return tx.Commit()
	}

	ageID := ageAdult
	if request.Control.AgePolicy == authority.AgePolicyTeen {
		ageID = ageTeen
	}
	switch request.Control.State {
	case authority.PolicyStateRevoked:
		if err = s.revokeAllLeases(ctx, tx, existing.lookup, now); err != nil {
			return err
		}
		if err = upsertDeletionTombstone(
			ctx,
			tx,
			s.environmentID,
			deletionTargetInstallation,
			existing.identity,
			existing.encryptionKeyVersion,
			request.Control.PolicyEpoch,
			now,
		); err != nil {
			return err
		}
		if _, err = tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.installation_states
			 SET encrypted_apns_token = NULL,
			     age_policy = $2,
			     policy_epoch = $3,
			     state = $4,
			     control_event_digest = $5,
				     control_expires_at = $6,
				     revoked_at = $7,
				     refreshed_at = $7
				 WHERE installation_lookup = $1
				   AND environment = $8`,
			existing.lookup,
			ageID,
			int64(request.Control.PolicyEpoch),
			stateRevoking,
			eventDigest[:],
			controlExpiresAt.UTC(),
			now,
			s.environmentID,
		); err != nil {
			return ErrStoreUnavailable
		}
	case authority.PolicyStateActive:
		// A newer allow epoch without matching fresh per-topic capabilities can
		// only block existing routes. Atomic full refresh is the sole transition
		// back to ACTIVE.
		if currentState == stateRevoking || currentState == stateExpired {
			return ErrRefreshConflict
		}
		if _, err = tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.installation_states
			 SET age_policy = $2,
			     policy_epoch = $3,
			     state = $4,
				     control_event_digest = $5,
				     control_expires_at = $6,
				     refreshed_at = $7
				 WHERE installation_lookup = $1
				   AND environment = $8`,
			existing.lookup,
			ageID,
			int64(request.Control.PolicyEpoch),
			stateAwaitingRefresh,
			eventDigest[:],
			controlExpiresAt.UTC(),
			now,
			s.environmentID,
		); err != nil {
			return ErrStoreUnavailable
		}
		if _, err = tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.subscription_leases
				 SET state = $2, policy_epoch = $3, control_expires_at = $4,
				     refreshed_at = $5
				 WHERE installation_lookup = $1
				   AND environment = $6`,
			existing.lookup,
			stateAwaitingRefresh,
			int64(request.Control.PolicyEpoch),
			controlExpiresAt.UTC(),
			now,
			s.environmentID,
		); err != nil {
			return ErrStoreUnavailable
		}
	default:
		return ErrRefreshInvalid
	}
	if err = tx.Commit(); err != nil {
		return ErrStoreUnavailable
	}
	if err = s.finalizeDeliveryMarkers(ctx); err != nil {
		return ErrStoreUnavailable
	}
	outcome := aggregateOutcomeActive
	if request.Control.State == authority.PolicyStateRevoked {
		outcome = aggregateOutcomeRevoked
	}
	issuedAt, parseErr := time.Parse(time.RFC3339Nano, request.Control.IssuedAt)
	if parseErr == nil {
		_ = s.RecordOperationalAggregate(
			ctx,
			aggregateEventSafetyControl,
			outcome,
			revocationLatencyBucket(now.Sub(issuedAt.UTC())),
		)
	}
	return nil
}

func (s *Store) revokeAllLeases(
	ctx context.Context,
	tx *sql.Tx,
	installationLookup []byte,
	now time.Time,
) error {
	if err := s.markDeliveryJobsSafetyForInstallationTx(
		ctx,
		tx,
		installationLookup,
		nil,
	); err != nil {
		return ErrStoreUnavailable
	}
	rows, err := tx.QueryContext(
		ctx,
		`SELECT route_identity, route_key_epoch, encryption_key_version
			 FROM hytch_push_vault.subscription_leases
			 WHERE installation_lookup = $1
			   AND environment = $2
			 FOR UPDATE`,
		installationLookup,
		s.environmentID,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	type leaseIdentity struct {
		routeIdentity        []byte
		routeKeyEpoch        int64
		encryptionKeyVersion uint32
	}
	var leases []leaseIdentity
	for rows.Next() {
		var lease leaseIdentity
		if err = rows.Scan(
			&lease.routeIdentity,
			&lease.routeKeyEpoch,
			&lease.encryptionKeyVersion,
		); err != nil {
			_ = rows.Close()
			return ErrStoreUnavailable
		}
		leases = append(leases, lease)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return ErrStoreUnavailable
	}
	_ = rows.Close()
	for _, lease := range leases {
		if lease.routeKeyEpoch <= 0 ||
			lease.routeKeyEpoch > maxRouteKeyEpoch ||
			retireRouteKeyHistory(
				ctx,
				tx,
				s.environmentID,
				lease.routeIdentity,
				uint32(lease.routeKeyEpoch),
				now,
			) != nil {
			return ErrStoreUnavailable
		}
		if err = upsertDeletionTombstone(
			ctx,
			tx,
			s.environmentID,
			deletionTargetRoute,
			lease.routeIdentity,
			lease.encryptionKeyVersion,
			uint64(lease.routeKeyEpoch),
			now,
		); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.subscription_leases
			 WHERE installation_lookup = $1
			   AND environment = $2`,
		installationLookup,
		s.environmentID,
	); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func equalDigest(left, right []byte) bool {
	if len(left) != sha256.Size || len(right) != sha256.Size {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
