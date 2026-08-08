package vault

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
)

const a9MaximumClockSkew = 5 * time.Second

type a9CurrentRouteState struct {
	databaseNow          time.Time
	keysetExpiresAt      time.Time
	keysetFreshUntil     time.Time
	watermarkExpiresAt   time.Time
	assertionExpiresAt   time.Time
	installationIdentity []byte
}

func a9TrustClockAligned(managerNow, databaseNow time.Time) bool {
	if managerNow.IsZero() || databaseNow.IsZero() ||
		a9trust.TopicEpoch(managerNow.UTC()) !=
			a9trust.TopicEpoch(databaseNow.UTC()) ||
		managerNow.UTC().Format("2006-01-02") !=
			databaseNow.UTC().Format("2006-01-02") {
		return false
	}
	difference := managerNow.UTC().Sub(databaseNow.UTC())
	if difference < 0 {
		difference = -difference
	}
	return difference <= a9MaximumClockSkew
}

func a9CurrentReferenceTime(
	evaluationTime time.Time,
	hostNow time.Time,
	databaseNow time.Time,
) (time.Time, bool) {
	evaluationTime = evaluationTime.UTC()
	hostNow = hostNow.UTC()
	databaseNow = databaseNow.UTC()
	if evaluationTime.IsZero() ||
		hostNow.IsZero() ||
		databaseNow.IsZero() ||
		hostNow.Before(evaluationTime) ||
		!a9TrustClockAligned(evaluationTime, databaseNow) ||
		!a9TrustClockAligned(hostNow, databaseNow) {
		return time.Time{}, false
	}
	reference := databaseNow
	if hostNow.After(reference) {
		reference = hostNow
	}
	if evaluationTime.After(reference) {
		reference = evaluationTime
	}
	return reference, true
}

func a9RouteStillCurrentAt(
	evaluationTime time.Time,
	hostNow time.Time,
	databaseNow time.Time,
	state a9CurrentRouteState,
	snapshot *interfaces.A9RouteSnapshot,
) (time.Time, bool) {
	reference, aligned := a9CurrentReferenceTime(
		evaluationTime,
		hostNow,
		databaseNow,
	)
	if !aligned ||
		snapshot == nil ||
		!reference.Before(state.authorityExpiresAt()) {
		return time.Time{}, false
	}
	if snapshot.TopicKeyEpoch == a9trust.TopicEpoch(reference) ||
		a9trust.PreviousTopicEpochVerificationUsable(
			snapshot.TopicKeyEpoch,
			reference,
			snapshot.AssertionExpiresAt.UTC(),
			true,
		) {
		return reference, true
	}
	return time.Time{}, false
}

func (state a9CurrentRouteState) authorityExpiresAt() time.Time {
	result := state.keysetExpiresAt
	for _, candidate := range []time.Time{
		state.keysetFreshUntil,
		state.watermarkExpiresAt,
		state.assertionExpiresAt,
	} {
		if result.IsZero() || candidate.Before(result) {
			result = candidate
		}
	}
	return result.UTC()
}

// requireA9CurrentRouteTx proves that one exact route snapshot is still
// eligible. It locks in the global A9 order: keyset, retention barrier,
// installation authority, binding, then route. Callers that also own a
// delivery job and Gate-6 rows must lock those only after this method returns.
func (s *Store) requireA9CurrentRouteTx(
	ctx context.Context,
	tx *sql.Tx,
	leaseID []byte,
	snapshot *interfaces.A9RouteSnapshot,
) (a9CurrentRouteState, bool, error) {
	if s == nil || !s.a9Enabled || tx == nil || ctx == nil ||
		len(leaseID) != 16 ||
		!validA9RouteSnapshot(snapshot, snapshotRouteKeyEpoch(snapshot), time.Time{}) {
		return a9CurrentRouteState{}, false, nil
	}

	state, current, err := s.lockA9CurrentKeysetTx(ctx, tx, snapshot)
	if err != nil || !current {
		return a9CurrentRouteState{}, current, err
	}
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return a9CurrentRouteState{}, false, storeDatabaseError(err)
	}

	authority, current, err := s.lockA9CurrentAuthorityTx(
		ctx,
		tx,
		snapshot,
		state.databaseNow,
	)
	if err != nil || !current {
		return a9CurrentRouteState{}, current, err
	}
	state.watermarkExpiresAt = authority.watermarkExpiresAt

	current, err = s.lockA9CurrentBindingTx(ctx, tx, snapshot)
	if err != nil || !current {
		return a9CurrentRouteState{}, current, err
	}
	current, err = s.requireNoWinningA9TombstoneTx(ctx, tx, snapshot)
	if err != nil || !current {
		return a9CurrentRouteState{}, current, err
	}

	installationIdentity, current, err := s.lockA9CurrentRouteProjectionTx(
		ctx,
		tx,
		leaseID,
		snapshot,
	)
	if err != nil || !current {
		zero(installationIdentity)
		return a9CurrentRouteState{}, current, err
	}
	state.installationIdentity = installationIdentity

	assertion, current, err := s.loadA9CurrentAssertionTx(
		ctx,
		tx,
		snapshot,
		state.databaseNow,
	)
	if err != nil || !current {
		zero(state.installationIdentity)
		return a9CurrentRouteState{}, current, err
	}
	state.assertionExpiresAt = assertion.expiresAt

	current, err = s.requireA9CurrentDescriptorsTx(
		ctx,
		tx,
		snapshot,
		state.databaseNow,
		authority,
		assertion,
	)
	if err != nil || !current {
		zero(state.installationIdentity)
		return a9CurrentRouteState{}, current, err
	}
	return state, true, nil
}

func snapshotRouteKeyEpoch(
	snapshot *interfaces.A9RouteSnapshot,
) uint32 {
	if snapshot == nil {
		return 0
	}
	return snapshot.RouteKeyEpoch
}

func (s *Store) lockA9CurrentKeysetTx(
	ctx context.Context,
	tx *sql.Tx,
	snapshot *interfaces.A9RouteSnapshot,
) (a9CurrentRouteState, bool, error) {
	if snapshot == nil {
		return a9CurrentRouteState{}, false, nil
	}
	return s.lockA9CurrentKeysetReceiptTx(
		ctx,
		tx,
		snapshot.KeysetSequence,
		snapshot.KeysetHash,
	)
}

func (s *Store) lockA9CurrentKeysetReceiptTx(
	ctx context.Context,
	tx *sql.Tx,
	expectedSequence uint64,
	expectedHash [32]byte,
) (a9CurrentRouteState, bool, error) {
	if s == nil || tx == nil || expectedSequence == 0 ||
		expectedSequence > a9MaxSafeInteger {
		return a9CurrentRouteState{}, false, nil
	}
	var (
		databaseNow time.Time
		sequence    int64
		hash        []byte
		state       int16
		uncertainty int16
		expiresAt   sql.NullTime
		refreshedAt time.Time
	)
	err := tx.QueryRowContext(
		ctx,
		`SELECT pg_catalog.clock_timestamp(),
		        keyset_sequence, signed_keyset_hash, state,
		        uncertainty_reason, expires_at, refreshed_at
		   FROM hytch_push_vault.a9_keyset_state
		  WHERE environment = $1
		  FOR SHARE`,
		s.environmentID,
	).Scan(
		&databaseNow,
		&sequence,
		&hash,
		&state,
		&uncertainty,
		&expiresAt,
		&refreshedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return a9CurrentRouteState{}, false, nil
	}
	if err != nil {
		return a9CurrentRouteState{}, false, storeDatabaseError(err)
	}
	databaseNow = databaseNow.UTC()
	if sequence <= 0 ||
		uint64(sequence) != expectedSequence ||
		!bytes.Equal(hash, expectedHash[:]) ||
		state != 1 ||
		uncertainty != 0 ||
		!expiresAt.Valid ||
		!databaseNow.Before(expiresAt.Time.UTC()) ||
		refreshedAt.UTC().After(databaseNow) ||
		!refreshedAt.UTC().After(databaseNow.Add(-6*time.Hour)) {
		return a9CurrentRouteState{}, false, nil
	}
	return a9CurrentRouteState{
		databaseNow:      databaseNow,
		keysetExpiresAt:  expiresAt.Time.UTC(),
		keysetFreshUntil: refreshedAt.UTC().Add(6 * time.Hour),
	}, true, nil
}

type a9CurrentAuthority struct {
	watermarkIssuedAt     time.Time
	watermarkExpiresAt    time.Time
	watermarkSigningKeyID []byte
}

func (s *Store) lockA9CurrentAuthorityTx(
	ctx context.Context,
	tx *sql.Tx,
	snapshot *interfaces.A9RouteSnapshot,
	now time.Time,
) (a9CurrentAuthority, bool, error) {
	var (
		epoch              []byte
		contiguous         int64
		generation         int64
		state              int16
		uncertainty        int16
		watermarkSequence  sql.NullInt64
		watermarkCommitted sql.NullInt64
		watermarkStatus    sql.NullInt64
		watermarkReason    sql.NullInt64
		watermarkIssued    sql.NullTime
		watermarkExpires   sql.NullTime
		watermarkSigningID []byte
		watermarkKeyset    sql.NullInt64
		watermarkKeyHash   []byte
	)
	err := tx.QueryRowContext(
		ctx,
		`SELECT sequencer_epoch, contiguous_stream_sequence,
		        subscription_generation, state, uncertainty_reason,
		        watermark_sequence, watermark_committed_through,
		        watermark_status, watermark_uncertainty_reason,
		        watermark_issued_at, watermark_expires_at,
		        watermark_signing_key_id, watermark_keyset_sequence,
		        watermark_keyset_hash
		   FROM hytch_push_vault.a9_installation_authority
		  WHERE environment = $1
		    AND installation_binding_id = $2
		  FOR SHARE`,
		s.environmentID,
		snapshot.InstallationBindingID[:],
	).Scan(
		&epoch,
		&contiguous,
		&generation,
		&state,
		&uncertainty,
		&watermarkSequence,
		&watermarkCommitted,
		&watermarkStatus,
		&watermarkReason,
		&watermarkIssued,
		&watermarkExpires,
		&watermarkSigningID,
		&watermarkKeyset,
		&watermarkKeyHash,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return a9CurrentAuthority{}, false, nil
	}
	if err != nil {
		return a9CurrentAuthority{}, false, storeDatabaseError(err)
	}
	if !bytes.Equal(epoch, snapshot.SequencerEpoch[:]) ||
		contiguous < 0 ||
		uint64(contiguous) > a9MaxSafeInteger ||
		generation <= 0 ||
		uint64(generation) != snapshot.SubscriptionGeneration ||
		contiguous < int64(snapshot.AssertionStreamSequence) ||
		state != a9AuthorityActive ||
		uncertainty != 0 ||
		!watermarkSequence.Valid ||
		watermarkSequence.Int64 <= 0 ||
		uint64(watermarkSequence.Int64) > a9MaxSafeInteger ||
		watermarkSequence.Int64 < int64(snapshot.WatermarkSequence) ||
		!watermarkCommitted.Valid ||
		watermarkCommitted.Int64 < 0 ||
		uint64(watermarkCommitted.Int64) > a9MaxSafeInteger ||
		watermarkCommitted.Int64 > contiguous ||
		watermarkCommitted.Int64 < int64(snapshot.AssertionStreamSequence) ||
		!watermarkStatus.Valid ||
		watermarkStatus.Int64 != int64(a9trust.WatermarkStatusCurrent) ||
		!watermarkReason.Valid ||
		watermarkReason.Int64 != int64(a9trust.WatermarkUncertaintyNone) ||
		!watermarkIssued.Valid ||
		watermarkIssued.Time.UTC().After(now) ||
		!watermarkExpires.Valid ||
		!watermarkExpires.Time.UTC().After(
			watermarkIssued.Time.UTC(),
		) ||
		watermarkExpires.Time.UTC().Sub(
			watermarkIssued.Time.UTC(),
		) > 30*time.Second ||
		!now.Before(watermarkExpires.Time.UTC()) ||
		len(watermarkSigningID) != 32 ||
		!watermarkKeyset.Valid ||
		watermarkKeyset.Int64 != int64(snapshot.KeysetSequence) ||
		!bytes.Equal(watermarkKeyHash, snapshot.KeysetHash[:]) {
		return a9CurrentAuthority{}, false, nil
	}
	return a9CurrentAuthority{
		watermarkIssuedAt:     watermarkIssued.Time.UTC(),
		watermarkExpiresAt:    watermarkExpires.Time.UTC(),
		watermarkSigningKeyID: append([]byte(nil), watermarkSigningID...),
	}, true, nil
}

func (s *Store) lockA9CurrentBindingTx(
	ctx context.Context,
	tx *sql.Tx,
	snapshot *interfaces.A9RouteSnapshot,
) (bool, error) {
	var found bool
	err := tx.QueryRowContext(
		ctx,
		`SELECT TRUE
		   FROM hytch_push_vault.a9_bindings
		  WHERE environment = $1
		    AND installation_binding_id = $2
		    AND binding_id = $3
		    AND sequencer_epoch = $4
		    AND binding_version = $5
		    AND state = $6
		    AND active_assertion_hash = $7
		    AND active_assertion_stream_sequence = $8
		    AND active_topic_key_epoch = $9
		    AND active_topic_binding = $10
		    AND active_keyset_sequence = $11
		    AND active_keyset_hash = $12
		  FOR SHARE`,
		s.environmentID,
		snapshot.InstallationBindingID[:],
		snapshot.BindingID[:],
		snapshot.SequencerEpoch[:],
		int64(snapshot.BindingVersion),
		a9BindingActive,
		snapshot.AssertionHash[:],
		int64(snapshot.AssertionStreamSequence),
		int64(snapshot.TopicKeyEpoch),
		snapshot.TopicBinding[:],
		int64(snapshot.KeysetSequence),
		snapshot.KeysetHash[:],
	).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, storeDatabaseError(err)
	}
	return found, nil
}

func (s *Store) requireNoWinningA9TombstoneTx(
	ctx context.Context,
	tx *sql.Tx,
	snapshot *interfaces.A9RouteSnapshot,
) (bool, error) {
	var revoked bool
	if err := tx.QueryRowContext(
		ctx,
		`SELECT EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.a9_binding_tombstones
		      WHERE environment = $1
		        AND installation_binding_id = $2
		        AND binding_id = $3
		        AND binding_version >= $4
		 )`,
		s.environmentID,
		snapshot.InstallationBindingID[:],
		snapshot.BindingID[:],
		int64(snapshot.BindingVersion),
	).Scan(&revoked); err != nil {
		return false, storeDatabaseError(err)
	}
	return !revoked, nil
}

func (s *Store) lockA9CurrentRouteProjectionTx(
	ctx context.Context,
	tx *sql.Tx,
	leaseID []byte,
	snapshot *interfaces.A9RouteSnapshot,
) ([]byte, bool, error) {
	var installationIdentity []byte
	err := tx.QueryRowContext(
		ctx,
		`SELECT installation_identity
		   FROM hytch_push_vault.a9_subscription_routes
		  WHERE lease_id = $1
		    AND environment = $2
		    AND installation_binding_id = $3
		    AND sequencer_epoch = $4
		    AND subscription_generation = $5
		    AND binding_id = $6
		    AND binding_version = $7
		    AND assertion_hash = $8
		    AND assertion_stream_sequence = $9
		    AND topic_key_epoch = $10
		    AND topic_binding = $11
		    AND route_key_epoch = $12
		    AND keyset_sequence = $13
		    AND keyset_hash = $14
		    AND watermark_sequence = $15
		  FOR SHARE`,
		leaseID,
		s.environmentID,
		snapshot.InstallationBindingID[:],
		snapshot.SequencerEpoch[:],
		int64(snapshot.SubscriptionGeneration),
		snapshot.BindingID[:],
		int64(snapshot.BindingVersion),
		snapshot.AssertionHash[:],
		int64(snapshot.AssertionStreamSequence),
		int64(snapshot.TopicKeyEpoch),
		snapshot.TopicBinding[:],
		int64(snapshot.RouteKeyEpoch),
		int64(snapshot.KeysetSequence),
		snapshot.KeysetHash[:],
		int64(snapshot.WatermarkSequence),
	).Scan(&installationIdentity)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, storeDatabaseError(err)
	}
	if len(installationIdentity) != 32 {
		zero(installationIdentity)
		return nil, false, ErrStoreUnavailable
	}
	result := append([]byte(nil), installationIdentity...)
	zero(installationIdentity)
	return result, true, nil
}

type a9CurrentAssertion struct {
	issuedAt              time.Time
	expiresAt             time.Time
	signingKeyID          []byte
	tupleCommitmentKeyID  []byte
	rosterCommitmentKeyID []byte
	topicCommitmentKeyID  []byte
}

// loadA9CurrentAssertionTx intentionally does not constrain
// a9_assertions.lease_id: that column holds the signed assertion's
// modern-api roster-lease reference, while the route row's lease_id is the
// bridge-generated Gate-6 vault lease — disjoint namespaces that no code
// path ever maps onto each other (the replacement request carries no
// assertion lease id). The route-to-assertion linkage the contract requires
// is enforced by assertion_hash plus the identity predicates below, and the
// route row itself was already matched and locked field-for-field by
// lockA9CurrentRouteProjectionTx, including its own lease_id.
func (s *Store) loadA9CurrentAssertionTx(
	ctx context.Context,
	tx *sql.Tx,
	snapshot *interfaces.A9RouteSnapshot,
	now time.Time,
) (a9CurrentAssertion, bool, error) {
	var assertion a9CurrentAssertion
	err := tx.QueryRowContext(
		ctx,
		`SELECT issued_at, expires_at, signing_key_id,
		        tuple_commitment_key_id, roster_commitment_key_id,
		        topic_commitment_key_id
		   FROM hytch_push_vault.a9_assertions
		  WHERE environment = $1
		    AND assertion_hash = $2
		    AND installation_binding_id = $3
		    AND sequencer_epoch = $4
		    AND assertion_stream_sequence = $5
		    AND binding_id = $6
		    AND binding_version = $7
		    AND topic_key_epoch = $8
		    AND topic_binding = $9
		    AND keyset_sequence = $10
		    AND keyset_hash = $11`,
		s.environmentID,
		snapshot.AssertionHash[:],
		snapshot.InstallationBindingID[:],
		snapshot.SequencerEpoch[:],
		int64(snapshot.AssertionStreamSequence),
		snapshot.BindingID[:],
		int64(snapshot.BindingVersion),
		int64(snapshot.TopicKeyEpoch),
		snapshot.TopicBinding[:],
		int64(snapshot.KeysetSequence),
		snapshot.KeysetHash[:],
	).Scan(
		&assertion.issuedAt,
		&assertion.expiresAt,
		&assertion.signingKeyID,
		&assertion.tupleCommitmentKeyID,
		&assertion.rosterCommitmentKeyID,
		&assertion.topicCommitmentKeyID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return a9CurrentAssertion{}, false, nil
	}
	if err != nil {
		return a9CurrentAssertion{}, false, storeDatabaseError(err)
	}
	assertion.issuedAt = assertion.issuedAt.UTC()
	assertion.expiresAt = assertion.expiresAt.UTC()
	if assertion.issuedAt.After(now) ||
		!assertion.expiresAt.After(assertion.issuedAt) ||
		assertion.expiresAt.Sub(assertion.issuedAt) > 30*time.Second ||
		!now.Before(assertion.expiresAt) ||
		!assertion.expiresAt.Equal(snapshot.AssertionExpiresAt.UTC()) ||
		len(assertion.signingKeyID) != 32 ||
		len(assertion.tupleCommitmentKeyID) != 32 ||
		len(assertion.rosterCommitmentKeyID) != 32 ||
		len(assertion.topicCommitmentKeyID) != 32 {
		return a9CurrentAssertion{}, false, nil
	}
	return assertion, true, nil
}

func (s *Store) requireA9CurrentDescriptorsTx(
	ctx context.Context,
	tx *sql.Tx,
	snapshot *interfaces.A9RouteSnapshot,
	now time.Time,
	authority a9CurrentAuthority,
	assertion a9CurrentAssertion,
) (bool, error) {
	var descriptorsCurrent bool
	err := tx.QueryRowContext(
		ctx,
		`SELECT
		   EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.a9_online_key_descriptors
		      WHERE environment = $1
		        AND keyset_sequence = $2
		        AND key_use = 1
		        AND key_id = $3
		        AND not_before <= $4
		        AND not_before <= $5
		        AND not_after >= $6
		        AND not_after > $5
		   )
		   AND EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.a9_online_key_descriptors
		      WHERE environment = $1
		        AND keyset_sequence = $2
		        AND key_use = 1
		        AND key_id = $7
		        AND not_before <= $8
		        AND not_before <= $5
		        AND not_after >= $9
		        AND not_after > $5
		   )
		   AND EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.a9_commitment_key_descriptors
		      WHERE environment = $1
		        AND keyset_sequence = $2
		        AND purpose = 1
		        AND key_id = $10
		        AND topic_key_epoch IS NULL
		        AND not_before <= $4
		        AND not_before <= $5
		        AND not_after >= $6
		        AND not_after > $5
		   )
		   AND EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.a9_commitment_key_descriptors
		      WHERE environment = $1
		        AND keyset_sequence = $2
		        AND purpose = 2
		        AND key_id = $11
		        AND topic_key_epoch IS NULL
		        AND not_before <= $4
		        AND not_before <= $5
		        AND not_after >= $6
		        AND not_after > $5
		   )
		   AND EXISTS (
		     SELECT 1
		       FROM hytch_push_vault.a9_commitment_key_descriptors
		      WHERE environment = $1
		        AND keyset_sequence = $2
		        AND purpose = 3
		        AND key_id = $12
		        AND topic_key_epoch = $13
		        AND not_before <= $4
		        AND not_before <= $5
		        AND not_after >= $6
		        AND not_after > $5
		   )`,
		s.environmentID,
		int64(snapshot.KeysetSequence),
		assertion.signingKeyID,
		assertion.issuedAt,
		now,
		assertion.expiresAt,
		authority.watermarkSigningKeyID,
		authority.watermarkIssuedAt,
		authority.watermarkExpiresAt,
		assertion.rosterCommitmentKeyID,
		assertion.tupleCommitmentKeyID,
		assertion.topicCommitmentKeyID,
		int64(snapshot.TopicKeyEpoch),
	).Scan(&descriptorsCurrent)
	if err != nil {
		return false, storeDatabaseError(err)
	}
	return descriptorsCurrent, nil
}
