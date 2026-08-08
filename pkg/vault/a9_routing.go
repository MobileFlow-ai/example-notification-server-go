package vault

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

type a9TopicLookupCandidate struct {
	topicKeyEpoch uint32
	topicBinding  [32]byte
}

type a9RouteCandidate struct {
	leaseID  []byte
	snapshot interfaces.A9RouteSnapshot
}

type a9CurrentRouteCandidate struct {
	route a9RouteCandidate
	state a9CurrentRouteState
}

type a9PreparedRouteCurrentness struct {
	snapshot       interfaces.A9RouteSnapshot
	state          a9CurrentRouteState
	gate6ExpiresAt time.Time
}

func (s *Store) getSubscriptionsA9Once(
	ctx context.Context,
	requestedTopic *topicpkg.Topic,
	thirtyDayPeriod int,
) ([]interfaces.Subscription, error) {
	if s == nil || s.db == nil || !s.a9Enabled || s.a9Trust == nil ||
		requestedTopic == nil ||
		requestedTopic.Kind() != topicpkg.TopicKindGroupMessagesV1 ||
		len(requestedTopic.Bytes()) != 33 ||
		thirtyDayPeriod < 0 {
		return nil, ErrRefreshInvalid
	}
	now := s.now().UTC()
	lease, keysetSequence, keysetHash, err :=
		s.a9Trust.AcquireCurrentTopicBindingLease(ctx, now)
	if err != nil || lease == nil || keysetSequence == 0 {
		if lease != nil {
			lease.Close()
		}
		return nil, ErrStoreUnavailable
	}
	candidates, verdict := lease.CandidateTopicBindings(
		ctx,
		requestedTopic.Bytes(),
		now,
	)
	if !verdict.IsEligible() || len(candidates) == 0 ||
		len(candidates) > 2 {
		lease.Close()
		return nil, ErrStoreUnavailable
	}
	currentEpoch := a9trust.TopicEpoch(now)
	lookups := make([]a9TopicLookupCandidate, 0, len(candidates))
	for index := range candidates {
		candidate := candidates[index]
		expectedEpoch := currentEpoch
		if index == 1 && currentEpoch > 0 {
			expectedEpoch = currentEpoch - 1
		}
		if candidate.TopicKeyEpoch == 0 ||
			candidate.TopicKeyEpoch != expectedEpoch {
			lease.Close()
			return nil, ErrStoreUnavailable
		}
		lookups = append(lookups, a9TopicLookupCandidate{
			topicKeyEpoch: candidate.TopicKeyEpoch,
			topicBinding:  candidate.TopicBinding,
		})
	}
	return s.getSubscriptionsA9WithLease(
		ctx,
		requestedTopic,
		thirtyDayPeriod,
		now,
		keysetSequence,
		keysetHash,
		lease,
		lookups,
	)
}

func (s *Store) getSubscriptionsA9WithLease(
	ctx context.Context,
	requestedTopic *topicpkg.Topic,
	thirtyDayPeriod int,
	now time.Time,
	keysetSequence uint64,
	keysetHash [32]byte,
	topicBindingLease a9trust.TopicBindingLease,
	lookups []a9TopicLookupCandidate,
) ([]interfaces.Subscription, error) {
	if s == nil || s.db == nil || !s.a9Enabled || requestedTopic == nil ||
		thirtyDayPeriod < 0 || now.IsZero() ||
		keysetSequence == 0 || topicBindingLease == nil ||
		len(lookups) == 0 || len(lookups) > 2 {
		if topicBindingLease != nil {
			topicBindingLease.Close()
		}
		return nil, ErrStoreUnavailable
	}
	leaseOpen := true
	defer func() {
		if leaseOpen {
			topicBindingLease.Close()
		}
	}()

	tx, err := s.db.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelSerializable},
	)
	if err != nil {
		return nil, storeDatabaseError(err)
	}
	defer func() { _ = tx.Rollback() }()
	keysetState, current, err := s.lockA9CurrentKeysetReceiptTx(
		ctx,
		tx,
		keysetSequence,
		keysetHash,
	)
	if err != nil {
		return nil, storeDatabaseError(err)
	}
	if !current || !a9TrustClockAligned(now, keysetState.databaseNow) {
		return nil, ErrStoreUnavailable
	}
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return nil, ErrStoreUnavailable
	}
	candidates, err := s.discoverA9RouteCandidatesTx(ctx, tx, lookups)
	if err != nil {
		return nil, err
	}
	staged := make([]a9CurrentRouteCandidate, 0, len(candidates))
	defer func() {
		for index := range staged {
			zero(staged[index].state.installationIdentity)
		}
	}()
	for index := range candidates {
		candidate := candidates[index]
		state, routeCurrent, currentErr := s.requireA9CurrentRouteTx(
			ctx,
			tx,
			candidate.leaseID,
			&candidate.snapshot,
		)
		if currentErr != nil {
			return nil, currentErr
		}
		if !routeCurrent {
			continue
		}
		if !a9TrustClockAligned(now, state.databaseNow) {
			zero(state.installationIdentity)
			return nil, ErrStoreUnavailable
		}
		recomputed, verdict := topicBindingLease.TopicBindingForEpoch(
			ctx,
			requestedTopic.Bytes(),
			candidate.snapshot.TopicKeyEpoch,
			now,
			candidate.snapshot.AssertionExpiresAt,
			true,
		)
		matches := verdict.IsEligible() &&
			a9trust.EqualBinding(
				recomputed,
				candidate.snapshot.TopicBinding[:],
			)
		clear(recomputed)
		if !matches {
			zero(state.installationIdentity)
			if !verdict.IsEligible() &&
				verdict.Terminal == "INCONCLUSIVE" {
				return nil, ErrStoreUnavailable
			}
			continue
		}
		staged = append(staged, a9CurrentRouteCandidate{
			route: candidate,
			state: state,
		})
	}

	// No TOPIC secret remains reachable while Gate-6 route keys and nonces are
	// opened below. The database locks acquired above retain A9 currentness.
	topicBindingLease.Close()
	leaseOpen = false

	subscriptions := make([]interfaces.Subscription, 0, len(staged))
	preparedCurrentness := make(
		[]a9PreparedRouteCurrentness,
		0,
		len(staged),
	)
	committed := false
	defer func() {
		if !committed {
			wipeA9PreparedSubscriptions(subscriptions)
		}
	}()
	for index := range staged {
		selected := &staged[index]
		var databaseNow time.Time
		if err = tx.QueryRowContext(
			ctx,
			`SELECT pg_catalog.clock_timestamp()`,
		).Scan(&databaseNow); err != nil {
			return nil, storeDatabaseError(err)
		}
		databaseNow = databaseNow.UTC()
		if !a9TrustClockAligned(now, databaseNow) ||
			!databaseNow.Before(
				selected.state.authorityExpiresAt(),
			) {
			return nil, ErrStoreUnavailable
		}
		row, gate6Current, loadErr := s.loadA9Gate6RouteTx(
			ctx,
			tx,
			selected.route.leaseID,
			selected.state.installationIdentity,
			databaseNow,
		)
		if loadErr != nil {
			return nil, loadErr
		}
		if !gate6Current {
			continue
		}
		if row.routeKeyEpoch != selected.route.snapshot.RouteKeyEpoch {
			return nil, ErrStoreUnavailable
		}
		subscription, prepared, prepareErr := s.prepareRoute(
			ctx,
			tx,
			requestedTopic,
			thirtyDayPeriod,
			databaseNow,
			row,
		)
		if prepareErr != nil {
			return nil, prepareErr
		}
		if !prepared {
			continue
		}
		if subscription.SecureRoute == nil {
			return nil, ErrStoreUnavailable
		}
		subscription.SecureRoute.A9 = cloneA9RouteSnapshot(
			&selected.route.snapshot,
		)
		subscriptions = append(subscriptions, subscription)
		preparedCurrentness = append(
			preparedCurrentness,
			a9PreparedRouteCurrentness{
				snapshot:       selected.route.snapshot,
				state:          selected.state,
				gate6ExpiresAt: a9Gate6RouteExpiresAt(row),
			},
		)
	}
	if len(preparedCurrentness) > 0 {
		var finalDatabaseNow time.Time
		if err = tx.QueryRowContext(
			ctx,
			`SELECT pg_catalog.clock_timestamp()`,
		).Scan(&finalDatabaseNow); err != nil {
			return nil, storeDatabaseError(err)
		}
		finalHostNow := s.now().UTC()
		for index := range preparedCurrentness {
			prepared := &preparedCurrentness[index]
			reference, stillCurrent := a9RouteStillCurrentAt(
				now,
				finalHostNow,
				finalDatabaseNow.UTC(),
				prepared.state,
				&prepared.snapshot,
			)
			if !stillCurrent ||
				!reference.Before(prepared.gate6ExpiresAt) {
				return nil, ErrStoreUnavailable
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, storeDatabaseError(err)
	}
	committed = true
	return subscriptions, nil
}

func wipeA9PreparedSubscriptions(subscriptions []interfaces.Subscription) {
	for index := range subscriptions {
		subscription := &subscriptions[index]
		if subscription.HmacKey != nil {
			zero(subscription.HmacKey.Key)
			subscription.HmacKey = nil
		}
		if subscription.SecureRoute != nil {
			route := subscription.SecureRoute
			zero(route.LeaseID)
			zero(route.RouteKey)
			zero(route.RouteAlias)
			zero(route.ReceiveCapability)
			if route.A9 != nil {
				*route.A9 = interfaces.A9RouteSnapshot{}
				route.A9 = nil
			}
			subscription.SecureRoute = nil
		}
	}
	clear(subscriptions)
}

// discoverA9RouteCandidatesTx performs only an indexed, secret-free
// projection lookup. It deliberately takes no row locks: callers establish
// currentness in the global A9 lock order before touching Gate-6 state or
// allocating a delivery sequence.
func (s *Store) discoverA9RouteCandidatesTx(
	ctx context.Context,
	tx *sql.Tx,
	lookups []a9TopicLookupCandidate,
) ([]a9RouteCandidate, error) {
	if s == nil || tx == nil || !s.a9Enabled || len(lookups) == 0 ||
		len(lookups) > 2 {
		return nil, ErrStoreUnavailable
	}
	seenLookups := make(map[a9TopicLookupCandidate]struct{}, len(lookups))
	seenLeases := make(map[string]struct{})
	var candidates []a9RouteCandidate
	for _, lookup := range lookups {
		if lookup.topicKeyEpoch == 0 {
			return nil, ErrStoreUnavailable
		}
		if _, duplicate := seenLookups[lookup]; duplicate {
			return nil, ErrStoreUnavailable
		}
		seenLookups[lookup] = struct{}{}

		rows, err := tx.QueryContext(
			ctx,
			`SELECT route.lease_id,
			        route.installation_binding_id,
			        route.sequencer_epoch,
			        route.subscription_generation,
			        route.binding_id,
			        route.binding_version,
			        route.assertion_hash,
			        route.assertion_stream_sequence,
			        assertion.expires_at,
			        route.topic_key_epoch,
			        route.topic_binding,
			        route.route_key_epoch,
			        route.keyset_sequence,
			        route.keyset_hash,
			        route.watermark_sequence
			   FROM hytch_push_vault.a9_subscription_routes AS route
			   JOIN hytch_push_vault.a9_assertions AS assertion
			     ON assertion.environment = route.environment
			    AND assertion.assertion_hash = route.assertion_hash
			  WHERE route.environment = $1
			    AND route.topic_key_epoch = $2
			    AND route.topic_binding = $3`,
			s.environmentID,
			int64(lookup.topicKeyEpoch),
			lookup.topicBinding[:],
		)
		if err != nil {
			return nil, storeDatabaseError(err)
		}
		for rows.Next() {
			var (
				candidate              a9RouteCandidate
				installationBindingID  []byte
				sequencerEpoch         []byte
				subscriptionGeneration int64
				bindingID              []byte
				bindingVersion         int64
				assertionHash          []byte
				assertionSequence      int64
				topicKeyEpoch          int64
				topicBinding           []byte
				routeKeyEpoch          int64
				keysetSequence         int64
				keysetHash             []byte
				watermarkSequence      int64
			)
			if err = rows.Scan(
				&candidate.leaseID,
				&installationBindingID,
				&sequencerEpoch,
				&subscriptionGeneration,
				&bindingID,
				&bindingVersion,
				&assertionHash,
				&assertionSequence,
				&candidate.snapshot.AssertionExpiresAt,
				&topicKeyEpoch,
				&topicBinding,
				&routeKeyEpoch,
				&keysetSequence,
				&keysetHash,
				&watermarkSequence,
			); err != nil {
				_ = rows.Close()
				return nil, storeDatabaseError(err)
			}
			if len(candidate.leaseID) != 16 ||
				len(installationBindingID) != 16 ||
				len(sequencerEpoch) != 16 ||
				subscriptionGeneration <= 0 ||
				uint64(subscriptionGeneration) > a9MaxSafeInteger ||
				len(bindingID) != 16 ||
				bindingVersion <= 0 ||
				uint64(bindingVersion) > a9MaxSafeInteger ||
				len(assertionHash) != 32 ||
				assertionSequence <= 0 ||
				uint64(assertionSequence) > a9MaxSafeInteger ||
				topicKeyEpoch <= 0 ||
				uint64(topicKeyEpoch) > uint64(^uint32(0)) ||
				len(topicBinding) != 32 ||
				routeKeyEpoch <= 0 ||
				uint64(routeKeyEpoch) > uint64(^uint32(0)) ||
				keysetSequence <= 0 ||
				uint64(keysetSequence) > a9MaxSafeInteger ||
				len(keysetHash) != 32 ||
				watermarkSequence <= 0 ||
				uint64(watermarkSequence) > a9MaxSafeInteger {
				_ = rows.Close()
				return nil, ErrStoreUnavailable
			}
			copy(
				candidate.snapshot.InstallationBindingID[:],
				installationBindingID,
			)
			copy(candidate.snapshot.SequencerEpoch[:], sequencerEpoch)
			candidate.snapshot.SubscriptionGeneration =
				uint64(subscriptionGeneration)
			copy(candidate.snapshot.BindingID[:], bindingID)
			candidate.snapshot.BindingVersion = uint64(bindingVersion)
			copy(candidate.snapshot.AssertionHash[:], assertionHash)
			candidate.snapshot.AssertionStreamSequence =
				uint64(assertionSequence)
			candidate.snapshot.AssertionExpiresAt =
				candidate.snapshot.AssertionExpiresAt.UTC()
			candidate.snapshot.TopicKeyEpoch = uint32(topicKeyEpoch)
			copy(candidate.snapshot.TopicBinding[:], topicBinding)
			candidate.snapshot.RouteKeyEpoch = uint32(routeKeyEpoch)
			candidate.snapshot.KeysetSequence = uint64(keysetSequence)
			copy(candidate.snapshot.KeysetHash[:], keysetHash)
			candidate.snapshot.WatermarkSequence =
				uint64(watermarkSequence)
			if candidate.snapshot.TopicKeyEpoch !=
				lookup.topicKeyEpoch ||
				candidate.snapshot.TopicBinding !=
					lookup.topicBinding ||
				!validA9RouteSnapshot(
					&candidate.snapshot,
					candidate.snapshot.RouteKeyEpoch,
					time.Time{},
				) {
				_ = rows.Close()
				return nil, ErrStoreUnavailable
			}
			leaseKey := string(candidate.leaseID)
			if _, duplicate := seenLeases[leaseKey]; duplicate {
				_ = rows.Close()
				return nil, ErrStoreUnavailable
			}
			seenLeases[leaseKey] = struct{}{}
			candidate.leaseID = append([]byte(nil), candidate.leaseID...)
			candidates = append(candidates, candidate)
		}
		if err = rows.Err(); err != nil {
			_ = rows.Close()
			return nil, storeDatabaseError(err)
		}
		if err = rows.Close(); err != nil {
			return nil, storeDatabaseError(err)
		}
	}
	sort.Slice(candidates, func(left, right int) bool {
		if comparison := bytes.Compare(
			candidates[left].snapshot.InstallationBindingID[:],
			candidates[right].snapshot.InstallationBindingID[:],
		); comparison != 0 {
			return comparison < 0
		}
		if comparison := bytes.Compare(
			candidates[left].snapshot.BindingID[:],
			candidates[right].snapshot.BindingID[:],
		); comparison != 0 {
			return comparison < 0
		}
		return bytes.Compare(
			candidates[left].leaseID,
			candidates[right].leaseID,
		) < 0
	})
	return candidates, nil
}

// loadA9Gate6RouteTx locks Gate-6 in its native installation-then-lease
// order, after the caller has locked and recomputed the exact A9 projection.
func (s *Store) loadA9Gate6RouteTx(
	ctx context.Context,
	tx *sql.Tx,
	leaseID []byte,
	installationIdentity []byte,
	now time.Time,
) (routeRow, bool, error) {
	if s == nil || tx == nil || len(leaseID) != 16 ||
		len(installationIdentity) != 32 || now.IsZero() {
		return routeRow{}, false, ErrStoreUnavailable
	}
	var (
		installationLookup      []byte
		agePolicy               int16
		installationPolicyEpoch int64
		installationExpiresAt   time.Time
		installationControl     time.Time
	)
	err := tx.QueryRowContext(
		ctx,
		`SELECT installation_lookup, age_policy, policy_epoch,
		        expires_at, control_expires_at
		   FROM hytch_push_vault.installation_states
		  WHERE installation_identity = $1
		    AND environment = $2
		    AND state = $3
		    AND expires_at > $4
		    AND control_expires_at > $4
		  FOR SHARE`,
		installationIdentity,
		s.environmentID,
		stateActive,
		now.UTC(),
	).Scan(
		&installationLookup,
		&agePolicy,
		&installationPolicyEpoch,
		&installationExpiresAt,
		&installationControl,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return routeRow{}, false, nil
	}
	if err != nil {
		return routeRow{}, false, storeDatabaseError(err)
	}
	if len(installationLookup) != 32 ||
		installationPolicyEpoch <= 0 ||
		uint64(installationPolicyEpoch) > a9MaxSafeInteger {
		return routeRow{}, false, ErrStoreUnavailable
	}

	var row routeRow
	var routeKeyEpoch int64
	err = tx.QueryRowContext(
		ctx,
		`SELECT lease_id, installation_lookup, encrypted_topic,
		        encrypted_route_key, encrypted_hmac_keys,
		        encrypted_receive_capability, refreshed_at, expires_at,
		        control_expires_at, policy_epoch, route_key_epoch,
		        encrypted_nonce_state
		   FROM hytch_push_vault.subscription_leases
		  WHERE lease_id = $1
		    AND environment = $2
		    AND installation_lookup = $3
		    AND installation_identity = $4
		    AND state = $5
		    AND topic_kind = $6
		    AND push_mode = $7
		    AND expires_at > $8
		    AND control_expires_at > $8
		    AND policy_epoch = $9
		  FOR UPDATE`,
		leaseID,
		s.environmentID,
		installationLookup,
		installationIdentity,
		stateActive,
		topicConversation,
		pushAlert,
		now.UTC(),
		installationPolicyEpoch,
	).Scan(
		&row.leaseID,
		&row.installationLookup,
		&row.encryptedTopic,
		&row.encryptedRouteKey,
		&row.encryptedHMACKeys,
		&row.encryptedCapability,
		&row.refreshedAt,
		&row.expiresAt,
		&row.controlExpiresAt,
		&row.policyEpoch,
		&routeKeyEpoch,
		&row.encryptedNonceState,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return routeRow{}, false, nil
	}
	if err != nil {
		return routeRow{}, false, storeDatabaseError(err)
	}
	if len(row.leaseID) != 16 ||
		!bytes.Equal(row.leaseID, leaseID) ||
		len(row.installationLookup) != 32 ||
		!bytes.Equal(row.installationLookup, installationLookup) ||
		routeKeyEpoch <= 0 ||
		uint64(routeKeyEpoch) > uint64(^uint32(0)) {
		return routeRow{}, false, ErrStoreUnavailable
	}
	row.routeKeyEpoch = uint32(routeKeyEpoch)
	row.agePolicy = agePolicy
	row.installationPolicyEpoch = uint64(installationPolicyEpoch)
	row.installationExpiresAt = installationExpiresAt.UTC()
	row.installationControlExpiry = installationControl.UTC()
	return row, true, nil
}

func a9Gate6RouteExpiresAt(row routeRow) time.Time {
	result := row.expiresAt.UTC()
	for _, candidate := range []time.Time{
		row.controlExpiresAt.UTC(),
		row.installationExpiresAt.UTC(),
		row.installationControlExpiry.UTC(),
	} {
		if result.IsZero() || candidate.Before(result) {
			result = candidate
		}
	}
	return result.UTC()
}
