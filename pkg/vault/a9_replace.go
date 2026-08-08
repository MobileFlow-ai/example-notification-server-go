package vault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9api"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
)

type a9ValidatedSubscription struct {
	bindingID               [16]byte
	bindingVersion          uint64
	assertionHash           [32]byte
	topicBinding            [32]byte
	topicKeyEpoch           uint32
	routeKeyEpoch           uint32
	assertionStreamSequence uint64
	keysetSequence          uint64
	keysetHash              [32]byte
}

// Replace validates A9 authority and Gate-6 authority, then publishes both
// projections as one complete serializable replacement. No negative outcome
// creates or advances a route.
func (s *Store) Replace(
	ctx context.Context,
	request *a9api.ReplaceRequest,
	receipt a9api.KeysetReceipt,
) (a9api.Result, error) {
	refresh, err := s.a9RefreshRequest(request)
	if err != nil || !s.validA9Replace(request, receipt) {
		return a9api.Result{}, ErrStoreUnavailable
	}
	defer wipeA9RefreshRequest(&refresh)
	for attempt := 0; attempt < a9TransactionAttempts; attempt++ {
		result, replaceErr := s.replaceA9Once(
			ctx,
			request,
			receipt,
			refresh,
		)
		if replaceErr == nil {
			if result.Outcome == a9api.ResultOutcomeApplied {
				// Marker finalization is intentionally outside the authority
				// transaction. Failure cannot make an uncommitted route live.
				if err = s.finalizeDeliveryMarkers(ctx); err != nil {
					return a9api.Result{}, ErrStoreUnavailable
				}
				_ = s.RecordOperationalAggregate(
					ctx,
					aggregateEventLeaseRefresh,
					aggregateOutcomeActive,
					0,
				)
			}
			return result, nil
		}
		if !isSerializationFailure(replaceErr) {
			return a9api.Result{}, ErrStoreUnavailable
		}
	}
	return a9api.Result{}, ErrStoreUnavailable
}

func (s *Store) replaceA9Once(
	ctx context.Context,
	request *a9api.ReplaceRequest,
	receipt a9api.KeysetReceipt,
	refresh RefreshRequest,
) (a9api.Result, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return a9api.Result{}, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()

	dbNow, err := s.requireA9KeysetTx(
		ctx,
		tx,
		receipt.Sequence,
		receipt.Hash,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return a9api.Result{}, storeDatabaseError(err)
	}

	authority, err := s.loadA9AuthorityTx(
		ctx,
		tx,
		request.InstallationBindingID,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	if authority == nil {
		if err = s.insertA9AuthorityTx(
			ctx,
			tx,
			request.InstallationBindingID,
			request.SequencerEpoch,
			a9AuthorityUncertain,
			a9UncertaintyAuthorityReference,
			dbNow,
		); err != nil {
			return a9api.Result{}, err
		}
		authority = &a9AuthorityRow{
			epoch:             request.SequencerEpoch,
			state:             a9AuthorityUncertain,
			uncertaintyReason: a9UncertaintyAuthorityReference,
		}
	}

	idempotencyKey := canonicalA9UUID(request.IdempotencyKey)
	if replay, found, receiptErr := s.a9ReceiptResultTx(
		ctx,
		tx,
		idempotencyKey,
		a9OperationReplace,
		request.InstallationBindingID,
		request.SequencerEpoch,
		request.RequestHash,
		authority,
		dbNow,
	); receiptErr != nil {
		return a9api.Result{}, receiptErr
	} else if found {
		return commitA9Result(tx, replay)
	}

	negative := func(
		state int16,
		outcome int16,
		latchReason int16,
	) (a9api.Result, error) {
		if latchReason != 0 {
			if latchErr := s.latchA9UncertaintyTx(
				ctx,
				tx,
				request.InstallationBindingID,
				latchReason,
				dbNow,
			); latchErr != nil {
				return a9api.Result{}, latchErr
			}
			state = a9ResultUncertain
		}
		result := s.a9Result(
			request.InstallationBindingID,
			request.SequencerEpoch,
			authority.generation,
			state,
			outcome,
			authority.contiguous,
		)
		if receiptErr := s.insertA9ReceiptTx(
			ctx,
			tx,
			idempotencyKey,
			a9OperationReplace,
			request.InstallationBindingID,
			request.SequencerEpoch,
			request.RequestHash,
			result,
		); receiptErr != nil {
			return a9api.Result{}, receiptErr
		}
		return commitA9Result(tx, result)
	}

	if authority.epoch != request.SequencerEpoch {
		return negative(
			a9ResultUncertain,
			a9OutcomeConflict,
			a9UncertaintyEpoch,
		)
	}
	if authority.state == a9AuthorityUncertain &&
		authority.uncertaintyReason != a9UncertaintyEpoch {
		return negative(
			a9ResultUncertain,
			a9OutcomeInconclusive,
			0,
		)
	}
	if request.ExpectedSubscriptionGeneration != authority.generation ||
		request.SubscriptionGeneration != authority.generation+1 {
		state := a9ResultActive
		if authority.state == a9AuthorityUncertain {
			state = a9ResultUncertain
		}
		return negative(state, a9OutcomeStale, 0)
	}
	if !authority.watermarkSequence.Valid ||
		!authority.watermarkStatus.Valid ||
		authority.watermarkStatus.Int64 !=
			int64(a9trust.WatermarkStatusCurrent) ||
		!authority.watermarkExpiresAt.Valid ||
		!dbNow.Before(authority.watermarkExpiresAt.Time.UTC()) ||
		!authority.watermarkCommitted.Valid ||
		!authority.watermarkKeysetSeq.Valid ||
		authority.watermarkKeysetSeq.Int64 != int64(receipt.Sequence) ||
		!bytes.Equal(
			authority.watermarkKeysetHash,
			receipt.Hash[:],
		) {
		return negative(
			a9ResultUncertain,
			a9OutcomeInconclusive,
			a9UncertaintyArtifactExpired,
		)
	}

	normalized, err := s.validateRefresh(refresh, dbNow)
	if err != nil {
		return a9api.Result{}, ErrStoreUnavailable
	}
	defer wipeA9NormalizedSubscriptions(normalized)
	requestDigest, err := semanticRefreshDigest(refresh)
	if err != nil {
		return a9api.Result{}, ErrStoreUnavailable
	}

	validated, missing, revoked, err := s.validateA9SubscriptionsTx(
		ctx,
		tx,
		request,
		receipt,
		authority,
		dbNow,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	if revoked {
		return negative(a9ResultRevoked, a9OutcomeStale, 0)
	}
	if missing {
		return negative(
			a9ResultUncertain,
			a9OutcomeGap,
			a9UncertaintyAuthorityReference,
		)
	}

	installationIdentity, err := s.installationDeletionIdentity(
		refresh.InstallationID,
	)
	if err != nil {
		return a9api.Result{}, ErrStoreUnavailable
	}
	defer zero(installationIdentity)
	boundIdentity, err := s.loadA9Gate6BindingTx(
		ctx,
		tx,
		request.InstallationBindingID,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	if len(boundIdentity) != 0 &&
		!bytes.Equal(boundIdentity, installationIdentity) {
		return negative(
			a9ResultUncertain,
			a9OutcomeConflict,
			a9UncertaintyAuthorityReference,
		)
	}

	// Every authority and Gate-6 validation above is complete. From this point
	// onward all state changes remain private to this transaction until commit.
	result := s.a9Result(
		request.InstallationBindingID,
		request.SequencerEpoch,
		request.SubscriptionGeneration,
		a9ResultActive,
		a9OutcomeApplied,
		authority.contiguous,
	)
	if err = s.insertA9ReceiptTx(
		ctx,
		tx,
		idempotencyKey,
		a9OperationReplace,
		request.InstallationBindingID,
		request.SequencerEpoch,
		request.RequestHash,
		result,
	); err != nil {
		return a9api.Result{}, err
	}
	if err = s.cancelA9RoutesTx(
		ctx,
		tx,
		request.InstallationBindingID,
		nil,
		dbNow,
	); err != nil {
		return a9api.Result{}, err
	}
	if _, err = tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.a9_subscription_routes
		  WHERE environment = $1
		    AND installation_binding_id = $2`,
		s.environmentID,
		request.InstallationBindingID[:],
	); err != nil {
		return a9api.Result{}, storeDatabaseError(err)
	}

	installationLookup, leaseIDs, _, err := s.applyGate6RefreshTx(
		ctx,
		tx,
		refresh,
		normalized,
		requestDigest,
		request.ExpectedSubscriptionGeneration,
		dbNow,
	)
	if err != nil {
		return a9api.Result{}, err
	}
	defer zero(installationLookup)
	if err = s.bindA9InstallationToGate6Tx(
		ctx,
		tx,
		request.InstallationBindingID,
		installationIdentity,
	); err != nil {
		return a9api.Result{}, err
	}

	for index := range validated {
		subscription := validated[index]
		leaseID, ok := leaseIDs[string(
			request.Subscriptions[index].Topic[:],
		)]
		if !ok || len(leaseID) != 16 {
			return a9api.Result{}, ErrStoreUnavailable
		}
		if _, err = tx.ExecContext(
			ctx,
			`INSERT INTO hytch_push_vault.a9_subscription_routes (
			     lease_id, environment, installation_binding_id,
			     installation_identity, sequencer_epoch,
			     subscription_generation,
			     replacement_idempotency_key,
			     binding_id, binding_version, assertion_hash,
			     assertion_stream_sequence, topic_key_epoch,
			     topic_binding, route_key_epoch,
			     keyset_sequence, keyset_hash,
			     watermark_sequence, created_at, refreshed_at
			 ) VALUES (
			     $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
			     $15,$16,$17,$18,$18
			 )`,
			leaseID,
			s.environmentID,
			request.InstallationBindingID[:],
			installationIdentity,
			request.SequencerEpoch[:],
			int64(request.SubscriptionGeneration),
			idempotencyKey,
			subscription.bindingID[:],
			int64(subscription.bindingVersion),
			subscription.assertionHash[:],
			int64(subscription.assertionStreamSequence),
			int64(subscription.topicKeyEpoch),
			subscription.topicBinding[:],
			int64(subscription.routeKeyEpoch),
			int64(subscription.keysetSequence),
			subscription.keysetHash[:],
			authority.watermarkSequence.Int64,
			dbNow,
		); err != nil {
			return a9api.Result{}, storeDatabaseError(err)
		}
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.a9_installation_authority
		    SET subscription_generation = $3,
		        state = $4,
		        uncertainty_reason = 0,
		        updated_at = $5
		  WHERE environment = $1
		    AND installation_binding_id = $2`,
		s.environmentID,
		request.InstallationBindingID[:],
		int64(request.SubscriptionGeneration),
		a9AuthorityActive,
		dbNow,
	); err != nil {
		return a9api.Result{}, storeDatabaseError(err)
	}
	return commitA9Result(tx, result)
}

func (s *Store) validateA9SubscriptionsTx(
	ctx context.Context,
	tx *sql.Tx,
	request *a9api.ReplaceRequest,
	receipt a9api.KeysetReceipt,
	authority *a9AuthorityRow,
	now time.Time,
) ([]a9ValidatedSubscription, bool, bool, error) {
	order := make([]int, len(request.Subscriptions))
	for index := range order {
		order[index] = index
	}
	sort.Slice(order, func(left, right int) bool {
		return bytes.Compare(
			request.Subscriptions[order[left]].BindingID[:],
			request.Subscriptions[order[right]].BindingID[:],
		) < 0
	})

	byIndex := make([]a9ValidatedSubscription, len(request.Subscriptions))
	for _, index := range order {
		subscription := &request.Subscriptions[index]
		var (
			streamSequence uint64
			keysetSequence uint64
			keysetHash     []byte
		)
		err := tx.QueryRowContext(
			ctx,
			`SELECT assertion.assertion_stream_sequence,
			        assertion.keyset_sequence,
			        assertion.keyset_hash
			   FROM hytch_push_vault.a9_bindings AS binding
			   JOIN hytch_push_vault.a9_assertions AS assertion
			     ON assertion.environment = binding.environment
			    AND assertion.installation_binding_id =
			        binding.installation_binding_id
			    AND assertion.sequencer_epoch = binding.sequencer_epoch
			    AND assertion.binding_id = binding.binding_id
			    AND assertion.binding_version = binding.binding_version
			    AND assertion.assertion_hash =
			        binding.active_assertion_hash
			    AND assertion.assertion_stream_sequence =
			        binding.active_assertion_stream_sequence
			    AND assertion.topic_key_epoch =
			        binding.active_topic_key_epoch
			    AND assertion.topic_binding =
			        binding.active_topic_binding
			    AND assertion.keyset_sequence =
			        binding.active_keyset_sequence
			    AND assertion.keyset_hash = binding.active_keyset_hash
			  WHERE binding.environment = $1
			    AND binding.installation_binding_id = $2
			    AND binding.binding_id = $3
			    AND binding.sequencer_epoch = $4
			    AND binding.binding_version = $5
			    AND binding.state = $6
			    AND binding.active_assertion_hash = $7
			    AND binding.active_topic_key_epoch = $8
			    AND binding.active_topic_binding = $9
			    AND assertion.expires_at > $10
			    AND assertion.assertion_stream_sequence <= $11
			    AND assertion.keyset_sequence = $12
			    AND assertion.keyset_hash = $13
			  FOR UPDATE OF binding, assertion`,
			s.environmentID,
			request.InstallationBindingID[:],
			subscription.BindingID[:],
			request.SequencerEpoch[:],
			int64(subscription.BindingVersion),
			a9BindingActive,
			subscription.AssertionHash[:],
			int64(subscription.TopicKeyEpoch),
			subscription.TopicBinding[:],
			now,
			authority.watermarkCommitted.Int64,
			int64(receipt.Sequence),
			receipt.Hash[:],
		).Scan(
			&streamSequence,
			&keysetSequence,
			&keysetHash,
		)
		if errors.Is(err, sql.ErrNoRows) {
			revoked, revokeErr := s.a9SubscriptionRevokedTx(
				ctx,
				tx,
				request.InstallationBindingID,
				subscription.BindingID,
				subscription.BindingVersion,
			)
			return nil, !revoked, revoked, revokeErr
		}
		if err != nil || len(keysetHash) != 32 {
			return nil, false, false, storeDatabaseError(err)
		}
		var fixedHash [32]byte
		copy(fixedHash[:], keysetHash)
		byIndex[index] = a9ValidatedSubscription{
			bindingID:               subscription.BindingID,
			bindingVersion:          subscription.BindingVersion,
			assertionHash:           subscription.AssertionHash,
			topicBinding:            subscription.TopicBinding,
			topicKeyEpoch:           subscription.TopicKeyEpoch,
			routeKeyEpoch:           subscription.RouteKeyEpoch,
			assertionStreamSequence: streamSequence,
			keysetSequence:          keysetSequence,
			keysetHash:              fixedHash,
		}
	}
	return byIndex, false, false, nil
}

func (s *Store) a9SubscriptionRevokedTx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
	bindingID [16]byte,
	version uint64,
) (bool, error) {
	var exists bool
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
		installationBindingID[:],
		bindingID[:],
		int64(version),
	).Scan(&exists); err != nil {
		return false, storeDatabaseError(err)
	}
	return exists, nil
}

func (s *Store) loadA9Gate6BindingTx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
) ([]byte, error) {
	var identity []byte
	err := tx.QueryRowContext(
		ctx,
		`SELECT installation_identity
		   FROM hytch_push_vault.a9_installation_gate6_bindings
		  WHERE environment = $1
		    AND installation_binding_id = $2`,
		s.environmentID,
		installationBindingID[:],
	).Scan(&identity)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil || len(identity) != 32 {
		return nil, storeDatabaseError(err)
	}
	return identity, nil
}

func (s *Store) bindA9InstallationToGate6Tx(
	ctx context.Context,
	tx *sql.Tx,
	installationBindingID [16]byte,
	installationIdentity []byte,
) error {
	if len(installationIdentity) != 32 {
		return ErrStoreUnavailable
	}
	result, err := tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a9_installation_gate6_bindings (
		     environment, installation_binding_id, installation_identity
		 ) VALUES ($1,$2,$3)
		 ON CONFLICT (
		   environment, installation_binding_id
		 ) DO NOTHING`,
		s.environmentID,
		installationBindingID[:],
		installationIdentity,
	)
	if err != nil {
		return storeDatabaseError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ErrStoreUnavailable
	}
	if affected == 1 {
		return nil
	}
	var stored []byte
	if err = tx.QueryRowContext(
		ctx,
		`SELECT installation_identity
		   FROM hytch_push_vault.a9_installation_gate6_bindings
		  WHERE environment = $1
		    AND installation_binding_id = $2`,
		s.environmentID,
		installationBindingID[:],
	).Scan(&stored); err != nil ||
		!bytes.Equal(stored, installationIdentity) {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *Store) a9RefreshRequest(
	request *a9api.ReplaceRequest,
) (RefreshRequest, error) {
	if request == nil {
		return RefreshRequest{}, ErrStoreUnavailable
	}
	var policy authority.PolicyControlV1
	if err := decodeA9Gate6Object(request.PolicyControl, &policy); err != nil {
		return RefreshRequest{}, err
	}
	subscriptions := make(
		[]SubscriptionRefresh,
		len(request.Subscriptions),
	)
	for index := range request.Subscriptions {
		incoming := &request.Subscriptions[index]
		var capability authority.ReceiveCapabilityV1
		if err := decodeA9Gate6Object(
			incoming.ReceiveCapability,
			&capability,
		); err != nil {
			return RefreshRequest{}, err
		}
		hmacKeys := make([]HMACKeyInput, len(incoming.HMACKeys))
		for keyIndex := range incoming.HMACKeys {
			key := &incoming.HMACKeys[keyIndex]
			hmacKeys[keyIndex] = HMACKeyInput{
				ThirtyDayPeriodsSinceEpoch: key.ThirtyDayPeriodsSinceEpoch,
				Key:                        append([]byte(nil), key.Key[:]...),
			}
		}
		subscriptions[index] = SubscriptionRefresh{
			Topic:         append([]byte(nil), incoming.Topic[:]...),
			RouteKey:      append([]byte(nil), incoming.RouteKey[:]...),
			RouteKeyEpoch: incoming.RouteKeyEpoch,
			HMACKeys:      hmacKeys,
			Capability:    capability,
		}
	}
	return RefreshRequest{
		Environment:          request.Environment,
		InstallationID:       hex.EncodeToString(request.LegacyInstallationID[:]),
		AccountIncarnationID: canonicalA9UUID(request.AccountIncarnationID),
		Generation:           request.SubscriptionGeneration,
		IdempotencyKey:       canonicalA9UUID(request.IdempotencyKey),
		APNSToken:            append([]byte(nil), request.APNSToken[:]...),
		PayloadSchema:        request.PayloadSchema,
		Subscriptions:        subscriptions,
		PolicyControl:        policy,
	}, nil
}

func decodeA9Gate6Object(raw []byte, destination any) error {
	if len(raw) == 0 || destination == nil {
		return ErrStoreUnavailable
	}
	value, err := a9trust.ParseStrictJSON(raw)
	if err != nil {
		return ErrStoreUnavailable
	}
	canonical, err := a9trust.Canonicalize(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return ErrStoreUnavailable
	}
	clear(canonical)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(destination); err != nil {
		return ErrStoreUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrStoreUnavailable
	}
	return nil
}

func wipeA9RefreshRequest(request *RefreshRequest) {
	if request == nil {
		return
	}
	zero(request.APNSToken)
	request.APNSToken = nil
	for index := range request.Subscriptions {
		subscription := &request.Subscriptions[index]
		zero(subscription.Topic)
		subscription.Topic = nil
		zero(subscription.RouteKey)
		subscription.RouteKey = nil
		for keyIndex := range subscription.HMACKeys {
			zero(subscription.HMACKeys[keyIndex].Key)
			subscription.HMACKeys[keyIndex].Key = nil
		}
		clear(subscription.HMACKeys)
		subscription.HMACKeys = nil
		subscription.Capability = authority.ReceiveCapabilityV1{}
	}
	clear(request.Subscriptions)
	request.Subscriptions = nil
	request.PolicyControl = authority.PolicyControlV1{}
	request.InstallationID = ""
	request.AccountIncarnationID = ""
	request.IdempotencyKey = ""
}

func wipeA9NormalizedSubscriptions(
	subscriptions []normalizedSubscription,
) {
	for index := range subscriptions {
		subscription := &subscriptions[index]
		zero(subscription.topic)
		subscription.topic = nil
		zero(subscription.routeKey)
		subscription.routeKey = nil
		for keyIndex := range subscription.hmacKeys {
			zero(subscription.hmacKeys[keyIndex].Key)
			subscription.hmacKeys[keyIndex].Key = nil
		}
		clear(subscription.hmacKeys)
		subscription.hmacKeys = nil
		subscription.capability = authority.ReceiveCapabilityV1{}
	}
	clear(subscriptions)
}

func (s *Store) validA9Replace(
	request *a9api.ReplaceRequest,
	receipt a9api.KeysetReceipt,
) bool {
	return s != nil &&
		s.db != nil &&
		request != nil &&
		request.Environment == s.environment &&
		request.SubscriptionGeneration > 0 &&
		request.SubscriptionGeneration <= a9MaxSafeInteger &&
		request.ExpectedSubscriptionGeneration < a9MaxSafeInteger &&
		request.SubscriptionGeneration ==
			request.ExpectedSubscriptionGeneration+1 &&
		receipt.Sequence > 0 &&
		receipt.Sequence <= a9MaxSafeInteger &&
		request.PayloadSchema == "hytch_push_wrapper_v1" &&
		len(request.Subscriptions) <= maxRefreshTopics
}

// applyGate6RefreshTx is the transaction-owned form of Refresh. It reuses the
// same validation and vault primitives but never begins or commits a nested
// transaction.
func (s *Store) applyGate6RefreshTx(
	ctx context.Context,
	tx *sql.Tx,
	request RefreshRequest,
	normalized []normalizedSubscription,
	requestDigest [32]byte,
	expectedGeneration uint64,
	now time.Time,
) ([]byte, map[string][]byte, time.Time, error) {
	lookupEpoch := LookupEpoch(now)
	installationLookup, err := s.environmentLookupDigest(
		"installation",
		lookupEpoch,
		[]byte(request.InstallationID),
	)
	if err != nil {
		return nil, nil, time.Time{}, ErrStoreUnavailable
	}
	incarnationLookup, err := s.environmentLookupDigest(
		"incarnation",
		lookupEpoch,
		[]byte(request.AccountIncarnationID),
	)
	if err != nil {
		return nil, nil, time.Time{}, ErrStoreUnavailable
	}
	installationIdentity, err := s.installationDeletionIdentity(
		request.InstallationID,
	)
	if err != nil {
		return nil, nil, time.Time{}, ErrStoreUnavailable
	}
	defer zero(installationIdentity)
	defer zero(installationLookup)
	defer zero(incarnationLookup)
	if err = requireTombstoneAdvance(
		ctx,
		tx,
		s.environmentID,
		deletionTargetInstallation,
		installationIdentity,
		request.PolicyControl.PolicyEpoch,
		now,
	); err != nil {
		return nil, nil, time.Time{}, err
	}
	existingInstallation, err := s.findInstallation(
		ctx,
		tx,
		request.InstallationID,
		now,
	)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	if existingInstallation == nil && expectedGeneration != 0 {
		return nil, nil, time.Time{}, ErrRefreshConflict
	}
	if existingInstallation != nil {
		if existingInstallation.generation != expectedGeneration ||
			!hmac.Equal(
				existingInstallation.identity,
				installationIdentity,
			) {
			return nil, nil, time.Time{}, ErrRefreshConflict
		}
	}
	controlEventDigest, err := controlDigest(request.PolicyControl)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	if existingInstallation != nil {
		existingIncarnationLookup, digestErr := s.environmentLookupDigest(
			"incarnation",
			existingInstallation.lookupKeyEpoch,
			[]byte(request.AccountIncarnationID),
		)
		if digestErr != nil {
			return nil, nil, time.Time{}, ErrStoreUnavailable
		}
		incarnationChanged := !equalBytes(
			existingIncarnationLookup,
			existingInstallation.incarnationLookup,
		)
		switch {
		case request.PolicyControl.PolicyEpoch <
			existingInstallation.policyEpoch:
			return nil, nil, time.Time{}, ErrRefreshConflict
		case incarnationChanged &&
			request.PolicyControl.PolicyEpoch <=
				existingInstallation.policyEpoch:
			return nil, nil, time.Time{}, ErrRefreshConflict
		case request.PolicyControl.PolicyEpoch ==
			existingInstallation.policyEpoch &&
			!equalDigest(
				existingInstallation.controlEventDigest,
				controlEventDigest[:],
			):
			return nil, nil, time.Time{}, ErrRefreshConflict
		case request.PolicyControl.PolicyEpoch ==
			existingInstallation.policyEpoch &&
			existingInstallation.state != stateActive &&
			existingInstallation.state != stateAwaitingRefresh:
			return nil, nil, time.Time{}, ErrRefreshConflict
		case existingInstallation.state == stateBlockedRekeyNeeded:
			return nil, nil, time.Time{}, ErrRefreshConflict
		}
		apnsTokenChanged := len(
			existingInstallation.encryptedAPNSToken,
		) == 0
		if !apnsTokenChanged {
			currentToken, openErr := s.encryption.Open(
				installationContext(
					existingInstallation.lookup,
					"apns-token",
				),
				existingInstallation.encryptedAPNSToken,
			)
			if openErr != nil {
				return nil, nil, time.Time{}, ErrStoreUnavailable
			}
			apnsTokenChanged = !hmac.Equal(
				currentToken,
				request.APNSToken,
			)
			zero(currentToken)
		}
		if apnsTokenChanged {
			if err = s.markDeliveryJobsSafetyForInstallationTx(
				ctx,
				tx,
				existingInstallation.lookup,
				nil,
			); err != nil {
				return nil, nil, time.Time{}, ErrStoreUnavailable
			}
		}
		if !bytes.Equal(
			existingInstallation.lookup,
			installationLookup,
		) {
			if _, err = tx.ExecContext(
				ctx,
				`UPDATE hytch_push_vault.installation_states
				    SET installation_lookup = $1,
				        incarnation_lookup = $2,
				        lookup_key_epoch = $3
				  WHERE installation_lookup = $4
				    AND environment = $5`,
				installationLookup,
				incarnationLookup,
				int64(lookupEpoch),
				existingInstallation.lookup,
				s.environmentID,
			); err != nil {
				return nil, nil, time.Time{}, ErrStoreUnavailable
			}
		}
	}

	tokenCiphertext, err := s.encryption.Seal(
		installationContext(installationLookup, "apns-token"),
		request.APNSToken,
	)
	if err != nil {
		return nil, nil, time.Time{}, ErrStoreUnavailable
	}
	controlExpiresAt, err := time.Parse(
		time.RFC3339Nano,
		request.PolicyControl.ExpiresAt,
	)
	if err != nil {
		return nil, nil, time.Time{}, ErrRefreshInvalid
	}
	controlTTL := time.Minute
	if request.PolicyControl.AgePolicy == authority.AgePolicyTeen {
		controlTTL = 30 * time.Second
	}
	if maximum := now.Add(controlTTL); controlExpiresAt.After(maximum) {
		controlExpiresAt = maximum
	}
	expiresAt := now.Add(s.leaseTTL)
	ageID := ageAdult
	if request.PolicyControl.AgePolicy == authority.AgePolicyTeen {
		ageID = ageTeen
	}
	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.installation_states AS installation (
		     installation_lookup, installation_identity,
		     incarnation_lookup, lookup_key_epoch,
		     generation, idempotency_digest, control_event_digest,
		     encrypted_apns_token,
		     environment, payload_schema, age_policy, policy_epoch, state,
		     encryption_key_version, created_at, refreshed_at, expires_at,
		     control_expires_at, revoked_at
		 ) VALUES (
		     $1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$12,$13,
		     $14,$14,$15,$16,NULL
		 )
		 ON CONFLICT (installation_lookup) DO UPDATE SET
		     installation_identity = EXCLUDED.installation_identity,
		     incarnation_lookup = EXCLUDED.incarnation_lookup,
		     lookup_key_epoch = EXCLUDED.lookup_key_epoch,
		     generation = EXCLUDED.generation,
		     idempotency_digest = EXCLUDED.idempotency_digest,
		     control_event_digest = EXCLUDED.control_event_digest,
		     encrypted_apns_token = EXCLUDED.encrypted_apns_token,
		     environment = EXCLUDED.environment,
		     payload_schema = EXCLUDED.payload_schema,
		     age_policy = EXCLUDED.age_policy,
		     policy_epoch = EXCLUDED.policy_epoch,
		     state = EXCLUDED.state,
		     encryption_key_version = EXCLUDED.encryption_key_version,
		     refreshed_at = EXCLUDED.refreshed_at,
		     expires_at = EXCLUDED.expires_at,
		     control_expires_at = EXCLUDED.control_expires_at,
		     revoked_at = NULL
		   WHERE installation.environment = EXCLUDED.environment`,
		installationLookup,
		installationIdentity,
		incarnationLookup,
		int64(lookupEpoch),
		int64(request.Generation),
		requestDigest[:],
		controlEventDigest[:],
		tokenCiphertext,
		s.environmentID,
		ageID,
		int64(request.PolicyControl.PolicyEpoch),
		stateActive,
		int32(s.encryption.ActiveVersion()),
		now,
		expiresAt,
		controlExpiresAt.UTC(),
	); err != nil {
		return nil, nil, time.Time{}, storeDatabaseError(err)
	}

	existingLeases, err := s.loadExistingLeases(
		ctx,
		tx,
		installationLookup,
	)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	seenExisting := make(map[string]struct{}, len(normalized))
	for _, subscription := range normalized {
		key := string(subscription.topic)
		existing := existingLeases[key]
		if existing != nil {
			seenExisting[key] = struct{}{}
		}
		if err = s.upsertLease(
			ctx,
			tx,
			request.InstallationID,
			installationLookup,
			lookupEpoch,
			request.Generation,
			request.PolicyControl.PolicyEpoch,
			now,
			expiresAt,
			controlExpiresAt.UTC(),
			subscription,
			existing,
		); err != nil {
			return nil, nil, time.Time{}, err
		}
	}
	for rawTopic, existing := range existingLeases {
		if _, ok := seenExisting[rawTopic]; ok {
			continue
		}
		if err = s.eraseLease(ctx, tx, existing, now); err != nil {
			return nil, nil, time.Time{}, err
		}
	}
	currentLeases, err := s.loadExistingLeases(
		ctx,
		tx,
		installationLookup,
	)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	leaseIDs := make(map[string][]byte, len(currentLeases))
	for rawTopic, lease := range currentLeases {
		leaseIDs[rawTopic] = append([]byte(nil), lease.leaseID...)
		zero(lease.topic)
	}
	return append([]byte(nil), installationLookup...),
		leaseIDs,
		expiresAt,
		nil
}
