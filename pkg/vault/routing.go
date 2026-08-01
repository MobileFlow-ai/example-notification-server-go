package vault

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/authority"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	topicutil "github.com/xmtp/example-notification-server-go/pkg/topics"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

var _ interfaces.Installations = (*Store)(nil)
var _ interfaces.Subscriptions = (*Store)(nil)

func (s *Store) Register(
	context.Context,
	interfaces.Installation,
) (*interfaces.RegisterResponse, error) {
	return nil, ErrRefreshInvalid
}

func (s *Store) Delete(context.Context, string) error {
	return ErrRefreshInvalid
}

func (s *Store) Subscribe(context.Context, string, []*topicpkg.Topic) error {
	return ErrRefreshInvalid
}

func (s *Store) Unsubscribe(context.Context, string, []*topicpkg.Topic) error {
	return ErrRefreshInvalid
}

func (s *Store) SubscribeWithMetadata(
	context.Context,
	string,
	[]interfaces.SubscriptionInput,
) error {
	return ErrRefreshInvalid
}

type routeRow struct {
	leaseID                   []byte
	installationLookup        []byte
	encryptedTopic            []byte
	encryptedRouteKey         []byte
	encryptedHMACKeys         []byte
	encryptedCapability       []byte
	refreshedAt               time.Time
	expiresAt                 time.Time
	controlExpiresAt          time.Time
	policyEpoch               uint64
	routeKeyEpoch             uint32
	encryptedNonceState       []byte
	agePolicy                 int16
	installationPolicyEpoch   uint64
	installationExpiresAt     time.Time
	installationControlExpiry time.Time
}

func (s *Store) GetSubscriptions(
	ctx context.Context,
	requestedTopic *topicpkg.Topic,
	thirtyDayPeriod int,
) ([]interfaces.Subscription, error) {
	const maxSerializationAttempts = 3
	for attempt := 0; attempt < maxSerializationAttempts; attempt++ {
		subscriptions, err := s.getSubscriptionsOnce(
			ctx,
			requestedTopic,
			thirtyDayPeriod,
		)
		if err == nil || !isSerializationFailure(err) {
			return subscriptions, err
		}
		if attempt+1 == maxSerializationAttempts {
			break
		}
		delay := time.Duration(attempt+1) * 10 * time.Millisecond
		select {
		case <-ctx.Done():
			return nil, ErrStoreUnavailable
		case <-time.After(delay):
		}
	}
	return nil, ErrStoreUnavailable
}

func (s *Store) getSubscriptionsOnce(
	ctx context.Context,
	requestedTopic *topicpkg.Topic,
	thirtyDayPeriod int,
) ([]interfaces.Subscription, error) {
	if s == nil || s.db == nil || requestedTopic == nil ||
		thirtyDayPeriod < 0 {
		return nil, ErrRefreshInvalid
	}
	if s.a9Enabled {
		return s.getSubscriptionsA9Once(
			ctx,
			requestedTopic,
			thirtyDayPeriod,
		)
	}
	if err := s.RequireRetentionSafe(ctx); err != nil {
		return nil, ErrStoreUnavailable
	}
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, storeDatabaseError(err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return nil, ErrStoreUnavailable
	}

	rowsByLease := make(map[string]routeRow)
	for _, epoch := range CandidateEpochs(now) {
		topicLookup, lookupErr := s.environmentLookupDigest(
			"topic",
			epoch,
			requestedTopic.Bytes(),
		)
		if lookupErr != nil {
			return nil, ErrStoreUnavailable
		}
		rows, queryErr := tx.QueryContext(
			ctx,
			`SELECT
			     l.lease_id,
			     l.installation_lookup,
			     l.encrypted_topic,
			     l.encrypted_route_key,
			     l.encrypted_hmac_keys,
			     l.encrypted_receive_capability,
			     l.refreshed_at,
			     l.expires_at,
			     l.control_expires_at,
			     l.policy_epoch,
			     l.route_key_epoch,
			     l.encrypted_nonce_state,
			     i.age_policy,
			     i.policy_epoch,
			     i.control_expires_at
			 FROM hytch_push_vault.subscription_leases AS l
			 JOIN hytch_push_vault.installation_states AS i
			   ON i.installation_lookup = l.installation_lookup
			 WHERE l.topic_lookup = $1
			   AND l.lookup_key_epoch = $2
			   AND l.state = $3
			   AND l.push_mode = $4
			   AND l.expires_at > $5
			   AND l.control_expires_at > $5
			   AND i.state = $3
			   AND i.expires_at > $5
			   AND i.control_expires_at > $5
			   AND i.policy_epoch = l.policy_epoch
			   AND l.environment = $6
			   AND i.environment = $6
			 FOR UPDATE OF l`,
			topicLookup,
			int64(epoch),
			stateActive,
			pushAlert,
			now,
			s.environmentID,
		)
		if queryErr != nil {
			return nil, storeDatabaseError(queryErr)
		}
		for rows.Next() {
			var row routeRow
			var routeKeyEpoch int64
			if queryErr = rows.Scan(
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
				&row.agePolicy,
				&row.installationPolicyEpoch,
				&row.installationControlExpiry,
			); queryErr != nil {
				_ = rows.Close()
				return nil, storeDatabaseError(queryErr)
			}
			if routeKeyEpoch <= 0 {
				_ = rows.Close()
				return nil, ErrStoreUnavailable
			}
			row.routeKeyEpoch = uint32(routeKeyEpoch)
			rowsByLease[string(row.leaseID)] = row
		}
		if queryErr = rows.Err(); queryErr != nil {
			_ = rows.Close()
			return nil, storeDatabaseError(queryErr)
		}
		_ = rows.Close()
	}

	subscriptions := make([]interfaces.Subscription, 0, len(rowsByLease))
	committed := false
	defer func() {
		if !committed {
			wipeA9PreparedSubscriptions(subscriptions)
		}
	}()
	for _, row := range rowsByLease {
		subscription, ok, routeErr := s.prepareRoute(
			ctx,
			tx,
			requestedTopic,
			thirtyDayPeriod,
			now,
			row,
		)
		if routeErr != nil {
			return nil, routeErr
		}
		if ok {
			subscriptions = append(subscriptions, subscription)
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, storeDatabaseError(err)
	}
	committed = true
	return subscriptions, nil
}

func (s *Store) prepareRoute(
	ctx context.Context,
	tx *sql.Tx,
	requestedTopic *topicpkg.Topic,
	thirtyDayPeriod int,
	now time.Time,
	row routeRow,
) (interfaces.Subscription, bool, error) {
	if row.installationPolicyEpoch != row.policyEpoch ||
		!now.Before(row.expiresAt) ||
		!now.Before(row.controlExpiresAt) ||
		!now.Before(row.installationControlExpiry) ||
		(row.agePolicy == ageTeen && !s.teenConversationEnabled) {
		return interfaces.Subscription{}, false, nil
	}
	rawTopic, err := s.encryption.Open(
		leaseContext(row.leaseID, "topic"),
		row.encryptedTopic,
	)
	if err != nil {
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	defer zero(rawTopic)
	if !equalBytes(rawTopic, requestedTopic.Bytes()) {
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	routeKey, err := s.encryption.Open(
		leaseContext(row.leaseID, "route-key"),
		row.encryptedRouteKey,
	)
	if err != nil || len(routeKey) != 32 {
		zero(routeKey)
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	var (
		exactKey        *interfaces.HmacKey
		capabilityBytes []byte
		routeAlias      []byte
	)
	preparedForReturn := false
	defer func() {
		if preparedForReturn {
			return
		}
		zero(routeKey)
		if exactKey != nil {
			zero(exactKey.Key)
			exactKey = nil
		}
		zero(capabilityBytes)
		zero(routeAlias)
	}()
	hmacBytes, err := s.encryption.Open(
		leaseContext(row.leaseID, "hmac-keys"),
		row.encryptedHMACKeys,
	)
	if err != nil {
		zero(routeKey)
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	defer zero(hmacBytes)
	var hmacKeys []HMACKeyInput
	defer func() { wipeHMACKeyInputs(hmacKeys) }()
	if err = json.Unmarshal(hmacBytes, &hmacKeys); err != nil {
		zero(routeKey)
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	for _, candidate := range hmacKeys {
		if int(candidate.ThirtyDayPeriodsSinceEpoch) == thirtyDayPeriod &&
			len(candidate.Key) == 32 {
			exactKey = &interfaces.HmacKey{
				ThirtyDayPeriodsSinceEpoch: thirtyDayPeriod,
				Key:                        append([]byte(nil), candidate.Key...),
			}
			break
		}
	}
	if requestedTopic.Kind() == topicpkg.TopicKindGroupMessagesV1 && exactKey == nil {
		zero(routeKey)
		return interfaces.Subscription{}, false, nil
	}

	capabilityBytes, err = s.encryption.Open(
		leaseContext(row.leaseID, "capability"),
		row.encryptedCapability,
	)
	if err != nil {
		zero(routeKey)
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	var capability authority.ReceiveCapabilityV1
	if err = json.Unmarshal(capabilityBytes, &capability); err != nil {
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	topicDigestBytes := sha256.Sum256(requestedTopic.Bytes())
	topicDigest := hex.EncodeToString(topicDigestBytes[:])
	maxTTL := time.Minute
	if row.agePolicy == ageTeen {
		maxTTL = 30 * time.Second
	}
	if err = authority.VerifyReceiveCapability(
		capability,
		s.authorityKeys,
		authority.VerifyOptions{
			Now:                 now,
			MaxTTL:              maxTTL,
			ExpectedEnvironment: s.environment,
			ExpectedTopicDigest: topicDigest,
		},
	); err != nil {
		zero(routeKey)
		zero(capabilityBytes)
		if errors.Is(err, authority.ErrCapabilityExpired) {
			return interfaces.Subscription{}, false, nil
		}
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	if capability.PolicyEpoch != row.policyEpoch ||
		capability.EffectivePushMode() != authority.PushModeAlertAllowed ||
		!capabilityMatchesRoute(
			capability,
			routeKey,
			rawTopic,
			s.environment,
			now,
		) {
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.Subscription{}, false, nil
	}
	routeAlias, err = base64.RawURLEncoding.DecodeString(
		capability.RouteAlias,
	)
	if err != nil || len(routeAlias) != gate8wrapper.RouteAliasSize {
		zero(routeKey)
		zero(capabilityBytes)
		zero(routeAlias)
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}

	nonceBytes, err := s.encryption.Open(
		leaseContext(row.leaseID, "nonce-state"),
		row.encryptedNonceState,
	)
	if err != nil {
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	nonce, err := decodeNonceState(nonceBytes)
	zero(nonceBytes)
	if err != nil {
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	if nonce.NextSequence > gate8wrapper.MaxCanonicalInteger {
		_, _ = tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.subscription_leases
				 SET state = $2
				 WHERE lease_id = $1
				   AND environment = $3`,
			row.leaseID,
			stateBlockedRekeyNeeded,
			s.environmentID,
		)
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.Subscription{}, false, nil
	}
	allocatedSequence := nonce.NextSequence
	nonce.NextSequence++
	nextNonceBytes := encodeNonceState(nonce)
	encryptedNonceState, err := s.encryption.Seal(
		leaseContext(row.leaseID, "nonce-state"),
		nextNonceBytes,
	)
	zero(nextNonceBytes)
	if err != nil {
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.subscription_leases
			 SET encrypted_nonce_state = $2
			 WHERE lease_id = $1
			   AND state = $3
			   AND environment = $4`,
		row.leaseID,
		encryptedNonceState,
		stateActive,
		s.environmentID,
	)
	if err != nil {
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.Subscription{}, false, storeDatabaseError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.Subscription{}, false, ErrStoreUnavailable
	}
	expectedPeriod := thirtyDayPeriod
	preparedForReturn = true
	return interfaces.Subscription{
		CreatedAt:             row.refreshedAt,
		InstallationId:        base64.RawURLEncoding.EncodeToString(row.leaseID),
		Topic:                 topicutil.TopicToString(requestedTopic),
		TopicV4:               requestedTopic,
		IsActive:              true,
		IsSilent:              false,
		ExpectedHmacKeyPeriod: &expectedPeriod,
		HmacKey:               exactKey,
		SecureRoute: &interfaces.SecureRoute{
			LeaseID:           append([]byte(nil), row.leaseID...),
			RouteKey:          routeKey,
			RouteKeyEpoch:     row.routeKeyEpoch,
			NoncePrefix:       nonce.Prefix,
			DeliverySequence:  allocatedSequence,
			AliasDay:          capability.AliasDay,
			RouteAlias:        routeAlias,
			ReceiveCapability: capabilityBytes,
			LeaseExpiresAt:    row.expiresAt,
			ControlExpiresAt:  row.controlExpiresAt,
			PolicyEpoch:       row.policyEpoch,
		},
	}, true, nil
}

func wipeHMACKeyInputs(keys []HMACKeyInput) {
	for index := range keys {
		zero(keys[index].Key)
		keys[index].Key = nil
	}
	clear(keys)
}

func (s *Store) GetInstallations(
	ctx context.Context,
	opaqueLeaseIDs []string,
) ([]interfaces.Installation, error) {
	if len(opaqueLeaseIDs) == 0 {
		return []interfaces.Installation{}, nil
	}
	if err := s.RequireRetentionSafe(ctx); err != nil {
		return nil, ErrStoreUnavailable
	}
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return nil, ErrStoreUnavailable
	}
	out := make([]interfaces.Installation, 0, len(opaqueLeaseIDs))
	for _, opaqueLeaseID := range opaqueLeaseIDs {
		leaseID, decodeErr := base64.RawURLEncoding.DecodeString(opaqueLeaseID)
		if decodeErr != nil || len(leaseID) != 16 {
			return nil, ErrStoreUnavailable
		}
		var installationLookup []byte
		var encryptedToken []byte
		var refreshedAt time.Time
		if err = tx.QueryRowContext(
			ctx,
			`SELECT i.installation_lookup, i.encrypted_apns_token, i.refreshed_at
			 FROM hytch_push_vault.subscription_leases AS l
			 JOIN hytch_push_vault.installation_states AS i
			   ON i.installation_lookup = l.installation_lookup
			 WHERE l.lease_id = $1
			   AND l.state = $2
			   AND l.expires_at > $3
			   AND l.control_expires_at > $3
			   AND i.state = $2
			   AND i.expires_at > $3
			   AND i.control_expires_at > $3
			   AND i.policy_epoch = l.policy_epoch
			   AND l.environment = $4
			   AND i.environment = $4`,
			leaseID,
			stateActive,
			now,
			s.environmentID,
		).Scan(&installationLookup, &encryptedToken, &refreshedAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, ErrStoreUnavailable
		}
		token, err := s.encryption.Open(
			installationContext(installationLookup, "apns-token"),
			encryptedToken,
		)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
		out = append(out, interfaces.Installation{
			Id: opaqueLeaseID,
			DeliveryMechanism: interfaces.DeliveryMechanism{
				Kind:      interfaces.APNS,
				Token:     hex.EncodeToString(token),
				UpdatedAt: refreshedAt,
			},
			PayloadFormat: interfaces.PayloadFormatV3,
		})
		zero(token)
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrStoreUnavailable
	}
	return out, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
