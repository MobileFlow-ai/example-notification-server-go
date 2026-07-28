package vault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	topicutil "github.com/xmtp/example-notification-server-go/pkg/topics"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

const (
	welcomeMinuteLimit         = 1
	welcomeHourLimit           = 5
	welcomeCircuitTTL          = 30 * time.Minute
	welcomeBudgetRetention     = time.Hour
	welcomeBudgetLockNamespace = int32(0x4859574c)
)

var (
	ErrWelcomeInvalid     = errors.New("welcome authorization invalid")
	ErrWelcomeConflict    = errors.New("welcome authorization conflict")
	ErrWelcomeUnavailable = errors.New("welcome authorization unavailable")
)

type WelcomeAuthorizationRequest struct {
	Topic         []byte
	Authorization authority.WelcomeAuthorizationV1
}

var _ interfaces.WelcomeSubscriptions = (*Store)(nil)

// AuthorizeWelcome persists authority before an XMTP stream event can be
// routed. Both the topic and the exact outer-envelope digest are authenticated
// by the signed authorization; neither is recoverable from an index.
func (s *Store) AuthorizeWelcome(
	ctx context.Context,
	request WelcomeAuthorizationRequest,
) error {
	if s == nil || !s.welcomeEnabled {
		return ErrWelcomeUnavailable
	}
	if err := s.RequireRetentionSafe(ctx); err != nil {
		return ErrWelcomeUnavailable
	}
	now := s.now().UTC()
	parsedTopic, envelopeDigest, err := s.validateWelcomeRequest(
		request,
		now,
	)
	if err != nil || parsedTopic.Kind() != topicpkg.TopicKindWelcomeMessagesV1 {
		return ErrWelcomeInvalid
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ErrWelcomeUnavailable
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return ErrWelcomeUnavailable
	}

	installation, err := s.findInstallation(
		ctx,
		tx,
		request.Authorization.InstallationID,
		now,
	)
	if err != nil {
		return ErrWelcomeUnavailable
	}
	if installation == nil ||
		installation.state != stateActive ||
		installation.policyEpoch != request.Authorization.PolicyEpoch ||
		!now.Before(installation.expiresAt) {
		return ErrWelcomeInvalid
	}
	expectedIncarnation, err := s.environmentLookupDigest(
		"incarnation",
		installation.lookupKeyEpoch,
		[]byte(request.Authorization.AccountIncarnationID),
	)
	if err != nil ||
		!hmac.Equal(expectedIncarnation, installation.incarnationLookup) {
		return ErrWelcomeInvalid
	}

	lease, err := s.findWelcomeLeaseForAuthorization(
		ctx,
		tx,
		installation.lookup,
		request.Topic,
		now,
	)
	if err != nil {
		return err
	}
	if lease == nil ||
		lease.agePolicy != ageAdult ||
		lease.policyEpoch != request.Authorization.PolicyEpoch ||
		lease.installationPolicyEpoch != request.Authorization.PolicyEpoch {
		return ErrWelcomeInvalid
	}
	if err = s.validateWelcomeLeaseCapability(
		request.Topic,
		now,
		lease,
		request.Authorization,
	); err != nil {
		return err
	}

	nonceBytes, err := base64.RawURLEncoding.DecodeString(
		request.Authorization.Nonce,
	)
	if err != nil {
		return ErrWelcomeInvalid
	}
	// The authorization identity must not rotate with the seven-day lookup
	// epoch. Otherwise the same still-valid signed nonce could be inserted
	// again immediately after an installation lookup rotation.
	nonceIdentity := lengthDelimited(installation.identity, nonceBytes)
	nonceLookup, err := s.environmentLookupDigest(
		"welcome-nonce",
		0,
		nonceIdentity,
	)
	zero(nonceIdentity)
	zero(nonceBytes)
	if err != nil {
		return ErrWelcomeUnavailable
	}
	authorizationID := append([]byte(nil), nonceLookup[:16]...)

	// Welcome grants live for at most a minute and are retained for at most an
	// hour. A stable, environment-scoped lookup for that bounded lifetime
	// keeps exact-envelope correlation and replay uniqueness intact across a
	// seven-day lookup boundary.
	envelopeLookup, err := s.environmentLookupDigest(
		"welcome-envelope",
		0,
		envelopeDigest,
	)
	if err != nil {
		return ErrWelcomeUnavailable
	}
	authorizationBytes, err := json.Marshal(request.Authorization)
	if err != nil {
		return ErrWelcomeInvalid
	}
	encryptedAuthorization, err := s.encryption.Seal(
		welcomeAuthorizationContext(authorizationID),
		authorizationBytes,
	)
	zero(authorizationBytes)
	if err != nil {
		return ErrWelcomeUnavailable
	}
	issuedAt, expiresAt, err := welcomeTimes(request.Authorization)
	if err != nil {
		return ErrWelcomeInvalid
	}
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.welcome_authorizations (
		     authorization_id, lease_id, environment, envelope_lookup,
		     encrypted_authorization, policy_epoch, issued_at, expires_at,
		     consumed_at
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL)`,
		authorizationID,
		lease.leaseID,
		s.environmentID,
		envelopeLookup,
		encryptedAuthorization,
		int64(request.Authorization.PolicyEpoch),
		issuedAt,
		expiresAt,
	)
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return ErrWelcomeConflict
		}
		return ErrWelcomeUnavailable
	}
	if err = tx.Commit(); err != nil {
		return ErrWelcomeUnavailable
	}
	return nil
}

func (s *Store) validateWelcomeRequest(
	request WelcomeAuthorizationRequest,
	now time.Time,
) (*topicpkg.Topic, []byte, error) {
	parsedTopic, err := topicpkg.ParseTopic(request.Topic)
	if err != nil || parsedTopic.Kind() != topicpkg.TopicKindWelcomeMessagesV1 {
		return nil, nil, ErrWelcomeInvalid
	}
	topicDigest := sha256.Sum256(request.Topic)
	envelopeDigest, err := hex.DecodeString(
		request.Authorization.OuterEnvelopeDigest,
	)
	if err != nil || len(envelopeDigest) != sha256.Size {
		return nil, nil, ErrWelcomeInvalid
	}
	if err = authority.VerifyWelcomeAuthorization(
		request.Authorization,
		s.authorityKeys,
		authority.WelcomeVerifyOptions{
			Now:                          now,
			ExpectedEnvironment:          s.environment,
			ExpectedInstallationID:       request.Authorization.InstallationID,
			ExpectedAccountIncarnationID: request.Authorization.AccountIncarnationID,
			ExpectedTopicDigest:          hex.EncodeToString(topicDigest[:]),
			ExpectedOuterEnvelopeDigest:  hex.EncodeToString(envelopeDigest),
			ExpectedPolicyEpoch:          request.Authorization.PolicyEpoch,
		},
	); err != nil {
		return nil, nil, ErrWelcomeInvalid
	}
	return parsedTopic, envelopeDigest, nil
}

type welcomeAuthorizationLease struct {
	leaseID                 []byte
	encryptedCapability     []byte
	agePolicy               int16
	policyEpoch             uint64
	installationPolicyEpoch uint64
}

func (s *Store) findWelcomeLeaseForAuthorization(
	ctx context.Context,
	tx *sql.Tx,
	installationLookup []byte,
	rawTopic []byte,
	now time.Time,
) (*welcomeAuthorizationLease, error) {
	for _, epoch := range CandidateEpochs(now) {
		topicLookup, err := s.environmentLookupDigest(
			"topic",
			epoch,
			rawTopic,
		)
		if err != nil {
			return nil, ErrWelcomeUnavailable
		}
		row := &welcomeAuthorizationLease{}
		var encryptedTopic []byte
		err = tx.QueryRowContext(
			ctx,
			`SELECT l.lease_id, l.encrypted_topic,
			        l.encrypted_receive_capability, i.age_policy,
			        l.policy_epoch, i.policy_epoch
			 FROM hytch_push_vault.subscription_leases AS l
			 JOIN hytch_push_vault.installation_states AS i
			   ON i.installation_lookup = l.installation_lookup
			 WHERE l.installation_lookup = $1
			   AND l.topic_lookup = $2
			   AND l.lookup_key_epoch = $3
			   AND l.topic_kind = $4
			   AND l.push_mode = $5
			   AND l.state = $6
			   AND i.state = $7
			   AND l.environment = $8
			   AND i.environment = $8
			   AND l.expires_at > $9
			   AND l.control_expires_at > $9
			   AND i.expires_at > $9
			   AND i.control_expires_at > $9
			 FOR UPDATE OF l, i`,
			installationLookup,
			topicLookup,
			int64(epoch),
			topicWelcome,
			pushSuppressed,
			stateSuppressed,
			stateActive,
			s.environmentID,
			now,
		).Scan(
			&row.leaseID,
			&encryptedTopic,
			&row.encryptedCapability,
			&row.agePolicy,
			&row.policyEpoch,
			&row.installationPolicyEpoch,
		)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, ErrWelcomeUnavailable
		}
		decryptedTopic, err := s.encryption.Open(
			leaseContext(row.leaseID, "topic"),
			encryptedTopic,
		)
		if err != nil {
			return nil, ErrWelcomeUnavailable
		}
		matches := hmac.Equal(decryptedTopic, rawTopic)
		zero(decryptedTopic)
		if !matches {
			return nil, ErrWelcomeUnavailable
		}
		return row, nil
	}
	return nil, nil
}

func (s *Store) validateWelcomeLeaseCapability(
	rawTopic []byte,
	now time.Time,
	lease *welcomeAuthorizationLease,
	authorization authority.WelcomeAuthorizationV1,
) error {
	capabilityBytes, err := s.encryption.Open(
		leaseContext(lease.leaseID, "capability"),
		lease.encryptedCapability,
	)
	if err != nil {
		return ErrWelcomeUnavailable
	}
	defer zero(capabilityBytes)
	var capability authority.ReceiveCapabilityV1
	if err = json.Unmarshal(capabilityBytes, &capability); err != nil {
		return ErrWelcomeUnavailable
	}
	topicDigestBytes := sha256.Sum256(rawTopic)
	if err = authority.VerifyReceiveCapability(
		capability,
		s.authorityKeys,
		authority.VerifyOptions{
			Now:                            now,
			MaxTTL:                         time.Minute,
			ExpectedEnvironment:            s.environment,
			ExpectedInstallationID:         authorization.InstallationID,
			ExpectedAccountIncarnationID:   authorization.AccountIncarnationID,
			ExpectedTopicDigest:            hex.EncodeToString(topicDigestBytes[:]),
			ExpectedConversationCommitment: authorization.ExpectedConversationCommitment,
		},
	); err != nil ||
		capability.PolicyEpoch != lease.policyEpoch ||
		capability.ConversationGrantVersion != authorization.GrantVersion ||
		capability.PushMode != authority.PushModeSuppressed ||
		!sameConversationCommitment(capability, authorization) {
		return ErrWelcomeInvalid
	}
	return nil
}

type welcomeRouteRow struct {
	authorizationID          []byte
	leaseID                  []byte
	encryptedAuthorization   []byte
	authorizationPolicyEpoch uint64
	authorizationExpiresAt   time.Time
	consumedAt               sql.NullTime
	installationLookup       []byte
	incarnationLookup        []byte
	lookupKeyEpoch           uint64
	encryptedToken           []byte
	installationRefreshedAt  time.Time
	agePolicy                int16
	installationState        int16
	installationPolicyEpoch  uint64
	installationExpiresAt    time.Time
	installationControlAt    time.Time
	encryptedTopic           []byte
	encryptedRouteKey        []byte
	encryptedCapability      []byte
	routeKeyEpoch            uint32
	encryptedNonceState      []byte
	leaseState               int16
	pushMode                 int16
	topicKind                int16
	leasePolicyEpoch         uint64
	leaseRefreshedAt         time.Time
	leaseExpiresAt           time.Time
	leaseControlAt           time.Time
}

// GetWelcomeSubscriptions validates an unconsumed authorization and allocates
// a nonce, but deliberately does not consume the one-use grant or budget.
// EnqueueDeliveryJob finalizes both in the same transaction that inserts the
// durable APNS job, so backpressure or a crash before enqueue cannot lose the
// Welcome. Nonce gaps are safe. An absent optional implementation at the
// listener leaves Welcome delivery closed.
func (s *Store) GetWelcomeSubscriptions(
	ctx context.Context,
	requestedTopic *topicpkg.Topic,
	outerEnvelopeDigest []byte,
) ([]interfaces.WelcomeSubscription, error) {
	if requestedTopic == nil ||
		requestedTopic.Kind() != topicpkg.TopicKindWelcomeMessagesV1 ||
		len(outerEnvelopeDigest) != sha256.Size {
		return nil, ErrWelcomeInvalid
	}
	if s == nil || !s.welcomeEnabled {
		return nil, nil
	}
	if err := s.RequireRetentionSafe(ctx); err != nil {
		return nil, ErrWelcomeUnavailable
	}
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, ErrWelcomeUnavailable
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return nil, ErrWelcomeUnavailable
	}

	envelopeLookup, err := s.environmentLookupDigest(
		"welcome-envelope",
		0,
		outerEnvelopeDigest,
	)
	if err != nil {
		return nil, ErrWelcomeUnavailable
	}
	rows, queryErr := tx.QueryContext(
		ctx,
		`SELECT
		     a.authorization_id, a.lease_id, a.encrypted_authorization,
		     a.policy_epoch, a.expires_at, a.consumed_at,
		     i.installation_lookup, i.incarnation_lookup,
		     i.lookup_key_epoch, i.encrypted_apns_token, i.refreshed_at,
		     i.age_policy, i.state, i.policy_epoch, i.expires_at,
		     i.control_expires_at,
		     l.encrypted_topic, l.encrypted_route_key,
		     l.encrypted_receive_capability, l.route_key_epoch,
		     l.encrypted_nonce_state, l.state, l.push_mode, l.topic_kind,
		     l.policy_epoch, l.refreshed_at, l.expires_at,
		     l.control_expires_at
		 FROM hytch_push_vault.welcome_authorizations AS a
		 JOIN hytch_push_vault.subscription_leases AS l
		   ON l.lease_id = a.lease_id
		 JOIN hytch_push_vault.installation_states AS i
		   ON i.installation_lookup = l.installation_lookup
		 WHERE a.envelope_lookup = $1
		   AND a.environment = $2
		   AND l.environment = $2
		   AND i.environment = $2
		 FOR UPDATE OF a, l, i`,
		envelopeLookup,
		s.environmentID,
	)
	if queryErr != nil {
		return nil, ErrWelcomeUnavailable
	}
	rowsByAuthorization := make(map[string]welcomeRouteRow)
	for rows.Next() {
		var row welcomeRouteRow
		var routeKeyEpoch int64
		if queryErr = rows.Scan(
			&row.authorizationID,
			&row.leaseID,
			&row.encryptedAuthorization,
			&row.authorizationPolicyEpoch,
			&row.authorizationExpiresAt,
			&row.consumedAt,
			&row.installationLookup,
			&row.incarnationLookup,
			&row.lookupKeyEpoch,
			&row.encryptedToken,
			&row.installationRefreshedAt,
			&row.agePolicy,
			&row.installationState,
			&row.installationPolicyEpoch,
			&row.installationExpiresAt,
			&row.installationControlAt,
			&row.encryptedTopic,
			&row.encryptedRouteKey,
			&row.encryptedCapability,
			&routeKeyEpoch,
			&row.encryptedNonceState,
			&row.leaseState,
			&row.pushMode,
			&row.topicKind,
			&row.leasePolicyEpoch,
			&row.leaseRefreshedAt,
			&row.leaseExpiresAt,
			&row.leaseControlAt,
		); queryErr != nil {
			_ = rows.Close()
			return nil, ErrWelcomeUnavailable
		}
		if routeKeyEpoch <= 0 {
			_ = rows.Close()
			return nil, ErrWelcomeUnavailable
		}
		row.routeKeyEpoch = uint32(routeKeyEpoch)
		rowsByAuthorization[string(row.authorizationID)] = row
	}
	if queryErr = rows.Err(); queryErr != nil {
		_ = rows.Close()
		return nil, ErrWelcomeUnavailable
	}
	_ = rows.Close()

	result := make([]interfaces.WelcomeSubscription, 0, len(rowsByAuthorization))
	for _, row := range rowsByAuthorization {
		route, allowed, routeErr := s.consumeWelcomeRoute(
			ctx,
			tx,
			requestedTopic,
			outerEnvelopeDigest,
			now,
			row,
		)
		if routeErr != nil {
			return nil, routeErr
		}
		if allowed {
			result = append(result, route)
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrWelcomeUnavailable
	}
	return result, nil
}

func (s *Store) consumeWelcomeRoute(
	ctx context.Context,
	tx *sql.Tx,
	requestedTopic *topicpkg.Topic,
	outerEnvelopeDigest []byte,
	now time.Time,
	row welcomeRouteRow,
) (interfaces.WelcomeSubscription, bool, error) {
	if row.consumedAt.Valid ||
		row.agePolicy != ageAdult ||
		row.installationState != stateActive ||
		row.leaseState != stateSuppressed ||
		row.pushMode != pushSuppressed ||
		row.topicKind != topicWelcome ||
		row.authorizationPolicyEpoch != row.installationPolicyEpoch ||
		row.authorizationPolicyEpoch != row.leasePolicyEpoch ||
		!now.Before(row.authorizationExpiresAt) ||
		!now.Before(row.installationExpiresAt) ||
		!now.Before(row.installationControlAt) ||
		!now.Before(row.leaseExpiresAt) ||
		!now.Before(row.leaseControlAt) {
		return interfaces.WelcomeSubscription{}, false, nil
	}

	authorizationBytes, err := s.encryption.Open(
		welcomeAuthorizationContext(row.authorizationID),
		row.encryptedAuthorization,
	)
	if err != nil {
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	var authorization authority.WelcomeAuthorizationV1
	if err = json.Unmarshal(authorizationBytes, &authorization); err != nil {
		zero(authorizationBytes)
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	zero(authorizationBytes)

	topicDigestBytes := sha256.Sum256(requestedTopic.Bytes())
	topicDigest := hex.EncodeToString(topicDigestBytes[:])
	envelopeDigest := hex.EncodeToString(outerEnvelopeDigest)
	if err = authority.VerifyWelcomeAuthorization(
		authorization,
		s.authorityKeys,
		authority.WelcomeVerifyOptions{
			Now:                          now,
			ExpectedEnvironment:          s.environment,
			ExpectedInstallationID:       authorization.InstallationID,
			ExpectedAccountIncarnationID: authorization.AccountIncarnationID,
			ExpectedTopicDigest:          topicDigest,
			ExpectedOuterEnvelopeDigest:  envelopeDigest,
			ExpectedPolicyEpoch:          row.leasePolicyEpoch,
		},
	); err != nil {
		return interfaces.WelcomeSubscription{}, false, nil
	}
	expectedIncarnation, err := s.environmentLookupDigest(
		"incarnation",
		row.lookupKeyEpoch,
		[]byte(authorization.AccountIncarnationID),
	)
	if err != nil {
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	if !hmac.Equal(expectedIncarnation, row.incarnationLookup) {
		return interfaces.WelcomeSubscription{}, false, nil
	}
	expectedInstallation, err := s.environmentLookupDigest(
		"installation",
		row.lookupKeyEpoch,
		[]byte(authorization.InstallationID),
	)
	if err != nil {
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	if !hmac.Equal(expectedInstallation, row.installationLookup) {
		return interfaces.WelcomeSubscription{}, false, nil
	}

	rawTopic, err := s.encryption.Open(
		leaseContext(row.leaseID, "topic"),
		row.encryptedTopic,
	)
	if err != nil {
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	if !hmac.Equal(rawTopic, requestedTopic.Bytes()) {
		zero(rawTopic)
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	defer zero(rawTopic)

	routeKey, capabilityBytes, nonce, err := s.openWelcomeRoute(
		requestedTopic,
		now,
		row,
		authorization,
	)
	if err != nil {
		return interfaces.WelcomeSubscription{}, false, err
	}
	var routeCapability authority.ReceiveCapabilityV1
	if err = json.Unmarshal(capabilityBytes, &routeCapability); err != nil {
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	routeAlias, err := base64.RawURLEncoding.DecodeString(
		routeCapability.RouteAlias,
	)
	if err != nil || len(routeAlias) != gate8wrapper.RouteAliasSize {
		zero(routeKey)
		zero(capabilityBytes)
		zero(routeAlias)
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	defer zero(routeAlias)
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
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	updateResult, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.subscription_leases
			 SET encrypted_nonce_state = $2
			 WHERE lease_id = $1
			   AND state = $3
			   AND environment = $4`,
		row.leaseID,
		encryptedNonceState,
		stateSuppressed,
		s.environmentID,
	)
	if err != nil {
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	affected, err := updateResult.RowsAffected()
	if err != nil || affected != 1 {
		zero(routeKey)
		zero(capabilityBytes)
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}

	token, err := s.encryption.Open(
		installationContext(row.installationLookup, "apns-token"),
		row.encryptedToken,
	)
	if err != nil || len(token) != 32 {
		zero(routeKey)
		zero(capabilityBytes)
		zero(token)
		return interfaces.WelcomeSubscription{}, false, ErrWelcomeUnavailable
	}
	tokenHex := hex.EncodeToString(token)
	zero(token)
	opaqueLeaseID := base64.RawURLEncoding.EncodeToString(row.leaseID)
	return interfaces.WelcomeSubscription{
		Installation: interfaces.Installation{
			Id: opaqueLeaseID,
			DeliveryMechanism: interfaces.DeliveryMechanism{
				Kind:      interfaces.APNS,
				Token:     tokenHex,
				UpdatedAt: row.installationRefreshedAt,
			},
			PayloadFormat: interfaces.PayloadFormatV3,
		},
		Subscription: interfaces.Subscription{
			CreatedAt:      row.leaseRefreshedAt,
			InstallationId: opaqueLeaseID,
			Topic:          topicutil.TopicToString(requestedTopic),
			TopicV4:        requestedTopic,
			IsActive:       true,
			IsSilent:       true,
			SecureRoute: &interfaces.SecureRoute{
				LeaseID:           append([]byte(nil), row.leaseID...),
				RouteKey:          routeKey,
				RouteKeyEpoch:     row.routeKeyEpoch,
				NoncePrefix:       nonce.Prefix,
				DeliverySequence:  allocatedSequence,
				AliasDay:          routeCapability.AliasDay,
				RouteAlias:        append([]byte(nil), routeAlias...),
				ReceiveCapability: capabilityBytes,
				LeaseExpiresAt:    row.leaseExpiresAt,
				ControlExpiresAt:  row.leaseControlAt,
				PolicyEpoch:       row.leasePolicyEpoch,
				WelcomeAuthorized: true,
				WelcomeAuthorizationID: append(
					[]byte(nil),
					row.authorizationID...,
				),
				WelcomeEnvelopeDigest: append(
					[]byte(nil),
					outerEnvelopeDigest...,
				),
			},
		},
	}, true, nil
}

func (s *Store) openWelcomeRoute(
	requestedTopic *topicpkg.Topic,
	now time.Time,
	row welcomeRouteRow,
	authorization authority.WelcomeAuthorizationV1,
) ([]byte, []byte, nonceState, error) {
	routeKey, err := s.encryption.Open(
		leaseContext(row.leaseID, "route-key"),
		row.encryptedRouteKey,
	)
	if err != nil || len(routeKey) != gate8wrapper.RouteKeySize {
		zero(routeKey)
		return nil, nil, nonceState{}, ErrWelcomeUnavailable
	}
	capabilityBytes, err := s.encryption.Open(
		leaseContext(row.leaseID, "capability"),
		row.encryptedCapability,
	)
	if err != nil {
		zero(routeKey)
		return nil, nil, nonceState{}, ErrWelcomeUnavailable
	}
	var capability authority.ReceiveCapabilityV1
	if err = json.Unmarshal(capabilityBytes, &capability); err != nil {
		zero(routeKey)
		zero(capabilityBytes)
		return nil, nil, nonceState{}, ErrWelcomeUnavailable
	}
	topicDigestBytes := sha256.Sum256(requestedTopic.Bytes())
	if err = authority.VerifyReceiveCapability(
		capability,
		s.authorityKeys,
		authority.VerifyOptions{
			Now:                            now,
			MaxTTL:                         time.Minute,
			ExpectedEnvironment:            s.environment,
			ExpectedInstallationID:         authorization.InstallationID,
			ExpectedAccountIncarnationID:   authorization.AccountIncarnationID,
			ExpectedTopicDigest:            hex.EncodeToString(topicDigestBytes[:]),
			ExpectedConversationCommitment: authorization.ExpectedConversationCommitment,
		},
	); err != nil ||
		capability.PolicyEpoch != row.leasePolicyEpoch ||
		capability.ConversationGrantVersion != authorization.GrantVersion ||
		capability.PushMode != authority.PushModeSuppressed ||
		!sameConversationCommitment(capability, authorization) ||
		!capabilityMatchesRoute(
			capability,
			routeKey,
			requestedTopic.Bytes(),
			s.environment,
			now,
		) {
		zero(routeKey)
		zero(capabilityBytes)
		return nil, nil, nonceState{}, ErrWelcomeUnavailable
	}
	nonceBytes, err := s.encryption.Open(
		leaseContext(row.leaseID, "nonce-state"),
		row.encryptedNonceState,
	)
	if err != nil {
		zero(routeKey)
		zero(capabilityBytes)
		return nil, nil, nonceState{}, ErrWelcomeUnavailable
	}
	nonce, err := decodeNonceState(nonceBytes)
	zero(nonceBytes)
	if err != nil || nonce.NextSequence > gate8wrapper.MaxCanonicalInteger {
		zero(routeKey)
		zero(capabilityBytes)
		return nil, nil, nonceState{}, ErrWelcomeUnavailable
	}
	return routeKey, capabilityBytes, nonce, nil
}

func sameConversationCommitment(
	capability authority.ReceiveCapabilityV1,
	authorization authority.WelcomeAuthorizationV1,
) bool {
	if capability.ExpectedConversationCommitment == "" ||
		authorization.ExpectedConversationCommitment == "" {
		return false
	}
	return hmac.Equal(
		[]byte(capability.ExpectedConversationCommitment),
		[]byte(authorization.ExpectedConversationCommitment),
	)
}

// finalizeWelcomeEnqueue consumes the one-use grant and destination budget
// inside the caller's durable-job transaction. A caller must commit even when
// allowed is false: budget denial intentionally burns the authorization while
// enqueue/backpressure errors roll the whole transaction back.
func (s *Store) finalizeWelcomeEnqueue(
	ctx context.Context,
	tx *sql.Tx,
	leaseID []byte,
	job SerializedDeliveryJob,
	now time.Time,
) (bool, error) {
	if !s.welcomeEnabled ||
		len(job.WelcomeAuthorizationID) != 16 ||
		len(job.WelcomeEnvelopeDigest) != sha256.Size {
		return false, ErrDeliveryJobInvalid
	}
	var (
		encryptedAuthorization []byte
		policyEpoch            int64
		expiresAt              time.Time
		consumedAt             sql.NullTime
	)
	err := tx.QueryRowContext(
		ctx,
		`SELECT encrypted_authorization, policy_epoch, expires_at, consumed_at
		 FROM hytch_push_vault.welcome_authorizations
		 WHERE authorization_id = $1
		   AND lease_id = $2
		   AND environment = $3
		 FOR UPDATE`,
		job.WelcomeAuthorizationID,
		leaseID,
		s.environmentID,
	).Scan(
		&encryptedAuthorization,
		&policyEpoch,
		&expiresAt,
		&consumedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, deliveryQueueDatabaseError(err)
	}
	if consumedAt.Valid ||
		policyEpoch <= 0 || uint64(policyEpoch) != job.PolicyEpoch ||
		!now.Before(expiresAt.UTC()) {
		return false, nil
	}
	authorizationBytes, err := s.encryption.Open(
		welcomeAuthorizationContext(job.WelcomeAuthorizationID),
		encryptedAuthorization,
	)
	if err != nil {
		return false, ErrDeliveryQueueUnavailable
	}
	defer zero(authorizationBytes)
	var authorization authority.WelcomeAuthorizationV1
	if err = json.Unmarshal(authorizationBytes, &authorization); err != nil {
		return false, ErrDeliveryQueueUnavailable
	}
	envelopeDigest := hex.EncodeToString(job.WelcomeEnvelopeDigest)
	if err = authority.VerifyWelcomeAuthorization(
		authorization,
		s.authorityKeys,
		authority.WelcomeVerifyOptions{
			Now:                          now,
			ExpectedEnvironment:          s.environment,
			ExpectedInstallationID:       authorization.InstallationID,
			ExpectedAccountIncarnationID: authorization.AccountIncarnationID,
			ExpectedOuterEnvelopeDigest:  envelopeDigest,
			ExpectedPolicyEpoch:          job.PolicyEpoch,
		},
	); err != nil {
		return false, nil
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.welcome_authorizations
		 SET consumed_at = $4
		 WHERE authorization_id = $1
		   AND lease_id = $2
		   AND environment = $3
		   AND consumed_at IS NULL`,
		job.WelcomeAuthorizationID,
		leaseID,
		s.environmentID,
		now,
	)
	if err != nil {
		return false, deliveryQueueDatabaseError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, deliveryQueueDatabaseError(err)
	}
	if affected != 1 {
		return false, nil
	}
	allowed, err := s.consumeWelcomeBudget(
		ctx,
		tx,
		[]byte(authorization.InstallationID),
		now,
	)
	if err != nil {
		return false, deliveryQueueDatabaseError(err)
	}
	return allowed, nil
}

func (s *Store) consumeWelcomeBudget(
	ctx context.Context,
	tx *sql.Tx,
	destinationIdentity []byte,
	now time.Time,
) (bool, error) {
	var globalCircuitOpenUntil sql.NullTime
	err := tx.QueryRowContext(
		ctx,
		`SELECT circuit_open_until
		 FROM hytch_push_vault.welcome_global_circuit
		 WHERE environment = $1
		 FOR UPDATE`,
		s.environmentID,
	).Scan(&globalCircuitOpenUntil)
	if err != nil {
		return false, ErrWelcomeUnavailable
	}
	if globalCircuitOpenUntil.Valid &&
		now.Before(globalCircuitOpenUntil.Time) {
		return false, nil
	}

	budgetEpoch, err := welcomeBudgetEpoch(now)
	if err != nil {
		return false, ErrWelcomeUnavailable
	}
	destinationLookup, err := s.environmentLookupDigest(
		"welcome-budget",
		budgetEpoch,
		destinationIdentity,
	)
	if err != nil {
		return false, ErrWelcomeUnavailable
	}
	// Serialize the first budget row creation as well as updates. Without this
	// destination-scoped transaction lock, two bridge instances could both
	// observe a missing row and leave the circuit outcome dependent on a unique
	// constraint race.
	advisoryKey := int32(binary.BigEndian.Uint32(destinationLookup[:4]))
	if _, err = tx.ExecContext(
		ctx,
		`SELECT pg_advisory_xact_lock($1, $2)`,
		welcomeBudgetLockNamespace,
		advisoryKey,
	); err != nil {
		return false, ErrWelcomeUnavailable
	}
	minuteStart := now.Truncate(time.Minute)
	hourStart := now.Truncate(time.Hour)
	var storedMinuteStart time.Time
	var minuteCount int
	var storedHourStart time.Time
	var hourCount int
	var circuitOpenUntil sql.NullTime
	err = tx.QueryRowContext(
		ctx,
		`SELECT minute_window_start, minute_count, hour_window_start,
		        hour_count, circuit_open_until
		 FROM hytch_push_vault.welcome_budgets
		 WHERE environment = $1
		   AND destination_lookup = $2
		 FOR UPDATE`,
		s.environmentID,
		destinationLookup,
	).Scan(
		&storedMinuteStart,
		&minuteCount,
		&storedHourStart,
		&hourCount,
		&circuitOpenUntil,
	)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(
			ctx,
			`INSERT INTO hytch_push_vault.welcome_budgets (
			     environment, destination_lookup,
			     minute_window_start, minute_count,
			     hour_window_start, hour_count, circuit_open_until,
			     updated_at, expires_at
			 ) VALUES ($1,$2,$3,1,$4,1,NULL,$5,$6)`,
			s.environmentID,
			destinationLookup,
			minuteStart,
			hourStart,
			now,
			now.Add(welcomeBudgetRetention),
		)
		if err != nil {
			return false, ErrWelcomeUnavailable
		}
		return true, nil
	}
	if err != nil {
		return false, ErrWelcomeUnavailable
	}
	if circuitOpenUntil.Valid && now.Before(circuitOpenUntil.Time) {
		return false, nil
	}
	if !storedMinuteStart.Equal(minuteStart) {
		storedMinuteStart = minuteStart
		minuteCount = 0
	}
	if !storedHourStart.Equal(hourStart) {
		storedHourStart = hourStart
		hourCount = 0
	}
	if minuteCount >= welcomeMinuteLimit || hourCount >= welcomeHourLimit {
		globalOpenUntil := now.Add(welcomeCircuitTTL)
		if _, err = tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.welcome_global_circuit
			 SET circuit_open_until = $1, updated_at = $2
			 WHERE environment = $3`,
			globalOpenUntil,
			now,
			s.environmentID,
		); err != nil {
			return false, ErrWelcomeUnavailable
		}
		_, err = tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.welcome_budgets
			 SET minute_window_start = $3, minute_count = $4,
			     hour_window_start = $5, hour_count = $6,
			     circuit_open_until = $7, updated_at = $8, expires_at = $9
			 WHERE environment = $1
			   AND destination_lookup = $2`,
			s.environmentID,
			destinationLookup,
			storedMinuteStart,
			minuteCount,
			storedHourStart,
			hourCount,
			globalOpenUntil,
			now,
			now.Add(welcomeBudgetRetention),
		)
		if err != nil {
			return false, ErrWelcomeUnavailable
		}
		return false, nil
	}
	_, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.welcome_budgets
		 SET minute_window_start = $3, minute_count = $4,
		     hour_window_start = $5, hour_count = $6,
		     circuit_open_until = NULL, updated_at = $7, expires_at = $8
		 WHERE environment = $1
		   AND destination_lookup = $2`,
		s.environmentID,
		destinationLookup,
		storedMinuteStart,
		minuteCount+1,
		storedHourStart,
		hourCount+1,
		now,
		now.Add(welcomeBudgetRetention),
	)
	if err != nil {
		return false, ErrWelcomeUnavailable
	}
	return true, nil
}

func welcomeBudgetEpoch(now time.Time) (uint64, error) {
	unix := now.UTC().Unix()
	if unix < 0 {
		return 0, ErrWelcomeUnavailable
	}
	return uint64(unix / int64(time.Hour/time.Second)), nil
}

func welcomeAuthorizationContext(authorizationID []byte) []byte {
	return vaultContext("welcome-authorization", authorizationID, "grant")
}

func lengthDelimited(values ...[]byte) []byte {
	var size int
	for _, value := range values {
		size += 8 + len(value)
	}
	out := make([]byte, 0, size)
	for _, value := range values {
		out = binary.BigEndian.AppendUint64(out, uint64(len(value)))
		out = append(out, value...)
	}
	return out
}

func welcomeTimes(
	authorization authority.WelcomeAuthorizationV1,
) (time.Time, time.Time, error) {
	issuedAt, err := time.Parse(time.RFC3339Nano, authorization.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, authorization.ExpiresAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return issuedAt.UTC(), expiresAt.UTC(), nil
}
