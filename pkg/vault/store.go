package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/authority"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/xmtpd/pkg/topic"
)

const (
	maxRefreshTopics = 2048
	maxHMACKeys      = 3
	maxRouteKeyEpoch = int64(1<<32 - 1)
	// An authenticated route that rotates more than this many times inside
	// the live history horizon fails closed instead of growing unbounded.
	maxRouteKeyHistoryRows = 64

	environmentDevelopment int16 = 1
	environmentProduction  int16 = 2

	ageAdult int16 = 1
	ageTeen  int16 = 2

	topicConversation int16 = 1
	topicWelcome      int16 = 2

	pushSuppressed int16 = 1
	pushAlert      int16 = 2

	deletionTargetInstallation int16 = 1
	deletionTargetRoute        int16 = 2

	stateRegistering        int16 = 1
	stateActive             int16 = 2
	stateDeliveryPending    int16 = 3
	stateSuppressed         int16 = 4
	stateRevoking           int16 = 5
	stateExpired            int16 = 6
	stateBlocked            int16 = 7
	stateBlockedRekeyNeeded int16 = 8
	stateAwaitingRefresh    int16 = 9
)

var (
	ErrRefreshInvalid   = errors.New("subscription refresh invalid")
	ErrRefreshConflict  = errors.New("subscription refresh conflict")
	ErrStoreUnavailable = errors.New("subscription vault unavailable")
)

type HMACKeyInput struct {
	ThirtyDayPeriodsSinceEpoch uint32 `json:"thirty_day_periods_since_epoch"`
	Key                        []byte `json:"key"`
}

type SubscriptionRefresh struct {
	Topic         []byte
	RouteKey      []byte
	RouteKeyEpoch uint32
	HMACKeys      []HMACKeyInput
	Capability    authority.ReceiveCapabilityV1
}

type RefreshRequest struct {
	Environment          string
	InstallationID       string
	AccountIncarnationID string
	Generation           uint64
	IdempotencyKey       string
	APNSToken            []byte
	PayloadSchema        string
	Subscriptions        []SubscriptionRefresh
	PolicyControl        authority.PolicyControlV1
}

type RefreshResult struct {
	AcceptedGeneration uint64
	ActiveLeaseCount   int
	LeaseExpiresAt     time.Time
}

type StoreOptions struct {
	Environment             string
	LeaseTTL                time.Duration
	Encryption              *Keyring
	Lookup                  *LookupKey
	AuthorityKeys           map[string]ed25519.PublicKey
	TeenConversationEnabled bool
	WelcomeEnabled          bool
	Now                     func() time.Time
	Random                  io.Reader
}

type Store struct {
	db                      *sql.DB
	environment             string
	environmentID           int16
	lookupEnvironment       string
	leaseTTL                time.Duration
	encryption              *Keyring
	lookup                  *LookupKey
	authorityKeys           map[string]ed25519.PublicKey
	teenConversationEnabled bool
	welcomeEnabled          bool
	now                     func() time.Time
	random                  io.Reader
	aggregateRandom         io.Reader
}

func NewStore(db *sql.DB, opts StoreOptions) (*Store, error) {
	if opts.WelcomeEnabled ||
		db == nil || opts.Encryption == nil || opts.Lookup == nil ||
		len(opts.AuthorityKeys) == 0 {
		return nil, ErrStoreUnavailable
	}
	environmentID, err := encodeEnvironment(opts.Environment)
	if err != nil {
		return nil, err
	}
	lookupEnvironment, err := stableLookupEnvironment(opts.Environment)
	if err != nil {
		return nil, err
	}
	leaseTTL := opts.LeaseTTL
	if leaseTTL == 0 {
		leaseTTL = 7 * 24 * time.Hour
	}
	if leaseTTL <= 0 || leaseTTL > 7*24*time.Hour {
		return nil, ErrStoreUnavailable
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	return &Store{
		db:                      db,
		environment:             opts.Environment,
		environmentID:           environmentID,
		lookupEnvironment:       lookupEnvironment,
		leaseTTL:                leaseTTL,
		encryption:              opts.Encryption,
		lookup:                  opts.Lookup,
		authorityKeys:           opts.AuthorityKeys,
		teenConversationEnabled: opts.TeenConversationEnabled,
		welcomeEnabled:          false,
		now:                     now,
		random:                  random,
		aggregateRandom:         rand.Reader,
	}, nil
}

func (s *Store) Refresh(ctx context.Context, request RefreshRequest) (*RefreshResult, error) {
	now := s.now().UTC()
	normalized, err := s.validateRefresh(request, now)
	if err != nil {
		return nil, err
	}
	if err = s.RequireRetentionSafe(ctx); err != nil {
		return nil, ErrStoreUnavailable
	}
	requestDigest, err := semanticRefreshDigest(request)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if err = s.requireRetentionSafeTx(ctx, tx); err != nil {
		return nil, ErrStoreUnavailable
	}

	lookupEpoch := LookupEpoch(now)
	installationLookup, err := s.environmentLookupDigest(
		"installation",
		lookupEpoch,
		[]byte(request.InstallationID),
	)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	incarnationLookup, err := s.environmentLookupDigest(
		"incarnation",
		lookupEpoch,
		[]byte(request.AccountIncarnationID),
	)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	installationIdentity, err := s.installationDeletionIdentity(
		request.InstallationID,
	)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	if err = requireTombstoneAdvance(
		ctx,
		tx,
		s.environmentID,
		deletionTargetInstallation,
		installationIdentity,
		request.PolicyControl.PolicyEpoch,
		now,
	); err != nil {
		return nil, err
	}

	existingInstallation, err := s.findInstallation(
		ctx,
		tx,
		request.InstallationID,
		now,
	)
	if err != nil {
		return nil, err
	}
	controlEventDigest, err := controlDigest(request.PolicyControl)
	if err != nil {
		return nil, err
	}
	if existingInstallation != nil {
		if !hmac.Equal(
			existingInstallation.identity,
			installationIdentity,
		) {
			return nil, ErrStoreUnavailable
		}
		existingIncarnationLookup, digestErr := s.environmentLookupDigest(
			"incarnation",
			existingInstallation.lookupKeyEpoch,
			[]byte(request.AccountIncarnationID),
		)
		if digestErr != nil {
			return nil, ErrStoreUnavailable
		}
		incarnationChanged := !equalBytes(
			existingIncarnationLookup,
			existingInstallation.incarnationLookup,
		)
		switch {
		case request.Generation < existingInstallation.generation:
			return nil, ErrRefreshConflict
		case request.Generation == existingInstallation.generation:
			if !hmac.Equal(requestDigest[:], existingInstallation.idempotencyDigest) {
				return nil, ErrRefreshConflict
			}
			count, countErr := s.countActiveLeases(ctx, tx, existingInstallation.lookup)
			if countErr != nil {
				return nil, countErr
			}
			return &RefreshResult{
				AcceptedGeneration: request.Generation,
				ActiveLeaseCount:   count,
				LeaseExpiresAt:     existingInstallation.expiresAt,
			}, nil
		case request.PolicyControl.PolicyEpoch < existingInstallation.policyEpoch:
			return nil, ErrRefreshConflict
		case incarnationChanged &&
			request.PolicyControl.PolicyEpoch <= existingInstallation.policyEpoch:
			return nil, ErrRefreshConflict
		case request.PolicyControl.PolicyEpoch == existingInstallation.policyEpoch &&
			!equalDigest(
				existingInstallation.controlEventDigest,
				controlEventDigest[:],
			):
			// A higher generation is not authority to reverse a revoke or
			// a different blocked transition at the same policy epoch.
			return nil, ErrRefreshConflict
		case request.PolicyControl.PolicyEpoch == existingInstallation.policyEpoch &&
			existingInstallation.state != stateActive &&
			existingInstallation.state != stateAwaitingRefresh:
			// Only AdvancePolicy(active) creates the awaiting-refresh state.
			// Invalid-token, revoke, expiry, and rekey blocks cannot be
			// reversed by replaying authority at the same epoch.
			return nil, ErrRefreshConflict
		case existingInstallation.state == stateBlockedRekeyNeeded:
			return nil, ErrRefreshConflict
		}
		apnsTokenChanged := len(existingInstallation.encryptedAPNSToken) == 0
		if !apnsTokenChanged {
			currentToken, openErr := s.encryption.Open(
				installationContext(
					existingInstallation.lookup,
					"apns-token",
				),
				existingInstallation.encryptedAPNSToken,
			)
			if openErr != nil {
				return nil, ErrStoreUnavailable
			}
			apnsTokenChanged = !hmac.Equal(currentToken, request.APNSToken)
			zero(currentToken)
		}
		if apnsTokenChanged {
			if err = s.markDeliveryJobsSafetyForInstallationTx(
				ctx,
				tx,
				existingInstallation.lookup,
				nil,
			); err != nil {
				return nil, ErrStoreUnavailable
			}
		}
		if !bytes.Equal(existingInstallation.lookup, installationLookup) {
			if _, err = tx.ExecContext(
				ctx,
				`UPDATE hytch_push_vault.installation_states
					 SET installation_lookup = $1, incarnation_lookup = $2,
					     lookup_key_epoch = $3
					 WHERE installation_lookup = $4
					   AND environment = $5`,
				installationLookup,
				incarnationLookup,
				int64(lookupEpoch),
				existingInstallation.lookup,
				s.environmentID,
			); err != nil {
				return nil, ErrStoreUnavailable
			}
		}
	}

	tokenCiphertext, err := s.encryption.Seal(
		installationContext(installationLookup, "apns-token"),
		request.APNSToken,
	)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	controlExpiresAt, err := time.Parse(
		time.RFC3339Nano,
		request.PolicyControl.ExpiresAt,
	)
	if err != nil {
		return nil, ErrRefreshInvalid
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
		return nil, ErrStoreUnavailable
	}

	existingLeases, err := s.loadExistingLeases(ctx, tx, installationLookup)
	if err != nil {
		return nil, err
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
			return nil, err
		}
	}
	for rawTopic, existing := range existingLeases {
		if _, ok := seenExisting[rawTopic]; ok {
			continue
		}
		if err = s.eraseLease(ctx, tx, existing, now); err != nil {
			return nil, err
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, ErrStoreUnavailable
	}
	if err = s.finalizeDeliveryMarkers(ctx); err != nil {
		return nil, ErrStoreUnavailable
	}
	// Aggregate failure never weakens routing authority or copies raw fields.
	_ = s.RecordOperationalAggregate(
		ctx,
		aggregateEventLeaseRefresh,
		aggregateOutcomeActive,
		0,
	)
	return &RefreshResult{
		AcceptedGeneration: request.Generation,
		ActiveLeaseCount:   len(normalized),
		LeaseExpiresAt:     expiresAt,
	}, nil
}

type normalizedSubscription struct {
	topic         []byte
	topicKind     int16
	routeKey      []byte
	routeKeyEpoch uint32
	hmacKeys      []HMACKeyInput
	capability    authority.ReceiveCapabilityV1
	pushMode      int16
	state         int16
	issuedAt      time.Time
	capExpiresAt  time.Time
}

func (s *Store) validateRefresh(
	request RefreshRequest,
	now time.Time,
) ([]normalizedSubscription, error) {
	if request.Environment != s.environment ||
		!authority.ValidEnvironment(request.Environment) ||
		request.Generation == 0 ||
		request.Generation > gate8wrapper.MaxCanonicalInteger ||
		request.PayloadSchema != "hytch_push_wrapper_v1" ||
		!authority.ValidInstallationID(request.InstallationID) ||
		!authority.ValidAccountIncarnationID(request.AccountIncarnationID) ||
		len(request.IdempotencyKey) < 16 ||
		len(request.IdempotencyKey) > 128 ||
		len(request.APNSToken) != 32 ||
		request.Subscriptions == nil ||
		len(request.Subscriptions) > maxRefreshTopics {
		return nil, ErrRefreshInvalid
	}
	if request.PolicyControl.AgePolicy == authority.AgePolicyTeen &&
		!s.teenConversationEnabled {
		return nil, ErrRefreshInvalid
	}
	if request.PolicyControl.State != authority.PolicyStateActive {
		return nil, ErrRefreshInvalid
	}
	if err := authority.VerifyPolicyControl(
		request.PolicyControl,
		s.authorityKeys,
		authority.PolicyVerifyOptions{
			Now:                          now,
			ExpectedEnvironment:          s.environment,
			ExpectedInstallationID:       request.InstallationID,
			ExpectedAccountIncarnationID: request.AccountIncarnationID,
		},
	); err != nil {
		return nil, ErrRefreshInvalid
	}

	maxTTL := time.Minute
	if request.PolicyControl.AgePolicy == authority.AgePolicyTeen {
		maxTTL = 30 * time.Second
	}
	seen := make(map[string]struct{}, len(request.Subscriptions))
	normalized := make([]normalizedSubscription, 0, len(request.Subscriptions))
	for _, subscription := range request.Subscriptions {
		parsed, err := topic.ParseTopic(subscription.Topic)
		if err != nil || len(subscription.RouteKey) != 32 ||
			subscription.RouteKeyEpoch == 0 {
			return nil, ErrRefreshInvalid
		}
		key := string(subscription.Topic)
		if _, duplicate := seen[key]; duplicate {
			return nil, ErrRefreshInvalid
		}
		seen[key] = struct{}{}

		kind := topicConversation
		switch parsed.Kind() {
		case topic.TopicKindGroupMessagesV1:
			if err = validateHMACKeys(subscription.HMACKeys); err != nil {
				return nil, err
			}
		case topic.TopicKindWelcomeMessagesV1:
			// Welcome is hard-closed in this build. Reject its route material
			// before any retention lookup or persistence rather than retaining a
			// dormant signed capability, topic, or route key.
			return nil, ErrRefreshInvalid
		default:
			return nil, ErrRefreshInvalid
		}

		topicDigestBytes := sha256.Sum256(subscription.Topic)
		topicDigest := hex.EncodeToString(topicDigestBytes[:])
		if subscription.Capability.PolicyEpoch != request.PolicyControl.PolicyEpoch {
			return nil, ErrRefreshInvalid
		}
		if !capabilityMatchesRoute(
			subscription.Capability,
			subscription.RouteKey,
			subscription.Topic,
			s.environment,
			now,
		) {
			return nil, ErrRefreshInvalid
		}
		if err = authority.VerifyReceiveCapability(
			subscription.Capability,
			s.authorityKeys,
			authority.VerifyOptions{
				Now:                          now,
				MaxTTL:                       maxTTL,
				ExpectedEnvironment:          s.environment,
				ExpectedInstallationID:       request.InstallationID,
				ExpectedAccountIncarnationID: request.AccountIncarnationID,
				ExpectedTopicDigest:          topicDigest,
			},
		); err != nil {
			return nil, ErrRefreshInvalid
		}
		issuedAt, err := time.Parse(time.RFC3339Nano, subscription.Capability.IssuedAt)
		if err != nil {
			return nil, ErrRefreshInvalid
		}
		capExpiresAt, err := time.Parse(time.RFC3339Nano, subscription.Capability.ExpiresAt)
		if err != nil {
			return nil, ErrRefreshInvalid
		}
		if maximum := now.Add(maxTTL); capExpiresAt.After(maximum) {
			capExpiresAt = maximum
		}
		pushModeID := pushSuppressed
		state := stateSuppressed
		if subscription.Capability.EffectivePushMode() == authority.PushModeAlertAllowed {
			pushModeID = pushAlert
			state = stateActive
		}
		normalized = append(normalized, normalizedSubscription{
			topic:         append([]byte(nil), subscription.Topic...),
			topicKind:     kind,
			routeKey:      append([]byte(nil), subscription.RouteKey...),
			routeKeyEpoch: subscription.RouteKeyEpoch,
			hmacKeys:      cloneHMACKeys(subscription.HMACKeys),
			capability:    subscription.Capability,
			pushMode:      pushModeID,
			state:         state,
			issuedAt:      issuedAt.UTC(),
			capExpiresAt:  capExpiresAt.UTC(),
		})
	}
	return normalized, nil
}

func validateHMACKeys(keys []HMACKeyInput) error {
	if len(keys) == 0 || len(keys) > maxHMACKeys {
		return ErrRefreshInvalid
	}
	seen := make(map[uint32]struct{}, len(keys))
	for _, key := range keys {
		if len(key.Key) != 32 {
			return ErrRefreshInvalid
		}
		if _, duplicate := seen[key.ThirtyDayPeriodsSinceEpoch]; duplicate {
			return ErrRefreshInvalid
		}
		seen[key.ThirtyDayPeriodsSinceEpoch] = struct{}{}
	}
	return nil
}

func semanticRefreshDigest(
	request RefreshRequest,
) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return [sha256.Size]byte{}, ErrRefreshInvalid
	}
	return sha256.Sum256(encoded), nil
}

func capabilityMatchesRoute(
	capability authority.ReceiveCapabilityV1,
	routeKey []byte,
	rawTopic []byte,
	environment string,
	now time.Time,
) bool {
	if capability.AliasDay != gate8wrapper.UTCDay(now) {
		return false
	}
	alias, err := gate8wrapper.DeriveRouteAlias(
		routeKey,
		rawTopic,
		gate8wrapper.Environment(environment),
		capability.AliasDay,
	)
	if err != nil {
		return false
	}
	expected := base64.RawURLEncoding.EncodeToString(alias[:])
	return hmac.Equal([]byte(expected), []byte(capability.RouteAlias))
}

type installationState struct {
	lookup               []byte
	identity             []byte
	incarnationLookup    []byte
	lookupKeyEpoch       uint64
	environmentID        int16
	generation           uint64
	idempotencyDigest    []byte
	controlEventDigest   []byte
	encryptedAPNSToken   []byte
	policyEpoch          uint64
	state                int16
	encryptionKeyVersion uint32
	expiresAt            time.Time
}

func (s *Store) findInstallation(
	ctx context.Context,
	tx *sql.Tx,
	installationID string,
	now time.Time,
) (*installationState, error) {
	if !authority.ValidInstallationID(installationID) {
		return nil, ErrRefreshInvalid
	}
	expectedIdentity, err := s.installationDeletionIdentity(installationID)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	for _, epoch := range CandidateEpochs(now) {
		lookup, err := s.environmentLookupDigest(
			"installation",
			epoch,
			[]byte(installationID),
		)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
		row := &installationState{}
		err = tx.QueryRowContext(
			ctx,
			`SELECT installation_lookup, installation_identity,
			        incarnation_lookup, lookup_key_epoch,
			        environment, generation, idempotency_digest, control_event_digest,
			        encrypted_apns_token, policy_epoch, state,
			        encryption_key_version, expires_at
				 FROM hytch_push_vault.installation_states
				 WHERE installation_lookup = $1
				 FOR UPDATE`,
			lookup,
		).Scan(
			&row.lookup,
			&row.identity,
			&row.incarnationLookup,
			&row.lookupKeyEpoch,
			&row.environmentID,
			&row.generation,
			&row.idempotencyDigest,
			&row.controlEventDigest,
			&row.encryptedAPNSToken,
			&row.policyEpoch,
			&row.state,
			&row.encryptionKeyVersion,
			&row.expiresAt,
		)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, ErrStoreUnavailable
		}
		if row.environmentID != s.environmentID ||
			!hmac.Equal(row.identity, expectedIdentity) {
			return nil, ErrStoreUnavailable
		}
		return row, nil
	}
	return nil, nil
}

type existingLease struct {
	leaseID              []byte
	topic                []byte
	routeIdentity        []byte
	routeKeyEpoch        uint32
	encryptionKeyVersion uint32
	encryptedNonceState  []byte
	encryptedRouteKey    []byte
}

func (s *Store) loadExistingLeases(
	ctx context.Context,
	tx *sql.Tx,
	installationLookup []byte,
) (map[string]*existingLease, error) {
	rows, err := tx.QueryContext(
		ctx,
		`SELECT lease_id, route_identity, route_key_epoch,
		        encryption_key_version,
		        encrypted_nonce_state, encrypted_topic,
		        encrypted_route_key
			 FROM hytch_push_vault.subscription_leases
			 WHERE installation_lookup = $1
			   AND environment = $2
			 FOR UPDATE`,
		installationLookup,
		s.environmentID,
	)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	defer func() {
		_ = rows.Close()
	}()

	out := make(map[string]*existingLease)
	for rows.Next() {
		lease := &existingLease{}
		var routeKeyEpoch int64
		var encryptedTopic []byte
		if err = rows.Scan(
			&lease.leaseID,
			&lease.routeIdentity,
			&routeKeyEpoch,
			&lease.encryptionKeyVersion,
			&lease.encryptedNonceState,
			&encryptedTopic,
			&lease.encryptedRouteKey,
		); err != nil {
			return nil, ErrStoreUnavailable
		}
		if routeKeyEpoch <= 0 || routeKeyEpoch > maxRouteKeyEpoch ||
			len(lease.routeIdentity) != sha256.Size {
			return nil, ErrStoreUnavailable
		}
		lease.routeKeyEpoch = uint32(routeKeyEpoch)
		lease.topic, err = s.encryption.Open(
			leaseContext(lease.leaseID, "topic"),
			encryptedTopic,
		)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
		out[string(lease.topic)] = lease
	}
	if err = rows.Err(); err != nil {
		return nil, ErrStoreUnavailable
	}
	return out, nil
}

func (s *Store) upsertLease(
	ctx context.Context,
	tx *sql.Tx,
	installationID string,
	installationLookup []byte,
	lookupEpoch uint64,
	generation uint64,
	policyEpoch uint64,
	now time.Time,
	expiresAt time.Time,
	controlExpiresAt time.Time,
	subscription normalizedSubscription,
	existing *existingLease,
) error {
	routeIdentity, err := s.routeHistoryIdentity(
		installationID,
		subscription.topic,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	if err = requireTombstoneAdvance(
		ctx,
		tx,
		s.environmentID,
		deletionTargetRoute,
		routeIdentity,
		uint64(subscription.routeKeyEpoch),
		now,
	); err != nil {
		return err
	}
	if existing != nil && !hmac.Equal(existing.routeIdentity, routeIdentity) {
		return ErrStoreUnavailable
	}
	routeKeyCommitment, err := s.routeKeyCommitment(subscription.routeKey)
	if err != nil {
		return ErrStoreUnavailable
	}
	leaseID := make([]byte, 16)
	noncePrefix := uint32(0)
	nextSequence := uint64(0)
	if existing == nil {
		if _, err := io.ReadFull(s.random, leaseID); err != nil {
			return ErrStoreUnavailable
		}
		prefixBytes := make([]byte, 4)
		if _, err := io.ReadFull(s.random, prefixBytes); err != nil {
			return ErrStoreUnavailable
		}
		noncePrefix = binary.BigEndian.Uint32(prefixBytes)
	} else {
		copy(leaseID, existing.leaseID)
		switch {
		case subscription.routeKeyEpoch < existing.routeKeyEpoch:
			return ErrRefreshConflict
		case subscription.routeKeyEpoch == existing.routeKeyEpoch:
			oldRouteKey, openErr := s.encryption.Open(
				leaseContext(existing.leaseID, "route-key"),
				existing.encryptedRouteKey,
			)
			if openErr != nil {
				return ErrStoreUnavailable
			}
			sameKey := hmac.Equal(oldRouteKey, subscription.routeKey)
			zero(oldRouteKey)
			if !sameKey {
				return ErrRefreshConflict
			}
			encryptedState, openErr := s.encryption.Open(
				leaseContext(existing.leaseID, "nonce-state"),
				existing.encryptedNonceState,
			)
			if openErr != nil {
				return ErrStoreUnavailable
			}
			preserved, decodeErr := decodeNonceState(encryptedState)
			zero(encryptedState)
			if decodeErr != nil {
				return ErrStoreUnavailable
			}
			noncePrefix = preserved.Prefix
			nextSequence = preserved.NextSequence
		default:
			oldRouteKey, openErr := s.encryption.Open(
				leaseContext(existing.leaseID, "route-key"),
				existing.encryptedRouteKey,
			)
			if openErr != nil {
				return ErrStoreUnavailable
			}
			sameKey := hmac.Equal(oldRouteKey, subscription.routeKey)
			zero(oldRouteKey)
			if sameKey {
				// Advancing the epoch resets the delivery sequence. Reusing the
				// AES-GCM route key would therefore make nonce safety depend on
				// a random 32-bit prefix never colliding across epochs.
				return ErrRefreshConflict
			}
			if err := s.markDeliveryJobsSafetyForLeaseTx(
				ctx,
				tx,
				existing.leaseID,
			); err != nil {
				return ErrStoreUnavailable
			}
			prefixBytes := make([]byte, 4)
			if _, err := io.ReadFull(s.random, prefixBytes); err != nil {
				return ErrStoreUnavailable
			}
			noncePrefix = binary.BigEndian.Uint32(prefixBytes)
		}
	}

	historyExpiresAt := expiresAt.Add(8 * 24 * time.Hour)
	if err = s.recordRouteKeyHistory(
		ctx,
		tx,
		routeIdentity,
		routeKeyCommitment,
		subscription.routeKeyEpoch,
		existing != nil,
		now,
		historyExpiresAt,
	); err != nil {
		return err
	}
	topicLookup, err := s.environmentLookupDigest(
		"topic",
		lookupEpoch,
		subscription.topic,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	encryptedTopic, err := s.encryption.Seal(
		leaseContext(leaseID, "topic"),
		subscription.topic,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	encryptedRouteKey, err := s.encryption.Seal(
		leaseContext(leaseID, "route-key"),
		subscription.routeKey,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	nonceStateBytes := encodeNonceState(nonceState{
		Prefix:       noncePrefix,
		NextSequence: nextSequence,
	})
	encryptedNonceState, err := s.encryption.Seal(
		leaseContext(leaseID, "nonce-state"),
		nonceStateBytes,
	)
	zero(nonceStateBytes)
	if err != nil {
		return ErrStoreUnavailable
	}
	hmacBytes, err := json.Marshal(subscription.hmacKeys)
	if err != nil {
		return ErrStoreUnavailable
	}
	encryptedHMACKeys, err := s.encryption.Seal(
		leaseContext(leaseID, "hmac-keys"),
		hmacBytes,
	)
	zero(hmacBytes)
	if err != nil {
		return ErrStoreUnavailable
	}
	capabilityBytes, err := json.Marshal(subscription.capability)
	if err != nil {
		return ErrStoreUnavailable
	}
	encryptedCapability, err := s.encryption.Seal(
		leaseContext(leaseID, "capability"),
		capabilityBytes,
	)
	zero(capabilityBytes)
	if err != nil {
		return ErrStoreUnavailable
	}
	leaseControlExpiry := controlExpiresAt
	if subscription.capExpiresAt.Before(leaseControlExpiry) {
		leaseControlExpiry = subscription.capExpiresAt
	}
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.subscription_leases AS lease (
		     lease_id, installation_lookup, route_identity, topic_lookup,
		     lookup_key_epoch,
		     encrypted_topic, encrypted_route_key, encrypted_hmac_keys,
		     encrypted_receive_capability, environment, payload_schema,
		     topic_kind, push_mode, state, generation, policy_epoch,
		     route_key_epoch, encrypted_nonce_state,
		     encryption_key_version, issued_at, refreshed_at, expires_at,
		     control_expires_at, revoked_at
		 ) VALUES (
		     $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$12,$13,$14,$15,
		     $16,$17,$18,$19,$20,$21,$22,NULL
		 )
		 ON CONFLICT (lease_id) DO UPDATE SET
		     installation_lookup = EXCLUDED.installation_lookup,
		     route_identity = EXCLUDED.route_identity,
		     topic_lookup = EXCLUDED.topic_lookup,
		     lookup_key_epoch = EXCLUDED.lookup_key_epoch,
		     encrypted_topic = EXCLUDED.encrypted_topic,
		     encrypted_route_key = EXCLUDED.encrypted_route_key,
		     encrypted_hmac_keys = EXCLUDED.encrypted_hmac_keys,
		     encrypted_receive_capability = EXCLUDED.encrypted_receive_capability,
		     environment = EXCLUDED.environment,
		     payload_schema = EXCLUDED.payload_schema,
		     topic_kind = EXCLUDED.topic_kind,
		     push_mode = EXCLUDED.push_mode,
		     state = EXCLUDED.state,
		     generation = EXCLUDED.generation,
		     policy_epoch = EXCLUDED.policy_epoch,
		     route_key_epoch = EXCLUDED.route_key_epoch,
		     encrypted_nonce_state = EXCLUDED.encrypted_nonce_state,
		     encryption_key_version = EXCLUDED.encryption_key_version,
		     issued_at = EXCLUDED.issued_at,
			     refreshed_at = EXCLUDED.refreshed_at,
			     expires_at = EXCLUDED.expires_at,
			     control_expires_at = EXCLUDED.control_expires_at,
			     revoked_at = NULL
			 WHERE lease.environment = EXCLUDED.environment`,
		leaseID,
		installationLookup,
		routeIdentity,
		topicLookup,
		int64(lookupEpoch),
		encryptedTopic,
		encryptedRouteKey,
		encryptedHMACKeys,
		encryptedCapability,
		s.environmentID,
		subscription.topicKind,
		subscription.pushMode,
		subscription.state,
		int64(generation),
		int64(policyEpoch),
		int64(subscription.routeKeyEpoch),
		encryptedNonceState,
		int32(s.encryption.ActiveVersion()),
		subscription.issuedAt,
		now,
		expiresAt,
		leaseControlExpiry,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *Store) routeHistoryIdentity(
	installationID string,
	rawTopic []byte,
) ([]byte, error) {
	if s == nil || s.lookup == nil ||
		!authority.ValidInstallationID(installationID) ||
		len(rawTopic) == 0 {
		return nil, ErrStoreUnavailable
	}
	input := lengthDelimited(
		[]byte(s.lookupEnvironment),
		[]byte(installationID),
		rawTopic,
	)
	defer zero(input)
	identity, err := s.lookup.Digest("route-history", 0, input)
	if err != nil || len(identity) != sha256.Size {
		return nil, ErrStoreUnavailable
	}
	return identity, nil
}

func (s *Store) installationDeletionIdentity(
	installationID string,
) ([]byte, error) {
	if s == nil || s.lookup == nil ||
		!authority.ValidInstallationID(installationID) {
		return nil, ErrStoreUnavailable
	}
	input := lengthDelimited(
		[]byte(s.lookupEnvironment),
		[]byte(installationID),
	)
	defer zero(input)
	identity, err := s.lookup.Digest(
		"installation-deletion",
		0,
		input,
	)
	if err != nil || len(identity) != sha256.Size {
		return nil, ErrStoreUnavailable
	}
	return identity, nil
}

func (s *Store) routeKeyCommitment(routeKey []byte) ([]byte, error) {
	if s == nil || s.lookup == nil || len(routeKey) != 32 {
		return nil, ErrStoreUnavailable
	}
	commitment, err := s.environmentLookupDigest(
		"route-key-commitment",
		0,
		routeKey,
	)
	if err != nil || len(commitment) != sha256.Size {
		return nil, ErrStoreUnavailable
	}
	return commitment, nil
}

func retireRouteKeyHistory(
	ctx context.Context,
	tx *sql.Tx,
	environmentID int16,
	routeIdentity []byte,
	routeKeyEpoch uint32,
	now time.Time,
) error {
	now = now.UTC()
	if tx == nil ||
		(environmentID != environmentDevelopment &&
			environmentID != environmentProduction) ||
		len(routeIdentity) != sha256.Size ||
		routeKeyEpoch == 0 {
		return ErrStoreUnavailable
	}
	var currentExists bool
	if err := tx.QueryRowContext(
		ctx,
		`SELECT EXISTS (
		   SELECT 1
		     FROM hytch_push_vault.route_key_history
			    WHERE environment = $1
			      AND route_identity = $2
			      AND route_key_epoch = $3
			      AND expires_at > $4
			 )`,
		environmentID,
		routeIdentity,
		int64(routeKeyEpoch),
		now,
	).Scan(&currentExists); err != nil || !currentExists {
		return ErrStoreUnavailable
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.route_key_history
			    SET updated_at = $3,
			        expires_at = $4
			  WHERE environment = $1
			    AND route_identity = $2`,
		environmentID,
		routeIdentity,
		now,
		now.Add(8*24*time.Hour),
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	updated, err := result.RowsAffected()
	if err != nil || updated <= 0 {
		return ErrStoreUnavailable
	}
	return nil
}

// recordRouteKeyHistory is an append-only nonce-lineage fence. Every retained
// commitment for the route identity is locked and extended together so an
// older A key cannot age out while a newer B key remains live and then be
// accepted again as B→A. The row cap fails closed under abnormal rekey churn.
func (s *Store) recordRouteKeyHistory(
	ctx context.Context,
	tx *sql.Tx,
	routeIdentity []byte,
	routeKeyCommitment []byte,
	routeKeyEpoch uint32,
	allowSameEpoch bool,
	now time.Time,
	expiresAt time.Time,
) error {
	now = now.UTC()
	expiresAt = expiresAt.UTC()
	if s == nil || tx == nil ||
		len(routeIdentity) != sha256.Size ||
		len(routeKeyCommitment) != sha256.Size ||
		routeKeyEpoch == 0 ||
		!expiresAt.After(now) ||
		expiresAt.After(now.Add(15*24*time.Hour)) {
		return ErrStoreUnavailable
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.route_key_history
			  WHERE expires_at <= $1
			    AND environment = $4
			    AND (
			      route_identity = $2
			      OR route_key_commitment = $3
			    )`,
		now,
		routeIdentity,
		routeKeyCommitment,
		s.environmentID,
	); err != nil {
		return ErrStoreUnavailable
	}
	rows, err := tx.QueryContext(
		ctx,
		`SELECT route_key_epoch, route_key_commitment
			   FROM hytch_push_vault.route_key_history
			  WHERE route_identity = $1
			    AND environment = $2
			  ORDER BY route_key_epoch DESC
			  FOR UPDATE`,
		routeIdentity,
		s.environmentID,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	var (
		historyCount  int
		maxEpoch      int64
		maxCommitment []byte
	)
	for rows.Next() {
		var (
			storedEpoch      int64
			storedCommitment []byte
		)
		if err = rows.Scan(&storedEpoch, &storedCommitment); err != nil {
			_ = rows.Close()
			return ErrStoreUnavailable
		}
		if storedEpoch <= 0 || storedEpoch > maxRouteKeyEpoch ||
			len(storedCommitment) != sha256.Size {
			_ = rows.Close()
			return ErrStoreUnavailable
		}
		if historyCount == 0 {
			maxEpoch = storedEpoch
			maxCommitment = append([]byte(nil), storedCommitment...)
		}
		historyCount++
	}
	if err = rows.Close(); err != nil {
		return ErrStoreUnavailable
	}
	if err = rows.Err(); err != nil {
		return ErrStoreUnavailable
	}
	proposedEpoch := int64(routeKeyEpoch)
	switch {
	case historyCount == 0:
	case proposedEpoch < maxEpoch:
		return ErrRefreshConflict
	case proposedEpoch == maxEpoch:
		if !allowSameEpoch ||
			!hmac.Equal(maxCommitment, routeKeyCommitment) {
			return ErrRefreshConflict
		}
	case historyCount >= maxRouteKeyHistoryRows:
		return ErrRefreshConflict
	}

	var (
		committedIdentity []byte
		committedEpoch    int64
	)
	err = tx.QueryRowContext(
		ctx,
		`SELECT route_identity, route_key_epoch
			   FROM hytch_push_vault.route_key_history
			  WHERE route_key_commitment = $1
			    AND environment = $2
			  FOR UPDATE`,
		routeKeyCommitment,
		s.environmentID,
	).Scan(&committedIdentity, &committedEpoch)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return ErrStoreUnavailable
	case !hmac.Equal(committedIdentity, routeIdentity) ||
		committedEpoch != proposedEpoch:
		return ErrRefreshConflict
	}

	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.route_key_history
			    SET updated_at = $2,
			        expires_at = $3
			  WHERE route_identity = $1
			    AND environment = $4`,
		routeIdentity,
		now,
		expiresAt,
		s.environmentID,
	); err != nil {
		return ErrStoreUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.route_key_history (
			     environment, route_identity, route_key_epoch,
			     route_key_commitment,
			     updated_at, expires_at
			 ) VALUES ($1,$2,$3,$4,$5,$6)
			 ON CONFLICT (
			   environment, route_identity, route_key_epoch
			 ) DO UPDATE SET
			     updated_at = EXCLUDED.updated_at,
			     expires_at = EXCLUDED.expires_at`,
		s.environmentID,
		routeIdentity,
		proposedEpoch,
		routeKeyCommitment,
		now,
		expiresAt,
	); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *Store) eraseLease(
	ctx context.Context,
	tx *sql.Tx,
	lease *existingLease,
	now time.Time,
) error {
	if err := s.markDeliveryJobsSafetyForLeaseTx(
		ctx,
		tx,
		lease.leaseID,
	); err != nil {
		return ErrStoreUnavailable
	}
	currentRouteKey, err := s.encryption.Open(
		leaseContext(lease.leaseID, "route-key"),
		lease.encryptedRouteKey,
	)
	if err != nil {
		return ErrStoreUnavailable
	}
	routeKeyCommitment, err := s.routeKeyCommitment(currentRouteKey)
	zero(currentRouteKey)
	if err != nil {
		return ErrStoreUnavailable
	}
	if err = s.recordRouteKeyHistory(
		ctx,
		tx,
		lease.routeIdentity,
		routeKeyCommitment,
		lease.routeKeyEpoch,
		true,
		now,
		now.Add(8*24*time.Hour),
	); err != nil {
		return err
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
	if _, err = tx.ExecContext(
		ctx,
		`DELETE FROM hytch_push_vault.subscription_leases
		  WHERE lease_id = $1 AND environment = $2`,
		lease.leaseID,
		s.environmentID,
	); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *Store) countActiveLeases(
	ctx context.Context,
	tx *sql.Tx,
	installationLookup []byte,
) (int, error) {
	var count int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM hytch_push_vault.subscription_leases
		 WHERE installation_lookup = $1
		   AND state IN ($2, $3)
		   AND environment = $4`,
		installationLookup,
		stateActive,
		stateSuppressed,
		s.environmentID,
	).Scan(&count); err != nil {
		return 0, ErrStoreUnavailable
	}
	return count, nil
}

func encodeEnvironment(value string) (int16, error) {
	switch value {
	case "dev":
		return environmentDevelopment, nil
	case "production":
		return environmentProduction, nil
	default:
		return 0, ErrRefreshInvalid
	}
}

// stableLookupEnvironment preserves the original vault lookup/tombstone
// namespace while the signed A9 and wrapper wire enum uses "dev". Re-keying
// these identities on an enum spelling change would orphan live ciphertext and,
// more importantly, make existing deletion fences unreachable.
func stableLookupEnvironment(value string) (string, error) {
	switch value {
	case authority.EnvironmentDev:
		return "development", nil
	case authority.EnvironmentProduction:
		return authority.EnvironmentProduction, nil
	default:
		return "", ErrRefreshInvalid
	}
}

// environmentLookupDigest prevents stores that intentionally share the vault
// schema and lookup root from addressing each other's installations,
// incarnations, topics, or route-key history. The label and length-delimited
// stable lookup namespace make the separation explicit and unambiguous.
func (s *Store) environmentLookupDigest(
	domain string,
	epoch uint64,
	value []byte,
) ([]byte, error) {
	if s == nil || s.lookup == nil || s.environmentID == 0 ||
		len(s.lookupEnvironment) == 0 || len(value) == 0 {
		return nil, ErrLookupUnavailable
	}
	input := make(
		[]byte,
		0,
		len("hytch.push.vault.environment.v1\x00")+
			16+len(s.lookupEnvironment)+len(value),
	)
	input = append(input, "hytch.push.vault.environment.v1\x00"...)
	input = binary.BigEndian.AppendUint64(
		input,
		uint64(len(s.lookupEnvironment)),
	)
	input = append(input, s.lookupEnvironment...)
	input = binary.BigEndian.AppendUint64(input, uint64(len(value)))
	input = append(input, value...)
	defer zero(input)
	return s.lookup.Digest(domain, epoch, input)
}

func installationContext(lookup []byte, field string) []byte {
	return vaultContext("installation", lookup, field)
}

func leaseContext(leaseID []byte, field string) []byte {
	return vaultContext("lease", leaseID, field)
}

func vaultContext(kind string, identifier []byte, field string) []byte {
	out := make([]byte, 0, len(kind)+len(identifier)+len(field)+18)
	out = append(out, "hytch.push.vault.v1\x00"...)
	out = append(out, kind...)
	out = append(out, 0)
	out = binary.BigEndian.AppendUint64(out, uint64(len(identifier)))
	out = append(out, identifier...)
	out = append(out, 0)
	return append(out, field...)
}

func cloneHMACKeys(keys []HMACKeyInput) []HMACKeyInput {
	out := make([]HMACKeyInput, len(keys))
	for idx, key := range keys {
		out[idx] = HMACKeyInput{
			ThirtyDayPeriodsSinceEpoch: key.ThirtyDayPeriodsSinceEpoch,
			Key:                        append([]byte(nil), key.Key...),
		}
	}
	return out
}

// keep otherwise-useful state labels compile-time referenced while their
// worker transitions are implemented in the next package layer.
var _ = []int16{
	stateRegistering,
	stateDeliveryPending,
	stateRevoking,
	stateExpired,
	stateBlocked,
	stateBlockedRekeyNeeded,
	stateAwaitingRefresh,
}
