package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

type signedStoreFixture struct {
	store          *Store
	now            *time.Time
	privateKey     ed25519.PrivateKey
	keyID          string
	installationID string
	incarnationID  string
}

func newSignedStoreFixture(t *testing.T) (*signedStoreFixture, *sql.DB) {
	t.Helper()
	db := testdb.CreateTestDb(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rootKey := bytes.Repeat([]byte{0x31}, 32)
	keyring, err := NewKeyring(1, map[uint32][]byte{1: rootKey})
	require.NoError(t, err)
	lookup, err := NewLookupKey(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store, err := NewStore(db, StoreOptions{
		Environment:   "development",
		LeaseTTL:      7 * 24 * time.Hour,
		Encryption:    keyring,
		Lookup:        lookup,
		AuthorityKeys: map[string]ed25519.PublicKey{"test-key": publicKey},
		Now:           func() time.Time { return now },
	})
	require.NoError(t, err)
	sweeper, err := NewRetentionSweeper(db, RetentionOptions{
		SweepInterval:        15 * time.Minute,
		Environment:          "development",
		Lookup:               lookup,
		EncryptionKeyVersion: keyring.ActiveVersion(),
		Now:                  func() time.Time { return now },
	})
	require.NoError(t, err)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)
	return &signedStoreFixture{
		store:          store,
		now:            &now,
		privateKey:     privateKey,
		keyID:          "test-key",
		installationID: "installation-test-01",
		incarnationID:  "incarnation-test-01",
	}, db
}

func (fixture *signedStoreFixture) policy(
	t *testing.T,
	epoch uint64,
	state authority.PolicyState,
	age authority.AgePolicy,
	incarnationID string,
) authority.PolicyControlV1 {
	t.Helper()
	control := authority.PolicyControlV1{
		SchemaVersion:        1,
		Environment:          fixture.store.environment,
		InstallationID:       fixture.installationID,
		AccountIncarnationID: incarnationID,
		PolicyEpoch:          epoch,
		State:                state,
		AgePolicy:            age,
		IssuedAt:             fixture.now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt:            fixture.now.Add(30 * time.Second).Format(time.RFC3339Nano),
		SigningKeyID:         fixture.keyID,
		Algorithm:            "Ed25519",
	}
	signingBytes, err := control.SigningBytes()
	require.NoError(t, err)
	control.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(fixture.privateKey, signingBytes),
	)
	return control
}

func (fixture *signedStoreFixture) subscription(
	t *testing.T,
	topic *topicpkg.Topic,
	routeByte byte,
	routeEpoch uint32,
	period uint32,
	mode authority.PushMode,
	policyEpoch uint64,
) SubscriptionRefresh {
	t.Helper()
	rawTopic := topic.Bytes()
	routeKey := bytes.Repeat([]byte{routeByte}, 32)
	aliasDay := gate8wrapper.UTCDay(*fixture.now)
	alias, err := gate8wrapper.DeriveRouteAlias(
		routeKey,
		rawTopic,
		gate8wrapper.Environment(fixture.store.environment),
		aliasDay,
	)
	require.NoError(t, err)
	topicDigest := sha256.Sum256(rawTopic)
	expectedConversationCommitment := ""
	if topic.Kind() == topicpkg.TopicKindWelcomeMessagesV1 {
		commitment, commitmentErr := authority.ExpectedConversationCommitment(
			fixture.store.environment,
			fixture.installationID,
			fixture.incarnationID,
			"conversation-test-01",
		)
		require.NoError(t, commitmentErr)
		expectedConversationCommitment = hex.EncodeToString(commitment[:])
	}
	capability := authority.ReceiveCapabilityV1{
		SchemaVersion:                  1,
		Environment:                    fixture.store.environment,
		InstallationID:                 fixture.installationID,
		AccountIncarnationID:           fixture.incarnationID,
		PolicyEpoch:                    policyEpoch,
		TopicDigest:                    hex.EncodeToString(topicDigest[:]),
		AliasDay:                       aliasDay,
		RouteAlias:                     base64.RawURLEncoding.EncodeToString(alias[:]),
		ConversationGrantVersion:       1,
		RosterVersion:                  1,
		ExpectedConversationCommitment: expectedConversationCommitment,
		PushMode:                       mode,
		IssuedAt:                       fixture.now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt:                      fixture.now.Add(30 * time.Second).Format(time.RFC3339Nano),
		Nonce: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{routeByte + 1}, 16),
		),
		SigningKeyID: fixture.keyID,
		Algorithm:    "Ed25519",
	}
	signingBytes, err := capability.SigningBytes()
	require.NoError(t, err)
	capability.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(fixture.privateKey, signingBytes),
	)
	subscription := SubscriptionRefresh{
		Topic:         append([]byte(nil), rawTopic...),
		RouteKey:      routeKey,
		RouteKeyEpoch: routeEpoch,
		Capability:    capability,
	}
	if topic.Kind() == topicpkg.TopicKindGroupMessagesV1 {
		subscription.HMACKeys = []HMACKeyInput{{
			ThirtyDayPeriodsSinceEpoch: period,
			Key:                        bytes.Repeat([]byte{0x77}, 32),
		}}
	}
	return subscription
}

func (fixture *signedStoreFixture) refresh(
	t *testing.T,
	generation uint64,
	policy authority.PolicyControlV1,
	subscriptions ...SubscriptionRefresh,
) RefreshRequest {
	t.Helper()
	return RefreshRequest{
		Environment:          fixture.store.environment,
		InstallationID:       fixture.installationID,
		AccountIncarnationID: policy.AccountIncarnationID,
		Generation:           generation,
		IdempotencyKey:       "idempotency-test-0001",
		APNSToken:            bytes.Repeat([]byte{0xa1}, 32),
		PayloadSchema:        "hytch_push_wrapper_v1",
		Subscriptions:        subscriptions,
		PolicyControl:        policy,
	}
}

func testTopic(t *testing.T, kind topicpkg.TopicKind, value byte) *topicpkg.Topic {
	t.Helper()
	return topicpkg.NewTopic(kind, bytes.Repeat([]byte{value}, 16))
}

func TestSecureStoreAtomicTopicListsEncryptedRoutingAndSequences(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	period := uint32(688)
	firstDM := testTopic(t, topicpkg.TopicKindGroupMessagesV1, 0x11)
	stitchedDM := testTopic(t, topicpkg.TopicKindGroupMessagesV1, 0x12)
	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x13)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	request := fixture.refresh(
		t,
		1,
		control,
		fixture.subscription(
			t,
			firstDM,
			0x21,
			1,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		fixture.subscription(
			t,
			stitchedDM,
			0x22,
			1,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		fixture.subscription(
			t,
			welcome,
			0x23,
			1,
			period,
			authority.PushModeSuppressed,
			1,
		),
	)
	nonIJSON := request
	nonIJSON.Generation = gate8wrapper.MaxCanonicalInteger + 1
	_, err := fixture.store.Refresh(t.Context(), nonIJSON)
	require.ErrorIs(t, err, ErrRefreshInvalid)

	result, err := fixture.store.Refresh(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, 3, result.ActiveLeaseCount)
	require.Equal(t, fixture.now.Add(7*24*time.Hour), result.LeaseExpiresAt)

	// A semantic replay is idempotent regardless of request object identity.
	replayed, err := fixture.store.Refresh(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, result.AcceptedGeneration, replayed.AcceptedGeneration)
	require.Equal(t, result.ActiveLeaseCount, replayed.ActiveLeaseCount)
	require.True(t, result.LeaseExpiresAt.Equal(replayed.LeaseExpiresAt))

	for _, topic := range []*topicpkg.Topic{firstDM, stitchedDM} {
		subscriptions, routeErr := fixture.store.GetSubscriptions(
			t.Context(),
			topic,
			int(period),
		)
		require.NoError(t, routeErr)
		require.Len(t, subscriptions, 1)
		require.NotNil(t, subscriptions[0].SecureRoute)
		require.Equal(t, uint64(0), subscriptions[0].SecureRoute.DeliverySequence)
		require.Equal(t, int(period), *subscriptions[0].ExpectedHmacKeyPeriod)
		installations, installErr := fixture.store.GetInstallations(
			t.Context(),
			[]string{subscriptions[0].InstallationId},
		)
		require.NoError(t, installErr)
		require.Len(t, installations, 1)
		require.Equal(
			t,
			hex.EncodeToString(request.APNSToken),
			installations[0].DeliveryMechanism.Token,
		)
	}
	second, err := fixture.store.GetSubscriptions(
		t.Context(),
		firstDM,
		int(period),
	)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Equal(t, uint64(1), second[0].SecureRoute.DeliverySequence)

	var (
		encryptedToken      []byte
		encryptedTopic      []byte
		encryptedRouteKey   []byte
		encryptedNonceState []byte
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT i.encrypted_apns_token, l.encrypted_topic,
		        l.encrypted_route_key, l.encrypted_nonce_state
		 FROM hytch_push_vault.installation_states AS i
		 JOIN hytch_push_vault.subscription_leases AS l
		   ON l.installation_lookup = i.installation_lookup
		 WHERE l.topic_kind = $1
		 LIMIT 1`,
		topicConversation,
	).Scan(
		&encryptedToken,
		&encryptedTopic,
		&encryptedRouteKey,
		&encryptedNonceState,
	))
	require.NotContains(t, encryptedToken, request.APNSToken)
	require.NotContains(t, encryptedTopic, firstDM.Bytes())
	require.NotContains(t, encryptedRouteKey, bytes.Repeat([]byte{0x21}, 32))
	require.NotEqual(t, nonceStateBytes, len(encryptedNonceState))

	var plaintextNonceColumns int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		 FROM information_schema.columns
		 WHERE table_schema = 'hytch_push_vault'
		   AND table_name = 'subscription_leases'
		   AND column_name IN ('nonce_prefix', 'next_delivery_sequence')`,
	).Scan(&plaintextNonceColumns))
	require.Zero(t, plaintextNonceColumns)

	var aggregateCells int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		 FROM hytch_push_vault.operational_aggregates
		 WHERE event_name = $1
		   AND component = $2
		   AND traffic_class = 0`,
		aggregateEventLeaseRefresh,
		aggregateComponentBridge,
	).Scan(&aggregateCells))
	require.Equal(t, 1, aggregateCells)
}

func TestWelcomeRouteRequiresExactSuppressedPushMode(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, _ := newSignedStoreFixture(t)
	period := uint32(688)
	conversation := testTopic(
		t,
		topicpkg.TopicKindGroupMessagesV1,
		0x14,
	)
	welcome := testTopic(
		t,
		topicpkg.TopicKindWelcomeMessagesV1,
		0x15,
	)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)

	_, err := fixture.store.Refresh(
		t.Context(),
		fixture.refresh(
			t,
			1,
			control,
			fixture.subscription(
				t,
				conversation,
				0x24,
				1,
				period,
				authority.PushModeAlertAllowed,
				1,
			),
			fixture.subscription(
				t,
				welcome,
				0x25,
				1,
				period,
				authority.PushMode("future-mode"),
				1,
			),
		),
	)
	require.ErrorIs(t, err, ErrRefreshInvalid)
}

func TestSharedVaultDatabaseIsolatesDevelopmentAndProduction(t *testing.T) {
	requireVaultIntegrationTests(t)
	development, db := newSignedStoreFixture(t)
	productionStore, err := NewStore(db, StoreOptions{
		Environment:             "production",
		LeaseTTL:                development.store.leaseTTL,
		Encryption:              development.store.encryption,
		Lookup:                  development.store.lookup,
		AuthorityKeys:           development.store.authorityKeys,
		TeenConversationEnabled: development.store.teenConversationEnabled,
		WelcomeEnabled:          development.store.welcomeEnabled,
		Now: func() time.Time {
			return *development.now
		},
	})
	require.NoError(t, err)
	productionSweeper, err := NewRetentionSweeper(db, RetentionOptions{
		SweepInterval:        15 * time.Minute,
		Environment:          "production",
		Lookup:               development.store.lookup,
		EncryptionKeyVersion: development.store.encryption.ActiveVersion(),
		Now: func() time.Time {
			return *development.now
		},
	})
	require.NoError(t, err)
	_, err = productionSweeper.Sweep(t.Context())
	require.NoError(t, err)
	production := &signedStoreFixture{
		store:          productionStore,
		now:            development.now,
		privateKey:     development.privateKey,
		keyID:          development.keyID,
		installationID: development.installationID,
		incarnationID:  development.incarnationID,
	}
	period := uint32(688)
	conversation := testTopic(
		t,
		topicpkg.TopicKindGroupMessagesV1,
		0x24,
	)
	welcome := testTopic(
		t,
		topicpkg.TopicKindWelcomeMessagesV1,
		0x25,
	)
	refreshFor := func(fixture *signedStoreFixture, tokenByte byte) RefreshRequest {
		control := fixture.policy(
			t,
			1,
			authority.PolicyStateActive,
			authority.AgePolicyAdult,
			fixture.incarnationID,
		)
		request := fixture.refresh(
			t,
			1,
			control,
			fixture.subscription(
				t,
				conversation,
				0x26,
				1,
				period,
				authority.PushModeAlertAllowed,
				1,
			),
			fixture.subscription(
				t,
				welcome,
				0x27,
				1,
				period,
				authority.PushModeSuppressed,
				1,
			),
		)
		request.APNSToken = bytes.Repeat([]byte{tokenByte}, 32)
		return request
	}
	developmentRequest := refreshFor(development, 0xd1)
	productionRequest := refreshFor(production, 0xe1)
	_, err = development.store.Refresh(t.Context(), developmentRequest)
	require.NoError(t, err)
	_, err = production.store.Refresh(t.Context(), productionRequest)
	require.NoError(t, err)

	var (
		installationRows       int
		installationLookups    int
		installationIdentities int
		incarnationLookups     int
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*),
		        COUNT(DISTINCT installation_lookup),
		        COUNT(DISTINCT installation_identity),
		        COUNT(DISTINCT incarnation_lookup)
		   FROM hytch_push_vault.installation_states`,
	).Scan(
		&installationRows,
		&installationLookups,
		&installationIdentities,
		&incarnationLookups,
	))
	require.Equal(t, 2, installationRows)
	require.Equal(t, installationRows, installationLookups)
	require.Equal(t, installationRows, installationIdentities)
	require.Equal(t, installationRows, incarnationLookups)

	var (
		conversationRows    int
		topicLookups        int
		routeIdentities     int
		routeHistoryRows    int
		routeKeyCommitments int
	)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*),
		        COUNT(DISTINCT topic_lookup),
		        COUNT(DISTINCT route_identity)
		   FROM hytch_push_vault.subscription_leases
		  WHERE topic_kind = $1`,
		topicConversation,
	).Scan(
		&conversationRows,
		&topicLookups,
		&routeIdentities,
	))
	require.Equal(t, 2, conversationRows)
	require.Equal(t, conversationRows, topicLookups)
	require.Equal(t, conversationRows, routeIdentities)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*), COUNT(DISTINCT route_key_commitment)
		   FROM hytch_push_vault.route_key_history`,
	).Scan(&routeHistoryRows, &routeKeyCommitments))
	require.Equal(t, 4, routeHistoryRows)
	require.Equal(t, routeHistoryRows, routeKeyCommitments)

	developmentRoutes, err := development.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.NoError(t, err)
	require.Len(t, developmentRoutes, 1)
	productionRoutes, err := production.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.NoError(t, err)
	require.Len(t, productionRoutes, 1)
	require.NotEqual(
		t,
		developmentRoutes[0].InstallationId,
		productionRoutes[0].InstallationId,
	)

	developmentInstallations, err := development.store.GetInstallations(
		t.Context(),
		[]string{developmentRoutes[0].InstallationId},
	)
	require.NoError(t, err)
	require.Len(t, developmentInstallations, 1)
	require.Equal(
		t,
		hex.EncodeToString(developmentRequest.APNSToken),
		developmentInstallations[0].DeliveryMechanism.Token,
	)
	productionInstallations, err := production.store.GetInstallations(
		t.Context(),
		[]string{productionRoutes[0].InstallationId},
	)
	require.NoError(t, err)
	require.Len(t, productionInstallations, 1)
	require.Equal(
		t,
		hex.EncodeToString(productionRequest.APNSToken),
		productionInstallations[0].DeliveryMechanism.Token,
	)
	crossEnvironmentInstallations, err := development.store.GetInstallations(
		t.Context(),
		[]string{productionRoutes[0].InstallationId},
	)
	require.NoError(t, err)
	require.Empty(t, crossEnvironmentInstallations)
	crossEnvironmentInstallations, err = production.store.GetInstallations(
		t.Context(),
		[]string{developmentRoutes[0].InstallationId},
	)
	require.NoError(t, err)
	require.Empty(t, crossEnvironmentInstallations)

	developmentRevoke := development.policy(
		t,
		2,
		authority.PolicyStateRevoked,
		authority.AgePolicyAdult,
		development.incarnationID,
	)
	require.NoError(t, development.store.AdvancePolicy(
		t.Context(),
		PolicyAdvanceRequest{Control: developmentRevoke},
	))
	developmentRoutes, err = development.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.NoError(t, err)
	require.Empty(t, developmentRoutes)
	productionRoutes, err = production.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.NoError(t, err)
	require.Len(t, productionRoutes, 1)
}

func TestAdvancePolicyFailsClosedOnStoredEnvironmentOrIdentityMismatch(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	for _, testCase := range []struct {
		name      string
		mutateSQL string
		mutateArg any
	}{
		{
			name:      "environment",
			mutateSQL: `UPDATE hytch_push_vault.installation_states SET environment = $1`,
			mutateArg: environmentProduction,
		},
		{
			name:      "stable identity",
			mutateSQL: `UPDATE hytch_push_vault.installation_states SET installation_identity = $1`,
			mutateArg: bytes.Repeat([]byte{0xff}, sha256.Size),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture, db := newSignedStoreFixture(t)
			conversation := testTopic(
				t,
				topicpkg.TopicKindGroupMessagesV1,
				0x28,
			)
			welcome := testTopic(
				t,
				topicpkg.TopicKindWelcomeMessagesV1,
				0x29,
			)
			control := fixture.policy(
				t,
				1,
				authority.PolicyStateActive,
				authority.AgePolicyAdult,
				fixture.incarnationID,
			)
			_, err := fixture.store.Refresh(
				t.Context(),
				fixture.refresh(
					t,
					1,
					control,
					fixture.subscription(
						t,
						conversation,
						0x2a,
						1,
						688,
						authority.PushModeAlertAllowed,
						1,
					),
					fixture.subscription(
						t,
						welcome,
						0x2b,
						1,
						688,
						authority.PushModeSuppressed,
						1,
					),
				),
			)
			require.NoError(t, err)
			_, err = db.ExecContext(
				t.Context(),
				testCase.mutateSQL,
				testCase.mutateArg,
			)
			require.NoError(t, err)

			advanced := fixture.policy(
				t,
				2,
				authority.PolicyStateActive,
				authority.AgePolicyAdult,
				fixture.incarnationID,
			)
			require.ErrorIs(
				t,
				fixture.store.AdvancePolicy(
					t.Context(),
					PolicyAdvanceRequest{Control: advanced},
				),
				ErrStoreUnavailable,
			)
		})
	}
}

func TestTeenConversationRoutingIsDisabledByDefault(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	conversation := testTopic(
		t,
		topicpkg.TopicKindGroupMessagesV1,
		0x29,
	)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyTeen,
		fixture.incarnationID,
	)
	request := fixture.refresh(
		t,
		1,
		control,
		fixture.subscription(
			t,
			conversation,
			0x2a,
			1,
			688,
			authority.PushModeAlertAllowed,
			1,
		),
	)

	_, err := fixture.store.Refresh(t.Context(), request)
	require.ErrorIs(t, err, ErrRefreshInvalid)
	require.ErrorIs(
		t,
		fixture.store.AdvancePolicy(
			t.Context(),
			PolicyAdvanceRequest{Control: control},
		),
		ErrRefreshInvalid,
	)

	var installationCount int
	var leaseCount int
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*)
			   FROM hytch_push_vault.installation_states`,
		).Scan(&installationCount),
	)
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*)
			   FROM hytch_push_vault.subscription_leases`,
		).Scan(&leaseCount),
	)
	require.Zero(t, installationCount)
	require.Zero(t, leaseCount)

	routes, err := fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		688,
	)
	require.NoError(t, err)
	require.Empty(t, routes)
}

func TestTeenConversationKillSwitchStopsPersistedRoutesAndClaims(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, _ := newSignedStoreFixture(t)
	fixture.store.teenConversationEnabled = true
	period := uint32(688)
	conversation := testTopic(
		t,
		topicpkg.TopicKindGroupMessagesV1,
		0x2c,
	)
	welcome := testTopic(
		t,
		topicpkg.TopicKindWelcomeMessagesV1,
		0x2d,
	)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyTeen,
		fixture.incarnationID,
	)
	control.ExpiresAt = fixture.now.Add(29 * time.Second).Format(
		time.RFC3339Nano,
	)
	controlSigningBytes, err := control.SigningBytes()
	require.NoError(t, err)
	control.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(fixture.privateKey, controlSigningBytes),
	)
	request := fixture.refresh(
		t,
		1,
		control,
		fixture.subscription(
			t,
			conversation,
			0x2e,
			1,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		fixture.subscription(
			t,
			welcome,
			0x2f,
			1,
			period,
			authority.PushModeSuppressed,
			1,
		),
	)
	for idx := range request.Subscriptions {
		request.Subscriptions[idx].Capability.ExpiresAt = fixture.now.Add(
			29 * time.Second,
		).Format(time.RFC3339Nano)
		capabilitySigningBytes, signingErr :=
			request.Subscriptions[idx].Capability.SigningBytes()
		require.NoError(t, signingErr)
		request.Subscriptions[idx].Capability.Signature =
			base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(fixture.privateKey, capabilitySigningBytes),
			)
	}
	_, err = fixture.store.Refresh(t.Context(), request)
	require.NoError(t, err)
	routes, err := fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	route := routes[0].SecureRoute
	require.NotNil(t, route)
	job := SerializedDeliveryJob{
		DeviceToken:      hex.EncodeToString(request.APNSToken),
		Topic:            "com.example.hytch.dev",
		Payload:          []byte(`{"aps":{"alert":"New message"}}`),
		PushType:         "alert",
		Priority:         10,
		Expiration:       fixture.now.Add(20 * time.Second),
		TrafficClass:     DeliveryTrafficConversation,
		PolicyEpoch:      route.PolicyEpoch,
		RouteKeyEpoch:    route.RouteKeyEpoch,
		NoncePrefix:      route.NoncePrefix,
		DeliverySequence: route.DeliverySequence,
		AliasDay:         route.AliasDay,
		RouteAlias:       append([]byte(nil), route.RouteAlias...),
	}
	jobID, err := fixture.store.EnqueueDeliveryJob(
		t.Context(),
		route.LeaseID,
		job,
		"teen-kill-switch-source",
		10,
	)
	require.NoError(t, err)
	claimed, err := fixture.store.ClaimDeliveryJobs(
		t.Context(),
		1,
		2*time.Second,
	)
	require.NoError(t, err)
	require.Len(t, claimed, 1)

	fixture.store.teenConversationEnabled = false
	routes, err = fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.NoError(t, err)
	require.Empty(t, routes)
	guard, valid, err := fixture.store.AcquireDeliveryAttempt(
		t.Context(),
		claimed[0],
	)
	require.NoError(t, err)
	require.False(t, valid)
	require.Nil(t, guard)
	require.NoError(t, fixture.store.FinalizeDeliveryJob(
		t.Context(),
		jobID,
		DeliveryFinalSafetyInvalidated,
	))
}

func TestPreRegistrationRevokeFencesLowerPolicyEpoch(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	conversation := testTopic(t, topicpkg.TopicKindGroupMessagesV1, 0x2a)
	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x2b)

	revoke := fixture.policy(
		t,
		2,
		authority.PolicyStateRevoked,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	require.NoError(t, fixture.store.AdvancePolicy(
		t.Context(),
		PolicyAdvanceRequest{Control: revoke},
	))

	var storedGeneration int64
	var storedState int16
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT generation, state
		 FROM hytch_push_vault.installation_states`,
	).Scan(&storedGeneration, &storedState))
	require.Zero(t, storedGeneration)
	require.Equal(t, stateRevoking, storedState)

	staleActive := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	staleRefresh := fixture.refresh(
		t,
		1,
		staleActive,
		fixture.subscription(
			t,
			conversation,
			0x2c,
			1,
			688,
			authority.PushModeAlertAllowed,
			1,
		),
		fixture.subscription(
			t,
			welcome,
			0x2d,
			1,
			688,
			authority.PushModeSuppressed,
			1,
		),
	)
	_, err := fixture.store.Refresh(t.Context(), staleRefresh)
	require.ErrorIs(t, err, ErrRefreshConflict)

	freshActive := fixture.policy(
		t,
		3,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	freshRefresh := fixture.refresh(
		t,
		1,
		freshActive,
		fixture.subscription(
			t,
			conversation,
			0x2e,
			1,
			688,
			authority.PushModeAlertAllowed,
			3,
		),
		fixture.subscription(
			t,
			welcome,
			0x2f,
			1,
			688,
			authority.PushModeSuppressed,
			3,
		),
	)
	result, err := fixture.store.Refresh(t.Context(), freshRefresh)
	require.NoError(t, err)
	require.Equal(t, 2, result.ActiveLeaseCount)
}

func TestActivePolicyAdvanceRequiresAndAcceptsMatchingFullRefresh(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	period := uint32(688)
	conversation := testTopic(t, topicpkg.TopicKindGroupMessagesV1, 0x35)
	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x36)

	initialControl := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	initial := fixture.refresh(
		t,
		1,
		initialControl,
		fixture.subscription(
			t,
			conversation,
			0x37,
			1,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		fixture.subscription(
			t,
			welcome,
			0x38,
			1,
			period,
			authority.PushModeSuppressed,
			1,
		),
	)
	_, err := fixture.store.Refresh(t.Context(), initial)
	require.NoError(t, err)

	advancedControl := fixture.policy(
		t,
		2,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	require.NoError(t, fixture.store.AdvancePolicy(
		t.Context(),
		PolicyAdvanceRequest{Control: advancedControl},
	))
	var storedState int16
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT state FROM hytch_push_vault.installation_states`,
	).Scan(&storedState))
	require.Equal(t, stateAwaitingRefresh, storedState)

	refresh := fixture.refresh(
		t,
		2,
		advancedControl,
		fixture.subscription(
			t,
			conversation,
			0x37,
			1,
			period,
			authority.PushModeAlertAllowed,
			2,
		),
		fixture.subscription(
			t,
			welcome,
			0x38,
			1,
			period,
			authority.PushModeSuppressed,
			2,
		),
	)
	refresh.IdempotencyKey = "idempotency-test-0002"
	result, err := fixture.store.Refresh(t.Context(), refresh)
	require.NoError(t, err)
	require.Equal(t, 2, result.ActiveLeaseCount)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT state FROM hytch_push_vault.installation_states`,
	).Scan(&storedState))
	require.Equal(t, stateActive, storedState)
}

func TestRefreshClampsAcceptedFutureSkewAuthorityExpiry(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	period := uint32(688)
	conversation := testTopic(t, topicpkg.TopicKindGroupMessagesV1, 0x39)
	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x3a)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	control.IssuedAt = fixture.now.Add(4 * time.Second).Format(
		time.RFC3339Nano,
	)
	control.ExpiresAt = fixture.now.Add(64 * time.Second).Format(
		time.RFC3339Nano,
	)
	control.Signature = ""
	controlBytes, err := control.SigningBytes()
	require.NoError(t, err)
	control.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(fixture.privateKey, controlBytes),
	)

	subscriptions := []SubscriptionRefresh{
		fixture.subscription(
			t,
			conversation,
			0x49,
			1,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		fixture.subscription(
			t,
			welcome,
			0x4a,
			1,
			period,
			authority.PushModeSuppressed,
			1,
		),
	}
	for idx := range subscriptions {
		subscriptions[idx].Capability.IssuedAt = control.IssuedAt
		subscriptions[idx].Capability.ExpiresAt = control.ExpiresAt
		subscriptions[idx].Capability.Signature = ""
		capabilityBytes, signingErr :=
			subscriptions[idx].Capability.SigningBytes()
		require.NoError(t, signingErr)
		subscriptions[idx].Capability.Signature =
			base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(fixture.privateKey, capabilityBytes),
			)
	}
	request := fixture.refresh(t, 1, control, subscriptions...)
	_, err = fixture.store.Refresh(t.Context(), request)
	require.NoError(t, err)

	var installationExpiry time.Time
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT control_expires_at
			   FROM hytch_push_vault.installation_states`,
		).Scan(&installationExpiry),
	)
	require.Equal(t, fixture.now.Add(time.Minute), installationExpiry.UTC())
	var outsideClamp int
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*)
			   FROM hytch_push_vault.subscription_leases
			  WHERE control_expires_at <> $1`,
			fixture.now.Add(time.Minute),
		).Scan(&outsideClamp),
	)
	require.Zero(t, outsideClamp)
}

func TestLookupRootReplacementFailsClosed(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	period := uint32(688)
	request := fixture.refresh(
		t,
		1,
		fixture.policy(
			t,
			1,
			authority.PolicyStateActive,
			authority.AgePolicyAdult,
			fixture.incarnationID,
		),
		fixture.subscription(
			t,
			testTopic(t, topicpkg.TopicKindGroupMessagesV1, 0x5a),
			0x6a,
			1,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		fixture.subscription(
			t,
			testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x5b),
			0x6b,
			1,
			period,
			authority.PushModeSuppressed,
			1,
		),
	)
	_, err := fixture.store.Refresh(t.Context(), request)
	require.NoError(t, err)

	replacementLookup, err := NewLookupKey(bytes.Repeat([]byte{0x7f}, 32))
	require.NoError(t, err)
	replacement, err := NewStore(db, StoreOptions{
		Environment:   fixture.store.environment,
		LeaseTTL:      fixture.store.leaseTTL,
		Encryption:    fixture.store.encryption,
		Lookup:        replacementLookup,
		AuthorityKeys: fixture.store.authorityKeys,
		Now:           func() time.Time { return *fixture.now },
		Random:        &sequenceReader{},
	})
	require.NoError(t, err)
	_, err = replacement.Refresh(t.Context(), request)
	require.ErrorIs(t, err, ErrStoreUnavailable)
}

func TestSecureStoreRejectsStaleHMACAliasIncarnationAndRevokeReplay(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, _ := newSignedStoreFixture(t)
	period := uint32(688)
	conversation := testTopic(t, topicpkg.TopicKindGroupMessagesV1, 0x31)
	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x32)
	active := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	conversationSubscription := fixture.subscription(
		t,
		conversation,
		0x41,
		1,
		period,
		authority.PushModeAlertAllowed,
		1,
	)
	welcomeSubscription := fixture.subscription(
		t,
		welcome,
		0x42,
		1,
		period,
		authority.PushModeSuppressed,
		1,
	)
	request := fixture.refresh(
		t,
		1,
		active,
		conversationSubscription,
		welcomeSubscription,
	)
	_, err := fixture.store.Refresh(t.Context(), request)
	require.NoError(t, err)

	stale, err := fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period+1),
	)
	require.NoError(t, err)
	require.Empty(t, stale)

	badAlias := request
	badAlias.Generation = 2
	badAlias.IdempotencyKey = "idempotency-test-0002"
	badAlias.Subscriptions = append(
		[]SubscriptionRefresh(nil),
		request.Subscriptions...,
	)
	badAlias.Subscriptions[0].Capability.RouteAlias = base64.RawURLEncoding.EncodeToString(
		bytes.Repeat([]byte{0xff}, gate8wrapper.RouteAliasSize),
	)
	signingBytes, signErr := badAlias.Subscriptions[0].Capability.SigningBytes()
	require.NoError(t, signErr)
	badAlias.Subscriptions[0].Capability.Signature =
		base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(fixture.privateKey, signingBytes),
		)
	_, err = fixture.store.Refresh(t.Context(), badAlias)
	require.ErrorIs(t, err, ErrRefreshInvalid)

	wrongIncarnationControl := fixture.policy(
		t,
		2,
		authority.PolicyStateRevoked,
		authority.AgePolicyAdult,
		"other-incarnation",
	)
	err = fixture.store.AdvancePolicy(t.Context(), PolicyAdvanceRequest{
		Control: wrongIncarnationControl,
	})
	require.ErrorIs(t, err, ErrRefreshConflict)

	revoked := fixture.policy(
		t,
		2,
		authority.PolicyStateRevoked,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	require.NoError(t, fixture.store.AdvancePolicy(
		t.Context(),
		PolicyAdvanceRequest{Control: revoked},
	))
	afterRevoke, err := fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.NoError(t, err)
	require.Empty(t, afterRevoke)

	activeAtRevokedEpoch := fixture.policy(
		t,
		2,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	fixtureRequest := fixture.refresh(
		t,
		3,
		activeAtRevokedEpoch,
		fixture.subscription(
			t,
			conversation,
			0x51,
			2,
			period,
			authority.PushModeAlertAllowed,
			2,
		),
		fixture.subscription(
			t,
			welcome,
			0x52,
			2,
			period,
			authority.PushModeSuppressed,
			2,
		),
	)
	fixtureRequest.IdempotencyKey = "idempotency-test-0003"
	_, err = fixture.store.Refresh(t.Context(), fixtureRequest)
	require.ErrorIs(t, err, ErrRefreshConflict)
}

func TestRetentionUnsafeBlocksRegistrationAndRouting(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	period := uint32(688)
	conversation := testTopic(t, topicpkg.TopicKindGroupMessagesV1, 0x61)
	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x62)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	request := fixture.refresh(
		t,
		1,
		control,
		fixture.subscription(
			t,
			conversation,
			0x71,
			1,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		fixture.subscription(
			t,
			welcome,
			0x72,
			1,
			period,
			authority.PushModeSuppressed,
			1,
		),
	)

	_, err := db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.retention_state
		 SET is_safe = FALSE,
		     fixed_outcome = $1
		 WHERE environment = $2`,
		retentionOutcomeUnsafe,
		fixture.store.environmentID,
	)
	require.NoError(t, err)

	_, err = fixture.store.Refresh(t.Context(), request)
	require.ErrorIs(t, err, ErrStoreUnavailable)

	_, err = fixture.store.GetSubscriptions(
		t.Context(),
		conversation,
		int(period),
	)
	require.ErrorIs(t, err, ErrStoreUnavailable)
}

func TestRefreshCancelsJobsForTokenAndRouteKeyRotation(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	period := uint32(688)
	conversation := testTopic(t, topicpkg.TopicKindGroupMessagesV1, 0x63)
	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x64)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	conversationLease := fixture.subscription(
		t,
		conversation,
		0x73,
		1,
		period,
		authority.PushModeAlertAllowed,
		1,
	)
	welcomeLease := fixture.subscription(
		t,
		welcome,
		0x74,
		1,
		period,
		authority.PushModeSuppressed,
		1,
	)
	request := fixture.refresh(
		t,
		1,
		control,
		conversationLease,
		welcomeLease,
	)
	_, err := fixture.store.Refresh(t.Context(), request)
	require.NoError(t, err)

	resolveConversationRoute := func() interfaces.SecureRoute {
		subscriptions, routeErr := fixture.store.GetSubscriptions(
			t.Context(),
			conversation,
			int(period),
		)
		require.NoError(t, routeErr)
		require.Len(t, subscriptions, 1)
		require.NotNil(t, subscriptions[0].SecureRoute)
		return *subscriptions[0].SecureRoute
	}
	jobForRoute := func(
		route interfaces.SecureRoute,
		deviceToken []byte,
	) SerializedDeliveryJob {
		return SerializedDeliveryJob{
			DeviceToken:      hex.EncodeToString(deviceToken),
			Topic:            "com.example.hytch.dev",
			Payload:          []byte(`{"aps":{"alert":"New message"}}`),
			PushType:         "alert",
			Priority:         10,
			Expiration:       fixture.now.Add(20 * time.Second),
			TrafficClass:     DeliveryTrafficConversation,
			PolicyEpoch:      route.PolicyEpoch,
			RouteKeyEpoch:    route.RouteKeyEpoch,
			NoncePrefix:      route.NoncePrefix,
			DeliverySequence: route.DeliverySequence,
			AliasDay:         route.AliasDay,
			RouteAlias: append(
				[]byte(nil),
				route.RouteAlias...,
			),
		}
	}
	enqueueForConversation := func() {
		route := resolveConversationRoute()
		_, routeErr := fixture.store.EnqueueDeliveryJob(
			t.Context(),
			route.LeaseID,
			jobForRoute(route, request.APNSToken),
			"route-event-"+request.IdempotencyKey,
			10,
		)
		require.NoError(t, routeErr)
	}
	countJobs := func() int {
		var count int
		require.NoError(t, db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*) FROM hytch_push_vault.delivery_jobs`,
		).Scan(&count))
		return count
	}

	enqueueForConversation()
	require.Equal(t, 1, countJobs())

	sameRoute := request
	sameRoute.Generation = 2
	sameRoute.IdempotencyKey = "idempotency-test-0002"
	_, err = fixture.store.Refresh(t.Context(), sameRoute)
	require.NoError(t, err)
	require.Equal(t, 1, countJobs(), "ordinary authority refresh preserves retries")

	reusedKeyAtNewEpoch := fixture.refresh(
		t,
		3,
		control,
		fixture.subscription(
			t,
			conversation,
			0x73,
			2,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		welcomeLease,
	)
	reusedKeyAtNewEpoch.IdempotencyKey = "idempotency-test-reused-route-key"
	_, err = fixture.store.Refresh(t.Context(), reusedKeyAtNewEpoch)
	require.ErrorIs(t, err, ErrRefreshConflict)
	require.Equal(t, 1, countJobs(), "rejected epoch advance preserves old job")

	staleRoute := resolveConversationRoute()
	staleToken := append([]byte(nil), request.APNSToken...)
	rotatedRoute := fixture.refresh(
		t,
		3,
		control,
		fixture.subscription(
			t,
			conversation,
			0x75,
			2,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		welcomeLease,
	)
	rotatedRoute.IdempotencyKey = "idempotency-test-0003"
	_, err = fixture.store.Refresh(t.Context(), rotatedRoute)
	require.NoError(t, err)
	require.Zero(t, countJobs(), "old wrapper cannot survive route-key rotation")
	_, err = fixture.store.EnqueueDeliveryJob(
		t.Context(),
		staleRoute.LeaseID,
		jobForRoute(staleRoute, staleToken),
		"stale-route-after-rotation",
		10,
	)
	require.ErrorIs(t, err, ErrDeliveryJobInvalid)
	require.Zero(t, countJobs(), "stale route cannot be re-enqueued")

	request = rotatedRoute
	staleTokenRoute := resolveConversationRoute()
	staleDeviceToken := append([]byte(nil), request.APNSToken...)
	enqueueForConversation()
	require.Equal(t, 1, countJobs())

	rotatedToken := rotatedRoute
	rotatedToken.Generation = 4
	rotatedToken.IdempotencyKey = "idempotency-test-0004"
	rotatedToken.APNSToken = bytes.Repeat([]byte{0xa2}, 32)
	_, err = fixture.store.Refresh(t.Context(), rotatedToken)
	require.NoError(t, err)
	require.Zero(t, countJobs(), "old-token retry cannot survive token rotation")
	_, err = fixture.store.EnqueueDeliveryJob(
		t.Context(),
		staleTokenRoute.LeaseID,
		jobForRoute(staleTokenRoute, staleDeviceToken),
		"stale-token-after-rotation",
		10,
	)
	require.ErrorIs(t, err, ErrDeliveryJobInvalid)
	require.Zero(t, countJobs(), "stale APNS token cannot be re-enqueued")

	removedRoute := fixture.refresh(t, 5, control, welcomeLease)
	removedRoute.IdempotencyKey = "idempotency-test-remove-route"
	removedRoute.APNSToken = append([]byte(nil), rotatedToken.APNSToken...)
	_, err = fixture.store.Refresh(t.Context(), removedRoute)
	require.NoError(t, err)

	reusedRemovedRoute := fixture.refresh(
		t,
		6,
		control,
		rotatedRoute.Subscriptions[0],
		welcomeLease,
	)
	reusedRemovedRoute.IdempotencyKey = "idempotency-test-readd-same"
	reusedRemovedRoute.APNSToken = append(
		[]byte(nil),
		rotatedToken.APNSToken...,
	)
	_, err = fixture.store.Refresh(t.Context(), reusedRemovedRoute)
	require.ErrorIs(t, err, ErrRefreshConflict)

	reusedRemovedKeyAtHigherEpoch := fixture.refresh(
		t,
		6,
		control,
		fixture.subscription(
			t,
			conversation,
			0x75,
			3,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		welcomeLease,
	)
	reusedRemovedKeyAtHigherEpoch.IdempotencyKey =
		"idempotency-test-readd-old-key"
	reusedRemovedKeyAtHigherEpoch.APNSToken = append(
		[]byte(nil),
		rotatedToken.APNSToken...,
	)
	_, err = fixture.store.Refresh(
		t.Context(),
		reusedRemovedKeyAtHigherEpoch,
	)
	require.ErrorIs(t, err, ErrRefreshConflict)

	rekeyedRemovedRoute := fixture.refresh(
		t,
		6,
		control,
		fixture.subscription(
			t,
			conversation,
			0x76,
			3,
			period,
			authority.PushModeAlertAllowed,
			1,
		),
		welcomeLease,
	)
	rekeyedRemovedRoute.IdempotencyKey = "idempotency-test-readd-new-key"
	rekeyedRemovedRoute.APNSToken = append(
		[]byte(nil),
		rotatedToken.APNSToken...,
	)
	_, err = fixture.store.Refresh(t.Context(), rekeyedRemovedRoute)
	require.NoError(t, err)
}
