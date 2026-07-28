package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

func (fixture *signedStoreFixture) welcomeAuthorization(
	t *testing.T,
	targetTopic *topicpkg.Topic,
	outerEnvelopeDigest []byte,
	nonceByte byte,
	ttl time.Duration,
) authority.WelcomeAuthorizationV1 {
	t.Helper()
	topicDigest := sha256.Sum256(targetTopic.Bytes())
	conversationCommitment, err := authority.ExpectedConversationCommitment(
		"development",
		fixture.installationID,
		fixture.incarnationID,
		"conversation-test-01",
	)
	require.NoError(t, err)
	authorization := authority.WelcomeAuthorizationV1{
		SchemaVersion:        1,
		Environment:          "development",
		InstallationID:       fixture.installationID,
		AccountIncarnationID: fixture.incarnationID,
		PolicyEpoch:          1,
		TopicDigest:          hex.EncodeToString(topicDigest[:]),
		OuterEnvelopeDigest:  hex.EncodeToString(outerEnvelopeDigest),
		ExpectedConversationCommitment: hex.EncodeToString(
			conversationCommitment[:],
		),
		GrantVersion: 1,
		Nonce: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{nonceByte}, 16),
		),
		IssuedAt:     fixture.now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt:    fixture.now.Add(ttl).Format(time.RFC3339Nano),
		SigningKeyID: fixture.keyID,
		Algorithm:    "Ed25519",
	}
	signingBytes, err := authorization.SigningBytes()
	require.NoError(t, err)
	authorization.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(fixture.privateKey, signingBytes),
	)
	return authorization
}

func setupWelcomeFixture(
	t *testing.T,
	age authority.AgePolicy,
) (*signedStoreFixture, *sql.DB, *topicpkg.Topic) {
	t.Helper()
	fixture, db := newSignedStoreFixture(t)
	fixture.store.welcomeEnabled = true
	if age == authority.AgePolicyTeen {
		// This fixture exercises the independent Welcome deny after the
		// default-off teen conversation gate has been explicitly opened.
		fixture.store.teenConversationEnabled = true
	}
	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x61)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		age,
		fixture.incarnationID,
	)
	if age == authority.AgePolicyTeen {
		control.ExpiresAt = fixture.now.Add(29 * time.Second).Format(
			time.RFC3339Nano,
		)
		signingBytes, err := control.SigningBytes()
		require.NoError(t, err)
		control.Signature = base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(fixture.privateKey, signingBytes),
		)
	}
	welcomeSubscription := fixture.subscription(
		t,
		welcome,
		0x62,
		1,
		0,
		authority.PushModeSuppressed,
		1,
	)
	if age == authority.AgePolicyTeen {
		welcomeSubscription.Capability.ExpiresAt = fixture.now.Add(
			29 * time.Second,
		).Format(time.RFC3339Nano)
		signingBytes, err := welcomeSubscription.Capability.SigningBytes()
		require.NoError(t, err)
		welcomeSubscription.Capability.Signature =
			base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(fixture.privateKey, signingBytes),
			)
	}
	request := fixture.refresh(
		t,
		1,
		control,
		welcomeSubscription,
	)
	_, err := fixture.store.Refresh(t.Context(), request)
	require.NoError(t, err)
	return fixture, db, welcome
}

func welcomeDeliveryJob(
	t *testing.T,
	fixture *signedStoreFixture,
	route interfaces.WelcomeSubscription,
) SerializedDeliveryJob {
	t.Helper()
	secureRoute := route.Subscription.SecureRoute
	require.NotNil(t, secureRoute)
	return SerializedDeliveryJob{
		DeviceToken:      route.Installation.DeliveryMechanism.Token,
		Topic:            "com.example.hytch",
		Payload:          []byte(`{"aps":{"content-available":1}}`),
		PushType:         "background",
		Priority:         5,
		Expiration:       fixture.now.Add(15 * time.Second),
		TrafficClass:     DeliveryTrafficWelcome,
		PolicyEpoch:      secureRoute.PolicyEpoch,
		RouteKeyEpoch:    secureRoute.RouteKeyEpoch,
		NoncePrefix:      secureRoute.NoncePrefix,
		DeliverySequence: secureRoute.DeliverySequence,
		AliasDay:         secureRoute.AliasDay,
		RouteAlias:       append([]byte(nil), secureRoute.RouteAlias...),
		WelcomeAuthorizationID: append(
			[]byte(nil),
			secureRoute.WelcomeAuthorizationID...,
		),
		WelcomeEnvelopeDigest: append(
			[]byte(nil),
			secureRoute.WelcomeEnvelopeDigest...,
		),
	}
}

func TestWelcomeKillSwitchDefaultsClosedAndStopsPersistedAuthority(t *testing.T) {
	requireVaultIntegrationTests(t)
	closedFixture, _ := newSignedStoreFixture(t)
	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x5f)
	digest := sha256.Sum256([]byte("closed"))
	require.ErrorIs(t, closedFixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{Topic: welcome.Bytes()},
	), ErrWelcomeUnavailable)
	routes, err := closedFixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		digest[:],
	)
	require.NoError(t, err)
	require.Empty(t, routes)

	fixture, db, welcome := setupWelcomeFixture(t, authority.AgePolicyAdult)
	authorization := fixture.welcomeAuthorization(
		t,
		welcome,
		digest[:],
		0x5f,
		20*time.Second,
	)
	require.NoError(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	))
	fixture.store.welcomeEnabled = false
	routes, err = fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		digest[:],
	)
	require.NoError(t, err)
	require.Empty(t, routes)
	var consumedAt sql.NullTime
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT consumed_at
			 FROM hytch_push_vault.welcome_authorizations
			 WHERE environment = $1
			 LIMIT 1`,
		fixture.store.environmentID,
	).Scan(&consumedAt))
	require.False(t, consumedAt.Valid)
}

func TestWelcomeCapabilityRequiresSignedConversationCommitment(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, _ := newSignedStoreFixture(t)
	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x60)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	subscription := fixture.subscription(
		t,
		welcome,
		0x61,
		1,
		0,
		authority.PushModeSuppressed,
		1,
	)
	subscription.Capability.ExpectedConversationCommitment = ""
	signingBytes, err := subscription.Capability.SigningBytes()
	require.NoError(t, err)
	subscription.Capability.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(fixture.privateKey, signingBytes),
	)
	_, err = fixture.store.Refresh(
		t.Context(),
		fixture.refresh(t, 1, control, subscription),
	)
	require.ErrorIs(t, err, ErrRefreshInvalid)
}

func TestWelcomeAuthorizationAndCapabilityCommitmentsMustMatch(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db, welcome := setupWelcomeFixture(t, authority.AgePolicyAdult)
	envelopeDigest := sha256.Sum256([]byte("commitment-mismatch"))
	authorization := fixture.welcomeAuthorization(
		t,
		welcome,
		envelopeDigest[:],
		0x70,
		20*time.Second,
	)
	otherCommitment, err := authority.ExpectedConversationCommitment(
		"development",
		fixture.installationID,
		fixture.incarnationID,
		"different-conversation",
	)
	require.NoError(t, err)
	authorization.ExpectedConversationCommitment = hex.EncodeToString(
		otherCommitment[:],
	)
	signingBytes, err := authorization.SigningBytes()
	require.NoError(t, err)
	authorization.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(fixture.privateKey, signingBytes),
	)

	require.ErrorIs(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	), ErrWelcomeInvalid)
	var count int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
			 FROM hytch_push_vault.welcome_authorizations
			 WHERE environment = $1`,
		fixture.store.environmentID,
	).Scan(&count))
	require.Zero(t, count)
}

func TestWelcomeAuthorizationCorrelatesExactlyAndConsumesOnce(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db, welcome := setupWelcomeFixture(t, authority.AgePolicyAdult)
	envelopeDigest := sha256.Sum256([]byte("authorized-before-stream"))
	authorization := fixture.welcomeAuthorization(
		t,
		welcome,
		envelopeDigest[:],
		0x71,
		20*time.Second,
	)
	require.NoError(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	))

	otherDigest := sha256.Sum256([]byte("same-nonce-other-envelope"))
	nonceReplay := fixture.welcomeAuthorization(
		t,
		welcome,
		otherDigest[:],
		0x71,
		20*time.Second,
	)
	require.ErrorIs(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: nonceReplay,
		},
	), ErrWelcomeConflict)

	var envelopeLookup, encryptedAuthorization []byte
	var storedEnvironment int16
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT environment, envelope_lookup, encrypted_authorization
		 FROM hytch_push_vault.welcome_authorizations
		 WHERE environment = $1
		 LIMIT 1`,
		fixture.store.environmentID,
	).Scan(
		&storedEnvironment,
		&envelopeLookup,
		&encryptedAuthorization,
	))
	require.Equal(t, fixture.store.environmentID, storedEnvironment)
	require.Len(t, envelopeLookup, sha256.Size)
	require.NotEqual(t, envelopeDigest[:], envelopeLookup)
	require.NotContains(
		t,
		encryptedAuthorization,
		[]byte(fixture.installationID),
	)
	require.NotContains(t, encryptedAuthorization, envelopeDigest[:])

	routes, err := fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		envelopeDigest[:],
	)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	require.True(t, routes[0].Subscription.IsSilent)
	require.NotNil(t, routes[0].Subscription.SecureRoute)
	require.True(t, routes[0].Subscription.SecureRoute.WelcomeAuthorized)
	require.Equal(t, uint64(0), routes[0].Subscription.SecureRoute.DeliverySequence)
	require.Len(
		t,
		routes[0].Subscription.SecureRoute.WelcomeAuthorizationID,
		16,
	)
	require.Equal(
		t,
		envelopeDigest[:],
		routes[0].Subscription.SecureRoute.WelcomeEnvelopeDigest,
	)
	require.NotEmpty(t, routes[0].Subscription.SecureRoute.AliasDay)
	require.Len(
		t,
		routes[0].Subscription.SecureRoute.RouteAlias,
		gate8wrapper.RouteAliasSize,
	)

	jobID, err := fixture.store.EnqueueDeliveryJob(
		t.Context(),
		routes[0].Subscription.SecureRoute.LeaseID,
		welcomeDeliveryJob(t, fixture, routes[0]),
		"welcome-event-once",
		10,
	)
	require.NoError(t, err)
	require.Len(t, jobID, 16)

	replay, err := fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		envelopeDigest[:],
	)
	require.NoError(t, err)
	require.Empty(t, replay)
}

func TestWelcomeReplayIdentitySurvivesLookupEpochRotation(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db := newSignedStoreFixture(t)
	fixture.store.welcomeEnabled = true

	epochSeconds := uint64(lookupRotationInterval / time.Second)
	nextBoundary := time.Unix(
		int64((LookupEpoch(*fixture.now)+1)*epochSeconds),
		0,
	).UTC()
	*fixture.now = nextBoundary.Add(-time.Second)
	sweeper, err := NewRetentionSweeper(db, RetentionOptions{
		SweepInterval:        15 * time.Minute,
		Environment:          fixture.store.environment,
		Lookup:               fixture.store.lookup,
		EncryptionKeyVersion: fixture.store.encryption.ActiveVersion(),
		Now:                  fixture.store.now,
	})
	require.NoError(t, err)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)

	welcome := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x73)
	control := fixture.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.incarnationID,
	)
	subscription := fixture.subscription(
		t,
		welcome,
		0x74,
		1,
		0,
		authority.PushModeSuppressed,
		1,
	)
	firstRefresh := fixture.refresh(t, 1, control, subscription)
	_, err = fixture.store.Refresh(t.Context(), firstRefresh)
	require.NoError(t, err)

	envelopeDigest := sha256.Sum256([]byte("lookup-boundary-envelope"))
	authorization := fixture.welcomeAuthorization(
		t,
		welcome,
		envelopeDigest[:],
		0x75,
		20*time.Second,
	)
	require.NoError(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	))
	var firstInstallationLookup []byte
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT installation_lookup
		 FROM hytch_push_vault.installation_states`,
	).Scan(&firstInstallationLookup))

	*fixture.now = fixture.now.Add(2 * time.Second)
	// Seven-day lookup epochs roll at UTC midnight. The new-day route alias is
	// independently signed while the original policy control and Welcome
	// authorization are still valid.
	rotatedSubscription := fixture.subscription(
		t,
		welcome,
		0x74,
		1,
		0,
		authority.PushModeSuppressed,
		1,
	)
	secondRefresh := fixture.refresh(t, 2, control, rotatedSubscription)
	_, err = fixture.store.Refresh(t.Context(), secondRefresh)
	require.NoError(t, err)
	var secondInstallationLookup []byte
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT installation_lookup
		 FROM hytch_push_vault.installation_states`,
	).Scan(&secondInstallationLookup))
	require.NotEqual(t, firstInstallationLookup, secondInstallationLookup)

	require.ErrorIs(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	), ErrWelcomeConflict)
	var authorizationCount int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
			 FROM hytch_push_vault.welcome_authorizations
			 WHERE environment = $1`,
		fixture.store.environmentID,
	).Scan(&authorizationCount))
	require.Equal(t, 1, authorizationCount)

	routes, err := fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		envelopeDigest[:],
	)
	require.NoError(t, err)
	require.Len(t, routes, 1)
}

func TestWelcomeKillSwitchStopsAlreadyQueuedDelivery(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, _, welcome := setupWelcomeFixture(t, authority.AgePolicyAdult)
	envelopeDigest := sha256.Sum256([]byte("queued-before-disable"))
	authorization := fixture.welcomeAuthorization(
		t,
		welcome,
		envelopeDigest[:],
		0x72,
		20*time.Second,
	)
	require.NoError(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	))
	routes, err := fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		envelopeDigest[:],
	)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	jobID, err := fixture.store.EnqueueDeliveryJob(
		t.Context(),
		routes[0].Subscription.SecureRoute.LeaseID,
		welcomeDeliveryJob(t, fixture, routes[0]),
		"welcome-disable-after-queue",
		10,
	)
	require.NoError(t, err)
	require.Len(t, jobID, 16)
	claimed, err := fixture.store.ClaimDeliveryJobs(
		t.Context(),
		1,
		2*time.Second,
	)
	require.NoError(t, err)
	require.Len(t, claimed, 1)

	fixture.store.welcomeEnabled = false
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

func TestWelcomeQueueBackpressureRollsBackReservation(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db, welcome := setupWelcomeFixture(t, authority.AgePolicyAdult)
	envelopeDigest := sha256.Sum256([]byte("queue-rollback"))
	authorization := fixture.welcomeAuthorization(
		t,
		welcome,
		envelopeDigest[:],
		0x7a,
		20*time.Second,
	)
	require.NoError(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	))
	routes, err := fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		envelopeDigest[:],
	)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	leaseID := routes[0].Subscription.SecureRoute.LeaseID
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.delivery_jobs (
			     job_id, lease_id, encrypted_job, environment, state, attempts,
			     available_at, expires_at, created_at
			 ) VALUES ($1,$2,$3,$4,$5,0,$6,$7,$6)`,
		bytes.Repeat([]byte{0xbc}, 16),
		leaseID,
		[]byte{0x01},
		fixture.store.environmentID,
		deliveryJobPending,
		*fixture.now,
		fixture.now.Add(time.Minute),
	)
	require.NoError(t, err)
	_, err = fixture.store.EnqueueDeliveryJob(
		t.Context(),
		leaseID,
		welcomeDeliveryJob(t, fixture, routes[0]),
		"welcome-queue-full",
		1,
	)
	require.ErrorIs(t, err, ErrDeliveryQueueFull)

	var consumedAt sql.NullTime
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT consumed_at
			 FROM hytch_push_vault.welcome_authorizations
			 WHERE environment = $1
			 LIMIT 1`,
		fixture.store.environmentID,
	).Scan(&consumedAt))
	require.False(t, consumedAt.Valid)
	var budgets, dedupes int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
			   (SELECT COUNT(*)
			      FROM hytch_push_vault.welcome_budgets
			     WHERE environment = $1),
			   (SELECT COUNT(*)
			      FROM hytch_push_vault.delivery_dedupes
			     WHERE environment = $1)`,
		fixture.store.environmentID,
	).Scan(&budgets, &dedupes))
	require.Zero(t, budgets)
	require.Zero(t, dedupes)
}

func TestWelcomeHostileTopicEnvelopeMismatchAndExpiryProduceNoRoute(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, _, welcome := setupWelcomeFixture(t, authority.AgePolicyAdult)
	exactDigest := sha256.Sum256([]byte("exact-envelope"))
	authorization := fixture.welcomeAuthorization(
		t,
		welcome,
		exactDigest[:],
		0x72,
		10*time.Second,
	)
	require.NoError(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	))

	hostileDigest := sha256.Sum256([]byte("hostile-envelope"))
	routes, err := fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		hostileDigest[:],
	)
	require.NoError(t, err)
	require.Empty(t, routes)

	hostileTopic := testTopic(t, topicpkg.TopicKindWelcomeMessagesV1, 0x63)
	routes, err = fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		hostileTopic,
		exactDigest[:],
	)
	require.NoError(t, err)
	require.Empty(t, routes)

	*fixture.now = fixture.now.Add(11 * time.Second)
	routes, err = fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		exactDigest[:],
	)
	require.NoError(t, err)
	require.Empty(t, routes)
}

func TestWelcomeTeenAndDatabaseAmbiguityFailClosed(t *testing.T) {
	requireVaultIntegrationTests(t)
	teenFixture, _, welcome := setupWelcomeFixture(t, authority.AgePolicyTeen)
	envelopeDigest := sha256.Sum256([]byte("teen-envelope"))
	authorization := teenFixture.welcomeAuthorization(
		t,
		welcome,
		envelopeDigest[:],
		0x73,
		20*time.Second,
	)
	require.ErrorIs(t, teenFixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	), ErrWelcomeInvalid)

	fixture, db, adultWelcome := setupWelcomeFixture(t, authority.AgePolicyAdult)
	adultDigest := sha256.Sum256([]byte("ambiguous-envelope"))
	adultAuthorization := fixture.welcomeAuthorization(
		t,
		adultWelcome,
		adultDigest[:],
		0x74,
		20*time.Second,
	)
	require.NoError(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         adultWelcome.Bytes(),
			Authorization: adultAuthorization,
		},
	))
	_, err := db.ExecContext(
		t.Context(),
		`DROP TABLE hytch_push_vault.welcome_authorizations`,
	)
	require.NoError(t, err)
	routes, err := fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		adultWelcome,
		adultDigest[:],
	)
	require.ErrorIs(t, err, ErrWelcomeUnavailable)
	require.Empty(t, routes)
}

func TestWelcomeEnvironmentForeignKeysRejectStoredMismatch(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db, welcome := setupWelcomeFixture(t, authority.AgePolicyAdult)
	envelopeDigest := sha256.Sum256([]byte("stored-environment-mismatch"))
	authorization := fixture.welcomeAuthorization(
		t,
		welcome,
		envelopeDigest[:],
		0x79,
		20*time.Second,
	)

	_, err := db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.subscription_leases
		    SET environment = $1`,
		environmentProduction,
	)
	require.Error(t, err)
	require.NoError(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	))

	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.subscription_leases
		    SET environment = $1`,
		environmentProduction,
	)
	require.Error(t, err)
	routes, err := fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		envelopeDigest[:],
	)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	_, err = db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.installation_states
		    SET environment = $1`,
		environmentProduction,
	)
	require.Error(t, err)
	routes, err = fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		envelopeDigest[:],
	)
	require.NoError(t, err)
	require.Len(t, routes, 1)
}

func TestWelcomeSharedMinuteHourBudgetsAndCircuit(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db, welcome := setupWelcomeFixture(t, authority.AgePolicyAdult)
	envelopeDigest := sha256.Sum256([]byte("over-budget-envelope"))
	authorization := fixture.welcomeAuthorization(
		t,
		welcome,
		envelopeDigest[:],
		0x75,
		20*time.Second,
	)
	require.NoError(t, fixture.store.AuthorizeWelcome(
		t.Context(),
		WelcomeAuthorizationRequest{
			Topic:         welcome.Bytes(),
			Authorization: authorization,
		},
	))

	tx, err := db.BeginTx(t.Context(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	require.NoError(t, err)
	allowed, err := fixture.store.consumeWelcomeBudget(
		t.Context(),
		tx,
		[]byte(fixture.installationID),
		*fixture.now,
	)
	require.NoError(t, err)
	require.True(t, allowed)
	require.NoError(t, tx.Commit())

	routes, err := fixture.store.GetWelcomeSubscriptions(
		t.Context(),
		welcome,
		envelopeDigest[:],
	)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	jobID, err := fixture.store.EnqueueDeliveryJob(
		t.Context(),
		routes[0].Subscription.SecureRoute.LeaseID,
		welcomeDeliveryJob(t, fixture, routes[0]),
		"welcome-over-budget",
		10,
	)
	require.NoError(t, err)
	require.Empty(t, jobID)
	var consumedAt sql.NullTime
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT consumed_at
		 FROM hytch_push_vault.welcome_authorizations
		 WHERE environment = $1
		 LIMIT 1`,
		fixture.store.environmentID,
	).Scan(&consumedAt))
	require.True(t, consumedAt.Valid)

	var circuitOpenUntil time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT circuit_open_until
		 FROM hytch_push_vault.welcome_budgets
		 WHERE environment = $1
		   AND circuit_open_until IS NOT NULL
		 ORDER BY circuit_open_until DESC
		 LIMIT 1`,
		fixture.store.environmentID,
	).Scan(&circuitOpenUntil))
	require.True(t, fixture.now.Add(welcomeCircuitTTL).Equal(circuitOpenUntil))

	var globalCircuitOpenUntil time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT circuit_open_until
		 FROM hytch_push_vault.welcome_global_circuit
		 WHERE environment = $1`,
		fixture.store.environmentID,
	).Scan(&globalCircuitOpenUntil))
	require.True(
		t,
		fixture.now.Add(welcomeCircuitTTL).Equal(globalCircuitOpenUntil),
	)

	// A distinct bridge instance and destination observe the same database-held
	// circuit immediately.
	secondBridge := *fixture.store
	secondDestination := bytes.Repeat([]byte{0x81}, 32)
	tx, err = db.BeginTx(t.Context(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	require.NoError(t, err)
	allowed, err = secondBridge.consumeWelcomeBudget(
		t.Context(),
		tx,
		secondDestination,
		*fixture.now,
	)
	require.NoError(t, err)
	require.False(t, allowed)
	require.NoError(t, tx.Commit())

	hourDestination := bytes.Repeat([]byte{0x82}, 32)
	hourBase := fixture.now.Add(welcomeCircuitTTL)
	for minute := 0; minute < welcomeHourLimit; minute++ {
		at := hourBase.Add(time.Duration(minute) * time.Minute)
		tx, err = db.BeginTx(
			t.Context(),
			&sql.TxOptions{Isolation: sql.LevelSerializable},
		)
		require.NoError(t, err)
		allowed, err = fixture.store.consumeWelcomeBudget(
			t.Context(),
			tx,
			hourDestination,
			at,
		)
		require.NoError(t, err)
		require.True(t, allowed)
		require.NoError(t, tx.Commit())
	}
	tx, err = db.BeginTx(t.Context(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	require.NoError(t, err)
	allowed, err = fixture.store.consumeWelcomeBudget(
		t.Context(),
		tx,
		hourDestination,
		hourBase.Add(welcomeHourLimit*time.Minute),
	)
	require.NoError(t, err)
	require.False(t, allowed)
	require.NoError(t, tx.Commit())
}

func TestWelcomeGlobalCircuitIsEnvironmentScoped(t *testing.T) {
	requireVaultIntegrationTests(t)
	development, db := newSignedStoreFixture(t)
	production, err := NewStore(db, StoreOptions{
		Environment:   "production",
		LeaseTTL:      development.store.leaseTTL,
		Encryption:    development.store.encryption,
		Lookup:        development.store.lookup,
		AuthorityKeys: development.store.authorityKeys,
		Now: func() time.Time {
			return *development.now
		},
	})
	require.NoError(t, err)
	destination := []byte(development.installationID)
	attempt := func(store *Store) bool {
		tx, beginErr := db.BeginTx(
			t.Context(),
			&sql.TxOptions{Isolation: sql.LevelSerializable},
		)
		require.NoError(t, beginErr)
		allowed, consumeErr := store.consumeWelcomeBudget(
			t.Context(),
			tx,
			destination,
			*development.now,
		)
		require.NoError(t, consumeErr)
		require.NoError(t, tx.Commit())
		return allowed
	}

	require.True(t, attempt(development.store))
	require.False(t, attempt(development.store))
	require.True(t, attempt(production))

	var developmentCircuit, productionCircuit sql.NullTime
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
		   (SELECT circuit_open_until
		      FROM hytch_push_vault.welcome_global_circuit
		     WHERE environment = $1),
		   (SELECT circuit_open_until
		      FROM hytch_push_vault.welcome_global_circuit
		     WHERE environment = $2)`,
		development.store.environmentID,
		production.environmentID,
	).Scan(&developmentCircuit, &productionCircuit))
	require.True(t, developmentCircuit.Valid)
	require.False(t, productionCircuit.Valid)

	var developmentBudgets, productionBudgets int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT
		   (SELECT COUNT(*)
		      FROM hytch_push_vault.welcome_budgets
		     WHERE environment = $1),
		   (SELECT COUNT(*)
		      FROM hytch_push_vault.welcome_budgets
		     WHERE environment = $2)`,
		development.store.environmentID,
		production.environmentID,
	).Scan(&developmentBudgets, &productionBudgets))
	require.Equal(t, 1, developmentBudgets)
	require.Equal(t, 1, productionBudgets)
}

func TestWelcomeBudgetRetentionIsCappedAtOneHour(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db, _ := setupWelcomeFixture(t, authority.AgePolicyAdult)
	tx, err := db.BeginTx(t.Context(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	require.NoError(t, err)
	allowed, err := fixture.store.consumeWelcomeBudget(
		t.Context(),
		tx,
		[]byte(fixture.installationID),
		*fixture.now,
	)
	require.NoError(t, err)
	require.True(t, allowed)
	require.NoError(t, tx.Commit())

	var updatedAt, expiresAt time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT updated_at, expires_at
		 FROM hytch_push_vault.welcome_budgets
		 WHERE environment = $1
		 LIMIT 1`,
		fixture.store.environmentID,
	).Scan(&updatedAt, &expiresAt))
	require.LessOrEqual(t, expiresAt.Sub(updatedAt), welcomeBudgetRetention)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.welcome_budgets (
		     environment, destination_lookup,
		     minute_window_start, minute_count,
		     hour_window_start, hour_count, updated_at, expires_at
		 ) VALUES ($1,$2,$3,0,$3,0,$3,$4)`,
		fixture.store.environmentID,
		bytes.Repeat([]byte{0xa5}, 32),
		*fixture.now,
		fixture.now.Add(welcomeBudgetRetention+time.Second),
	)
	require.Error(t, err)
}

func TestWelcomeBudgetLookupRotatesAtUTCHourBoundary(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db, _ := setupWelcomeFixture(t, authority.AgePolicyAdult)
	destination := []byte(fixture.installationID)
	before := time.Date(2026, 7, 26, 12, 59, 59, 0, time.UTC)
	after := before.Add(time.Second)
	for _, at := range []time.Time{before, after} {
		tx, err := db.BeginTx(
			t.Context(),
			&sql.TxOptions{Isolation: sql.LevelSerializable},
		)
		require.NoError(t, err)
		allowed, err := fixture.store.consumeWelcomeBudget(
			t.Context(),
			tx,
			destination,
			at,
		)
		require.NoError(t, err)
		require.True(t, allowed)
		require.NoError(t, tx.Commit())
	}
	var rows, distinctLookups int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*), COUNT(DISTINCT destination_lookup)
		 FROM hytch_push_vault.welcome_budgets
		 WHERE environment = $1`,
		fixture.store.environmentID,
	).Scan(&rows, &distinctLookups))
	require.Equal(t, 2, rows)
	require.Equal(t, 2, distinctLookups)
}

func TestWelcomeConcurrentBridgeConsumersShareOneBudget(t *testing.T) {
	requireVaultIntegrationTests(t)
	fixture, db, welcome := setupWelcomeFixture(t, authority.AgePolicyAdult)
	digests := [][sha256.Size]byte{
		sha256.Sum256([]byte("concurrent-envelope-one")),
		sha256.Sum256([]byte("concurrent-envelope-two")),
	}
	for index := range digests {
		authorization := fixture.welcomeAuthorization(
			t,
			welcome,
			digests[index][:],
			byte(0x90+index),
			20*time.Second,
		)
		require.NoError(t, fixture.store.AuthorizeWelcome(
			t.Context(),
			WelcomeAuthorizationRequest{
				Topic:         welcome.Bytes(),
				Authorization: authorization,
			},
		))
	}

	routes := make([]interfaces.WelcomeSubscription, 0, len(digests))
	for index := range digests {
		resolved, err := fixture.store.GetWelcomeSubscriptions(
			t.Context(),
			welcome,
			digests[index][:],
		)
		require.NoError(t, err)
		require.Len(t, resolved, 1)
		routes = append(routes, resolved[0])
	}
	jobs := make([]SerializedDeliveryJob, len(routes))
	eventIDs := []string{"concurrent-welcome-a", "concurrent-welcome-b"}
	for index := range routes {
		jobs[index] = welcomeDeliveryJob(t, fixture, routes[index])
	}
	type routeResult struct {
		enqueued bool
		err      error
	}
	start := make(chan struct{})
	results := make(chan routeResult, len(digests))
	var wait sync.WaitGroup
	for index := range digests {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			jobID, err := fixture.store.EnqueueDeliveryJob(
				t.Context(),
				routes[index].Subscription.SecureRoute.LeaseID,
				jobs[index],
				eventIDs[index],
				10,
			)
			results <- routeResult{enqueued: len(jobID) == 16, err: err}
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)

	totalEnqueued := 0
	for result := range results {
		require.NoError(t, result.err)
		if result.enqueued {
			totalEnqueued++
		}
	}
	require.Equal(t, 1, totalEnqueued)
	var consumed, circuitOpen int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		 FROM hytch_push_vault.welcome_authorizations
		 WHERE environment = $1
		   AND consumed_at IS NOT NULL`,
		fixture.store.environmentID,
	).Scan(&consumed))
	require.Equal(t, 2, consumed)
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		 FROM hytch_push_vault.welcome_budgets
		 WHERE environment = $1
		   AND circuit_open_until > $2`,
		fixture.store.environmentID,
		*fixture.now,
	).Scan(&circuitOpen))
	require.Equal(t, 1, circuitOpen)
}
