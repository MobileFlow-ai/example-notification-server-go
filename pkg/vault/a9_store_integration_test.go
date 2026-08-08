package vault

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a9api"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

type a9RuntimeFixture struct {
	store        *Store
	db           *sql.DB
	signed       *signedStoreFixture
	now          time.Time
	keysetHash   [32]byte
	signingKeyID [32]byte
	tupleKeyID   [32]byte
	rosterKeyID  [32]byte
	topicKeyID   [32]byte
}

func newA9RuntimeFixture(t *testing.T) *a9RuntimeFixture {
	t.Helper()
	requireVaultIntegrationTests(t)
	signed, db := newSignedStoreFixture(t)
	var now time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.clock_timestamp()`,
	).Scan(&now))
	now = now.UTC()
	*signed.now = now
	sweeper, err := NewRetentionSweeper(db, RetentionOptions{
		SweepInterval:        15 * time.Minute,
		Environment:          signed.store.environment,
		Lookup:               signed.store.lookup,
		EncryptionKeyVersion: signed.store.encryption.ActiveVersion(),
		Now:                  signed.store.now,
	})
	require.NoError(t, err)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)

	fixture := &a9RuntimeFixture{
		store:  signed.store,
		db:     db,
		signed: signed,
		now:    now,
	}
	copy(fixture.keysetHash[:], bytes.Repeat([]byte{0x91}, 32))
	copy(fixture.signingKeyID[:], bytes.Repeat([]byte{0x92}, 32))
	copy(fixture.tupleKeyID[:], bytes.Repeat([]byte{0x93}, 32))
	copy(fixture.rosterKeyID[:], bytes.Repeat([]byte{0x94}, 32))
	copy(fixture.topicKeyID[:], bytes.Repeat([]byte{0x95}, 32))
	fixture.insertKeyset(t)
	return fixture
}

func canonicalGate6JSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	parsed, err := a9trust.ParseStrictJSON(encoded)
	require.NoError(t, err)
	canonical, err := a9trust.Canonicalize(parsed)
	require.NoError(t, err)
	return canonical
}

func (fixture *a9RuntimeFixture) replaceRequest(
	t *testing.T,
	seed byte,
	installation [16]byte,
	epoch [16]byte,
	binding [16]byte,
	assertionHash [32]byte,
	topicBinding [32]byte,
	expectedGeneration uint64,
	topic *topicpkg.Topic,
	policy authority.PolicyControlV1,
	subscription SubscriptionRefresh,
) *a9api.ReplaceRequest {
	t.Helper()
	var (
		idempotency [16]byte
		legacy      [32]byte
		incarnation [16]byte
		requestHash [32]byte
		transport   [32]byte
		topicBytes  [33]byte
		routeKey    [32]byte
	)
	parsedID, err := a9trust.ParseCanonicalUUID(
		fmt.Sprintf("00000000-0000-4000-8000-%012x", seed),
	)
	require.NoError(t, err)
	copy(idempotency[:], parsedID)
	decodedLegacy, err := hex.DecodeString(fixture.signed.installationID)
	require.NoError(t, err)
	copy(legacy[:], decodedLegacy)
	parsedIncarnation, err := a9trust.ParseCanonicalUUID(
		fixture.signed.incarnationID,
	)
	require.NoError(t, err)
	copy(incarnation[:], parsedIncarnation)
	copy(requestHash[:], bytes.Repeat([]byte{seed + 1}, 32))
	copy(transport[:], bytes.Repeat([]byte{seed + 2}, 32))
	copy(topicBytes[:], subscription.Topic)
	copy(routeKey[:], subscription.RouteKey)
	hmacKeys := make(
		[]a9api.RouteHMACKey,
		len(subscription.HMACKeys),
	)
	for index := range subscription.HMACKeys {
		hmacKeys[index].ThirtyDayPeriodsSinceEpoch =
			subscription.HMACKeys[index].
				ThirtyDayPeriodsSinceEpoch
		copy(
			hmacKeys[index].Key[:],
			subscription.HMACKeys[index].Key,
		)
	}
	return &a9api.ReplaceRequest{
		Environment:                    "dev",
		InstallationBindingID:          installation,
		SequencerEpoch:                 epoch,
		SubscriptionGeneration:         expectedGeneration + 1,
		ExpectedSubscriptionGeneration: expectedGeneration,
		IdempotencyKey:                 idempotency,
		LegacyInstallationID:           legacy,
		AccountIncarnationID:           incarnation,
		APNSToken: func() [32]byte {
			var token [32]byte
			copy(token[:], bytes.Repeat([]byte{0xa1}, 32))
			return token
		}(),
		PayloadSchema: "hytch_push_wrapper_v1",
		PolicyControl: canonicalGate6JSON(t, policy),
		Subscriptions: []a9api.Subscription{{
			BindingID:               binding,
			BindingVersion:          1,
			AssertionHash:           assertionHash,
			TopicBinding:            topicBinding,
			TopicKeyEpoch:           7,
			RouteKeyEpoch:           subscription.RouteKeyEpoch,
			Topic:                   topicBytes,
			TransportConversationID: transport,
			RouteKey:                routeKey,
			HMACKeys:                hmacKeys,
			ReceiveCapability: canonicalGate6JSON(
				t,
				subscription.Capability,
			),
		}},
		RequestHash: requestHash,
	}
}

func (fixture *a9RuntimeFixture) insertKeyset(t *testing.T) {
	t.Helper()
	_, err := fixture.db.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_accepted_keysets (
		    environment, keyset_sequence, signed_keyset_hash,
		    signed_keyset_jcs, root_signing_key_id,
		    issued_at, expires_at, accepted_at
		) VALUES (1,1,$1,$2,$3,$4,$5,$4)`,
		fixture.keysetHash[:],
		[]byte(`{"test":true}`),
		bytes.Repeat([]byte{0x90}, 32),
		fixture.now,
		fixture.now.Add(time.Hour),
	)
	require.NoError(t, err)
	_, err = fixture.db.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_online_key_descriptors (
		    environment, keyset_sequence, key_use, key_state,
		    key_id, public_key, not_before, not_after
		) VALUES (1,1,1,1,$1,$2,$3,$4)`,
		fixture.signingKeyID[:],
		bytes.Repeat([]byte{0x96}, 32),
		fixture.now,
		fixture.now.Add(time.Hour),
	)
	require.NoError(t, err)
	_, err = fixture.db.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_commitment_key_descriptors (
		    environment, keyset_sequence, purpose, key_id,
		    topic_key_epoch, not_before, not_after
		) VALUES
		    (1,1,1,$1,NULL,$4,$5),
		    (1,1,2,$2,NULL,$4,$5),
		    (1,1,3,$3,7,$4,$5)`,
		fixture.rosterKeyID[:],
		fixture.tupleKeyID[:],
		fixture.topicKeyID[:],
		fixture.now,
		fixture.now.Add(time.Hour),
	)
	require.NoError(t, err)
	_, err = fixture.db.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_keyset_state (
		    environment, keyset_sequence, signed_keyset_hash,
		    state, uncertainty_reason, expires_at, refreshed_at
		) VALUES (1,1,$1,1,0,$3,$2)
	`,
		fixture.keysetHash[:],
		fixture.now,
		fixture.now.Add(time.Hour),
	)
	require.NoError(t, err)
}

func (fixture *a9RuntimeFixture) control(
	seed byte,
	installation [16]byte,
	epoch [16]byte,
	stream uint64,
	binding [16]byte,
	version uint64,
	action a9trust.ControlAction,
) a9trust.VerifiedControl {
	var (
		assertionHash [32]byte
		signedHash    [32]byte
	)
	copy(assertionHash[:], bytes.Repeat([]byte{seed}, 32))
	copy(signedHash[:], bytes.Repeat([]byte{seed + 1}, 32))
	event := a9trust.VerifiedControl{
		Environment:              "dev",
		IdempotencyKey:           fmt.Sprintf("00000000-0000-4000-8000-%012x", seed),
		InstallationBindingID:    installation,
		SequencerEpoch:           epoch,
		StreamSequence:           stream,
		ExpectedPreviousSequence: stream - 1,
		BindingID:                binding,
		BindingVersion:           version,
		ExpectedBindingVersion:   version - 1,
		Action:                   action,
		AssertionHash:            assertionHash,
		IssuedAt:                 fixture.now.Add(-time.Second),
		ExpiresAt:                fixture.now.Add(25 * time.Second),
		SigningKeyID:             fixture.signingKeyID,
		SignedObjectHash:         signedHash,
		KeysetSequence:           1,
		KeysetHash:               fixture.keysetHash,
	}
	if action == a9trust.ControlActionRevoke {
		event.Reason = a9trust.ControlReasonAuthorityRevoked
		return event
	}
	var leaseID [16]byte
	copy(leaseID[:], bytes.Repeat([]byte{seed + 2}, 16))
	var tuple, roster, topicBinding [32]byte
	copy(tuple[:], bytes.Repeat([]byte{seed + 3}, 32))
	copy(roster[:], bytes.Repeat([]byte{seed + 4}, 32))
	copy(topicBinding[:], bytes.Repeat([]byte{seed + 5}, 32))
	event.Assertion = &a9trust.VerifiedAssertion{
		Hash:                   assertionHash,
		InstallationBindingID:  installation,
		SequencerEpoch:         epoch,
		StreamSequence:         stream,
		BindingID:              binding,
		BindingVersion:         version,
		LeaseID:                leaseID,
		TupleCommitment:        tuple,
		TupleCommitmentKeyID:   fixture.tupleKeyID,
		RosterCommitment:       roster,
		RosterCommitmentKeyID:  fixture.rosterKeyID,
		TopicBinding:           topicBinding,
		TopicKeyEpoch:          7,
		TopicCommitmentKeyID:   fixture.topicKeyID,
		ConversationGeneration: 1,
		RosterVersion:          1,
		IssuedAt:               event.IssuedAt,
		ExpiresAt:              event.ExpiresAt,
		SigningKeyID:           fixture.signingKeyID,
		KeysetSequence:         1,
		KeysetHash:             fixture.keysetHash,
	}
	return event
}

func (fixture *a9RuntimeFixture) watermark(
	seed byte,
	installation [16]byte,
	epoch [16]byte,
	sequence uint64,
	committed uint64,
	status a9trust.WatermarkStatus,
) a9trust.VerifiedWatermark {
	var hash [32]byte
	copy(hash[:], bytes.Repeat([]byte{seed}, 32))
	reason := a9trust.WatermarkUncertaintyNone
	if status == a9trust.WatermarkStatusUncertain {
		reason = a9trust.WatermarkUncertaintySourceUnavailable
	}
	return a9trust.VerifiedWatermark{
		Environment:                    "dev",
		InstallationBindingID:          installation,
		SequencerEpoch:                 epoch,
		WatermarkSequence:              sequence,
		CommittedThroughStreamSequence: committed,
		Status:                         status,
		UncertaintyReason:              reason,
		IssuedAt:                       fixture.now.Add(-time.Second),
		ExpiresAt:                      fixture.now.Add(25 * time.Second),
		SigningKeyID:                   fixture.signingKeyID,
		SignedObjectHash:               hash,
		KeysetSequence:                 1,
		KeysetHash:                     fixture.keysetHash,
	}
}

func TestA9StoreControlWatermarkAndDenialWins(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	var installation, epoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xa1}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xa2}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xa3}, 16))

	first := fixture.control(
		0x11, installation, epoch, 1, binding, 1,
		a9trust.ControlActionUpsert,
	)
	require.True(t, fixture.store.validA9Control(first))
	preflight, err := fixture.db.BeginTx(
		t.Context(),
		&sql.TxOptions{Isolation: sql.LevelSerializable},
	)
	require.NoError(t, err)
	_, err = fixture.store.requireA9KeysetTx(
		t.Context(),
		preflight,
		1,
		fixture.keysetHash,
	)
	require.NoError(t, err)
	require.NoError(
		t,
		fixture.store.requireRetentionSafeTx(t.Context(), preflight),
	)
	require.NoError(t, preflight.Rollback())
	result, err := fixture.store.ApplyControl(t.Context(), first)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeApplied, result.Outcome)
	require.Equal(t, uint64(1), result.AcceptedStreamSequence)

	replay, err := fixture.store.ApplyControl(t.Context(), first)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeReplay, replay.Outcome)

	current := fixture.watermark(
		0x21, installation, epoch, 1, 1,
		a9trust.WatermarkStatusCurrent,
	)
	result, err = fixture.store.ApplyWatermark(t.Context(), current)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeApplied, result.Outcome)

	replay, err = fixture.store.ApplyWatermark(t.Context(), current)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeReplay, replay.Outcome)

	jump := fixture.watermark(
		0x22, installation, epoch, 3, 1,
		a9trust.WatermarkStatusCurrent,
	)
	result, err = fixture.store.ApplyWatermark(t.Context(), jump)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeGap, result.Outcome)
	require.Equal(t, a9api.ResultStateUncertain, result.State)

	revoke := fixture.control(
		0x31, installation, epoch, 3, binding, 2,
		a9trust.ControlActionRevoke,
	)
	result, err = fixture.store.ApplyControl(t.Context(), revoke)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeApplied, result.Outcome)
	require.Equal(t, a9api.ResultStateUncertain, result.State)
	require.Equal(t, uint64(1), result.AcceptedStreamSequence)

	var (
		cursor         uint64
		tombstoneCount int
		watermarkCount int
	)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT contiguous_stream_sequence
		   FROM hytch_push_vault.a9_installation_authority
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&cursor))
	require.Equal(t, uint64(1), cursor)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_binding_tombstones
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&tombstoneCount))
	require.Equal(t, 1, tombstoneCount)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_watermarks
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&watermarkCount))
	require.Equal(t, 1, watermarkCount)
}

func TestA9StoreConcurrentControlsSerializeAndLatch(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	var installation, epoch, leftBinding, rightBinding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xb1}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xb2}, 16))
	copy(leftBinding[:], bytes.Repeat([]byte{0xb3}, 16))
	copy(rightBinding[:], bytes.Repeat([]byte{0xb4}, 16))
	events := []a9trust.VerifiedControl{
		fixture.control(
			0x41, installation, epoch, 1, leftBinding, 1,
			a9trust.ControlActionUpsert,
		),
		fixture.control(
			0x51, installation, epoch, 1, rightBinding, 1,
			a9trust.ControlActionUpsert,
		),
	}
	results := make([]a9api.Result, len(events))
	errorsSeen := make([]error, len(events))
	var wait sync.WaitGroup
	wait.Add(len(events))
	for index := range events {
		go func(index int) {
			defer wait.Done()
			results[index], errorsSeen[index] = fixture.store.ApplyControl(
				t.Context(),
				events[index],
			)
		}(index)
	}
	wait.Wait()
	for _, err := range errorsSeen {
		require.NoError(t, err)
	}
	outcomes := map[a9api.ResultOutcome]int{}
	for _, result := range results {
		outcomes[result.Outcome]++
	}
	require.Equal(t, 1, outcomes[a9api.ResultOutcomeApplied])
	require.Equal(t, 1, outcomes[a9api.ResultOutcomeConflict])

	var (
		cursor       uint64
		state        int16
		controlCount int
	)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT contiguous_stream_sequence, state
		   FROM hytch_push_vault.a9_installation_authority
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&cursor, &state))
	require.Equal(t, uint64(1), cursor)
	require.Equal(t, a9AuthorityUncertain, state)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_control_events
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&controlCount))
	require.Equal(t, 1, controlCount)
}

func TestA9StoreRejectsStaleKeysetBeforeAuthorityMutation(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	_, err := fixture.db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.a9_keyset_state
		    SET refreshed_at = pg_catalog.clock_timestamp() -
		        INTERVAL '6 hours'
		  WHERE environment = 1`,
	)
	require.NoError(t, err)
	var installation, epoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xc1}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xc2}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xc3}, 16))
	_, err = fixture.store.ApplyControl(
		t.Context(),
		fixture.control(
			0x61, installation, epoch, 1, binding, 1,
			a9trust.ControlActionUpsert,
		),
	)
	require.ErrorIs(t, err, ErrStoreUnavailable)

	var count int
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_installation_authority
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&count))
	require.Zero(t, count)
}

func TestA9StoreWatermarkUncertaintyExpiryAndBootstrapGap(t *testing.T) {
	testCases := []struct {
		name      string
		seed      byte
		watermark func(*a9RuntimeFixture, [16]byte, [16]byte) a9trust.VerifiedWatermark
	}{
		{
			name: "signed uncertainty persists",
			seed: 0x64,
			watermark: func(
				fixture *a9RuntimeFixture,
				installation [16]byte,
				epoch [16]byte,
			) a9trust.VerifiedWatermark {
				return fixture.watermark(
					0x65, installation, epoch, 1, 1,
					a9trust.WatermarkStatusUncertain,
				)
			},
		},
		{
			name: "expired at database clock",
			seed: 0x66,
			watermark: func(
				fixture *a9RuntimeFixture,
				installation [16]byte,
				epoch [16]byte,
			) a9trust.VerifiedWatermark {
				mark := fixture.watermark(
					0x67, installation, epoch, 1, 1,
					a9trust.WatermarkStatusCurrent,
				)
				mark.IssuedAt = fixture.now.Add(-2 * time.Second)
				mark.ExpiresAt = fixture.now.Add(-time.Nanosecond)
				return mark
			},
		},
		{
			name: "bootstrap sequence gap",
			seed: 0x68,
			watermark: func(
				fixture *a9RuntimeFixture,
				installation [16]byte,
				epoch [16]byte,
			) a9trust.VerifiedWatermark {
				return fixture.watermark(
					0x69, installation, epoch, 2, 1,
					a9trust.WatermarkStatusCurrent,
				)
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newA9RuntimeFixture(t)
			var installation, epoch, binding [16]byte
			copy(
				installation[:],
				bytes.Repeat([]byte{testCase.seed}, 16),
			)
			copy(epoch[:], bytes.Repeat([]byte{testCase.seed + 1}, 16))
			copy(binding[:], bytes.Repeat([]byte{testCase.seed + 2}, 16))
			_, err := fixture.store.ApplyControl(
				t.Context(),
				fixture.control(
					testCase.seed+3,
					installation,
					epoch,
					1,
					binding,
					1,
					a9trust.ControlActionUpsert,
				),
			)
			require.NoError(t, err)
			result, err := fixture.store.ApplyWatermark(
				t.Context(),
				testCase.watermark(fixture, installation, epoch),
			)
			require.NoError(t, err)
			require.Equal(t, a9api.ResultStateUncertain, result.State)
			require.Contains(
				t,
				[]a9api.ResultOutcome{
					a9api.ResultOutcomeGap,
					a9api.ResultOutcomeInconclusive,
				},
				result.Outcome,
			)
			var historyCount int
			require.NoError(t, fixture.db.QueryRowContext(
				t.Context(),
				`SELECT COUNT(*)
				   FROM hytch_push_vault.a9_watermarks
				  WHERE environment = 1
				    AND installation_binding_id = $1`,
				installation[:],
			).Scan(&historyCount))
			if testCase.name == "signed uncertainty persists" {
				require.Equal(t, 1, historyCount)
			} else {
				require.Zero(t, historyCount)
			}
		})
	}
}

func TestA9StoreRejectsDBExpiredEmbeddedAssertion(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	var installation, epoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xca}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xcb}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xcc}, 16))
	event := fixture.control(
		0x6a, installation, epoch, 1, binding, 1,
		a9trust.ControlActionUpsert,
	)
	event.Assertion.IssuedAt = fixture.now.Add(-2 * time.Second)
	event.Assertion.ExpiresAt = fixture.now.Add(-time.Nanosecond)
	result, err := fixture.store.ApplyControl(t.Context(), event)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeInconclusive, result.Outcome)
	require.Equal(t, a9api.ResultStateUncertain, result.State)

	var count int
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_assertions
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&count))
	require.Zero(t, count)
}

func TestA9StoreReplaceApplyReplayStaleAndRevoke(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	var installation, epoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xd1}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xd2}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xd3}, 16))
	control := fixture.control(
		0x71, installation, epoch, 1, binding, 1,
		a9trust.ControlActionUpsert,
	)
	_, err := fixture.store.ApplyControl(t.Context(), control)
	require.NoError(t, err)
	_, err = fixture.store.ApplyWatermark(
		t.Context(),
		fixture.watermark(
			0x72, installation, epoch, 1, 1,
			a9trust.WatermarkStatusCurrent,
		),
	)
	require.NoError(t, err)

	topic := topicpkg.NewTopic(
		topicpkg.TopicKindGroupMessagesV1,
		bytes.Repeat([]byte{0x31}, 32),
	)
	policy := fixture.signed.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.signed.incarnationID,
	)
	gate6Subscription := fixture.signed.subscription(
		t,
		topic,
		0x32,
		1,
		688,
		authority.PushModeAlertAllowed,
		1,
	)
	request := fixture.replaceRequest(
		t,
		0x73,
		installation,
		epoch,
		binding,
		control.AssertionHash,
		control.Assertion.TopicBinding,
		0,
		topic,
		policy,
		gate6Subscription,
	)
	converted, err := fixture.store.a9RefreshRequest(request)
	require.NoError(t, err)
	require.True(t, fixture.store.validA9Replace(
		request,
		a9api.KeysetReceipt{Sequence: 1, Hash: fixture.keysetHash},
	))
	expectedRefresh := fixture.signed.refresh(
		t,
		1,
		policy,
		gate6Subscription,
	)
	require.Equal(t, expectedRefresh.PolicyControl, converted.PolicyControl)
	require.Equal(t, expectedRefresh.Subscriptions, converted.Subscriptions)
	_, err = fixture.store.validateRefresh(converted, fixture.now)
	require.NoError(t, err)
	wipeA9RefreshRequest(&converted)
	result, err := fixture.store.Replace(
		t.Context(),
		request,
		a9api.KeysetReceipt{
			Sequence: 1,
			Hash:     fixture.keysetHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeApplied, result.Outcome)
	require.Equal(t, uint64(1), result.SubscriptionGeneration)

	replay, err := fixture.store.Replace(
		t.Context(),
		request,
		a9api.KeysetReceipt{
			Sequence: 1,
			Hash:     fixture.keysetHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeReplay, replay.Outcome)

	stale := fixture.replaceRequest(
		t,
		0x74,
		installation,
		epoch,
		binding,
		control.AssertionHash,
		control.Assertion.TopicBinding,
		0,
		topic,
		policy,
		gate6Subscription,
	)
	result, err = fixture.store.Replace(
		t.Context(),
		stale,
		a9api.KeysetReceipt{
			Sequence: 1,
			Hash:     fixture.keysetHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeStale, result.Outcome)

	revoke := fixture.control(
		0x75, installation, epoch, 2, binding, 2,
		a9trust.ControlActionRevoke,
	)
	result, err = fixture.store.ApplyControl(t.Context(), revoke)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultStateRevoked, result.State)
	_, err = fixture.store.ApplyWatermark(
		t.Context(),
		fixture.watermark(
			0x76, installation, epoch, 2, 2,
			a9trust.WatermarkStatusCurrent,
		),
	)
	require.NoError(t, err)

	revoked := fixture.replaceRequest(
		t,
		0x77,
		installation,
		epoch,
		binding,
		control.AssertionHash,
		control.Assertion.TopicBinding,
		1,
		topic,
		policy,
		gate6Subscription,
	)
	result, err = fixture.store.Replace(
		t.Context(),
		revoked,
		a9api.KeysetReceipt{
			Sequence: 1,
			Hash:     fixture.keysetHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeStale, result.Outcome)
	require.Equal(t, a9api.ResultStateRevoked, result.State)

	var (
		routeCount  int
		leaseCount  int
		mappingPair bool
	)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_subscription_routes
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&routeCount))
	require.Zero(t, routeCount)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.subscription_leases
		  WHERE environment = 1`,
	).Scan(&leaseCount))
	require.Equal(t, 1, leaseCount)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT EXISTS (
		   SELECT 1
		     FROM hytch_push_vault.a9_installation_gate6_bindings AS mapping
		     JOIN hytch_push_vault.subscription_leases AS lease
		       ON lease.environment = mapping.environment
		      AND lease.installation_identity =
		          mapping.installation_identity
		    WHERE mapping.environment = 1
		      AND mapping.installation_binding_id = $1
		 )`,
		installation[:],
	).Scan(&mappingPair))
	require.True(t, mappingPair)
}

func TestA9Gate6NestedObjectsRequireExactCanonicalJSON(t *testing.T) {
	var policy authority.PolicyControlV1
	require.Error(t, decodeA9Gate6Object(
		[]byte(`{"schema_version":1,"schema_version":1}`),
		&policy,
	))
	require.Error(t, decodeA9Gate6Object(
		[]byte(` {"schema_version":1}`),
		&policy,
	))

	var capability authority.ReceiveCapabilityV1
	require.Error(t, decodeA9Gate6Object(
		[]byte(`{"algorithm":"Ed25519","algorithm":"Ed25519"}`),
		&capability,
	))
	require.Error(t, decodeA9Gate6Object(
		[]byte("{\n\"schema_version\":1}"),
		&capability,
	))
}

func TestA9StoreStableIdentitySurvivesLookupEpochRotation(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	epochSeconds := uint64(lookupRotationInterval / time.Second)
	currentLookupEpoch := LookupEpoch(fixture.now)
	require.Greater(t, currentLookupEpoch, uint64(0))
	previousTime := time.Unix(
		int64((currentLookupEpoch-1)*epochSeconds+1),
		0,
	).UTC()
	*fixture.signed.now = previousTime
	topic := topicpkg.NewTopic(
		topicpkg.TopicKindGroupMessagesV1,
		bytes.Repeat([]byte{0x41}, 32),
	)
	legacyPolicy := fixture.signed.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.signed.incarnationID,
	)
	legacySubscription := fixture.signed.subscription(
		t,
		topic,
		0x42,
		1,
		688,
		authority.PushModeAlertAllowed,
		1,
	)
	_, err := fixture.store.Refresh(
		t.Context(),
		fixture.signed.refresh(
			t,
			1,
			legacyPolicy,
			legacySubscription,
		),
	)
	require.NoError(t, err)
	var oldLookup, stableIdentity []byte
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT installation_lookup, installation_identity
		   FROM hytch_push_vault.installation_states
		  WHERE environment = 1`,
	).Scan(&oldLookup, &stableIdentity))

	*fixture.signed.now = fixture.now
	var installation, epoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xe1}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xe2}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xe3}, 16))
	control := fixture.control(
		0x81, installation, epoch, 1, binding, 1,
		a9trust.ControlActionUpsert,
	)
	_, err = fixture.store.ApplyControl(t.Context(), control)
	require.NoError(t, err)
	_, err = fixture.store.ApplyWatermark(
		t.Context(),
		fixture.watermark(
			0x82, installation, epoch, 1, 1,
			a9trust.WatermarkStatusCurrent,
		),
	)
	require.NoError(t, err)
	_, err = fixture.db.ExecContext(
		t.Context(),
		`UPDATE hytch_push_vault.a9_installation_authority
		    SET subscription_generation = 1
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	)
	require.NoError(t, err)
	_, err = fixture.db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.a9_installation_gate6_bindings (
		     environment, installation_binding_id, installation_identity
		 ) VALUES (1,$1,$2)`,
		installation[:],
		stableIdentity,
	)
	require.NoError(t, err)

	currentPolicy := fixture.signed.policy(
		t,
		2,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.signed.incarnationID,
	)
	currentSubscription := fixture.signed.subscription(
		t,
		topic,
		0x43,
		2,
		688,
		authority.PushModeAlertAllowed,
		2,
	)
	request := fixture.replaceRequest(
		t,
		0x83,
		installation,
		epoch,
		binding,
		control.AssertionHash,
		control.Assertion.TopicBinding,
		1,
		topic,
		currentPolicy,
		currentSubscription,
	)
	result, err := fixture.store.Replace(
		t.Context(),
		request,
		a9api.KeysetReceipt{
			Sequence: 1,
			Hash:     fixture.keysetHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeApplied, result.Outcome)

	var newLookup, leaseIdentity, routeIdentity, mappingIdentity []byte
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT installation.installation_lookup,
		        lease.installation_identity,
		        route.installation_identity,
		        mapping.installation_identity
		   FROM hytch_push_vault.installation_states AS installation
		   JOIN hytch_push_vault.subscription_leases AS lease
		     ON lease.installation_lookup =
		        installation.installation_lookup
		    AND lease.environment = installation.environment
		   JOIN hytch_push_vault.a9_subscription_routes AS route
		     ON route.lease_id = lease.lease_id
		    AND route.environment = lease.environment
		   JOIN hytch_push_vault.a9_installation_gate6_bindings AS mapping
		     ON mapping.environment = route.environment
		    AND mapping.installation_binding_id =
		        route.installation_binding_id
		  WHERE route.installation_binding_id = $1`,
		installation[:],
	).Scan(
		&newLookup,
		&leaseIdentity,
		&routeIdentity,
		&mappingIdentity,
	))
	require.NotEqual(t, oldLookup, newLookup)
	for _, identity := range [][]byte{
		leaseIdentity,
		routeIdentity,
		mappingIdentity,
	} {
		require.Equal(t, stableIdentity, identity)
	}
}

func TestA9StoreNewEpochRecoveryRequiresCompleteReplacement(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	var installation, oldEpoch, newEpoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xf1}, 16))
	copy(oldEpoch[:], bytes.Repeat([]byte{0xf2}, 16))
	copy(newEpoch[:], bytes.Repeat([]byte{0xf3}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xf4}, 16))

	oldControl := fixture.control(
		0x91, installation, oldEpoch, 1, binding, 1,
		a9trust.ControlActionUpsert,
	)
	_, err := fixture.store.ApplyControl(t.Context(), oldControl)
	require.NoError(t, err)
	oldWatermark := fixture.watermark(
		0x92, installation, oldEpoch, 1, 1,
		a9trust.WatermarkStatusCurrent,
	)
	_, err = fixture.store.ApplyWatermark(t.Context(), oldWatermark)
	require.NoError(t, err)

	freshControl := fixture.control(
		0x93, installation, newEpoch, 1, binding, 1,
		a9trust.ControlActionUpsert,
	)
	result, err := fixture.store.ApplyControl(
		t.Context(),
		freshControl,
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultStateUncertain, result.State)

	oldReplay, err := fixture.store.ApplyControl(
		t.Context(),
		oldControl,
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeReplay, oldReplay.Outcome)
	oldWatermarkReplay, err := fixture.store.ApplyWatermark(
		t.Context(),
		oldWatermark,
	)
	require.NoError(t, err)
	require.Equal(
		t,
		a9api.ResultOutcomeInconclusive,
		oldWatermarkReplay.Outcome,
	)

	recoveryWatermark := fixture.watermark(
		0x94, installation, newEpoch, 1, 1,
		a9trust.WatermarkStatusCurrent,
	)
	result, err = fixture.store.ApplyWatermark(
		t.Context(),
		recoveryWatermark,
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeInconclusive, result.Outcome)

	topic := topicpkg.NewTopic(
		topicpkg.TopicKindGroupMessagesV1,
		bytes.Repeat([]byte{0x51}, 32),
	)
	policy := fixture.signed.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.signed.incarnationID,
	)
	gate6Subscription := fixture.signed.subscription(
		t,
		topic,
		0x52,
		1,
		688,
		authority.PushModeAlertAllowed,
		1,
	)
	request := fixture.replaceRequest(
		t,
		0x95,
		installation,
		newEpoch,
		binding,
		freshControl.AssertionHash,
		freshControl.Assertion.TopicBinding,
		0,
		topic,
		policy,
		gate6Subscription,
	)
	result, err = fixture.store.Replace(
		t.Context(),
		request,
		a9api.KeysetReceipt{
			Sequence: 1,
			Hash:     fixture.keysetHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeApplied, result.Outcome)
	require.Equal(t, a9api.ResultStateActive, result.State)

	conflict := freshControl
	conflict.SignedObjectHash[0] ^= 0xff
	result, err = fixture.store.ApplyControl(t.Context(), conflict)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeConflict, result.Outcome)

	blocked := fixture.replaceRequest(
		t,
		0x96,
		installation,
		newEpoch,
		binding,
		freshControl.AssertionHash,
		freshControl.Assertion.TopicBinding,
		1,
		topic,
		policy,
		gate6Subscription,
	)
	result, err = fixture.store.Replace(
		t.Context(),
		blocked,
		a9api.KeysetReceipt{
			Sequence: 1,
			Hash:     fixture.keysetHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeInconclusive, result.Outcome)
	require.Equal(t, a9api.ResultStateUncertain, result.State)

	var generation uint64
	var routeCount int
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT subscription_generation
		   FROM hytch_push_vault.a9_installation_authority
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&generation))
	require.Equal(t, uint64(1), generation)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_subscription_routes
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&routeCount))
	require.Equal(t, 1, routeCount)
}

func TestA9StoreConcurrentReplaceAndRevokeEndsDenied(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	var installation, epoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xda}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xdb}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xdc}, 16))
	control := fixture.control(
		0xa1, installation, epoch, 1, binding, 1,
		a9trust.ControlActionUpsert,
	)
	_, err := fixture.store.ApplyControl(t.Context(), control)
	require.NoError(t, err)
	_, err = fixture.store.ApplyWatermark(
		t.Context(),
		fixture.watermark(
			0xa2, installation, epoch, 1, 1,
			a9trust.WatermarkStatusCurrent,
		),
	)
	require.NoError(t, err)
	topic := topicpkg.NewTopic(
		topicpkg.TopicKindGroupMessagesV1,
		bytes.Repeat([]byte{0x61}, 32),
	)
	policy := fixture.signed.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.signed.incarnationID,
	)
	gate6Subscription := fixture.signed.subscription(
		t,
		topic,
		0x62,
		1,
		688,
		authority.PushModeAlertAllowed,
		1,
	)
	request := fixture.replaceRequest(
		t,
		0xa3,
		installation,
		epoch,
		binding,
		control.AssertionHash,
		control.Assertion.TopicBinding,
		0,
		topic,
		policy,
		gate6Subscription,
	)
	revoke := fixture.control(
		0xa4, installation, epoch, 2, binding, 2,
		a9trust.ControlActionRevoke,
	)

	var (
		replaceResult a9api.Result
		revokeResult  a9api.Result
		replaceErr    error
		revokeErr     error
		wait          sync.WaitGroup
	)
	wait.Add(2)
	go func() {
		defer wait.Done()
		replaceResult, replaceErr = fixture.store.Replace(
			t.Context(),
			request,
			a9api.KeysetReceipt{
				Sequence: 1,
				Hash:     fixture.keysetHash,
			},
		)
	}()
	go func() {
		defer wait.Done()
		revokeResult, revokeErr = fixture.store.ApplyControl(
			t.Context(),
			revoke,
		)
	}()
	wait.Wait()
	require.NoError(t, replaceErr)
	require.NoError(t, revokeErr)
	require.Contains(
		t,
		[]a9api.ResultOutcome{
			a9api.ResultOutcomeApplied,
			a9api.ResultOutcomeStale,
		},
		replaceResult.Outcome,
	)
	require.Equal(t, a9api.ResultOutcomeApplied, revokeResult.Outcome)

	var routeCount, tombstoneCount int
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_subscription_routes
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&routeCount))
	require.Zero(t, routeCount)
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a9_binding_tombstones
		  WHERE environment = 1
		    AND installation_binding_id = $1
		    AND binding_id = $2`,
		installation[:],
		binding[:],
	).Scan(&tombstoneCount))
	require.Equal(t, 1, tombstoneCount)
}

func TestA9StoreReplacementGapCreatesNoPositiveState(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	var installation, epoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xea}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xeb}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xec}, 16))
	control := fixture.control(
		0xb1, installation, epoch, 1, binding, 1,
		a9trust.ControlActionUpsert,
	)
	_, err := fixture.store.ApplyControl(t.Context(), control)
	require.NoError(t, err)
	_, err = fixture.store.ApplyWatermark(
		t.Context(),
		fixture.watermark(
			0xb2, installation, epoch, 1, 1,
			a9trust.WatermarkStatusCurrent,
		),
	)
	require.NoError(t, err)
	topic := topicpkg.NewTopic(
		topicpkg.TopicKindGroupMessagesV1,
		bytes.Repeat([]byte{0x71}, 32),
	)
	policy := fixture.signed.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.signed.incarnationID,
	)
	gate6Subscription := fixture.signed.subscription(
		t,
		topic,
		0x72,
		1,
		688,
		authority.PushModeAlertAllowed,
		1,
	)
	request := fixture.replaceRequest(
		t,
		0xb3,
		installation,
		epoch,
		binding,
		control.AssertionHash,
		control.Assertion.TopicBinding,
		0,
		topic,
		policy,
		gate6Subscription,
	)
	request.Subscriptions[0].AssertionHash[0] ^= 0xff
	result, err := fixture.store.Replace(
		t.Context(),
		request,
		a9api.KeysetReceipt{
			Sequence: 1,
			Hash:     fixture.keysetHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeGap, result.Outcome)
	require.Equal(t, a9api.ResultStateUncertain, result.State)

	var generation uint64
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT subscription_generation
		   FROM hytch_push_vault.a9_installation_authority
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&generation))
	require.Zero(t, generation)
	for _, table := range []string{
		"a9_subscription_routes",
		"subscription_leases",
		"delivery_jobs",
	} {
		var count int
		require.NoError(t, fixture.db.QueryRowContext(
			t.Context(),
			fmt.Sprintf(
				"SELECT COUNT(*) FROM hytch_push_vault.%s",
				table,
			),
		).Scan(&count))
		require.Zero(t, count, table)
	}
}

func TestA9StoreNegativeReceiptEpochCannotLaterResetAuthority(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	var installation, firstEpoch, receiptOnlyEpoch, currentEpoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xfa}, 16))
	copy(firstEpoch[:], bytes.Repeat([]byte{0xfb}, 16))
	copy(receiptOnlyEpoch[:], bytes.Repeat([]byte{0xfc}, 16))
	copy(currentEpoch[:], bytes.Repeat([]byte{0xfd}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xfe}, 16))
	_, err := fixture.store.ApplyControl(
		t.Context(),
		fixture.control(
			0xc1, installation, firstEpoch, 1, binding, 1,
			a9trust.ControlActionUpsert,
		),
	)
	require.NoError(t, err)

	negative := fixture.control(
		0xc2, installation, receiptOnlyEpoch, 2, binding, 1,
		a9trust.ControlActionUpsert,
	)
	result, err := fixture.store.ApplyControl(t.Context(), negative)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeInconclusive, result.Outcome)

	_, err = fixture.store.ApplyControl(
		t.Context(),
		fixture.control(
			0xc3, installation, currentEpoch, 1, binding, 1,
			a9trust.ControlActionUpsert,
		),
	)
	require.NoError(t, err)
	reuse := fixture.control(
		0xc4, installation, receiptOnlyEpoch, 1, binding, 1,
		a9trust.ControlActionUpsert,
	)
	result, err = fixture.store.ApplyControl(t.Context(), reuse)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeConflict, result.Outcome)

	var storedEpoch []byte
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT sequencer_epoch
		   FROM hytch_push_vault.a9_installation_authority
		  WHERE environment = 1
		    AND installation_binding_id = $1`,
		installation[:],
	).Scan(&storedEpoch))
	require.Equal(t, currentEpoch[:], storedEpoch)
}
