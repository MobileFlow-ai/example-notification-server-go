package vault

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
)

func TestSerializedDeliveryJobRejectsExactAPNSBoundary(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	job := SerializedDeliveryJob{
		DeviceToken:      strings.Repeat("ab", 32),
		Topic:            "com.example.app",
		Payload:          make([]byte, 4096),
		PushType:         "alert",
		Priority:         10,
		Expiration:       now.Add(time.Minute),
		TrafficClass:     DeliveryTrafficConversation,
		PolicyEpoch:      1,
		RouteKeyEpoch:    1,
		NoncePrefix:      1,
		DeliverySequence: 1,
		AliasDay:         gate8wrapper.UTCDay(now),
		RouteAlias:       make([]byte, gate8wrapper.RouteAliasSize),
	}
	require.ErrorIs(
		t,
		validateSerializedDeliveryJob(job, now),
		ErrDeliveryJobInvalid,
	)
}

func validSerializedA9Job(now time.Time) SerializedDeliveryJob {
	snapshot := &interfaces.A9RouteSnapshot{
		SubscriptionGeneration:  1,
		BindingVersion:          2,
		AssertionStreamSequence: 3,
		AssertionExpiresAt:      now.Add(time.Minute),
		TopicKeyEpoch:           4,
		RouteKeyEpoch:           5,
		KeysetSequence:          6,
		WatermarkSequence:       7,
	}
	copy(snapshot.InstallationBindingID[:], bytes.Repeat([]byte{0x11}, 16))
	copy(snapshot.SequencerEpoch[:], bytes.Repeat([]byte{0x12}, 16))
	copy(snapshot.BindingID[:], bytes.Repeat([]byte{0x13}, 16))
	copy(snapshot.AssertionHash[:], bytes.Repeat([]byte{0x14}, 32))
	copy(snapshot.TopicBinding[:], bytes.Repeat([]byte{0x15}, 32))
	copy(snapshot.KeysetHash[:], bytes.Repeat([]byte{0x16}, 32))
	return SerializedDeliveryJob{
		DeviceToken:      strings.Repeat("ab", 32),
		Topic:            "com.example.app",
		ProviderTopic:    bytes.Repeat([]byte{0x21}, 33),
		Payload:          []byte(`{"aps":{"alert":"wakeup"}}`),
		PushType:         "alert",
		Priority:         10,
		Expiration:       now.Add(time.Minute),
		TrafficClass:     DeliveryTrafficConversation,
		PolicyEpoch:      1,
		RouteKeyEpoch:    snapshot.RouteKeyEpoch,
		NoncePrefix:      1,
		DeliverySequence: 1,
		AliasDay:         gate8wrapper.UTCDay(now),
		RouteAlias:       make([]byte, gate8wrapper.RouteAliasSize),
		A9:               snapshot,
	}
}

func TestSerializedDeliveryJobRequiresCompleteA9Pair(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	valid := validSerializedA9Job(now)
	require.NoError(t, validateSerializedDeliveryJob(valid, now))

	tests := []struct {
		name   string
		mutate func(*SerializedDeliveryJob)
	}{
		{
			name: "provider topic without snapshot",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9 = nil
			},
		},
		{
			name: "snapshot without provider topic",
			mutate: func(job *SerializedDeliveryJob) {
				job.ProviderTopic = nil
			},
		},
		{
			name: "provider topic wrong length",
			mutate: func(job *SerializedDeliveryJob) {
				job.ProviderTopic = job.ProviderTopic[:32]
			},
		},
		{
			name: "subscription generation missing",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.SubscriptionGeneration = 0
			},
		},
		{
			name: "subscription generation exceeds canonical integer",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.SubscriptionGeneration =
					gate8wrapper.MaxCanonicalInteger + 1
			},
		},
		{
			name: "binding version missing",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.BindingVersion = 0
			},
		},
		{
			name: "binding version exceeds canonical integer",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.BindingVersion =
					gate8wrapper.MaxCanonicalInteger + 1
			},
		},
		{
			name: "assertion sequence missing",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.AssertionStreamSequence = 0
			},
		},
		{
			name: "assertion sequence exceeds canonical integer",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.AssertionStreamSequence =
					gate8wrapper.MaxCanonicalInteger + 1
			},
		},
		{
			name: "assertion expired",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.AssertionExpiresAt = now
			},
		},
		{
			name: "job outlives assertion",
			mutate: func(job *SerializedDeliveryJob) {
				job.Expiration = job.A9.AssertionExpiresAt.Add(
					time.Nanosecond,
				)
			},
		},
		{
			name: "welcome cannot carry A9",
			mutate: func(job *SerializedDeliveryJob) {
				job.TrafficClass = DeliveryTrafficWelcome
				job.PushType = "background"
				job.Priority = 5
				job.WelcomeAuthorizationID = bytes.Repeat(
					[]byte{0x31},
					16,
				)
				job.WelcomeEnvelopeDigest = bytes.Repeat(
					[]byte{0x32},
					32,
				)
			},
		},
		{
			name: "topic epoch missing",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.TopicKeyEpoch = 0
			},
		},
		{
			name: "route epoch missing",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.RouteKeyEpoch = 0
			},
		},
		{
			name: "route epoch mismatch",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.RouteKeyEpoch++
			},
		},
		{
			name: "keyset sequence missing",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.KeysetSequence = 0
			},
		},
		{
			name: "keyset sequence exceeds canonical integer",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.KeysetSequence =
					gate8wrapper.MaxCanonicalInteger + 1
			},
		},
		{
			name: "watermark sequence missing",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.WatermarkSequence = 0
			},
		},
		{
			name: "watermark sequence exceeds canonical integer",
			mutate: func(job *SerializedDeliveryJob) {
				job.A9.WatermarkSequence =
					gate8wrapper.MaxCanonicalInteger + 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			job := validSerializedA9Job(now)
			test.mutate(&job)
			require.ErrorIs(
				t,
				validateSerializedDeliveryJob(job, now),
				ErrDeliveryJobInvalid,
			)
		})
	}
}

func TestSerializedDeliveryJobCloneIsolatesA9Material(t *testing.T) {
	now := time.Date(
		2026,
		7,
		26,
		12,
		0,
		0,
		0,
		time.FixedZone("fixture", -6*60*60),
	)
	job := validSerializedA9Job(now)
	cloned := cloneSerializedDeliveryJob(job)

	require.NotSame(t, job.A9, cloned.A9)
	require.Equal(t, job.ProviderTopic, cloned.ProviderTopic)
	require.Equal(t, job.A9.AssertionExpiresAt, cloned.A9.AssertionExpiresAt)
	job.ProviderTopic[0] ^= 0xff
	job.A9.InstallationBindingID[0] ^= 0xff
	job.A9.AssertionExpiresAt = time.Time{}
	require.NotEqual(t, job.ProviderTopic, cloned.ProviderTopic)
	require.NotEqual(
		t,
		job.A9.InstallationBindingID,
		cloned.A9.InstallationBindingID,
	)
	require.False(t, cloned.A9.AssertionExpiresAt.IsZero())
}

func TestErasureMarkerRejectsA9Material(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	marker := SerializedDeliveryJob{
		DeviceToken:  strings.Repeat("ab", 32),
		Expiration:   now.Add(time.Minute),
		TrafficClass: DeliveryTrafficConversation,
		EraseOnly:    true,
	}
	require.NoError(t, validateErasureMarker(marker))

	marker.ProviderTopic = bytes.Repeat([]byte{0x21}, 33)
	require.ErrorIs(t, validateErasureMarker(marker), ErrDeliveryJobInvalid)
	marker.ProviderTopic = nil
	marker.A9 = validSerializedA9Job(now).A9
	require.ErrorIs(t, validateErasureMarker(marker), ErrDeliveryJobInvalid)
}

func TestA9DeliveryStillCurrentUsesStrictFinalDatabaseBoundary(t *testing.T) {
	managerNow := time.Date(2026, 7, 29, 17, 0, 0, 0, time.UTC)
	expiresAt := managerNow.Add(30 * time.Second)
	route := a9CurrentRouteState{
		keysetExpiresAt:    expiresAt,
		keysetFreshUntil:   expiresAt,
		watermarkExpiresAt: expiresAt,
		assertionExpiresAt: expiresAt,
	}
	snapshot := &interfaces.A9RouteSnapshot{
		AssertionExpiresAt: expiresAt.Add(2 * time.Second),
		TopicKeyEpoch:      a9trust.TopicEpoch(managerNow),
	}

	require.True(t, a9DeliveryStillCurrent(
		managerNow,
		managerNow.Add(a9MaximumClockSkew),
		managerNow.Add(a9MaximumClockSkew),
		expiresAt,
		expiresAt,
		route,
		snapshot,
	))
	require.False(t, a9DeliveryStillCurrent(
		managerNow,
		managerNow.Add(a9MaximumClockSkew+time.Nanosecond),
		managerNow.Add(a9MaximumClockSkew+time.Nanosecond),
		expiresAt,
		expiresAt,
		route,
		snapshot,
	))

	for _, test := range []struct {
		name           string
		jobExpiresAt   time.Time
		gate6ExpiresAt time.Time
		route          a9CurrentRouteState
	}{
		{
			name:           "job exact expiry",
			jobExpiresAt:   expiresAt,
			gate6ExpiresAt: expiresAt.Add(time.Second),
			route: a9CurrentRouteState{
				keysetExpiresAt:    expiresAt.Add(time.Second),
				keysetFreshUntil:   expiresAt.Add(time.Second),
				watermarkExpiresAt: expiresAt.Add(time.Second),
				assertionExpiresAt: expiresAt.Add(time.Second),
			},
		},
		{
			name:           "gate6 exact expiry",
			jobExpiresAt:   expiresAt.Add(time.Second),
			gate6ExpiresAt: expiresAt,
			route: a9CurrentRouteState{
				keysetExpiresAt:    expiresAt.Add(time.Second),
				keysetFreshUntil:   expiresAt.Add(time.Second),
				watermarkExpiresAt: expiresAt.Add(time.Second),
				assertionExpiresAt: expiresAt.Add(time.Second),
			},
		},
		{
			name:           "a9 exact expiry",
			jobExpiresAt:   expiresAt.Add(time.Second),
			gate6ExpiresAt: expiresAt.Add(time.Second),
			route:          route,
		},
		{
			name:           "keyset freshness exact expiry",
			jobExpiresAt:   expiresAt.Add(time.Second),
			gate6ExpiresAt: expiresAt.Add(time.Second),
			route: a9CurrentRouteState{
				keysetExpiresAt:    expiresAt.Add(time.Second),
				keysetFreshUntil:   expiresAt,
				watermarkExpiresAt: expiresAt.Add(time.Second),
				assertionExpiresAt: expiresAt.Add(time.Second),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.False(t, a9DeliveryStillCurrent(
				expiresAt,
				expiresAt,
				expiresAt,
				test.jobExpiresAt,
				test.gate6ExpiresAt,
				test.route,
				snapshot,
			))
		})
	}
}

func TestA9RouteStillCurrentRejectsPreviousTopicKeyAtOverlapBoundary(
	t *testing.T,
) {
	boundary := a9trust.TopicEpochBoundary(689)
	evaluationTime := boundary.Add(59 * time.Second)
	expiresAt := boundary.Add(2 * time.Minute)
	state := a9CurrentRouteState{
		keysetExpiresAt:    expiresAt,
		keysetFreshUntil:   expiresAt,
		watermarkExpiresAt: expiresAt,
		assertionExpiresAt: expiresAt,
	}
	snapshot := &interfaces.A9RouteSnapshot{
		AssertionExpiresAt: expiresAt,
		TopicKeyEpoch:      688,
	}

	_, current := a9RouteStillCurrentAt(
		evaluationTime,
		boundary.Add(60*time.Second-time.Nanosecond),
		boundary.Add(60*time.Second-time.Nanosecond),
		state,
		snapshot,
	)
	require.True(t, current)

	_, current = a9RouteStillCurrentAt(
		evaluationTime,
		boundary.Add(60*time.Second),
		boundary.Add(60*time.Second),
		state,
		snapshot,
	)
	require.False(t, current)
}
