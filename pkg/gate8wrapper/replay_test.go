package gate8wrapper

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type nilUnsafeReplayProtector struct {
	called bool
}

func (protector *nilUnsafeReplayProtector) CompareAndAdvanceAuthenticated(
	Header,
) error {
	protector.called = true
	return nil
}

type replayProtectorFunc func(Header) error

func (protect replayProtectorFunc) CompareAndAdvanceAuthenticated(
	header Header,
) error {
	return protect(header)
}

func TestOpenRequiresReplayProtector(t *testing.T) {
	envelope := sealReplayEnvelope(
		t,
		EnvironmentDevelopment,
		"2026-07-28",
		[]byte("topic-a"),
		2,
		[NoncePrefixSize]byte{1, 2, 3, 4},
		1,
	)

	_, err := openReplayEnvelope(
		envelope,
		[]byte("topic-a"),
		nil,
	)
	require.ErrorIs(t, err, ErrReplayState)

	var typedNil *ReplayWindow
	_, err = openReplayEnvelope(
		envelope,
		[]byte("topic-a"),
		typedNil,
	)
	require.ErrorIs(t, err, ErrReplayState)

	var unsafeTypedNil *nilUnsafeReplayProtector
	require.NotPanics(t, func() {
		_, err = openReplayEnvelope(
			envelope,
			[]byte("topic-a"),
			unsafeTypedNil,
		)
	})
	require.ErrorIs(t, err, ErrReplayState)
}

func TestOpenFailsClosedWhenDurableAdvanceFails(t *testing.T) {
	envelope := sealReplayEnvelope(
		t,
		EnvironmentDevelopment,
		"2026-07-28",
		[]byte("topic-a"),
		2,
		[NoncePrefixSize]byte{1, 2, 3, 4},
		1,
	)
	calls := 0
	protector := replayProtectorFunc(func(header Header) error {
		calls++
		require.Equal(t, envelope.Header, header)
		return fmt.Errorf("fixed persistence failure: %w", ErrReplayState)
	})

	plaintext, err := openReplayEnvelope(
		envelope,
		[]byte("topic-a"),
		protector,
	)

	require.ErrorIs(t, err, ErrReplayState)
	require.Equal(t, Plaintext{}, plaintext)
	require.Equal(t, 1, calls)
}

func TestReplayWindowRejectsLowerSequenceAndRestoresHighWater(t *testing.T) {
	scope := replayScope{
		environment: EnvironmentDevelopment,
		aliasDay:    "2026-07-28",
		topic:       []byte("topic-a"),
		routeEpoch:  2,
		noncePrefix: [NoncePrefixSize]byte{
			1, 2, 3, 4,
		},
	}
	window := &ReplayWindow{}
	_, err := openReplayEnvelope(
		sealReplayEnvelopeFromScope(t, scope, 9),
		scope.topic,
		window,
	)
	require.NoError(t, err)

	_, err = openReplayEnvelope(
		sealReplayEnvelopeFromScope(t, scope, 8),
		scope.topic,
		window,
	)
	require.ErrorIs(t, err, ErrReplay)

	state, initialized := window.Snapshot()
	require.True(t, initialized)
	require.Equal(t, uint64(9), state.HighestSequence)
	restored, err := RestoreReplayWindow(state)
	require.NoError(t, err)

	_, err = openReplayEnvelope(
		sealReplayEnvelopeFromScope(t, scope, 9),
		scope.topic,
		restored,
	)
	require.ErrorIs(t, err, ErrReplay)
	_, err = openReplayEnvelope(
		sealReplayEnvelopeFromScope(t, scope, 10),
		scope.topic,
		restored,
	)
	require.NoError(t, err)
}

func TestReplayWindowRejectsEveryScopeChange(t *testing.T) {
	baseline := replayScope{
		environment: EnvironmentDevelopment,
		aliasDay:    "2026-07-28",
		topic:       []byte("topic-a"),
		routeEpoch:  2,
		noncePrefix: [NoncePrefixSize]byte{
			1, 2, 3, 4,
		},
	}
	testCases := []struct {
		name  string
		scope replayScope
	}{
		{
			name: "environment",
			scope: replayScope{
				environment: EnvironmentProduction,
				aliasDay:    baseline.aliasDay,
				topic:       baseline.topic,
				routeEpoch:  baseline.routeEpoch,
				noncePrefix: baseline.noncePrefix,
			},
		},
		{
			name: "alias day",
			scope: replayScope{
				environment: baseline.environment,
				aliasDay:    "2026-07-29",
				topic:       baseline.topic,
				routeEpoch:  baseline.routeEpoch,
				noncePrefix: baseline.noncePrefix,
			},
		},
		{
			name: "route alias",
			scope: replayScope{
				environment: baseline.environment,
				aliasDay:    baseline.aliasDay,
				topic:       []byte("topic-b"),
				routeEpoch:  baseline.routeEpoch,
				noncePrefix: baseline.noncePrefix,
			},
		},
		{
			name: "route epoch",
			scope: replayScope{
				environment: baseline.environment,
				aliasDay:    baseline.aliasDay,
				topic:       baseline.topic,
				routeEpoch:  3,
				noncePrefix: baseline.noncePrefix,
			},
		},
		{
			name: "nonce prefix",
			scope: replayScope{
				environment: baseline.environment,
				aliasDay:    baseline.aliasDay,
				topic:       baseline.topic,
				routeEpoch:  baseline.routeEpoch,
				noncePrefix: [NoncePrefixSize]byte{
					5, 6, 7, 8,
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			window := &ReplayWindow{}
			_, err := openReplayEnvelope(
				sealReplayEnvelopeFromScope(t, baseline, 1),
				baseline.topic,
				window,
			)
			require.NoError(t, err)

			_, err = openReplayEnvelope(
				sealReplayEnvelopeFromScope(t, testCase.scope, 2),
				testCase.scope.topic,
				window,
			)
			require.ErrorIs(t, err, ErrReplayState)
		})
	}
}

func TestUnauthenticatedHighSequenceCannotPoisonReplay(t *testing.T) {
	scope := replayScope{
		environment: EnvironmentDevelopment,
		aliasDay:    "2026-07-28",
		topic:       []byte("topic-a"),
		routeEpoch:  2,
		noncePrefix: [NoncePrefixSize]byte{
			1, 2, 3, 4,
		},
	}
	tampered := sealReplayEnvelopeFromScope(t, scope, 100)
	tampered.Ciphertext = append([]byte(nil), tampered.Ciphertext...)
	tampered.Ciphertext[0] ^= 1

	window := &ReplayWindow{}
	_, err := openReplayEnvelope(tampered, scope.topic, window)
	require.ErrorIs(t, err, ErrAuthentication)

	_, err = openReplayEnvelope(
		sealReplayEnvelopeFromScope(t, scope, 1),
		scope.topic,
		window,
	)
	require.NoError(t, err)
}

func TestRestoreReplayWindowRejectsInvalidState(t *testing.T) {
	_, err := RestoreReplayWindow(ReplayState{})
	require.ErrorIs(t, err, ErrReplayState)
	_, err = RestoreReplayWindow(ReplayState{
		Environment:     EnvironmentDevelopment,
		AliasDay:        "2026-07-28",
		RouteKeyEpoch:   1,
		HighestSequence: MaxCanonicalInteger + 1,
	})
	require.ErrorIs(t, err, ErrReplayState)
}

type replayScope struct {
	environment Environment
	aliasDay    string
	topic       []byte
	routeEpoch  uint32
	noncePrefix [NoncePrefixSize]byte
}

func sealReplayEnvelopeFromScope(
	t *testing.T,
	scope replayScope,
	sequence uint64,
) Envelope {
	t.Helper()
	return sealReplayEnvelope(
		t,
		scope.environment,
		scope.aliasDay,
		scope.topic,
		scope.routeEpoch,
		scope.noncePrefix,
		sequence,
	)
}

func sealReplayEnvelope(
	t *testing.T,
	environment Environment,
	aliasDay string,
	topic []byte,
	routeEpoch uint32,
	noncePrefix [NoncePrefixSize]byte,
	sequence uint64,
) Envelope {
	t.Helper()
	envelope, err := Seal(SealRequest{
		RouteKey:         replayTestRouteKey(),
		Topic:            topic,
		Environment:      environment,
		AliasDay:         aliasDay,
		RouteKeyEpoch:    routeEpoch,
		NoncePrefix:      noncePrefix,
		DeliverySequence: sequence,
		Capability:       []byte("capability"),
		XMTPEnvelope:     []byte("ciphertext"),
		FitsWrapper:      func(SizeEstimate) bool { return true },
	})
	require.NoError(t, err)
	return envelope
}

func openReplayEnvelope(
	envelope Envelope,
	topic []byte,
	replay ReplayProtector,
) (Plaintext, error) {
	return Open(OpenRequest{
		RouteKey:              replayTestRouteKey(),
		Topic:                 topic,
		ExpectedEnvironment:   envelope.Header.Environment,
		ExpectedAliasDay:      envelope.Header.AliasDay,
		ExpectedRouteKeyEpoch: envelope.Header.RouteKeyEpoch,
		Envelope:              envelope,
		Replay:                replay,
	})
}

func replayTestRouteKey() []byte {
	key := make([]byte, RouteKeySize)
	for index := range key {
		key[index] = byte(index + 1)
	}
	return key
}
