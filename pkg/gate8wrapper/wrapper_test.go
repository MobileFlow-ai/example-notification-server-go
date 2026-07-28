package gate8wrapper

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDerivationVector(t *testing.T) {
	routeKey := make([]byte, RouteKeySize)
	for index := range routeKey {
		routeKey[index] = byte(index)
	}
	topic := []byte("topic-vector-01")

	alias, err := DeriveRouteAlias(
		routeKey,
		topic,
		EnvironmentDevelopment,
		"2026-07-26",
	)
	require.NoError(t, err)
	require.Equal(t, "d4737d693b0616f11aba24f8043cfa96", hex.EncodeToString(alias[:]))

	dayKey, err := DeriveDayKey(
		routeKey,
		EnvironmentDevelopment,
		"2026-07-26",
		alias,
		7,
	)
	require.NoError(t, err)
	require.Equal(
		t,
		"3a683131eec1b51a7ed0a2521b3a50346dc8fa34ad89dbb46773e2310f3ea0af",
		hex.EncodeToString(dayKey[:]),
	)
}

func TestSealVectorOpenAndReplay(t *testing.T) {
	routeKey := make([]byte, RouteKeySize)
	for index := range routeKey {
		routeKey[index] = byte(index)
	}
	prefix := [NoncePrefixSize]byte{0xaa, 0xbb, 0xcc, 0xdd}
	envelope, err := Seal(SealRequest{
		RouteKey:         routeKey,
		Topic:            []byte("topic-vector-01"),
		Environment:      EnvironmentDevelopment,
		AliasDay:         "2026-07-26",
		RouteKeyEpoch:    7,
		NoncePrefix:      prefix,
		DeliverySequence: 9,
		Capability:       []byte("cap"),
		XMTPEnvelope:     []byte("xmpt"),
		FitsWrapper:      func(SizeEstimate) bool { return true },
	})
	require.NoError(t, err)
	require.Equal(
		t,
		"d6652d5373b3428600ebf242ead12ac9ab8a9886123581210b5002fe41a7215f8baef93eac",
		hex.EncodeToString(envelope.Ciphertext),
	)

	aad, err := envelope.Header.CanonicalAAD()
	require.NoError(t, err)
	require.Equal(
		t,
		`{"alias_day":"2026-07-26","delivery_sequence":9,"environment":"development","nonce_prefix":"aabbccdd","route_alias":"d4737d693b0616f11aba24f8043cfa96","route_key_epoch":7,"schema_version":1}`,
		string(aad),
	)
	parsed, err := ParseCanonicalAAD(aad)
	require.NoError(t, err)
	require.Equal(t, envelope.Header, parsed)

	replay := &ReplayWindow{}
	opened, err := Open(OpenRequest{
		RouteKey:              routeKey,
		Topic:                 []byte("topic-vector-01"),
		ExpectedEnvironment:   EnvironmentDevelopment,
		ExpectedAliasDay:      "2026-07-26",
		ExpectedRouteKeyEpoch: 7,
		Envelope:              envelope,
		Replay:                replay,
	})
	require.NoError(t, err)
	require.Equal(t, ModeCiphertextInline, opened.DeliveryMode)
	require.Equal(t, []byte("cap"), opened.Capability)
	require.Equal(t, []byte("xmpt"), opened.XMTPEnvelope)

	_, err = Open(OpenRequest{
		RouteKey:              routeKey,
		Topic:                 []byte("topic-vector-01"),
		ExpectedEnvironment:   EnvironmentDevelopment,
		ExpectedAliasDay:      "2026-07-26",
		ExpectedRouteKeyEpoch: 7,
		Envelope:              envelope,
		Replay:                replay,
	})
	require.ErrorIs(t, err, ErrReplay)
}

func TestSealFallsBackToCompactForegroundSyncBeforeEncryption(t *testing.T) {
	hookCalls := 0
	envelope, err := Seal(SealRequest{
		RouteKey:         make([]byte, RouteKeySize),
		Topic:            []byte("welcome-topic"),
		Environment:      EnvironmentDevelopment,
		AliasDay:         "2026-07-26",
		RouteKeyEpoch:    1,
		NoncePrefix:      [NoncePrefixSize]byte{1, 2, 3, 4},
		DeliverySequence: 1,
		Capability:       []byte("signed-welcome-authorization"),
		XMTPEnvelope:     make([]byte, 8192),
		FitsWrapper: func(estimate SizeEstimate) bool {
			return estimate.Mode == ModeForegroundSync &&
				estimate.StandardBase64CiphertextBytes < 4096
		},
		OnForegroundSync: func() { hookCalls++ },
	})
	require.NoError(t, err)
	require.Equal(t, 1, hookCalls)

	opened, err := Open(OpenRequest{
		RouteKey:              make([]byte, RouteKeySize),
		Topic:                 []byte("welcome-topic"),
		ExpectedEnvironment:   EnvironmentDevelopment,
		ExpectedAliasDay:      "2026-07-26",
		ExpectedRouteKeyEpoch: 1,
		Envelope:              envelope,
		Replay:                &ReplayWindow{},
	})
	require.NoError(t, err)
	require.Equal(t, ModeForegroundSync, opened.DeliveryMode)
	require.Empty(t, opened.XMTPEnvelope)
}

func TestOpenFailsClosedOnRouteAEADSequenceReplayAndKeyState(t *testing.T) {
	routeKey := make([]byte, RouteKeySize)
	request := SealRequest{
		RouteKey:         routeKey,
		Topic:            []byte("topic"),
		Environment:      EnvironmentDevelopment,
		AliasDay:         "2026-07-26",
		RouteKeyEpoch:    2,
		NoncePrefix:      [NoncePrefixSize]byte{4, 3, 2, 1},
		DeliverySequence: 3,
		Capability:       []byte("capability"),
		XMTPEnvelope:     []byte("ciphertext"),
		FitsWrapper:      func(SizeEstimate) bool { return true },
	}
	envelope, err := Seal(request)
	require.NoError(t, err)

	open := func(envelope Envelope, topic []byte, epoch uint32) error {
		_, openErr := Open(OpenRequest{
			RouteKey:              routeKey,
			Topic:                 topic,
			ExpectedEnvironment:   EnvironmentDevelopment,
			ExpectedAliasDay:      "2026-07-26",
			ExpectedRouteKeyEpoch: epoch,
			Envelope:              envelope,
			Replay:                &ReplayWindow{},
		})
		return openErr
	}
	require.ErrorIs(t, open(envelope, []byte("wrong"), 2), ErrRouteMismatch)
	require.ErrorIs(t, open(envelope, []byte("topic"), 1), ErrRouteMismatch)

	tampered := envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[0] ^= 1
	require.ErrorIs(t, open(tampered, []byte("topic"), 2), ErrAuthentication)

	invalidSequence := envelope
	invalidSequence.Header.DeliverySequence = MaxCanonicalInteger + 1
	require.ErrorIs(t, open(invalidSequence, []byte("topic"), 2), ErrInvalidHeader)
}

func TestParseCanonicalAADRejectsAlternateEncoding(t *testing.T) {
	_, err := ParseCanonicalAAD([]byte(
		`{ "alias_day":"2026-07-26","delivery_sequence":1,"environment":"development","nonce_prefix":"00000000","route_alias":"00000000000000000000000000000000","route_key_epoch":1,"schema_version":1}`,
	))
	require.ErrorIs(t, err, ErrInvalidHeader)
}
