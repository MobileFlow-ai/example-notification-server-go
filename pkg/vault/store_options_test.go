package vault

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
)

func TestNewStoreHardClosesWelcomeConfiguration(t *testing.T) {
	keyring, err := NewKeyring(1, map[uint32][]byte{
		1: bytes.Repeat([]byte{0x31}, 32),
	})
	require.NoError(t, err)
	lookup, err := NewLookupKey(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	base := StoreOptions{
		Environment: "dev",
		Encryption:  keyring,
		Lookup:      lookup,
		AuthorityKeys: map[string]ed25519.PublicKey{
			"key-1": bytes.Repeat([]byte{0x53}, ed25519.PublicKeySize),
		},
	}

	closed := base
	closed.WelcomeEnabled = true
	_, err = NewStore(&sql.DB{}, closed)
	require.ErrorIs(t, err, ErrStoreUnavailable)

	store, err := NewStore(&sql.DB{}, base)
	require.NoError(t, err)
	require.False(t, store.welcomeEnabled)
}

func TestDevWireEnvironmentPreservesLegacyLookupAndDeletionNamespace(
	t *testing.T,
) {
	keyring, err := NewKeyring(1, map[uint32][]byte{
		1: bytes.Repeat([]byte{0x31}, 32),
	})
	require.NoError(t, err)
	lookup, err := NewLookupKey(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	store, err := NewStore(&sql.DB{}, StoreOptions{
		Environment: authority.EnvironmentDev,
		Encryption:  keyring,
		Lookup:      lookup,
		AuthorityKeys: map[string]ed25519.PublicKey{
			"key-1": bytes.Repeat([]byte{0x53}, ed25519.PublicKeySize),
		},
	})
	require.NoError(t, err)
	require.Equal(t, authority.EnvironmentDev, store.environment)
	require.Equal(t, "development", store.lookupEnvironment)

	const installationID = "" +
		"1123456789abcdef0123456789abcdef" +
		"0123456789abcdef0123456789abcdef"
	const lookupEpoch = uint64(688)
	value := []byte(installationID)
	legacyLookupInput := make(
		[]byte,
		0,
		len("hytch.push.vault.environment.v1\x00")+
			16+len("development")+len(value),
	)
	legacyLookupInput = append(
		legacyLookupInput,
		"hytch.push.vault.environment.v1\x00"...,
	)
	legacyLookupInput = binary.BigEndian.AppendUint64(
		legacyLookupInput,
		uint64(len("development")),
	)
	legacyLookupInput = append(legacyLookupInput, "development"...)
	legacyLookupInput = binary.BigEndian.AppendUint64(
		legacyLookupInput,
		uint64(len(value)),
	)
	legacyLookupInput = append(legacyLookupInput, value...)
	expectedLookup, err := lookup.Digest(
		"installation",
		lookupEpoch,
		legacyLookupInput,
	)
	require.NoError(t, err)
	actualLookup, err := store.environmentLookupDigest(
		"installation",
		lookupEpoch,
		value,
	)
	require.NoError(t, err)
	require.Equal(t, expectedLookup, actualLookup)

	rawTopic := bytes.Repeat([]byte{0x61}, 32)
	expectedRouteIdentity, err := lookup.Digest(
		"route-history",
		0,
		lengthDelimited(
			[]byte("development"),
			[]byte(installationID),
			rawTopic,
		),
	)
	require.NoError(t, err)
	actualRouteIdentity, err := store.routeHistoryIdentity(
		installationID,
		rawTopic,
	)
	require.NoError(t, err)
	require.Equal(t, expectedRouteIdentity, actualRouteIdentity)

	expectedDeletionIdentity, err := lookup.Digest(
		"installation-deletion",
		0,
		lengthDelimited(
			[]byte("development"),
			[]byte(installationID),
		),
	)
	require.NoError(t, err)
	actualDeletionIdentity, err := store.installationDeletionIdentity(
		installationID,
	)
	require.NoError(t, err)
	require.Equal(t, expectedDeletionIdentity, actualDeletionIdentity)
}
