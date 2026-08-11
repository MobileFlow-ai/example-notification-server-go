package vault

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a10registration"
	"github.com/xmtp/example-notification-server-go/pkg/a9api"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

func TestA10RegistrationSinkRotatesOnlyA9BoundActiveInstallation(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	fixture.store.a9Enabled = true
	var installation, epoch, binding [16]byte
	copy(installation[:], bytes.Repeat([]byte{0xa1}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xa2}, 16))
	copy(binding[:], bytes.Repeat([]byte{0xa3}, 16))
	control := fixture.control(0xc1, installation, epoch, 1, binding, 1, a9trust.ControlActionUpsert)
	_, err := fixture.store.ApplyControl(t.Context(), control)
	require.NoError(t, err)
	_, err = fixture.store.ApplyWatermark(t.Context(), fixture.watermark(0xc2, installation, epoch, 1, 1, a9trust.WatermarkStatusCurrent))
	require.NoError(t, err)

	topic := topicpkg.NewTopic(topicpkg.TopicKindGroupMessagesV1, bytes.Repeat([]byte{0x31}, 32))
	policy := fixture.signed.policy(t, 1, authority.PolicyStateActive, authority.AgePolicyAdult, fixture.signed.incarnationID)
	subscription := fixture.signed.subscription(t, topic, 0x32, 1, 688, authority.PushModeAlertAllowed, 1)
	request := fixture.replaceRequest(t, 0xc3, installation, epoch, binding, control.AssertionHash, control.Assertion.TopicBinding, 0, topic, policy, subscription)
	result, err := fixture.store.Replace(t.Context(), request, a9api.KeysetReceipt{Sequence: 1, Hash: fixture.keysetHash})
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeApplied, result.Outcome)

	sink, err := NewA10RegistrationSink(fixture.store, "com.mobileflow.hytchdev")
	require.NoError(t, err)
	decodedInstallation, err := hex.DecodeString(fixture.signed.installationID)
	require.NoError(t, err)
	registration := a10registration.VerifiedRegistration{
		Environment:           "dev",
		InstallationBindingID: installation,
		APNSTopic:             "com.mobileflow.hytchdev",
		PayloadSchema:         "hytch_push_wrapper_v1",
	}
	copy(registration.InstallationID[:], decodedInstallation)
	copy(registration.OwnerBinding[:], bytes.Repeat([]byte{0xb1}, 32))
	newToken := bytes.Repeat([]byte{0xb2}, 32)
	require.NoError(t, sink.registerVerified(t.Context(), registration, newToken))

	identity, err := fixture.store.installationDeletionIdentity(fixture.signed.installationID)
	require.NoError(t, err)
	var lookup, ciphertext []byte
	require.NoError(t, fixture.db.QueryRowContext(t.Context(), `SELECT installation_lookup, encrypted_apns_token FROM hytch_push_vault.installation_states WHERE environment = 1 AND installation_identity = $1`, identity).Scan(&lookup, &ciphertext))
	opened, err := fixture.store.encryption.Open(installationContext(lookup, "apns-token"), ciphertext)
	require.NoError(t, err)
	require.Equal(t, newToken, opened)
	zero(opened)

	conflictingOwner := registration
	copy(conflictingOwner.OwnerBinding[:], bytes.Repeat([]byte{0xb3}, 32))
	require.ErrorIs(t, sink.registerVerified(t.Context(), conflictingOwner, bytes.Repeat([]byte{0xb4}, 32)), ErrStoreUnavailable)

	_, err = fixture.store.ApplyControl(t.Context(), fixture.control(0xc4, installation, epoch, 2, binding, 2, a9trust.ControlActionRevoke))
	require.NoError(t, err)
	require.ErrorIs(t, sink.registerVerified(t.Context(), registration, bytes.Repeat([]byte{0xb5}, 32)), ErrStoreUnavailable)
}
