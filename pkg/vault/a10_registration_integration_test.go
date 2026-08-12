package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a10registration"
	"github.com/xmtp/example-notification-server-go/pkg/a9api"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

type a10TestRoundTripFunc func(*http.Request) (*http.Response, error)

func (function a10TestRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

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
		PayloadSchema:         "xmtp.encrypted.v4",
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

func TestA10HandlerPersistsVerifiedRegistrationAndReplayDurably(t *testing.T) {
	fixture := newA9RuntimeFixture(t)
	fixture.store.a9Enabled = true
	var installationBindingID, epoch, subscriptionBindingID [16]byte
	copy(installationBindingID[:], bytes.Repeat([]byte{0xd1}, 16))
	copy(epoch[:], bytes.Repeat([]byte{0xd2}, 16))
	copy(subscriptionBindingID[:], bytes.Repeat([]byte{0xd3}, 16))
	control := fixture.control(
		0xe1,
		installationBindingID,
		epoch,
		1,
		subscriptionBindingID,
		1,
		a9trust.ControlActionUpsert,
	)
	_, err := fixture.store.ApplyControl(t.Context(), control)
	require.NoError(t, err)
	_, err = fixture.store.ApplyWatermark(
		t.Context(),
		fixture.watermark(
			0xe2,
			installationBindingID,
			epoch,
			1,
			1,
			a9trust.WatermarkStatusCurrent,
		),
	)
	require.NoError(t, err)

	topic := topicpkg.NewTopic(
		topicpkg.TopicKindGroupMessagesV1,
		bytes.Repeat([]byte{0x41}, 32),
	)
	policy := fixture.signed.policy(
		t,
		1,
		authority.PolicyStateActive,
		authority.AgePolicyAdult,
		fixture.signed.incarnationID,
	)
	subscription := fixture.signed.subscription(
		t,
		topic,
		0x42,
		1,
		688,
		authority.PushModeAlertAllowed,
		1,
	)
	replace := fixture.replaceRequest(
		t,
		0xe3,
		installationBindingID,
		epoch,
		subscriptionBindingID,
		control.AssertionHash,
		control.Assertion.TopicBinding,
		0,
		topic,
		policy,
		subscription,
	)
	result, err := fixture.store.Replace(
		t.Context(),
		replace,
		a9api.KeysetReceipt{Sequence: 1, Hash: fixture.keysetHash},
	)
	require.NoError(t, err)
	require.Equal(t, a9api.ResultOutcomeApplied, result.Outcome)

	installationID, err := hex.DecodeString(fixture.signed.installationID)
	require.NoError(t, err)
	ownerBinding := bytes.Repeat([]byte{0xe4}, 32)
	apnsToken := bytes.Repeat([]byte{0xe5}, 32)
	body, credential, keyset, rootPin := a10RequestMaterial(
		t,
		fixture.now,
		installationID,
		installationBindingID[:],
		ownerBinding,
		apnsToken,
	)

	newHandler := func(t *testing.T) *a10registration.Handler {
		t.Helper()
		origin, managerErr := a10registration.ParseKeysetOrigin(
			"https://modern-api.internal",
		)
		require.NoError(t, managerErr)
		manager, managerErr := a10registration.NewKeysetManager(
			a10registration.KeysetManagerOptions{
				Environment: "dev",
				Origin:      origin,
				RootPin:     rootPin,
				Store:       database.NewA10KeysetStore(fixture.db),
				HTTPClient: &http.Client{Transport: a10TestRoundTripFunc(
					func(request *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Header: http.Header{
								"Content-Type": {"application/json"},
							},
							Body:    io.NopCloser(bytes.NewReader(keyset)),
							Request: request,
						}, nil
					},
				)},
				RequestTimeout: time.Second,
				Clock:          func() time.Time { return fixture.now },
			},
		)
		require.NoError(t, managerErr)
		require.NoError(t, manager.Refresh(t.Context()))
		sink, sinkErr := NewA10RegistrationSink(
			fixture.store,
			"com.mobileflow.hytchdev",
		)
		require.NoError(t, sinkErr)
		handler, handlerErr := a10registration.NewHandler(
			a10registration.Options{
				Enabled:      true,
				Environment:  "dev",
				AllowedTopic: "com.mobileflow.hytchdev",
				RootPin:      rootPin,
				Keysets:      manager,
				Replay:       database.NewA10ReplayStore(fixture.db),
				Sink:         sink,
				Clock:        func() time.Time { return fixture.now },
			},
		)
		require.NoError(t, handlerErr)
		return handler
	}
	serve := func(handler http.Handler) *httptest.ResponseRecorder {
		request := httptest.NewRequest(
			http.MethodPut,
			a10registration.Path,
			bytes.NewReader(body),
		)
		request.Header.Set("Authorization", "Bearer "+credential)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	first := serve(newHandler(t))
	require.Equal(t, http.StatusNoContent, first.Code)
	require.Empty(t, first.Body.String())

	identity, err := fixture.store.installationDeletionIdentity(
		fixture.signed.installationID,
	)
	require.NoError(t, err)
	var lookup, ciphertext, persistedOwner []byte
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT installation.installation_lookup,
		        installation.encrypted_apns_token,
		        binding.owner_binding
		   FROM hytch_push_vault.installation_states AS installation
		   JOIN hytch_push_vault.a10_registration_bindings AS binding
		     ON binding.environment = installation.environment
		    AND binding.installation_identity = installation.installation_identity
		  WHERE installation.environment = 1
		    AND installation.installation_identity = $1`,
		identity,
	).Scan(&lookup, &ciphertext, &persistedOwner))
	require.Equal(t, ownerBinding, persistedOwner)
	opened, err := fixture.store.encryption.Open(
		installationContext(lookup, "apns-token"),
		ciphertext,
	)
	require.NoError(t, err)
	require.Equal(t, apnsToken, opened)
	zero(opened)

	var replayCount int
	require.NoError(t, fixture.db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.a10_registration_replays
		  WHERE environment = 1
		    AND jti = 'a10a10a1-0812-4a10-8a10-a10a10a10a10'`,
	).Scan(&replayCount))
	require.Equal(t, 1, replayCount)

	second := serve(newHandler(t))
	require.Equal(t, http.StatusConflict, second.Code)
	require.Equal(t, "replay", second.Body.String())
}

func a10RequestMaterial(
	t *testing.T,
	now time.Time,
	installationID []byte,
	installationBindingID []byte,
	ownerBinding []byte,
	apnsToken []byte,
) ([]byte, string, []byte, a9trust.RootPin) {
	t.Helper()
	rootSeed := sha256.Sum256([]byte("a10-vault-integration-root"))
	onlineSeed := sha256.Sum256([]byte("a10-vault-integration-online"))
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed[:])
	onlinePrivate := ed25519.NewKeyFromSeed(onlineSeed[:])
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	onlinePublic := onlinePrivate.Public().(ed25519.PublicKey)
	rootID, err := a9trust.Ed25519KeyID(rootPublic)
	require.NoError(t, err)
	onlineID, err := a9trust.Ed25519KeyID(onlinePublic)
	require.NoError(t, err)
	var rootPin a9trust.RootPin
	rootPin.KeyID = rootID
	copy(rootPin.PublicKey[:], rootPublic)

	requestObject := map[string]any{
		"apns_token_base64url":      base64.RawURLEncoding.EncodeToString(apnsToken),
		"apns_topic":                "com.mobileflow.hytchdev",
		"environment":               "dev",
		"installation_binding_id":   base64.RawURLEncoding.EncodeToString(installationBindingID),
		"installation_id_base64url": base64.RawURLEncoding.EncodeToString(installationID),
		"owner_binding":             base64.RawURLEncoding.EncodeToString(ownerBinding),
		"payload_schema":            "xmtp.encrypted.v4",
		"protocol":                  "hytch.xmtp-push.registration-request",
		"schema_version":            1,
	}
	body := canonicalA10TestObject(t, requestObject)
	tokenHash := sha256.Sum256(apnsToken)
	bodyHash := sha256.Sum256(body)
	issuedAt := now.UTC().Truncate(time.Second)
	claims := map[string]any{
		"apns_token_sha256":         hex.EncodeToString(tokenHash[:]),
		"apns_topic":                requestObject["apns_topic"],
		"aud":                       a10registration.Audience,
		"environment":               "dev",
		"exp":                       issuedAt.Add(60 * time.Second).Unix(),
		"iat":                       issuedAt.Unix(),
		"installation_binding_id":   requestObject["installation_binding_id"],
		"installation_id_base64url": requestObject["installation_id_base64url"],
		"iss":                       "hytch-modern-api",
		"jti":                       "a10a10a1-0812-4a10-8a10-a10a10a10a10",
		"method":                    http.MethodPut,
		"nbf":                       issuedAt.Add(-time.Second).Unix(),
		"owner_binding":             requestObject["owner_binding"],
		"path":                      a10registration.Path,
		"request_sha256":            hex.EncodeToString(bodyHash[:]),
		"sub":                       "xmtp-push-registration",
	}
	header := map[string]any{"alg": "EdDSA", "kid": onlineID, "typ": "JWT"}
	credentialInput := base64.RawURLEncoding.EncodeToString(
		canonicalA10TestObject(t, header),
	) + "." + base64.RawURLEncoding.EncodeToString(
		canonicalA10TestObject(t, claims),
	)
	credential := credentialInput + "." + base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(onlinePrivate, []byte(credentialInput)),
	)

	keysetIssuedAt := issuedAt.Add(-time.Minute)
	keysetExpiresAt := issuedAt.Add(time.Hour)
	keyset := map[string]any{
		"environment":     "dev",
		"expires_at":      a10TestWireTime(keysetExpiresAt),
		"issued_at":       a10TestWireTime(keysetIssuedAt),
		"keyset_sequence": 1,
		"keys": []any{map[string]any{
			"key_id":               onlineID,
			"not_after":            a10TestWireTime(issuedAt.Add(2 * time.Hour)),
			"not_before":           a10TestWireTime(issuedAt.Add(-2 * time.Hour)),
			"public_key_base64url": base64.RawURLEncoding.EncodeToString(onlinePublic),
			"state":                "SIGN",
			"use":                  a10registration.KeyUse,
		}},
		"protocol":                 "hytch.xmtp-push.registration-keyset",
		"root_signature_algorithm": "Ed25519",
		"root_signing_key_id":      rootID,
		"schema_version":           1,
	}
	unsigned := canonicalA10TestObject(t, keyset)
	keyset["root_signature_base64url"] = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(
			rootPrivate,
			append([]byte("Hytch A10 registration keyset v1\x00"), unsigned...),
		),
	)
	return body, credential, canonicalA10TestObject(t, keyset), rootPin
}

func canonicalA10TestObject(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	parsed, err := a9trust.ParseStrictJSON(encoded)
	require.NoError(t, err)
	canonical, err := a9trust.Canonicalize(parsed)
	require.NoError(t, err)
	return canonical
}

func a10TestWireTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05.000Z")
}
