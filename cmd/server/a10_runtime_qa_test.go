package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a10registration"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	"github.com/xmtp/example-notification-server-go/pkg/api"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"go.uber.org/zap"
)

const a10RuntimeQAEnvironment = "A10_RUNTIME_QA"

type a10RuntimeQAMaterial struct {
	body                  []byte
	credential            string
	keyset                []byte
	rootPin               a9trust.RootPin
	installationID        []byte
	installationBindingID []byte
	ownerBinding          []byte
	apnsToken             []byte
}

// TestActivatedA10ServerAssemblyRuntimeQA is an explicit opt-in probe used by
// runtime-qa/run.sh. It crosses the production A10 initializer, durable keyset
// and replay stores, encrypted vault sink, and public API mount while keeping
// APNS and XMTP unconstructed. Every network peer is loopback-only and all key
// material is deterministic, synthetic test data.
func TestActivatedA10ServerAssemblyRuntimeQA(t *testing.T) {
	if os.Getenv(a10RuntimeQAEnvironment) != "1" {
		t.Skip("activated A10 runtime QA is opt-in")
	}

	db := testdb.CreateTestDb(t)
	var now time.Time
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.clock_timestamp()`,
	).Scan(&now))
	now = now.UTC()

	material := newA10RuntimeQAMaterial(t, now)
	keyring, err := vault.NewKeyring(
		1,
		map[uint32][]byte{1: bytes.Repeat([]byte{0x31}, 32)},
	)
	require.NoError(t, err)
	lookup, err := vault.NewLookupKey(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	store, err := vault.NewStore(db, vault.StoreOptions{
		Environment: "dev",
		LeaseTTL:    7 * 24 * time.Hour,
		Encryption:  keyring,
		Lookup:      lookup,
		AuthorityKeys: map[string]ed25519.PublicKey{
			"runtime-qa": append(ed25519.PublicKey(nil), material.rootPin.PublicKey[:]...),
		},
		A9Enabled: true,
		A9Trust:   &vault.A9TrustHandle{},
		Now:       func() time.Time { return now },
	})
	require.NoError(t, err)
	sweeper, err := vault.NewRetentionSweeper(db, vault.RetentionOptions{
		SweepInterval:        15 * time.Minute,
		Environment:          "dev",
		Lookup:               lookup,
		EncryptionKeyVersion: keyring.ActiveVersion(),
		Now:                  func() time.Time { return now },
	})
	require.NoError(t, err)
	_, err = sweeper.Sweep(t.Context())
	require.NoError(t, err)
	seedA10RuntimeQATarget(t, db, lookup, now, material)

	var keysetRequests atomic.Int32
	keysetServer := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodGet ||
			request.URL.Path != a10registration.KeysetWellKnownPath ||
			request.URL.RawQuery != "" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		keysetRequests.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(material.keyset)
	}))
	t.Cleanup(keysetServer.Close)

	config := validA10RuntimeOptions(t)
	config.A10.KeysetOrigin = keysetServer.URL
	config.A10.PinnedRootPublicKeyBase64URL = base64.RawURLEncoding.
		EncodeToString(material.rootPin.PublicKey[:])
	config.A10.PinnedRootKeyID = material.rootPin.KeyID
	config.Apns.P8CertificateBase64 = base64.StdEncoding.
		EncodeToString([]byte("runtime-qa-local-only"))
	require.True(t, a9RuntimeConfigurationValid(config))
	require.True(t, a10RuntimeConfigurationValid(config))
	require.True(t, apnsRuntimeConfigurationValid(config))

	dependencies := a10RuntimeDependencies{
		httpClient: keysetServer.Client(),
		clock:      func() time.Time { return now },
	}
	runtime := initializeA10RuntimeForQA(
		t,
		config,
		db,
		store,
		dependencies,
	)
	require.True(t, a10TrustReady(runtime.manager))

	firstURL, stopFirst := startA10RuntimeQAServer(t, runtime)
	status, body := sendA10RuntimeQARequest(
		t,
		firstURL,
		material.body,
		material.credential,
	)
	require.Equal(t, http.StatusNoContent, status)
	require.Empty(t, body)
	stopFirst()

	var ciphertext, persistedOwner []byte
	require.NoError(t, db.QueryRowContext(t.Context(), `
		SELECT installation.encrypted_apns_token, binding.owner_binding
		  FROM hytch_push_vault.installation_states AS installation
		  JOIN hytch_push_vault.a10_registration_bindings AS binding
		    ON binding.environment = installation.environment
		   AND binding.installation_identity = installation.installation_identity
		 WHERE binding.environment = 1
		   AND binding.installation_binding_id = $1`,
		material.installationBindingID,
	).Scan(&ciphertext, &persistedOwner))
	require.NotEmpty(t, ciphertext)
	require.False(t, bytes.Equal(ciphertext, material.apnsToken))
	require.True(t, bytes.Equal(persistedOwner, material.ownerBinding))
	var replayCount int
	require.NoError(t, db.QueryRowContext(t.Context(), `
		SELECT pg_catalog.count(*)
		  FROM hytch_push_vault.a10_registration_replays
		 WHERE environment = 1`,
	).Scan(&replayCount))
	require.Equal(t, 1, replayCount)

	rebuilt := initializeA10RuntimeForQA(
		t,
		config,
		db,
		store,
		dependencies,
	)
	secondURL, stopSecond := startA10RuntimeQAServer(t, rebuilt)
	status, body = sendA10RuntimeQARequest(
		t,
		secondURL,
		material.body,
		material.credential,
	)
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "replay", body)
	stopSecond()
	require.Equal(t, int32(2), keysetRequests.Load())
}

func initializeA10RuntimeForQA(
	t *testing.T,
	config options.Options,
	db *sql.DB,
	store *vault.Store,
	dependencies a10RuntimeDependencies,
) *a10Runtime {
	t.Helper()
	runtime, err := initializeA10RuntimeWithDependencies(
		t.Context(),
		config.A10,
		config.Vault.Environment,
		config.Apns.Topic,
		db,
		store,
		dependencies,
	)
	require.NoError(t, err)
	require.NotNil(t, runtime)
	require.NotNil(t, runtime.manager)
	require.NotNil(t, runtime.handler)
	return runtime
}

func startA10RuntimeQAServer(
	t *testing.T,
	runtime *a10Runtime,
) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := api.NewApiServer(
		zap.NewNop(),
		options.ApiOptions{},
		nil,
		nil,
		interfaces.ListenerTypeV4,
	)
	require.NoError(t, configureRuntimeRegistrationAPI(
		server,
		true,
		nil,
		runtime,
	))
	server.SetReadyCheck(func() bool {
		return a10TrustReady(runtime.manager)
	})
	require.NoError(t, server.SetListener(listener))
	require.NoError(t, server.Start())
	var once sync.Once
	stop := func() {
		once.Do(server.Stop)
	}
	t.Cleanup(stop)
	return "http://" + listener.Addr().String(), stop
}

func sendA10RuntimeQARequest(
	t *testing.T,
	baseURL string,
	body []byte,
	credential string,
) (int, string) {
	t.Helper()
	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPut,
		baseURL+a10registration.Path,
		bytes.NewReader(body),
	)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+credential)
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 64))
	require.NoError(t, err)
	return response.StatusCode, string(responseBody)
}

func seedA10RuntimeQATarget(
	t *testing.T,
	db *sql.DB,
	lookup *vault.LookupKey,
	now time.Time,
	material a10RuntimeQAMaterial,
) {
	t.Helper()
	identityInput := a10RuntimeQALengthDelimited(
		[]byte("development"),
		[]byte(hex.EncodeToString(material.installationID)),
	)
	identity, err := lookup.Digest("installation-deletion", 0, identityInput)
	require.NoError(t, err)
	require.Len(t, identity, sha256.Size)

	keysetHash := bytes.Repeat([]byte{0x51}, 32)
	rootKeyID := bytes.Repeat([]byte{0x52}, 32)
	signingKeyID := bytes.Repeat([]byte{0x53}, 32)
	sequencerEpoch := bytes.Repeat([]byte{0x54}, 16)
	watermarkHash := bytes.Repeat([]byte{0x55}, 32)
	installationLookup := bytes.Repeat([]byte{0x56}, 32)
	issuedAt := now.Add(-time.Second)
	watermarkExpiresAt := now.Add(20 * time.Second)

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	_, err = tx.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_accepted_keysets
		(environment, keyset_sequence, signed_keyset_hash,
		 signed_keyset_jcs, root_signing_key_id, issued_at,
		 expires_at, accepted_at)
		VALUES (1, 1, $1, $2, $3, $4, $5, $6)`,
		keysetHash,
		[]byte(`{"runtime_qa":true}`),
		rootKeyID,
		issuedAt,
		now.Add(time.Hour),
		now,
	)
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_online_key_descriptors
		(environment, keyset_sequence, key_use, key_state,
		 key_id, public_key, not_before, not_after)
		VALUES (1, 1, 1, 1, $1, $2, $3, $4)`,
		signingKeyID,
		bytes.Repeat([]byte{0x57}, 32),
		issuedAt,
		now.Add(time.Hour),
	)
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_keyset_state
		(environment, keyset_sequence, signed_keyset_hash, state,
		 uncertainty_reason, expires_at, refreshed_at)
		VALUES (1, 1, $1, 1, 0, $2, $3)`,
		keysetHash,
		now.Add(time.Hour),
		now,
	)
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_watermarks
		(environment, installation_binding_id, sequencer_epoch,
		 watermark_sequence, signed_watermark_hash,
		 committed_through_stream_sequence, status,
		 uncertainty_reason, issued_at, expires_at, signing_key_id,
		 keyset_sequence, keyset_hash, accepted_at)
		VALUES (1, $1, $2, 1, $3, 1, 1, 0, $4, $5, $6, 1, $7, $8)`,
		material.installationBindingID,
		sequencerEpoch,
		watermarkHash,
		issuedAt,
		watermarkExpiresAt,
		signingKeyID,
		keysetHash,
		now,
	)
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_installation_authority
		(environment, installation_binding_id, sequencer_epoch,
		 contiguous_stream_sequence, subscription_generation, state,
		 uncertainty_reason, watermark_sequence, watermark_signed_hash,
		 watermark_committed_through, watermark_status,
		 watermark_uncertainty_reason, watermark_issued_at,
		 watermark_expires_at, watermark_signing_key_id,
		 watermark_keyset_sequence, watermark_keyset_hash,
		 created_at, updated_at)
		VALUES (1, $1, $2, 1, 1, 1, 0, 1, $3, 1, 1, 0, $4, $5,
		        $6, 1, $7, $8, $8)`,
		material.installationBindingID,
		sequencerEpoch,
		watermarkHash,
		issuedAt,
		watermarkExpiresAt,
		signingKeyID,
		keysetHash,
		now,
	)
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.installation_states
		(installation_lookup, installation_identity, incarnation_lookup,
		 lookup_key_epoch, generation, idempotency_digest,
		 control_event_digest, encrypted_apns_token, environment,
		 payload_schema, age_policy, policy_epoch, state,
		 encryption_key_version, created_at, refreshed_at, expires_at,
		 control_expires_at)
		VALUES ($1, $2, $3, 1, 1, $4, $5, NULL, 1, 1, 1, 1, 2, 1,
		        $6, $6, $7, $8)`,
		installationLookup,
		identity,
		bytes.Repeat([]byte{0x58}, 32),
		bytes.Repeat([]byte{0x59}, 32),
		bytes.Repeat([]byte{0x5a}, 32),
		now,
		now.Add(time.Hour),
		now.Add(30*time.Second),
	)
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), `
		INSERT INTO hytch_push_vault.a9_installation_gate6_bindings
		(environment, installation_binding_id, installation_identity,
		 created_at)
		VALUES (1, $1, $2, $3)`,
		material.installationBindingID,
		identity,
		now,
	)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
}

func newA10RuntimeQAMaterial(
	t *testing.T,
	now time.Time,
) a10RuntimeQAMaterial {
	t.Helper()
	rootSeed := sha256.Sum256([]byte("a10-runtime-qa-root"))
	onlineSeed := sha256.Sum256([]byte("a10-runtime-qa-online"))
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

	installationID := bytes.Repeat([]byte{0x61}, 32)
	installationBindingID := bytes.Repeat([]byte{0x62}, 16)
	ownerBinding := bytes.Repeat([]byte{0x63}, 32)
	apnsToken := bytes.Repeat([]byte{0x64}, 32)
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
	body := canonicalA10RuntimeQAObject(t, requestObject)
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
		canonicalA10RuntimeQAObject(t, header),
	) + "." + base64.RawURLEncoding.EncodeToString(
		canonicalA10RuntimeQAObject(t, claims),
	)
	credential := credentialInput + "." + base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(onlinePrivate, []byte(credentialInput)),
	)

	keysetIssuedAt := issuedAt.Add(-time.Minute)
	keysetExpiresAt := issuedAt.Add(time.Hour)
	keyset := map[string]any{
		"environment":     "dev",
		"expires_at":      a10RuntimeQAWireTime(keysetExpiresAt),
		"issued_at":       a10RuntimeQAWireTime(keysetIssuedAt),
		"keyset_sequence": 1,
		"keys": []any{map[string]any{
			"key_id":               onlineID,
			"not_after":            a10RuntimeQAWireTime(issuedAt.Add(2 * time.Hour)),
			"not_before":           a10RuntimeQAWireTime(issuedAt.Add(-2 * time.Hour)),
			"public_key_base64url": base64.RawURLEncoding.EncodeToString(onlinePublic),
			"state":                "SIGN",
			"use":                  a10registration.KeyUse,
		}},
		"protocol":                 "hytch.xmtp-push.registration-keyset",
		"root_signature_algorithm": "Ed25519",
		"root_signing_key_id":      rootID,
		"schema_version":           1,
	}
	unsigned := canonicalA10RuntimeQAObject(t, keyset)
	keyset["root_signature_base64url"] = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(
			rootPrivate,
			append(
				[]byte("Hytch A10 registration keyset v1\x00"),
				unsigned...,
			),
		),
	)
	return a10RuntimeQAMaterial{
		body:                  body,
		credential:            credential,
		keyset:                canonicalA10RuntimeQAObject(t, keyset),
		rootPin:               rootPin,
		installationID:        installationID,
		installationBindingID: installationBindingID,
		ownerBinding:          ownerBinding,
		apnsToken:             apnsToken,
	}
}

func canonicalA10RuntimeQAObject(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	parsed, err := a9trust.ParseStrictJSON(encoded)
	require.NoError(t, err)
	canonical, err := a9trust.Canonicalize(parsed)
	require.NoError(t, err)
	return canonical
}

func a10RuntimeQAWireTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).
		Format("2006-01-02T15:04:05.000Z")
}

func a10RuntimeQALengthDelimited(values ...[]byte) []byte {
	var size int
	for _, value := range values {
		size += 8 + len(value)
	}
	out := make([]byte, 0, size)
	for _, value := range values {
		out = binary.BigEndian.AppendUint64(out, uint64(len(value)))
		out = append(out, value...)
	}
	return out
}
