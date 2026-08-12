package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a3trust"
	"github.com/xmtp/example-notification-server-go/pkg/api"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
	identityv1 "github.com/xmtp/xmtpd/pkg/proto/identity/api/v1"
	associations "github.com/xmtp/xmtpd/pkg/proto/identity/associations"
	validationv1 "github.com/xmtp/xmtpd/pkg/proto/mls_validation/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

const a3RuntimeQAEnvironment = "A3_RUNTIME_QA"

// TestActivatedA3ServerAssemblyRuntimeQA crosses the production A3
// initializer, both public ApiServer mounts, the incremental validation seam,
// and the durable PostgreSQL witness store. Its only peers and key material
// are synthetic in-process fixtures; it creates no external network client.
func TestActivatedA3ServerAssemblyRuntimeQA(t *testing.T) {
	if os.Getenv(a3RuntimeQAEnvironment) != "1" {
		t.Skip("activated A3 runtime QA is opt-in")
	}
	ownerDB := testdb.CreateTestDb(t)
	var now time.Time
	require.NoError(t, ownerDB.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.clock_timestamp()`,
	).Scan(&now))
	now = now.UTC()
	db := restrictA3RuntimeQADB(t, ownerDB)

	inboxID := strings.Repeat("a", 64)
	installation := bytes.Repeat([]byte{0x71}, 32)
	installationID := hex.EncodeToString(installation)
	update := &associations.IdentityUpdate{InboxId: inboxID}
	memberID := &associations.MemberIdentifier{
		Kind: &associations.MemberIdentifier_InstallationPublicKey{
			InstallationPublicKey: append([]byte(nil), installation...),
		},
	}
	state := &associations.AssociationState{
		InboxId: inboxID,
		Members: []*associations.MemberMap{{
			Key: memberID,
			Value: &associations.Member{
				Identifier: &associations.MemberIdentifier{
					Kind: &associations.MemberIdentifier_InstallationPublicKey{
						InstallationPublicKey: append([]byte(nil), installation...),
					},
				},
			},
		}},
	}
	identityClient := &a3RuntimeQAIdentityClient{
		inboxID: inboxID,
		update: &identityv1.GetIdentityUpdatesResponse_IdentityUpdateLog{
			SequenceId: 7, ServerTimestampNs: uint64(now.UnixNano()), Update: update,
		},
	}
	validationClient := &a3RuntimeQAValidationClient{state: state}

	witnessSeed := bytes.Repeat([]byte{0x72}, ed25519.SeedSize)
	seedPath := filepath.Join(a3RealTempDir(t), "a3-witness-seed")
	require.NoError(t, os.WriteFile(seedPath, witnessSeed, 0o400))
	sequencerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, ed25519.SeedSize))
	sequencerPublic := sequencerPrivate.Public().(ed25519.PublicKey)
	sequencerKeyID := a3trust.WitnessKeyID(sequencerPublic)
	sequencerJSON, err := json.Marshal(map[string]string{
		sequencerKeyID: base64.StdEncoding.EncodeToString(sequencerPublic),
	})
	require.NoError(t, err)
	config := a3RuntimeQAOptions(
		seedPath,
		string(sequencerJSON),
	)
	require.True(t, a3RuntimeConfigurationValid(config))
	dependencies := a3RuntimeDependencies{
		identityClient: identityClient, validationClient: validationClient,
		clock: func() time.Time { return now },
	}
	runtime, err := initializeA3RuntimeWithDependencies(
		t.Context(),
		config.A3,
		"dev",
		db,
		dependencies,
	)
	require.NoError(t, err)
	require.NotNil(t, runtime.association)
	require.NotNil(t, runtime.witness)

	baseURL, stop := startA3RuntimeQAServer(t, runtime)
	associationBody, err := json.Marshal(map[string]string{
		"environment": "dev", "inbox_id": inboxID,
		"installation_id": installationID,
	})
	require.NoError(t, err)
	status, responseBody := sendA3RuntimeQARequest(
		t,
		baseURL+a3trust.AssociationPath,
		config.A3.AssociationBearerToken,
		associationBody,
	)
	require.Equal(t, http.StatusOK, status)
	var observation struct {
		InstallationID string `json:"installation_id"`
		Associated     bool   `json:"associated"`
		Fresh          bool   `json:"fresh"`
		Position       string `json:"position"`
	}
	require.NoError(t, json.Unmarshal(responseBody, &observation))
	require.Equal(t, installationID, observation.InstallationID)
	require.True(t, observation.Associated)
	require.True(t, observation.Fresh)
	require.Equal(t, "7", observation.Position)

	witnessBody := a3RuntimeQAWitnessBody(t, now, sequencerPrivate)
	status, firstReceipt := sendA3RuntimeQARequest(
		t,
		baseURL+a3trust.WitnessPath,
		config.A3.WitnessBearerToken,
		witnessBody,
	)
	require.Equal(t, http.StatusOK, status)
	stop()
	require.NoError(t, runtime.Close())

	rebuilt, err := initializeA3RuntimeWithDependencies(
		t.Context(),
		config.A3,
		"dev",
		db,
		dependencies,
	)
	require.NoError(t, err)
	secondURL, stopSecond := startA3RuntimeQAServer(t, rebuilt)
	status, replayedReceipt := sendA3RuntimeQARequest(
		t,
		secondURL+a3trust.WitnessPath,
		config.A3.WitnessBearerToken,
		witnessBody,
	)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, firstReceipt, replayedReceipt)
	stopSecond()
	require.NoError(t, rebuilt.Close())
	var witnessRows int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.count(*)
		   FROM hytch_push_vault.a3_directory_witness_heads
		  WHERE environment = 1`,
	).Scan(&witnessRows))
	require.Equal(t, 1, witnessRows)
}

func restrictA3RuntimeQADB(t *testing.T, ownerDB *sql.DB) *sql.DB {
	t.Helper()
	role := fmt.Sprintf("a3_runtime_qa_%d", time.Now().UnixNano())
	quotedRole := `"` + role + `"`
	_, err := ownerDB.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`CREATE ROLE %s LOGIN PASSWORD 'a3-runtime-qa-password'`,
			quotedRole,
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = ownerDB.ExecContext(
			context.Background(),
			fmt.Sprintf(
				`DROP OWNED BY %[1]s; DROP ROLE IF EXISTS %[1]s`,
				quotedRole,
			),
		)
	})
	_, err = ownerDB.ExecContext(
		t.Context(),
		fmt.Sprintf(
			`REVOKE CREATE ON SCHEMA public FROM PUBLIC;
			 GRANT USAGE ON SCHEMA hytch_push_vault TO %[1]s;
		 GRANT SELECT, INSERT ON TABLE
		     hytch_push_vault.a3_directory_witness_heads
		 TO %[1]s;
			 GRANT SELECT ON TABLE public.schema_migrations
			 TO %[1]s`,
			quotedRole,
		),
	)
	require.NoError(t, err)
	var databaseName string
	require.NoError(t, ownerDB.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.current_database()`,
	).Scan(&databaseName))
	dsn, err := url.Parse(testdb.TEST_DSN)
	require.NoError(t, err)
	dsn.User = url.UserPassword(role, "a3-runtime-qa-password")
	dsn.Path = "/" + databaseName
	runtimeDB, err := database.CreateDB(dsn.String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = runtimeDB.Close() })
	return runtimeDB
}

type a3RuntimeQAIdentityClient struct {
	mu      sync.Mutex
	inboxID string
	update  *identityv1.GetIdentityUpdatesResponse_IdentityUpdateLog
}

func (client *a3RuntimeQAIdentityClient) GetIdentityUpdates(
	_ context.Context,
	request *identityv1.GetIdentityUpdatesRequest,
	_ ...grpc.CallOption,
) (*identityv1.GetIdentityUpdatesResponse, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	updates := []*identityv1.GetIdentityUpdatesResponse_IdentityUpdateLog{}
	if request.Requests[0].SequenceId == 0 {
		updates = append(updates, client.update)
	} else {
		return &identityv1.GetIdentityUpdatesResponse{}, nil
	}
	return &identityv1.GetIdentityUpdatesResponse{
		Responses: []*identityv1.GetIdentityUpdatesResponse_Response{{
			InboxId: client.inboxID, Updates: updates,
		}},
	}, nil
}

type a3RuntimeQAValidationClient struct {
	state *associations.AssociationState
}

func (client *a3RuntimeQAValidationClient) GetAssociationState(
	_ context.Context,
	_ *validationv1.GetAssociationStateRequest,
	_ ...grpc.CallOption,
) (*validationv1.GetAssociationStateResponse, error) {
	return &validationv1.GetAssociationStateResponse{
		AssociationState: client.state,
		StateDiff: &associations.AssociationStateDiff{
			NewMembers: []*associations.MemberIdentifier{
				client.state.Members[0].Key,
			},
		},
	}, nil
}

func a3RuntimeQAOptions(seedPath, sequencerKeys string) options.Options {
	return options.Options{
		Api:   options.ApiOptions{Enabled: true},
		Vault: options.VaultOptions{Environment: "dev"},
		A3: options.A3Options{
			AssociationEnabled:               true,
			AssociationBearerToken:           testA3OpaqueBearer(0x31),
			IdentityGRPCAddress:              "grpc.dev.xmtp.network:443",
			ValidationGRPCAddress:            "validation.invalid:443",
			AssociationRequestTimeoutSeconds: 10,
			AssociationMaximumClockSkewSec:   30, AssociationMaxPages: 4,
			AssociationMaxPageUpdates: 16, AssociationMaxUpdates: 16,
			AssociationMaxUpdateBytes:     64 * 1024,
			AssociationMaxHistoryBytes:    2 * 1024 * 1024,
			AssociationMaxValidationBytes: 16 * 1024 * 1024,
			AssociationMaxConcurrency:     2, AssociationRatePerSecond: 20,
			AssociationRateBurst: 20,
			WitnessEnabled:       true, WitnessBearerToken: testA3OpaqueBearer(0x41),
			WitnessSeedFilePath:            seedPath,
			WitnessSequencerPublicKeysJSON: sequencerKeys,
			WitnessRequestTimeoutSeconds:   10, WitnessMaximumAgeSeconds: 300,
			WitnessMaximumClockSkewSec: 30, WitnessMaxConcurrency: 2,
			WitnessRatePerSecond: 20, WitnessRateBurst: 20,
		},
	}
}

func startA3RuntimeQAServer(
	t *testing.T,
	runtime *a3Runtime,
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
	require.NoError(t, server.EnableA3TrustSurfaces(
		runtime.association,
		runtime.witness,
	))
	require.NoError(t, server.SetListener(listener))
	require.NoError(t, server.Start())
	var once sync.Once
	stop := func() { once.Do(server.Stop) }
	t.Cleanup(stop)
	return "http://" + listener.Addr().String(), stop
}

func sendA3RuntimeQARequest(
	t *testing.T,
	url string,
	token string,
	body []byte,
) (int, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(
		t.Context(), http.MethodPost, url, bytes.NewReader(body),
	)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	require.NoError(t, err)
	require.LessOrEqual(t, len(responseBody), 16*1024)
	return response.StatusCode, responseBody
}

func a3RuntimeQAWitnessBody(
	t *testing.T,
	now time.Time,
	sequencerPrivate ed25519.PrivateKey,
) []byte {
	t.Helper()
	emptyRoot := sha256.Sum256(nil)
	head := a3trust.TreeHead{
		Domain: "hytch.directory.tree-head/v1", Environment: "dev",
		PriorRootHash: hex.EncodeToString(emptyRoot[:]), PriorTreeSize: 0,
		Protocol: 1, RootHash: strings.Repeat("0", 63) + "1",
		TimestampMS: uint64(now.UnixMilli()), TreeSize: 1,
	}
	canonical, err := a3trust.CanonicalTreeHead(head)
	require.NoError(t, err)
	sequencerPublic := sequencerPrivate.Public().(ed25519.PublicKey)
	body, err := json.Marshal(map[string]any{
		"head":                     head,
		"signature_payload_base64": base64.StdEncoding.EncodeToString(canonical),
		"sequencer_key_id":         a3trust.WitnessKeyID(sequencerPublic),
		"sequencer_signature_base64": base64.StdEncoding.EncodeToString(
			ed25519.Sign(sequencerPrivate, canonical),
		),
		"consistency_proof": []string{},
	})
	require.NoError(t, err)
	return body
}
