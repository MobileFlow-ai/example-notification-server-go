package incidentaccess

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
)

func TestPrivateHTTPPathEnforcesTwoCredentialsAndRevocation(
	t *testing.T,
) {
	if os.Getenv("VAULT_INTEGRATION_TESTS") != "1" {
		t.Skip("set VAULT_INTEGRATION_TESTS=1")
	}
	db := testdb.CreateTestDb(t)
	now := time.Now().UTC().Truncate(time.Hour).Add(10 * time.Minute)
	var notices []vault.IncidentOversightNotice
	gate, err := vault.NewIncidentAccessGate(
		db,
		vault.IncidentAccessOptions{
			Environment:         "dev",
			RoleTTL:             20 * time.Minute,
			Now:                 func() time.Time { return now },
			AuthorizedApprovers: []string{"security:approver"},
			Broadcast: func(
				_ context.Context,
				notice vault.IncidentOversightNotice,
			) error {
				notices = append(notices, notice)
				return nil
			},
		},
	)
	require.NoError(t, err)
	handler := testHandler(t, gate)

	createResponse := serveAuthorized(
		handler.Mux(),
		CreateRequestPath,
		requesterSecret,
		`{
		  "ticket_reference":"incident:ticket-http",
		  "hypothesis":1,
		  "window_start":"`+
			now.Add(-time.Hour).Format(time.RFC3339)+`",
		  "window_end":"`+now.Format(time.RFC3339)+`"
		}`,
	)
	require.Equal(t, 201, createResponse.Code)
	var created statusResponseJSON
	require.NoError(t, json.Unmarshal(createResponse.Body.Bytes(), &created))
	require.NotEmpty(t, created.RequestIDB64)

	wrongRole := serveAuthorized(
		handler.Mux(),
		ApprovePath,
		requesterSecret,
		`{"request_id_b64":"`+created.RequestIDB64+`"}`,
	)
	require.Equal(t, 401, wrongRole.Code)
	require.Empty(t, notices)

	approveResponse := serveAuthorized(
		handler.Mux(),
		ApprovePath,
		approverSecret,
		`{"request_id_b64":"`+created.RequestIDB64+`"}`,
	)
	require.Equal(t, 200, approveResponse.Code)
	require.Len(t, notices, 1)

	queryBody, err := json.Marshal(queryRequestJSON{
		RequestIDB64: created.RequestIDB64,
		QueryKind:    int16(vault.RawVaultQueryInstallation),
		TargetB64: base64.RawURLEncoding.EncodeToString(
			make([]byte, 32),
		),
	})
	require.NoError(t, err)
	queryResponse := serveAuthorized(
		handler.Mux(),
		QueryPath,
		requesterSecret,
		string(queryBody),
	)
	require.Equal(t, 200, queryResponse.Code)
	require.JSONEq(
		t,
		`{"schema_version":1,"query_kind":1,"found":false}`,
		queryResponse.Body.String(),
	)

	revokeResponse := serveAuthorized(
		handler.Mux(),
		RevokePath,
		approverSecret,
		`{"request_id_b64":"`+created.RequestIDB64+`"}`,
	)
	require.Equal(t, 200, revokeResponse.Code)
	deniedAfterRevoke := serveAuthorized(
		handler.Mux(),
		QueryPath,
		requesterSecret,
		string(queryBody),
	)
	require.Equal(t, 403, deniedAfterRevoke.Code)

	var auditRows int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT pg_catalog.count(*)
		   FROM hytch_push_vault.access_audit
		  WHERE actor IN ('oncall:requester', 'security:approver')`,
	).Scan(&auditRows))
	require.GreaterOrEqual(t, auditRows, 4)
}
