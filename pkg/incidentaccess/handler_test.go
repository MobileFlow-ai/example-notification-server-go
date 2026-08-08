package incidentaccess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
)

type fakeGate struct {
	create func(
		context.Context,
		vault.CreateIncidentAccessRequest,
	) (*vault.IncidentAccessStatus, error)
	approve func(
		context.Context,
		vault.IncidentApproval,
	) (*vault.IncidentAccessStatus, error)
	revoke func(
		context.Context,
		vault.AccessRequestID,
		string,
	) error
	query func(
		context.Context,
		vault.RawVaultAccessRequest,
	) (vault.RawVaultQueryResult, error)
}

func (f *fakeGate) CreateRequest(
	ctx context.Context,
	request vault.CreateIncidentAccessRequest,
) (*vault.IncidentAccessStatus, error) {
	return f.create(ctx, request)
}

func (f *fakeGate) Approve(
	ctx context.Context,
	approval vault.IncidentApproval,
) (*vault.IncidentAccessStatus, error) {
	return f.approve(ctx, approval)
}

func (f *fakeGate) Revoke(
	ctx context.Context,
	requestID vault.AccessRequestID,
	actor string,
) error {
	return f.revoke(ctx, requestID, actor)
}

func (f *fakeGate) WithAuthorizedRawVaultQuery(
	ctx context.Context,
	request vault.RawVaultAccessRequest,
) (vault.RawVaultQueryResult, error) {
	return f.query(ctx, request)
}

type readTrackingBody struct {
	read bool
}

func (b *readTrackingBody) Read(_ []byte) (int, error) {
	b.read = true
	return 0, io.EOF
}

func (b *readTrackingBody) Close() error {
	return nil
}

func TestHandlerAuthenticatesBeforeReadingSensitiveBody(t *testing.T) {
	handler := testHandler(t, &fakeGate{})
	body := &readTrackingBody{}
	request := httptest.NewRequest(
		http.MethodPost,
		CreateRequestPath,
		nil,
	)
	request.Body = body
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.Mux().ServeHTTP(response, request)

	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.False(t, body.read)
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.JSONEq(t, `{"error":"unauthorized"}`, response.Body.String())
}

func TestHandlerDerivesRequesterAndApproverFromSeparateCredentials(
	t *testing.T,
) {
	now := time.Date(2026, 7, 27, 18, 0, 0, 0, time.UTC)
	requestID := vault.AccessRequestID{1}
	var created vault.CreateIncidentAccessRequest
	var approved vault.IncidentApproval
	gate := &fakeGate{
		create: func(
			_ context.Context,
			request vault.CreateIncidentAccessRequest,
		) (*vault.IncidentAccessStatus, error) {
			created = request
			return &vault.IncidentAccessStatus{
				RequestID:     requestID,
				State:         1,
				CoarseCreated: now,
			}, nil
		},
		approve: func(
			_ context.Context,
			approval vault.IncidentApproval,
		) (*vault.IncidentAccessStatus, error) {
			approved = approval
			expiry := now.Add(30 * time.Minute)
			return &vault.IncidentAccessStatus{
				RequestID:     requestID,
				State:         2,
				CoarseCreated: now,
				RoleExpiresAt: &expiry,
			}, nil
		},
	}
	handler := testHandler(t, gate)

	createBody := `{
	  "ticket_reference":"incident:ticket-001",
	  "hypothesis":1,
	  "window_start":"2026-07-27T17:00:00Z",
	  "window_end":"2026-07-27T18:00:00Z"
	}`
	createResponse := serveAuthorized(
		handler.Mux(),
		CreateRequestPath,
		requesterSecret,
		createBody,
	)
	require.Equal(t, http.StatusCreated, createResponse.Code)
	require.Equal(t, "oncall:requester", created.RequesterActor)
	require.Equal(
		t,
		vault.AccessPurposeIncidentResponse,
		created.Purpose,
	)
	require.Equal(t, vault.AccessDataClassRawVault, created.DataClass)
	require.NotContains(t, createResponse.Body.String(), requesterSecret)

	approveBody := `{"request_id_b64":"` +
		base64.RawURLEncoding.EncodeToString(requestID[:]) + `"}`
	approveResponse := serveAuthorized(
		handler.Mux(),
		ApprovePath,
		approverSecret,
		approveBody,
	)
	require.Equal(t, http.StatusOK, approveResponse.Code)
	require.Equal(t, "security:approver", approved.Actor)
	require.Equal(t, requestID, approved.RequestID)

	wrongRole := serveAuthorized(
		handler.Mux(),
		ApprovePath,
		requesterSecret,
		approveBody,
	)
	require.Equal(t, http.StatusUnauthorized, wrongRole.Code)
}

func TestHandlerReturnsOnlyTypedEncryptedQuerySnapshot(t *testing.T) {
	requestID := vault.AccessRequestID{2}
	target := bytes.Repeat([]byte{3}, 32)
	ciphertext := []byte{4, 5, 6}
	var captured vault.RawVaultAccessRequest
	gate := &fakeGate{
		query: func(
			_ context.Context,
			request vault.RawVaultAccessRequest,
		) (vault.RawVaultQueryResult, error) {
			captured = request
			return vault.RawVaultQueryResult{
				Value: &vault.RawVaultInstallationSnapshot{
					EncryptedAPNSToken: ciphertext,
					State:              2,
					PolicyEpoch:        7,
					CreatedAt: time.Date(
						2026, 7, 27, 17, 0, 0, 0, time.UTC,
					),
					RefreshedAt: time.Date(
						2026, 7, 27, 17, 1, 0, 0, time.UTC,
					),
					ExpiresAt: time.Date(
						2026, 7, 28, 17, 0, 0, 0, time.UTC,
					),
					ControlExpiresAt: time.Date(
						2026, 7, 28, 17, 0, 0, 0, time.UTC,
					),
				},
				ResultCount: 1,
			}, nil
		},
	}
	handler := testHandler(t, gate)
	body, err := json.Marshal(queryRequestJSON{
		RequestIDB64: base64.RawURLEncoding.EncodeToString(requestID[:]),
		QueryKind:    int16(vault.RawVaultQueryInstallation),
		TargetB64:    base64.RawURLEncoding.EncodeToString(target),
	})
	require.NoError(t, err)

	response := serveAuthorized(
		handler.Mux(),
		QueryPath,
		requesterSecret,
		string(body),
	)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "oncall:requester", captured.Actor)
	require.Equal(t, target, captured.Target)
	require.NotContains(t, response.Body.String(), base64.RawURLEncoding.EncodeToString(target))
	require.Contains(
		t,
		response.Body.String(),
		base64.RawURLEncoding.EncodeToString(ciphertext),
	)
	require.NotContains(t, response.Body.String(), requesterSecret)
}

func TestHandlerUsesFixedErrorsWithoutEchoingBody(t *testing.T) {
	const canary = "RAW_INCIDENT_QUERY_CANARY"
	gate := &fakeGate{
		create: func(
			context.Context,
			vault.CreateIncidentAccessRequest,
		) (*vault.IncidentAccessStatus, error) {
			return nil, vault.ErrIncidentAccessDenied
		},
	}
	handler := testHandler(t, gate)
	body := `{
	  "ticket_reference":"` + canary + `",
	  "hypothesis":1,
	  "window_start":"2026-07-27T17:00:00Z",
	  "window_end":"2026-07-27T18:00:00Z"
	}`
	response := serveAuthorized(
		handler.Mux(),
		CreateRequestPath,
		requesterSecret,
		body,
	)
	require.Equal(t, http.StatusForbidden, response.Code)
	require.JSONEq(t, `{"error":"access_denied"}`, response.Body.String())
	require.NotContains(t, response.Body.String(), canary)
}

func testHandler(t *testing.T, gate Gate) *Handler {
	t.Helper()
	authenticator, _, err := ParseActorCredentials(testCredentialJSON(t))
	require.NoError(t, err)
	handler, err := NewHandler(gate, authenticator)
	require.NoError(t, err)
	return handler
}

func serveAuthorized(
	handler http.Handler,
	path string,
	secret string,
	body string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		http.MethodPost,
		path,
		bytes.NewBufferString(body),
	)
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
