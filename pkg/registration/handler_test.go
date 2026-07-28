package registration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
)

const testBearer = "0123456789abcdef0123456789abcdef"

type fakeRefresher struct {
	calls          int
	request        vault.RefreshRequest
	result         *vault.RefreshResult
	err            error
	policyCalls    int
	policyRequest  vault.PolicyAdvanceRequest
	policyErr      error
	welcomeCalls   int
	welcomeRequest vault.WelcomeAuthorizationRequest
	welcomeErr     error
}

func (f *fakeRefresher) AuthorizeWelcome(
	_ context.Context,
	request vault.WelcomeAuthorizationRequest,
) error {
	f.welcomeCalls++
	f.welcomeRequest = request
	return f.welcomeErr
}

func (f *fakeRefresher) AdvancePolicy(
	_ context.Context,
	request vault.PolicyAdvanceRequest,
) error {
	f.policyCalls++
	f.policyRequest = request
	return f.policyErr
}

func (f *fakeRefresher) Refresh(
	_ context.Context,
	request vault.RefreshRequest,
) (*vault.RefreshResult, error) {
	f.calls++
	f.request = request
	return f.result, f.err
}

func encoded(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func validRequestBody(t *testing.T) string {
	t.Helper()
	body := map[string]any{
		"schema_version":         1,
		"environment":            "development",
		"installation_id":        "installation",
		"account_incarnation_id": "incarnation",
		"generation":             4,
		"idempotency_key":        "0123456789abcdef",
		"apns_token_b64":         encoded(make([]byte, 32)),
		"payload_schema":         "hytch_push_wrapper_v1",
		"policy_control": map[string]any{
			"schema_version": 1,
		},
		"subscriptions": []any{
			map[string]any{
				"topic_b64":       encoded([]byte{0, 1}),
				"route_key_b64":   encoded(make([]byte, 32)),
				"route_key_epoch": 2,
				"hmac_keys": []any{
					map[string]any{
						"thirty_day_periods_since_epoch": 7,
						"key_b64":                        encoded(make([]byte, 32)),
					},
				},
				"receive_capability": map[string]any{
					"schema_version": 1,
				},
			},
			map[string]any{
				"topic_b64":       encoded([]byte{1, 2}),
				"route_key_b64":   encoded(make([]byte, 32)),
				"route_key_epoch": 2,
				"hmac_keys":       []any{},
				"receive_capability": map[string]any{
					"schema_version": 1,
				},
			},
		},
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	return string(raw)
}

func TestHandlerRequiresBearerBeforeReadingSensitiveBody(t *testing.T) {
	fake := &fakeRefresher{}
	handler, err := NewHandler(fake, testBearer)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPut, RefreshPath, strings.NewReader(validRequestBody(t)))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Equal(t, 0, fake.calls)
	require.JSONEq(t, `{"error":"unauthorized"}`, response.Body.String())
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
}

func TestHandlerDecodesAtomicTopicList(t *testing.T) {
	expiresAt := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	fake := &fakeRefresher{result: &vault.RefreshResult{
		AcceptedGeneration: 4,
		ActiveLeaseCount:   2,
		LeaseExpiresAt:     expiresAt,
	}}
	handler, err := NewHandler(fake, testBearer)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPut, RefreshPath, strings.NewReader(validRequestBody(t)))
	request.Header.Set("Authorization", "Bearer "+testBearer)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, 1, fake.calls)
	require.Len(t, fake.request.Subscriptions, 2)
	require.Equal(t, uint64(4), fake.request.Generation)
	require.JSONEq(
		t,
		`{"schema_version":1,"accepted_generation":4,"active_lease_count":2,"lease_expires_at":"2026-08-02T12:00:00Z"}`,
		response.Body.String(),
	)
}

func TestHandlerRejectsUnknownFieldAndConflictIsContentFree(t *testing.T) {
	fake := &fakeRefresher{err: vault.ErrRefreshConflict}
	handler, err := NewHandler(fake, testBearer)
	require.NoError(t, err)

	unknown := strings.TrimSuffix(validRequestBody(t), "}") + `,"raw_topic":"secret"}`
	request := httptest.NewRequest(http.MethodPut, RefreshPath, strings.NewReader(unknown))
	request.Header.Set("Authorization", "Bearer "+testBearer)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Equal(t, 0, fake.calls)
	require.NotContains(t, response.Body.String(), "secret")

	request = httptest.NewRequest(http.MethodPut, RefreshPath, strings.NewReader(validRequestBody(t)))
	request.Header.Set("Authorization", "Bearer "+testBearer)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusConflict, response.Code)
	require.JSONEq(t, `{"error":"stale_generation"}`, response.Body.String())
}

func TestPolicyHandlerAcceptsSignedShapeWithoutEchoingIdentity(t *testing.T) {
	fake := &fakeRefresher{}
	handler, err := NewHandler(fake, testBearer)
	require.NoError(t, err)
	body := `{
		"schema_version":1,
		"environment":"development",
		"installation_id":"sensitive-installation",
		"account_incarnation_id":"sensitive-incarnation",
		"policy_epoch":9,
		"state":"revoked",
		"age_policy":"teen",
		"issued_at":"2026-07-26T12:00:00Z",
		"expires_at":"2026-07-26T12:00:30Z",
		"signing_key_id":"key-1",
		"algorithm":"Ed25519",
		"signature":"signed"
	}`
	request := httptest.NewRequest(http.MethodPost, PolicyPath, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testBearer)
	response := httptest.NewRecorder()

	handler.ServePolicyHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, 1, fake.policyCalls)
	require.Equal(t, uint64(9), fake.policyRequest.Control.PolicyEpoch)
	require.NotContains(t, response.Body.String(), "sensitive")
	require.JSONEq(
		t,
		`{"schema_version":1,"accepted_policy_epoch":9}`,
		response.Body.String(),
	)
}

func TestWelcomeHandlerAcceptsExactAuthorizationWithoutEchoingIdentity(t *testing.T) {
	fake := &fakeRefresher{}
	handler, err := NewHandler(fake, testBearer)
	require.NoError(t, err)
	body := `{
		"schema_version":1,
		"topic_b64":"AAE",
		"authorization":{
			"schema_version":1,
			"environment":"development",
			"installation_id":"sensitive-installation",
			"account_incarnation_id":"sensitive-incarnation",
			"policy_epoch":9,
			"topic_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"outer_envelope_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"grant_version":3,
			"nonce":"MDEyMzQ1Njc4OWFiY2RlZg",
			"issued_at":"2026-07-26T12:00:00Z",
			"expires_at":"2026-07-26T12:01:00Z",
			"signing_key_id":"key-1",
			"algorithm":"Ed25519",
			"signature":"signed"
		}
	}`
	request := httptest.NewRequest(http.MethodPost, WelcomePath, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testBearer)
	response := httptest.NewRecorder()

	handler.ServeWelcomeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, 1, fake.welcomeCalls)
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.Equal(t, []byte{0, 1}, fake.welcomeRequest.Topic)
	require.Equal(
		t,
		"sensitive-installation",
		fake.welcomeRequest.Authorization.InstallationID,
	)
	require.NotContains(t, response.Body.String(), "sensitive")
	require.JSONEq(
		t,
		`{"schema_version":1,"accepted":true}`,
		response.Body.String(),
	)
}

func TestWelcomeHandlerFailsClosedBeforeReadingBodyAndOnConflict(t *testing.T) {
	fake := &fakeRefresher{}
	handler, err := NewHandler(fake, testBearer)
	require.NoError(t, err)
	request := httptest.NewRequest(
		http.MethodPost,
		WelcomePath,
		strings.NewReader(`{"installation_id":"secret"}`),
	)
	response := httptest.NewRecorder()
	handler.ServeWelcomeHTTP(response, request)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Zero(t, fake.welcomeCalls)
	require.NotContains(t, response.Body.String(), "secret")

	fake.welcomeErr = vault.ErrWelcomeConflict
	body := `{
		"schema_version":1,
		"topic_b64":"AAE",
		"authorization":{"schema_version":1}
	}`
	request = httptest.NewRequest(http.MethodPost, WelcomePath, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testBearer)
	response = httptest.NewRecorder()
	handler.ServeWelcomeHTTP(response, request)
	require.Equal(t, http.StatusConflict, response.Code)
	require.JSONEq(t, `{"error":"authorization_conflict"}`, response.Body.String())
}
