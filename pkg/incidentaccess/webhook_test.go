package incidentaccess

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return f(request)
}

func TestOversightWebhookBroadcastContainsOnlyFixedCoarseFields(
	t *testing.T,
) {
	const oversightSecret = "oversight-secret-0123456789abcdef"
	var capturedBody string
	broadcast, err := newOversightWebhookBroadcast(
		"https://oversight.invalid/private/incident",
		oversightSecret,
		time.Second,
		roundTripFunc(func(
			request *http.Request,
		) (*http.Response, error) {
			require.Equal(t, http.MethodPost, request.Method)
			require.Equal(
				t,
				"Bearer "+oversightSecret,
				request.Header.Get("Authorization"),
			)
			body, readErr := io.ReadAll(request.Body)
			require.NoError(t, readErr)
			capturedBody = string(body)
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ignored")),
			}, nil
		}),
	)
	require.NoError(t, err)
	err = broadcast(
		t.Context(),
		vault.IncidentOversightNotice{
			Purpose:   vault.AccessPurposeIncidentResponse,
			DataClass: vault.AccessDataClassRawVault,
			CoarseApprovedHour: time.Date(
				2026, 7, 27, 18, 0, 0, 0, time.UTC,
			),
		},
	)
	require.NoError(t, err)
	require.JSONEq(
		t,
		`{
		  "schema_version":1,
		  "purpose":1,
		  "data_class":1,
		  "coarse_approved_hour":"2026-07-27T18:00:00Z"
		}`,
		capturedBody,
	)
	require.NotContains(t, capturedBody, oversightSecret)
	require.NotContains(t, capturedBody, "actor")
	require.NotContains(t, capturedBody, "request")
}

func TestOversightWebhookFailsClosedOnInvalidEndpointOrResponse(
	t *testing.T,
) {
	const oversightSecret = "oversight-secret-0123456789abcdef"
	for _, rawURL := range []string{
		"",
		"http://oversight.invalid/hook",
		"https://person@oversight.invalid/hook",
		"https://oversight.invalid/hook?secret=value",
		"https://oversight.invalid/hook#fragment",
	} {
		broadcast, err := NewOversightWebhookBroadcast(
			rawURL,
			oversightSecret,
			time.Second,
		)
		require.Nil(t, broadcast)
		require.ErrorIs(t, err, ErrInvalidConfiguration)
	}

	broadcast, err := newOversightWebhookBroadcast(
		"https://oversight.invalid/hook",
		oversightSecret,
		time.Second,
		roundTripFunc(func(
			*http.Request,
		) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("sensitive")),
			}, nil
		}),
	)
	require.NoError(t, err)
	err = broadcast(
		context.Background(),
		vault.IncidentOversightNotice{
			Purpose:   vault.AccessPurposeIncidentResponse,
			DataClass: vault.AccessDataClassRawVault,
			CoarseApprovedHour: time.Date(
				2026, 7, 27, 18, 0, 0, 0, time.UTC,
			),
		},
	)
	require.ErrorIs(t, err, vault.ErrIncidentAccessUnavailable)
}
