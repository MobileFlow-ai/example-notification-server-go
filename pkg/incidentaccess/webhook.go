package incidentaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/vault"
)

func NewOversightWebhookBroadcast(
	rawURL string,
	bearerSecret string,
	timeout time.Duration,
) (vault.IncidentOversightBroadcast, error) {
	return newOversightWebhookBroadcast(
		rawURL,
		bearerSecret,
		timeout,
		nil,
	)
}

func newOversightWebhookBroadcast(
	rawURL string,
	bearerSecret string,
	timeout time.Duration,
	transport http.RoundTripper,
) (vault.IncidentOversightBroadcast, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil ||
		endpoint.Scheme != "https" ||
		endpoint.Host == "" ||
		endpoint.User != nil ||
		endpoint.RawQuery != "" ||
		endpoint.Fragment != "" ||
		endpoint.Opaque != "" ||
		len(bearerSecret) < minBearerSecretBytes ||
		len(bearerSecret) > maxBearerSecretBytes ||
		strings.TrimSpace(bearerSecret) != bearerSecret ||
		timeout <= 0 ||
		timeout > 15*time.Second {
		return nil, ErrInvalidConfiguration
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(
			_ *http.Request,
			_ []*http.Request,
		) error {
			return errors.New("oversight redirect rejected")
		},
	}
	if transport != nil {
		client.Transport = transport
	}
	type oversightNoticeJSON struct {
		SchemaVersion      int    `json:"schema_version"`
		Purpose            int16  `json:"purpose"`
		DataClass          int16  `json:"data_class"`
		CoarseApprovedHour string `json:"coarse_approved_hour"`
	}
	return func(
		ctx context.Context,
		notice vault.IncidentOversightNotice,
	) error {
		if ctx == nil ||
			notice.Purpose != vault.AccessPurposeIncidentResponse ||
			notice.DataClass != vault.AccessDataClassRawVault ||
			notice.CoarseApprovedHour.IsZero() ||
			!notice.CoarseApprovedHour.Equal(
				notice.CoarseApprovedHour.UTC().Truncate(time.Hour),
			) {
			return vault.ErrIncidentAccessUnavailable
		}
		body, err := json.Marshal(oversightNoticeJSON{
			SchemaVersion: 1,
			Purpose:       int16(notice.Purpose),
			DataClass:     int16(notice.DataClass),
			CoarseApprovedHour: notice.CoarseApprovedHour.UTC().
				Format(time.RFC3339),
		})
		if err != nil {
			return vault.ErrIncidentAccessUnavailable
		}
		request, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			endpoint.String(),
			bytes.NewReader(body),
		)
		if err != nil {
			return vault.ErrIncidentAccessUnavailable
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Authorization", "Bearer "+bearerSecret)
		response, err := client.Do(request)
		if err != nil {
			return vault.ErrIncidentAccessUnavailable
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		closeErr := response.Body.Close()
		if response.StatusCode < http.StatusOK ||
			response.StatusCode >= http.StatusMultipleChoices ||
			closeErr != nil {
			return vault.ErrIncidentAccessUnavailable
		}
		return nil
	}, nil
}
