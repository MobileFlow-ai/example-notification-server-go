package registration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/authority"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
)

const (
	RefreshPath          = "/internal/v1/xmtp-push/subscriptions:replace"
	PolicyPath           = "/internal/v1/xmtp-push/policy:advance"
	WelcomePath          = "/internal/v1/xmtp-push/welcomes:authorize"
	maxRefreshBodyBytes  = 512 * 1024
	maxPolicyBodyBytes   = 64 * 1024
	maxWelcomeBodyBytes  = 64 * 1024
	maxBearerSecretBytes = 4096
)

type Refresher interface {
	Refresh(context.Context, vault.RefreshRequest) (*vault.RefreshResult, error)
}

type PolicyAdvancer interface {
	AdvancePolicy(context.Context, vault.PolicyAdvanceRequest) error
}

type WelcomeAuthorizer interface {
	AuthorizeWelcome(context.Context, vault.WelcomeAuthorizationRequest) error
}

type Handler struct {
	refresher    Refresher
	policy       PolicyAdvancer
	welcome      WelcomeAuthorizer
	bearerDigest [sha256.Size]byte
}

func NewHandler(refresher Refresher, bearerSecret string) (*Handler, error) {
	if refresher == nil || len(bearerSecret) < 32 ||
		len(bearerSecret) > maxBearerSecretBytes {
		return nil, vault.ErrStoreUnavailable
	}
	handler := &Handler{
		refresher:    refresher,
		bearerDigest: sha256.Sum256([]byte(bearerSecret)),
	}
	handler.policy, _ = refresher.(PolicyAdvancer)
	// Welcome routing is intentionally not attached in this build. Retaining
	// the fixed endpoint response avoids turning an old caller into an
	// accidental authorization path.
	return handler, nil
}

type refreshRequestJSON struct {
	SchemaVersion        uint32                    `json:"schema_version"`
	Environment          string                    `json:"environment"`
	InstallationID       string                    `json:"installation_id"`
	AccountIncarnationID string                    `json:"account_incarnation_id"`
	Generation           uint64                    `json:"generation"`
	IdempotencyKey       string                    `json:"idempotency_key"`
	APNSTokenB64         string                    `json:"apns_token_b64"`
	PayloadSchema        string                    `json:"payload_schema"`
	PolicyControl        authority.PolicyControlV1 `json:"policy_control"`
	Subscriptions        []subscriptionRefreshJSON `json:"subscriptions"`
}

type subscriptionRefreshJSON struct {
	TopicB64      string                        `json:"topic_b64"`
	RouteKeyB64   string                        `json:"route_key_b64"`
	RouteKeyEpoch uint32                        `json:"route_key_epoch"`
	HMACKeys      []hmacKeyJSON                 `json:"hmac_keys"`
	Capability    authority.ReceiveCapabilityV1 `json:"receive_capability"`
}

type hmacKeyJSON struct {
	ThirtyDayPeriodsSinceEpoch uint32 `json:"thirty_day_periods_since_epoch"`
	KeyB64                     string `json:"key_b64"`
}

type refreshResponseJSON struct {
	SchemaVersion      uint32 `json:"schema_version"`
	AcceptedGeneration uint64 `json:"accepted_generation"`
	ActiveLeaseCount   int    `json:"active_lease_count"`
	LeaseExpiresAt     string `json:"lease_expires_at"`
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPut {
		writer.Header().Set("Allow", http.MethodPut)
		writeFixedError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !h.authorized(request.Header.Get("Authorization")) {
		writeFixedError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}

	body, err := io.ReadAll(io.LimitReader(request.Body, maxRefreshBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxRefreshBodyBytes {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	var incoming refreshRequestJSON
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&incoming); err != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if err = requireJSONEOF(decoder); err != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	refresh, err := convertRefresh(incoming)
	if err != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}

	result, err := h.refresher.Refresh(request.Context(), refresh)
	switch {
	case errors.Is(err, vault.ErrRefreshInvalid):
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	case errors.Is(err, vault.ErrRefreshConflict):
		writeFixedError(writer, http.StatusConflict, "stale_generation")
		return
	case err != nil:
		writeFixedError(writer, http.StatusServiceUnavailable, "vault_unavailable")
		return
	}

	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(refreshResponseJSON{
		SchemaVersion:      1,
		AcceptedGeneration: result.AcceptedGeneration,
		ActiveLeaseCount:   result.ActiveLeaseCount,
		LeaseExpiresAt:     result.LeaseExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (h *Handler) ServePolicyHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeFixedError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !h.authorized(request.Header.Get("Authorization")) {
		writeFixedError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.policy == nil {
		writeFixedError(writer, http.StatusServiceUnavailable, "vault_unavailable")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxPolicyBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxPolicyBodyBytes {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	var control authority.PolicyControlV1
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&control); err != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if err = requireJSONEOF(decoder); err != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if !authority.ValidEnvironment(control.Environment) ||
		!authority.ValidInstallationID(control.InstallationID) ||
		!authority.ValidAccountIncarnationID(control.AccountIncarnationID) {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	err = h.policy.AdvancePolicy(request.Context(), vault.PolicyAdvanceRequest{
		Control: control,
	})
	switch {
	case errors.Is(err, vault.ErrRefreshInvalid):
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	case errors.Is(err, vault.ErrRefreshConflict):
		writeFixedError(writer, http.StatusConflict, "stale_policy_epoch")
		return
	case err != nil:
		writeFixedError(writer, http.StatusServiceUnavailable, "vault_unavailable")
		return
	}
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"schema_version":        1,
		"accepted_policy_epoch": control.PolicyEpoch,
	})
}

type welcomeAuthorizationJSON struct {
	SchemaVersion uint32                           `json:"schema_version"`
	TopicB64      string                           `json:"topic_b64"`
	Authorization authority.WelcomeAuthorizationV1 `json:"authorization"`
}

func (h *Handler) ServeWelcomeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeFixedError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !h.authorized(request.Header.Get("Authorization")) {
		writeFixedError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.welcome == nil {
		writeFixedError(writer, http.StatusServiceUnavailable, "vault_unavailable")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxWelcomeBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxWelcomeBodyBytes {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	var incoming welcomeAuthorizationJSON
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&incoming); err != nil ||
		requireJSONEOF(decoder) != nil ||
		incoming.SchemaVersion != 1 {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	topicBytes, err := decodeRawBase64(incoming.TopicB64)
	if err != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	err = h.welcome.AuthorizeWelcome(
		request.Context(),
		vault.WelcomeAuthorizationRequest{
			Topic:         topicBytes,
			Authorization: incoming.Authorization,
		},
	)
	switch {
	case errors.Is(err, vault.ErrWelcomeInvalid):
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	case errors.Is(err, vault.ErrWelcomeConflict):
		writeFixedError(writer, http.StatusConflict, "authorization_conflict")
		return
	case err != nil:
		writeFixedError(writer, http.StatusServiceUnavailable, "vault_unavailable")
		return
	}
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"schema_version": 1,
		"accepted":       true,
	})
}

func (h *Handler) authorized(header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	secret := strings.TrimPrefix(header, prefix)
	if len(secret) < 32 || len(secret) > maxBearerSecretBytes {
		return false
	}
	digest := sha256.Sum256([]byte(secret))
	return hmac.Equal(digest[:], h.bearerDigest[:])
}

func convertRefresh(
	incoming refreshRequestJSON,
) (vault.RefreshRequest, error) {
	if incoming.SchemaVersion != 1 ||
		!authority.ValidEnvironment(incoming.Environment) ||
		!authority.ValidInstallationID(incoming.InstallationID) ||
		!authority.ValidAccountIncarnationID(incoming.AccountIncarnationID) ||
		incoming.Subscriptions == nil {
		return vault.RefreshRequest{}, vault.ErrRefreshInvalid
	}
	token, err := decodeRawBase64(incoming.APNSTokenB64)
	if err != nil {
		return vault.RefreshRequest{}, vault.ErrRefreshInvalid
	}
	subscriptions := make([]vault.SubscriptionRefresh, len(incoming.Subscriptions))
	for index, subscription := range incoming.Subscriptions {
		topicBytes, decodeErr := decodeRawBase64(subscription.TopicB64)
		if decodeErr != nil {
			return vault.RefreshRequest{}, vault.ErrRefreshInvalid
		}
		routeKey, decodeErr := decodeRawBase64(subscription.RouteKeyB64)
		if decodeErr != nil {
			return vault.RefreshRequest{}, vault.ErrRefreshInvalid
		}
		hmacKeys := make([]vault.HMACKeyInput, len(subscription.HMACKeys))
		for keyIndex, key := range subscription.HMACKeys {
			keyBytes, keyErr := decodeRawBase64(key.KeyB64)
			if keyErr != nil {
				return vault.RefreshRequest{}, vault.ErrRefreshInvalid
			}
			hmacKeys[keyIndex] = vault.HMACKeyInput{
				ThirtyDayPeriodsSinceEpoch: key.ThirtyDayPeriodsSinceEpoch,
				Key:                        keyBytes,
			}
		}
		subscriptions[index] = vault.SubscriptionRefresh{
			Topic:         topicBytes,
			RouteKey:      routeKey,
			RouteKeyEpoch: subscription.RouteKeyEpoch,
			HMACKeys:      hmacKeys,
			Capability:    subscription.Capability,
		}
	}
	return vault.RefreshRequest{
		Environment:          incoming.Environment,
		InstallationID:       incoming.InstallationID,
		AccountIncarnationID: incoming.AccountIncarnationID,
		Generation:           incoming.Generation,
		IdempotencyKey:       incoming.IdempotencyKey,
		APNSToken:            token,
		PayloadSchema:        incoming.PayloadSchema,
		Subscriptions:        subscriptions,
		PolicyControl:        incoming.PolicyControl,
	}, nil
}

func decodeRawBase64(value string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, vault.ErrRefreshInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, vault.ErrRefreshInvalid
	}
	return decoded, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return vault.ErrRefreshInvalid
	}
	return nil
}

func writeFixedError(writer http.ResponseWriter, status int, code string) {
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": code})
}
