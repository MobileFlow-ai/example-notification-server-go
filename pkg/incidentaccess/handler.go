package incidentaccess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/vault"
)

const (
	CreateRequestPath = "/private/v1/incident-access/requests:create"
	ApprovePath       = "/private/v1/incident-access/requests:approve"
	RevokePath        = "/private/v1/incident-access/requests:revoke"
	QueryPath         = "/private/v1/incident-access/vault:query"

	maxRequestBodyBytes = 16 * 1024
)

type Gate interface {
	CreateRequest(
		context.Context,
		vault.CreateIncidentAccessRequest,
	) (*vault.IncidentAccessStatus, error)
	Approve(
		context.Context,
		vault.IncidentApproval,
	) (*vault.IncidentAccessStatus, error)
	Revoke(
		context.Context,
		vault.AccessRequestID,
		string,
	) error
	WithAuthorizedRawVaultQuery(
		context.Context,
		vault.RawVaultAccessRequest,
	) (vault.RawVaultQueryResult, error)
}

type Handler struct {
	gate          Gate
	authenticator *Authenticator
}

func NewHandler(
	gate Gate,
	authenticator *Authenticator,
) (*Handler, error) {
	if gate == nil ||
		authenticator == nil ||
		len(authenticator.credentials) < 2 {
		return nil, ErrInvalidConfiguration
	}
	return &Handler{
		gate:          gate,
		authenticator: authenticator,
	}, nil
}

func (h *Handler) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(CreateRequestPath, h.serveCreate)
	mux.HandleFunc(ApprovePath, h.serveApprove)
	mux.HandleFunc(RevokePath, h.serveRevoke)
	mux.HandleFunc(QueryPath, h.serveQuery)
	return mux
}

type createRequestJSON struct {
	TicketReference string `json:"ticket_reference"`
	Hypothesis      int16  `json:"hypothesis"`
	WindowStart     string `json:"window_start"`
	WindowEnd       string `json:"window_end"`
}

type requestIDJSON struct {
	RequestIDB64 string `json:"request_id_b64"`
}

type queryRequestJSON struct {
	RequestIDB64 string `json:"request_id_b64"`
	QueryKind    int16  `json:"query_kind"`
	TargetB64    string `json:"target_b64"`
}

type statusResponseJSON struct {
	SchemaVersion     int    `json:"schema_version"`
	RequestIDB64      string `json:"request_id_b64"`
	State             int16  `json:"state"`
	CoarseCreatedHour string `json:"coarse_created_hour"`
	RoleExpiresAt     string `json:"role_expires_at,omitempty"`
}

type fixedResponseJSON struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
}

type queryResponseJSON struct {
	SchemaVersion int   `json:"schema_version"`
	QueryKind     int16 `json:"query_kind"`
	Found         bool  `json:"found"`
	Snapshot      any   `json:"snapshot,omitempty"`
}

type installationSnapshotJSON struct {
	EncryptedAPNSTokenB64 string `json:"encrypted_apns_token_b64"`
	State                 int16  `json:"state"`
	PolicyEpoch           int64  `json:"policy_epoch"`
	CreatedAt             string `json:"created_at"`
	RefreshedAt           string `json:"refreshed_at"`
	ExpiresAt             string `json:"expires_at"`
	ControlExpiresAt      string `json:"control_expires_at"`
}

type leaseSnapshotJSON struct {
	EncryptedTopicB64             string `json:"encrypted_topic_b64"`
	EncryptedRouteKeyB64          string `json:"encrypted_route_key_b64"`
	EncryptedHMACKeysB64          string `json:"encrypted_hmac_keys_b64"`
	EncryptedReceiveCapabilityB64 string `json:"encrypted_receive_capability_b64"`
	EncryptedNonceStateB64        string `json:"encrypted_nonce_state_b64"`
	State                         int16  `json:"state"`
	PolicyEpoch                   int64  `json:"policy_epoch"`
	RouteKeyEpoch                 int64  `json:"route_key_epoch"`
	IssuedAt                      string `json:"issued_at"`
	RefreshedAt                   string `json:"refreshed_at"`
	ExpiresAt                     string `json:"expires_at"`
	ControlExpiresAt              string `json:"control_expires_at"`
}

type deliveryJobSnapshotJSON struct {
	EncryptedJobB64 string `json:"encrypted_job_b64"`
	State           int16  `json:"state"`
	Attempts        int16  `json:"attempts"`
	AvailableAt     string `json:"available_at"`
	CreatedAt       string `json:"created_at"`
	ExpiresAt       string `json:"expires_at"`
}

func (h *Handler) serveCreate(
	writer http.ResponseWriter,
	request *http.Request,
) {
	prepareResponse(writer)
	if !requirePOST(writer, request) {
		return
	}
	actor, ok := h.authenticator.requester(
		request.Header.Get("Authorization"),
	)
	if !ok {
		writeFixedError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	var incoming createRequestJSON
	if readJSON(writer, request, &incoming) != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	windowStart, startErr := time.Parse(time.RFC3339, incoming.WindowStart)
	windowEnd, endErr := time.Parse(time.RFC3339, incoming.WindowEnd)
	if startErr != nil || endErr != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	status, err := h.gate.CreateRequest(
		request.Context(),
		vault.CreateIncidentAccessRequest{
			RequesterActor:  actor,
			TicketReference: incoming.TicketReference,
			Hypothesis: vault.IncidentHypothesis(
				incoming.Hypothesis,
			),
			WindowStart: windowStart,
			WindowEnd:   windowEnd,
			Purpose:     vault.AccessPurposeIncidentResponse,
			DataClass:   vault.AccessDataClassRawVault,
		},
	)
	if !writeGateStatusError(writer, err) {
		return
	}
	response, err := statusResponse(status, 1)
	if err != nil {
		writeFixedError(
			writer,
			http.StatusServiceUnavailable,
			"access_unavailable",
		)
		return
	}
	writeJSON(writer, http.StatusCreated, response)
}

func (h *Handler) serveApprove(
	writer http.ResponseWriter,
	request *http.Request,
) {
	prepareResponse(writer)
	if !requirePOST(writer, request) {
		return
	}
	actor, ok := h.authenticator.approver(
		request.Header.Get("Authorization"),
	)
	if !ok {
		writeFixedError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	var incoming requestIDJSON
	if readJSON(writer, request, &incoming) != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	requestID, err := parseRequestID(incoming.RequestIDB64)
	if err != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	status, err := h.gate.Approve(
		request.Context(),
		vault.IncidentApproval{
			RequestID: requestID,
			Actor:     actor,
		},
	)
	if !writeGateStatusError(writer, err) {
		return
	}
	response, err := statusResponse(status, 2)
	if err != nil {
		writeFixedError(
			writer,
			http.StatusServiceUnavailable,
			"access_unavailable",
		)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (h *Handler) serveRevoke(
	writer http.ResponseWriter,
	request *http.Request,
) {
	prepareResponse(writer)
	if !requirePOST(writer, request) {
		return
	}
	actor, ok := h.authenticator.either(
		request.Header.Get("Authorization"),
	)
	if !ok {
		writeFixedError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	var incoming requestIDJSON
	if readJSON(writer, request, &incoming) != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	requestID, err := parseRequestID(incoming.RequestIDB64)
	if err != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	err = h.gate.Revoke(request.Context(), requestID, actor)
	if !writeGateStatusError(writer, err) {
		return
	}
	writeJSON(
		writer,
		http.StatusOK,
		fixedResponseJSON{SchemaVersion: 1, Status: "revoked"},
	)
}

func (h *Handler) serveQuery(
	writer http.ResponseWriter,
	request *http.Request,
) {
	prepareResponse(writer)
	if !requirePOST(writer, request) {
		return
	}
	actor, ok := h.authenticator.requester(
		request.Header.Get("Authorization"),
	)
	if !ok {
		writeFixedError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	var incoming queryRequestJSON
	if readJSON(writer, request, &incoming) != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	requestID, err := parseRequestID(incoming.RequestIDB64)
	if err != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	queryKind := vault.RawVaultQueryKind(incoming.QueryKind)
	expectedTargetSize := 0
	switch queryKind {
	case vault.RawVaultQueryInstallation:
		expectedTargetSize = 32
	case vault.RawVaultQueryLease, vault.RawVaultQueryDeliveryJob:
		expectedTargetSize = 16
	default:
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	target, err := decodeCanonicalBase64URL(
		incoming.TargetB64,
		expectedTargetSize,
	)
	if err != nil {
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := h.gate.WithAuthorizedRawVaultQuery(
		request.Context(),
		vault.RawVaultAccessRequest{
			RequestID: requestID,
			Actor:     actor,
			Purpose:   vault.AccessPurposeIncidentResponse,
			DataClass: vault.AccessDataClassRawVault,
			QueryKind: queryKind,
			Target:    target,
		},
	)
	if !writeGateStatusError(writer, err) {
		return
	}
	response, err := queryResponse(queryKind, result)
	if err != nil {
		writeFixedError(
			writer,
			http.StatusServiceUnavailable,
			"access_unavailable",
		)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func readJSON(
	writer http.ResponseWriter,
	request *http.Request,
	target any,
) error {
	mediaType, _, err := mime.ParseMediaType(
		request.Header.Get("Content-Type"),
	)
	if err != nil || mediaType != "application/json" {
		return ErrInvalidConfiguration
	}
	body, err := io.ReadAll(
		http.MaxBytesReader(
			writer,
			request.Body,
			maxRequestBodyBytes,
		),
	)
	if err != nil || len(body) == 0 {
		return ErrInvalidConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil ||
		requireJSONEOF(decoder) != nil {
		return ErrInvalidConfiguration
	}
	return nil
}

func requirePOST(
	writer http.ResponseWriter,
	request *http.Request,
) bool {
	if request.Method == http.MethodPost {
		return true
	}
	writer.Header().Set("Allow", http.MethodPost)
	writeFixedError(
		writer,
		http.StatusMethodNotAllowed,
		"method_not_allowed",
	)
	return false
}

func prepareResponse(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")
}

func writeGateStatusError(
	writer http.ResponseWriter,
	err error,
) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, vault.ErrIncidentAccessInvalid):
		writeFixedError(writer, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, vault.ErrIncidentAccessDenied):
		writeFixedError(writer, http.StatusForbidden, "access_denied")
	case errors.Is(err, vault.ErrIncidentQueryFailed):
		writeFixedError(
			writer,
			http.StatusServiceUnavailable,
			"query_failed",
		)
	default:
		writeFixedError(
			writer,
			http.StatusServiceUnavailable,
			"access_unavailable",
		)
	}
	return false
}

func writeFixedError(
	writer http.ResponseWriter,
	status int,
	code string,
) {
	writeJSON(
		writer,
		status,
		map[string]string{"error": code},
	)
}

func writeJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) {
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func parseRequestID(
	encoded string,
) (vault.AccessRequestID, error) {
	var result vault.AccessRequestID
	decoded, err := decodeCanonicalBase64URL(encoded, len(result))
	if err != nil {
		return result, err
	}
	copy(result[:], decoded)
	var aggregate byte
	for _, value := range result {
		aggregate |= value
	}
	if aggregate == 0 {
		return vault.AccessRequestID{}, ErrInvalidConfiguration
	}
	return result, nil
}

func statusResponse(
	status *vault.IncidentAccessStatus,
	expectedState int16,
) (statusResponseJSON, error) {
	var aggregate byte
	if status != nil {
		for _, value := range status.RequestID {
			aggregate |= value
		}
	}
	if status == nil ||
		aggregate == 0 ||
		status.State != expectedState ||
		status.CoarseCreated.IsZero() ||
		!status.CoarseCreated.Equal(
			status.CoarseCreated.UTC().Truncate(time.Hour),
		) ||
		(expectedState == 1 && status.RoleExpiresAt != nil) ||
		(expectedState == 2 &&
			(status.RoleExpiresAt == nil ||
				!status.RoleExpiresAt.After(status.CoarseCreated))) {
		return statusResponseJSON{}, ErrInvalidConfiguration
	}
	response := statusResponseJSON{
		SchemaVersion: 1,
		RequestIDB64: base64.RawURLEncoding.EncodeToString(
			status.RequestID[:],
		),
		State: status.State,
		CoarseCreatedHour: status.CoarseCreated.UTC().
			Format(time.RFC3339),
	}
	if status.RoleExpiresAt != nil {
		response.RoleExpiresAt = status.RoleExpiresAt.UTC().
			Format(time.RFC3339Nano)
	}
	return response, nil
}

func queryResponse(
	kind vault.RawVaultQueryKind,
	result vault.RawVaultQueryResult,
) (queryResponseJSON, error) {
	response := queryResponseJSON{
		SchemaVersion: 1,
		QueryKind:     int16(kind),
		Found:         result.ResultCount == 1,
	}
	if result.ResultCount == 0 && result.Value == nil {
		return response, nil
	}
	if result.ResultCount != 1 || result.Value == nil {
		return queryResponseJSON{}, ErrInvalidConfiguration
	}
	encode := base64.RawURLEncoding.EncodeToString
	format := func(value time.Time) string {
		return value.UTC().Format(time.RFC3339Nano)
	}
	switch kind {
	case vault.RawVaultQueryInstallation:
		snapshot, ok := result.Value.(*vault.RawVaultInstallationSnapshot)
		if !ok || snapshot == nil {
			return queryResponseJSON{}, ErrInvalidConfiguration
		}
		response.Snapshot = installationSnapshotJSON{
			EncryptedAPNSTokenB64: encode(snapshot.EncryptedAPNSToken),
			State:                 snapshot.State,
			PolicyEpoch:           snapshot.PolicyEpoch,
			CreatedAt:             format(snapshot.CreatedAt),
			RefreshedAt:           format(snapshot.RefreshedAt),
			ExpiresAt:             format(snapshot.ExpiresAt),
			ControlExpiresAt:      format(snapshot.ControlExpiresAt),
		}
	case vault.RawVaultQueryLease:
		snapshot, ok := result.Value.(*vault.RawVaultLeaseSnapshot)
		if !ok || snapshot == nil {
			return queryResponseJSON{}, ErrInvalidConfiguration
		}
		response.Snapshot = leaseSnapshotJSON{
			EncryptedTopicB64:    encode(snapshot.EncryptedTopic),
			EncryptedRouteKeyB64: encode(snapshot.EncryptedRouteKey),
			EncryptedHMACKeysB64: encode(snapshot.EncryptedHMACKeys),
			EncryptedReceiveCapabilityB64: encode(
				snapshot.EncryptedReceiveCapability,
			),
			EncryptedNonceStateB64: encode(snapshot.EncryptedNonceState),
			State:                  snapshot.State,
			PolicyEpoch:            snapshot.PolicyEpoch,
			RouteKeyEpoch:          snapshot.RouteKeyEpoch,
			IssuedAt:               format(snapshot.IssuedAt),
			RefreshedAt:            format(snapshot.RefreshedAt),
			ExpiresAt:              format(snapshot.ExpiresAt),
			ControlExpiresAt:       format(snapshot.ControlExpiresAt),
		}
	case vault.RawVaultQueryDeliveryJob:
		snapshot, ok := result.Value.(*vault.RawVaultDeliveryJobSnapshot)
		if !ok || snapshot == nil {
			return queryResponseJSON{}, ErrInvalidConfiguration
		}
		response.Snapshot = deliveryJobSnapshotJSON{
			EncryptedJobB64: encode(snapshot.EncryptedJob),
			State:           snapshot.State,
			Attempts:        snapshot.Attempts,
			AvailableAt:     format(snapshot.AvailableAt),
			CreatedAt:       format(snapshot.CreatedAt),
			ExpiresAt:       format(snapshot.ExpiresAt),
		}
	default:
		return queryResponseJSON{}, ErrInvalidConfiguration
	}
	return response, nil
}
