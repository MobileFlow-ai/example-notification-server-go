package a9api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9auth"
	"github.com/xmtp/example-notification-server-go/pkg/a9schema"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

const (
	ControlApplyPath         = "/internal/v1/xmtp-push/a9-authority:apply"
	WatermarkApplyPath       = "/internal/v1/xmtp-push/a9-watermarks:apply"
	SubscriptionsReplacePath = "/internal/v1/xmtp-push/subscriptions:replace"

	MaxRequestBodyBytes   int64 = 16 * 1024 * 1024
	maxAuthorizationBytes       = 8 * 1024
)

var ErrHandlerConfiguration = errors.New("a9 handler configuration invalid")

const (
	fixedRejectedBody       = `{"error":"request_rejected"}`
	fixedAuthenticationBody = `{"error":"authentication_rejected"}`
	fixedUnavailableBody    = `{"error":"temporarily_unavailable"}`
)

// TrustProvider exposes only the durable-current public snapshot and an exact
// provenance-bound, request-scoped topic-binding lease.
type TrustProvider interface {
	Verifier(
		context.Context,
		time.Time,
	) (map[string]any, error)
	AcquireTopicBindingLease(
		context.Context,
		time.Time,
		uint64,
		[32]byte,
	) (a9trust.TopicBindingLease, error)
}

// KeysetReceipt binds a replacement transaction to the exact root-verified
// keyset snapshot used by this request boundary.
type KeysetReceipt struct {
	Sequence uint64
	Hash     [32]byte
}

// Store owns the serializable authority, watermark, and replacement
// transactions. Implementations must return a Result describing committed
// state or an error for unavailable or ambiguous completion.
//
// Every method must, in the same serializable transaction as every check and
// mutation, lock a9_keyset_state and require the exact sequence/hash carried
// by the verified projection or receipt, uncertainty=false, unexpired keyset
// state, and a database-clock refreshed_at age below six hours. It must also
// recheck the artifact and referenced authority/watermark expiry relevant to
// that transaction using database time. A sampled handler time is never
// sufficient for these joins. ApplyControl and ApplyWatermark carry the
// receipt in KeysetSequence/KeysetHash; Replace receives it explicitly.
type Store interface {
	ApplyControl(
		context.Context,
		a9trust.VerifiedControl,
	) (Result, error)
	ApplyWatermark(
		context.Context,
		a9trust.VerifiedWatermark,
	) (Result, error)
	Replace(
		context.Context,
		*ReplaceRequest,
		KeysetReceipt,
	) (Result, error)
}

// KeyStateLatch makes an artifact verdict that explicitly requires durable
// keyset uncertainty visible to the trust manager. Transient snapshot and
// currentness failures never call this interface.
type KeyStateLatch interface {
	LatchArtifactUncertainty(a9trust.Verdict) error
}

type HandlerOptions struct {
	Environment string
	Trust       TrustProvider
	ReplayStore a9auth.ReplayStore
	Store       Store
	KeyState    KeyStateLatch
	Clock       func() time.Time
}

type Handler struct {
	environment string
	trust       TrustProvider
	replay      a9auth.ReplayStore
	store       Store
	keyState    KeyStateLatch
	clock       func() time.Time
}

func NewHandler(options HandlerOptions) (*Handler, error) {
	if (options.Environment != "dev" &&
		options.Environment != "production") ||
		options.Trust == nil ||
		options.ReplayStore == nil ||
		options.Store == nil ||
		options.KeyState == nil {
		return nil, ErrHandlerConfiguration
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Handler{
		environment: options.Environment,
		trust:       options.Trust,
		replay:      options.ReplayStore,
		store:       options.Store,
		keyState:    options.KeyState,
		clock:       clock,
	}, nil
}

func (handler *Handler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler == nil || request == nil {
		writeFixedError(writer, http.StatusServiceUnavailable)
		return
	}
	endpoint, ok := routeForPath(request)
	if !ok {
		writeFixedError(writer, http.StatusNotFound)
		return
	}
	if request.Method != endpoint.method {
		writer.Header().Set("Allow", endpoint.method)
		writeFixedError(writer, http.StatusMethodNotAllowed)
		return
	}
	if !exactRequestTarget(request, endpoint.path) ||
		request.TLS == nil {
		writeFixedError(writer, http.StatusBadRequest)
		return
	}
	compact, ok := canonicalBearer(request.Header.Values("Authorization"))
	if !ok {
		writeFixedError(writer, http.StatusUnauthorized)
		return
	}
	if !exactJSONContentType(request) {
		writeFixedError(writer, http.StatusUnsupportedMediaType)
		return
	}
	raw, status := readBoundedBody(request)
	if status != 0 {
		writeFixedError(writer, status)
		return
	}
	defer clear(raw)

	now := handler.clock().UTC()
	if now.IsZero() {
		writeFixedError(writer, http.StatusServiceUnavailable)
		return
	}
	keyset, err := handler.trust.Verifier(request.Context(), now)
	if err != nil || keyset == nil {
		writeFixedError(writer, http.StatusServiceUnavailable)
		return
	}

	_, err = a9auth.VerifyAndConsume(
		request.Context(),
		compact,
		a9auth.Expectations{
			Environment: handler.environment,
			Method:      endpoint.method,
			Path:        endpoint.path,
			RequestBody: raw,
			Now:         now,
			Keyset:      keyset,
		},
		handler.replay,
	)
	if err != nil {
		if errors.Is(err, a9auth.ErrReplayStoreUnavailable) {
			writeFixedError(writer, http.StatusServiceUnavailable)
			return
		}
		writeFixedError(writer, http.StatusUnauthorized)
		return
	}

	result, identity, status, ok := handler.dispatch(
		request.Context(),
		endpoint.kind,
		raw,
		keyset,
		now,
	)
	if !ok {
		writeFixedError(writer, status)
		return
	}
	if !identity.matches(result) {
		writeFixedError(writer, http.StatusServiceUnavailable)
		return
	}
	body, err := result.CanonicalJSON()
	if err != nil {
		writeFixedError(writer, http.StatusServiceUnavailable)
		return
	}
	status, err = result.HTTPStatus()
	if err != nil {
		writeFixedError(writer, http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, status, body)
}

func (handler *Handler) dispatch(
	ctx context.Context,
	kind endpointKind,
	raw []byte,
	keyset map[string]any,
	now time.Time,
) (Result, resultIdentity, int, bool) {
	switch kind {
	case endpointControl:
		verified, verdict := a9trust.VerifyControl(
			raw,
			a9trust.ControlExpectations{
				Environment:    handler.environment,
				EvaluationTime: now,
				Keyset:         keyset,
			},
		)
		if !verdict.IsEligible() {
			return Result{}, resultIdentity{},
				handler.statusForArtifactFailure(verdict), false
		}
		result, err := handler.store.ApplyControl(ctx, verified)
		if err != nil {
			return Result{}, resultIdentity{},
				http.StatusServiceUnavailable, false
		}
		return result, resultIdentity{
			environment:           verified.Environment,
			installationBindingID: verified.InstallationBindingID,
			sequencerEpoch:        verified.SequencerEpoch,
		}, 0, true
	case endpointWatermark:
		verified, verdict := a9trust.VerifyWatermark(
			raw,
			a9trust.WatermarkExpectations{
				Environment:    handler.environment,
				EvaluationTime: now,
				Keyset:         keyset,
			},
		)
		if !verdict.IsEligible() &&
			!verifiedSignedUncertainty(verified, verdict) {
			return Result{}, resultIdentity{},
				handler.statusForArtifactFailure(verdict), false
		}
		result, err := handler.store.ApplyWatermark(ctx, verified)
		if err != nil {
			return Result{}, resultIdentity{},
				http.StatusServiceUnavailable, false
		}
		return result, resultIdentity{
			environment:           verified.Environment,
			installationBindingID: verified.InstallationBindingID,
			sequencerEpoch:        verified.SequencerEpoch,
		}, 0, true
	case endpointReplace:
		receipt, ok := keysetReceipt(keyset, handler.environment)
		if !ok {
			return Result{}, resultIdentity{},
				http.StatusServiceUnavailable, false
		}
		lease, err := handler.trust.AcquireTopicBindingLease(
			ctx,
			now,
			receipt.Sequence,
			receipt.Hash,
		)
		if err != nil || lease == nil {
			return Result{}, resultIdentity{},
				http.StatusServiceUnavailable, false
		}
		binder := &trackingTopicBinder{delegate: lease}
		replace, err := decodeReplaceWithLease(
			ctx,
			raw,
			handler.environment,
			binder,
			lease,
			now,
		)
		if err != nil {
			if binder.failure.Terminal != "" {
				return Result{}, resultIdentity{},
					handler.statusForArtifactFailure(
						binder.failure,
					), false
			}
			return Result{}, resultIdentity{},
				http.StatusBadRequest, false
		}
		defer replace.Close()
		result, err := handler.store.Replace(ctx, replace, receipt)
		if err != nil {
			return Result{}, resultIdentity{},
				http.StatusServiceUnavailable, false
		}
		return result, resultIdentity{
			environment:           replace.Environment,
			installationBindingID: replace.InstallationBindingID,
			sequencerEpoch:        replace.SequencerEpoch,
		}, 0, true
	default:
		return Result{}, resultIdentity{},
			http.StatusNotFound, false
	}
}

func decodeReplaceWithLease(
	ctx context.Context,
	raw []byte,
	environment string,
	binder TopicBinder,
	lease a9trust.TopicBindingLease,
	now time.Time,
) (*ReplaceRequest, error) {
	defer lease.Close()
	return DecodeReplace(ctx, raw, environment, binder, now)
}

func keysetReceipt(
	keyset map[string]any,
	environment string,
) (KeysetReceipt, bool) {
	if keyset == nil ||
		a9schema.Validate(a9schema.KeysetKind, keyset) != nil {
		return KeysetReceipt{}, false
	}
	keysetEnvironment, ok := keyset["environment"].(string)
	if !ok || keysetEnvironment != environment {
		return KeysetReceipt{}, false
	}
	number, ok := keyset["keyset_sequence"].(json.Number)
	if !ok {
		return KeysetReceipt{}, false
	}
	sequence, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil || sequence == 0 || sequence > maxSafeInteger {
		return KeysetReceipt{}, false
	}
	canonical, err := a9trust.Canonicalize(keyset)
	if err != nil {
		return KeysetReceipt{}, false
	}
	return KeysetReceipt{
		Sequence: sequence,
		Hash:     sha256.Sum256(canonical),
	}, true
}

func (handler *Handler) statusForArtifactFailure(
	verdict a9trust.Verdict,
) int {
	if verdict.RequiresKeysetUncertainty() {
		_ = handler.keyState.LatchArtifactUncertainty(verdict)
		return http.StatusServiceUnavailable
	}
	if verdict.Terminal == "INCONCLUSIVE" {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

type endpointKind uint8

const (
	endpointControl endpointKind = iota + 1
	endpointWatermark
	endpointReplace
)

type endpoint struct {
	kind   endpointKind
	method string
	path   string
}

func routeForPath(request *http.Request) (endpoint, bool) {
	if request.URL == nil {
		return endpoint{}, false
	}
	switch request.URL.Path {
	case ControlApplyPath:
		return endpoint{
			kind: endpointControl, method: http.MethodPost,
			path: ControlApplyPath,
		}, true
	case WatermarkApplyPath:
		return endpoint{
			kind: endpointWatermark, method: http.MethodPost,
			path: WatermarkApplyPath,
		}, true
	case SubscriptionsReplacePath:
		return endpoint{
			kind: endpointReplace, method: http.MethodPut,
			path: SubscriptionsReplacePath,
		}, true
	default:
		return endpoint{}, false
	}
}

func exactRequestTarget(request *http.Request, path string) bool {
	return request.RequestURI == path &&
		request.URL.Path == path &&
		request.URL.RawPath == "" &&
		request.URL.EscapedPath() == path &&
		request.URL.RawQuery == "" &&
		!request.URL.ForceQuery &&
		request.URL.Fragment == "" &&
		request.URL.Opaque == ""
}

func exactJSONContentType(request *http.Request) bool {
	values := request.Header.Values("Content-Type")
	return len(values) == 1 &&
		values[0] == "application/json" &&
		len(request.Header.Values("Content-Encoding")) == 0
}

func canonicalBearer(values []string) (string, bool) {
	if len(values) != 1 ||
		len(values[0]) <= len("Bearer ") ||
		len(values[0]) > maxAuthorizationBytes ||
		!strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	compact := strings.TrimPrefix(values[0], "Bearer ")
	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		return "", false
	}
	for _, segment := range segments {
		if segment == "" {
			return "", false
		}
		for index := range segment {
			value := segment[index]
			if (value < 'A' || value > 'Z') &&
				(value < 'a' || value > 'z') &&
				(value < '0' || value > '9') &&
				value != '-' &&
				value != '_' {
				return "", false
			}
		}
	}
	return compact, true
}

func readBoundedBody(request *http.Request) ([]byte, int) {
	if request.Body == nil ||
		request.ContentLength == 0 ||
		request.ContentLength < -1 {
		return nil, http.StatusBadRequest
	}
	if request.ContentLength > MaxRequestBodyBytes {
		return nil, http.StatusRequestEntityTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(
		request.Body,
		MaxRequestBodyBytes+1,
	))
	if err != nil {
		clear(raw)
		return nil, http.StatusBadRequest
	}
	if len(raw) == 0 {
		return nil, http.StatusBadRequest
	}
	if int64(len(raw)) > MaxRequestBodyBytes {
		clear(raw)
		return nil, http.StatusRequestEntityTooLarge
	}
	if request.ContentLength >= 0 &&
		request.ContentLength != int64(len(raw)) {
		clear(raw)
		return nil, http.StatusBadRequest
	}
	return raw, 0
}

type resultIdentity struct {
	environment           string
	installationBindingID [16]byte
	sequencerEpoch        [16]byte
}

func (identity resultIdentity) matches(result Result) bool {
	return result.Environment == identity.environment &&
		result.InstallationBindingID == identity.installationBindingID &&
		result.SequencerEpoch == identity.sequencerEpoch
}

func verifiedSignedUncertainty(
	watermark a9trust.VerifiedWatermark,
	verdict a9trust.Verdict,
) bool {
	if watermark.Status != a9trust.WatermarkStatusUncertain ||
		verdict.Terminal != "INCONCLUSIVE" ||
		watermark.SignedObjectHash == ([32]byte{}) {
		return false
	}
	switch watermark.UncertaintyReason {
	case a9trust.WatermarkUncertaintySourceUnavailable:
		return verdict.Reason == "SOURCE_UNAVAILABLE"
	case a9trust.WatermarkUncertaintyOutboxGap:
		return verdict.Reason == "OUTBOX_GAP"
	case a9trust.WatermarkUncertaintyReplicaAmbiguity:
		return verdict.Reason == "REPLICA_AMBIGUITY"
	case a9trust.WatermarkUncertaintyOverflow:
		return verdict.Reason == "OVERFLOW"
	case a9trust.WatermarkUncertaintyClock:
		return verdict.Reason == "CLOCK_UNCERTAIN"
	default:
		return false
	}
}

type trackingTopicBinder struct {
	delegate TopicBinder
	failure  a9trust.Verdict
}

func (binder *trackingTopicBinder) TopicBindingForEpoch(
	ctx context.Context,
	topic []byte,
	epoch uint32,
	now time.Time,
	assertionExpiresAt time.Time,
	alreadyAccepted bool,
) ([]byte, a9trust.Verdict) {
	binding, verdict := binder.delegate.TopicBindingForEpoch(
		ctx,
		topic,
		epoch,
		now,
		assertionExpiresAt,
		alreadyAccepted,
	)
	if !verdict.IsEligible() && binder.failure.Terminal == "" {
		binder.failure = verdict
	}
	return binding, verdict
}

func writeFixedError(writer http.ResponseWriter, status int) {
	body := fixedRejectedBody
	switch status {
	case http.StatusUnauthorized:
		body = fixedAuthenticationBody
	case http.StatusServiceUnavailable:
		body = fixedUnavailableBody
	}
	writeJSON(writer, status, []byte(body))
}

func writeJSON(
	writer http.ResponseWriter,
	status int,
	body []byte,
) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}
