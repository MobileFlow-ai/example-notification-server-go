package a9api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9auth"
	"github.com/xmtp/example-notification-server-go/pkg/a9schema"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

type handlerEventLog struct {
	values []string
}

func (log *handlerEventLog) add(value string) {
	if log != nil {
		log.values = append(log.values, value)
	}
}

type handlerTrust struct {
	keyset       map[string]any
	binder       TopicBinder
	verifierErr  error
	topicVerdict a9trust.Verdict
	events       *handlerEventLog
	verifierCall int
	topicCall    int
	leaseCall    int
	leaseClose   int
	leaseErr     error
	leaseReceipt KeysetReceipt
}

func (trust *handlerTrust) Verifier(
	_ context.Context,
	_ time.Time,
) (map[string]any, error) {
	trust.verifierCall++
	trust.events.add("trust")
	if trust.verifierErr != nil {
		return nil, trust.verifierErr
	}
	return trust.keyset, nil
}

func (trust *handlerTrust) AcquireTopicBindingLease(
	_ context.Context,
	_ time.Time,
	sequence uint64,
	hash [32]byte,
) (a9trust.TopicBindingLease, error) {
	trust.leaseCall++
	trust.events.add("lease")
	trust.leaseReceipt = KeysetReceipt{Sequence: sequence, Hash: hash}
	if trust.leaseErr != nil {
		return nil, trust.leaseErr
	}
	expected, ok := keysetReceipt(trust.keyset, "dev")
	if !ok || expected != trust.leaseReceipt {
		return nil, errors.New("stale keyset lease receipt")
	}
	return &handlerTopicBindingLease{trust: trust}, nil
}

func (trust *handlerTrust) TopicBindingForEpoch(
	ctx context.Context,
	topic []byte,
	epoch uint32,
	now time.Time,
	assertionExpiresAt time.Time,
	alreadyAccepted bool,
) ([]byte, a9trust.Verdict) {
	trust.topicCall++
	trust.events.add("topic")
	if trust.topicVerdict.Terminal != "" {
		return nil, trust.topicVerdict
	}
	return trust.binder.TopicBindingForEpoch(
		ctx,
		topic,
		epoch,
		now,
		assertionExpiresAt,
		alreadyAccepted,
	)
}

type handlerTopicBindingLease struct {
	trust  *handlerTrust
	closed bool
}

func (lease *handlerTopicBindingLease) CandidateTopicBindings(
	context.Context,
	[]byte,
	time.Time,
) ([]a9trust.TopicBindingCandidate, a9trust.Verdict) {
	return nil, a9trust.Inconclusive("TRUST_UNAVAILABLE")
}

func (lease *handlerTopicBindingLease) TopicBindingForEpoch(
	ctx context.Context,
	topic []byte,
	epoch uint32,
	now time.Time,
	assertionExpiresAt time.Time,
	alreadyAccepted bool,
) ([]byte, a9trust.Verdict) {
	if lease == nil || lease.closed || lease.trust == nil {
		return nil, a9trust.Inconclusive("TRUST_UNAVAILABLE")
	}
	return lease.trust.TopicBindingForEpoch(
		ctx,
		topic,
		epoch,
		now,
		assertionExpiresAt,
		alreadyAccepted,
	)
}

func (lease *handlerTopicBindingLease) Close() {
	if lease == nil || lease.closed {
		return
	}
	lease.closed = true
	lease.trust.leaseClose++
	lease.trust.events.add("lease_close")
}

type handlerReplayStore struct {
	seen   map[string]bool
	err    error
	events *handlerEventLog
	calls  int
}

func (store *handlerReplayStore) Consume(
	_ context.Context,
	_ string,
	jti string,
	_ time.Time,
	_ time.Time,
) (bool, error) {
	store.calls++
	store.events.add("replay")
	if store.err != nil {
		return false, store.err
	}
	if store.seen == nil {
		store.seen = make(map[string]bool)
	}
	if store.seen[jti] {
		return false, nil
	}
	store.seen[jti] = true
	return true, nil
}

type handlerStore struct {
	err             error
	override        *Result
	events          *handlerEventLog
	controlCalls    int
	watermarkCalls  int
	replaceCalls    int
	control         a9trust.VerifiedControl
	watermark       a9trust.VerifiedWatermark
	retainedReplace *ReplaceRequest
	replaceReceipt  KeysetReceipt
	expectedReceipt *KeysetReceipt
	lastResult      Result
}

func (store *handlerStore) ApplyControl(
	_ context.Context,
	control a9trust.VerifiedControl,
) (Result, error) {
	store.controlCalls++
	store.events.add("control_store")
	store.control = control
	if store.err != nil {
		return Result{}, store.err
	}
	result := Result{
		Environment:            control.Environment,
		InstallationBindingID:  control.InstallationBindingID,
		SequencerEpoch:         control.SequencerEpoch,
		SubscriptionGeneration: 12,
		State:                  ResultStateActive,
		Outcome:                ResultOutcomeApplied,
		AcceptedStreamSequence: control.StreamSequence,
	}
	if control.Action == a9trust.ControlActionRevoke {
		result.State = ResultStateRevoked
	}
	return store.remember(result), nil
}

func (store *handlerStore) ApplyWatermark(
	_ context.Context,
	watermark a9trust.VerifiedWatermark,
) (Result, error) {
	store.watermarkCalls++
	store.events.add("watermark_store")
	store.watermark = watermark
	if store.err != nil {
		return Result{}, store.err
	}
	state := ResultStateActive
	if watermark.Status == a9trust.WatermarkStatusUncertain {
		state = ResultStateUncertain
	}
	return store.remember(Result{
		Environment:            watermark.Environment,
		InstallationBindingID:  watermark.InstallationBindingID,
		SequencerEpoch:         watermark.SequencerEpoch,
		SubscriptionGeneration: 12,
		State:                  state,
		Outcome:                ResultOutcomeApplied,
		AcceptedStreamSequence: watermark.CommittedThroughStreamSequence,
	}), nil
}

func (store *handlerStore) Replace(
	_ context.Context,
	replace *ReplaceRequest,
	receipt KeysetReceipt,
) (Result, error) {
	store.replaceCalls++
	store.events.add("replace_store")
	store.retainedReplace = replace
	store.replaceReceipt = receipt
	if store.expectedReceipt != nil &&
		receipt != *store.expectedReceipt {
		return Result{}, errors.New("keyset receipt rejected")
	}
	if store.err != nil {
		return Result{}, store.err
	}
	return store.remember(Result{
		Environment:            replace.Environment,
		InstallationBindingID:  replace.InstallationBindingID,
		SequencerEpoch:         replace.SequencerEpoch,
		SubscriptionGeneration: replace.SubscriptionGeneration,
		State:                  ResultStateActive,
		Outcome:                ResultOutcomeApplied,
		AcceptedStreamSequence: 7,
	}), nil
}

func (store *handlerStore) remember(result Result) Result {
	if store.override != nil {
		result = *store.override
	}
	store.lastResult = result
	return result
}

func (store *handlerStore) calls() int {
	return store.controlCalls + store.watermarkCalls + store.replaceCalls
}

type handlerKeyStateLatch struct {
	err      error
	events   *handlerEventLog
	calls    int
	verdicts []a9trust.Verdict
}

func (latch *handlerKeyStateLatch) LatchArtifactUncertainty(
	verdict a9trust.Verdict,
) error {
	latch.calls++
	latch.events.add("latch")
	latch.verdicts = append(latch.verdicts, verdict)
	return latch.err
}

type handlerHarness struct {
	handler *Handler
	trust   *handlerTrust
	replay  *handlerReplayStore
	store   *handlerStore
	latch   *handlerKeyStateLatch
	events  *handlerEventLog
}

func newHandlerHarness(
	t *testing.T,
	positive map[string]any,
	now time.Time,
) *handlerHarness {
	t.Helper()
	events := &handlerEventLog{}
	trust := &handlerTrust{
		keyset: objectValue(
			t,
			objectValue(t, positive["keyset"])["value"],
		),
		binder: publishedTopicBinder(t, positive),
		events: events,
	}
	replay := &handlerReplayStore{events: events}
	store := &handlerStore{events: events}
	latch := &handlerKeyStateLatch{events: events}
	handler, err := NewHandler(HandlerOptions{
		Environment: "dev",
		Trust:       trust,
		ReplayStore: replay,
		Store:       store,
		KeyState:    latch,
		Clock: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &handlerHarness{
		handler: handler,
		trust:   trust,
		replay:  replay,
		store:   store,
		latch:   latch,
		events:  events,
	}
}

func TestHandlerAcceptsPublishedVectorsOnExactRoutes(t *testing.T) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "service_jwt")
	controlBody := canonicalPositiveObject(t, positive, "control_upsert")
	watermarkBody := canonicalPositiveObject(t, positive, "watermark_current")
	replaceBody := []byte(stringValue(
		t,
		objectValue(t, positive["subscription_replace"])["canonical_body_utf8"],
	))

	tests := []struct {
		name       string
		method     string
		path       string
		body       []byte
		compact    string
		wantEvents []string
		storeCalls func(*handlerStore) int
	}{
		{
			name:    "control",
			method:  http.MethodPost,
			path:    ControlApplyPath,
			body:    controlBody,
			compact: publishedCompact(t, positive, "control_apply_service_jwt"),
			wantEvents: []string{
				"trust", "replay", "control_store",
			},
			storeCalls: func(store *handlerStore) int {
				return store.controlCalls
			},
		},
		{
			name:    "watermark",
			method:  http.MethodPost,
			path:    WatermarkApplyPath,
			body:    watermarkBody,
			compact: publishedCompact(t, positive, "watermark_apply_service_jwt"),
			wantEvents: []string{
				"trust", "replay", "watermark_store",
			},
			storeCalls: func(store *handlerStore) int {
				return store.watermarkCalls
			},
		},
		{
			name:    "complete subscription replacement",
			method:  http.MethodPut,
			path:    SubscriptionsReplacePath,
			body:    replaceBody,
			compact: publishedCompact(t, positive, "service_jwt"),
			wantEvents: []string{
				"trust", "replay", "lease", "topic",
				"lease_close", "replace_store",
			},
			storeCalls: func(store *handlerStore) int {
				return store.replaceCalls
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newHandlerHarness(t, positive, now)
			request := exactHandlerRequest(
				test.method,
				test.path,
				test.body,
				test.compact,
			)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("HTTP status = %d", response.Code)
			}
			assertCanonicalHandlerResult(t, response, harness.store.lastResult)
			if test.storeCalls(harness.store) != 1 ||
				harness.store.calls() != 1 {
				t.Fatal("the exact route did not call only its store method")
			}
			if test.path == SubscriptionsReplacePath {
				want, ok := keysetReceipt(
					harness.trust.keyset,
					"dev",
				)
				if !ok ||
					harness.store.replaceReceipt != want ||
					harness.trust.leaseReceipt != want ||
					harness.trust.leaseCall != 1 ||
					harness.trust.leaseClose != 1 {
					t.Fatal("replacement vault did not receive the exact keyset receipt")
				}
			}
			if harness.replay.calls != 1 ||
				harness.latch.calls != 0 ||
				!reflect.DeepEqual(
					harness.events.values,
					test.wantEvents,
				) {
				t.Fatalf(
					"boundary order = %v, want %v",
					harness.events.values,
					test.wantEvents,
				)
			}
		})
	}
}

func TestHandlerMapsOnlyCommittedCanonicalResultOutcomes(t *testing.T) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "control_apply_service_jwt")
	body := canonicalPositiveObject(t, positive, "control_upsert")
	control := objectValue(
		t,
		objectValue(t, positive["control_upsert"])["value"],
	)
	base := Result{
		Environment: "dev",
		InstallationBindingID: resultFixed16(
			t,
			control["installation_binding_id"],
		),
		SequencerEpoch: resultFixed16(
			t,
			control["sequencer_epoch"],
		),
		SubscriptionGeneration: 12,
		State:                  ResultStateActive,
		AcceptedStreamSequence: 7,
	}
	tests := []struct {
		outcome ResultOutcome
		state   ResultState
		status  int
	}{
		{ResultOutcomeApplied, ResultStateActive, http.StatusOK},
		{ResultOutcomeReplay, ResultStateActive, http.StatusOK},
		{ResultOutcomeStale, ResultStateActive, http.StatusConflict},
		{ResultOutcomeGap, ResultStateUncertain, http.StatusConflict},
		{ResultOutcomeConflict, ResultStateUncertain, http.StatusConflict},
		{
			ResultOutcomeInconclusive,
			ResultStateUncertain,
			http.StatusServiceUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(string(test.outcome), func(t *testing.T) {
			harness := newHandlerHarness(t, positive, now)
			result := base
			result.Outcome = test.outcome
			result.State = test.state
			harness.store.override = &result
			response := serveHandler(
				harness.handler,
				http.MethodPost,
				ControlApplyPath,
				body,
				publishedCompact(
					t,
					positive,
					"control_apply_service_jwt",
				),
			)
			if response.Code != test.status {
				t.Fatalf(
					"HTTP status = %d, want %d",
					response.Code,
					test.status,
				)
			}
			assertCanonicalHandlerResult(t, response, result)
		})
	}
}

func TestHandlerConsumesReplayBeforeMalformedSchemaIsExposed(
	t *testing.T,
) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "control_apply_service_jwt")
	body := []byte(`{"protocol":"not-an-a9-control"}`)
	compact := boundServiceJWT(
		t,
		positive,
		"control_apply_service_jwt",
		body,
		"00000000-0000-4000-8000-000000000101",
	)
	harness := newHandlerHarness(t, positive, now)

	first := httptest.NewRecorder()
	harness.handler.ServeHTTP(
		first,
		exactHandlerRequest(
			http.MethodPost,
			ControlApplyPath,
			body,
			compact,
		),
	)
	assertFixedHandlerError(t, first, http.StatusBadRequest)
	if harness.replay.calls != 1 || harness.store.calls() != 0 {
		t.Fatal("malformed schema was processed before durable JTI consume")
	}

	second := httptest.NewRecorder()
	harness.handler.ServeHTTP(
		second,
		exactHandlerRequest(
			http.MethodPost,
			ControlApplyPath,
			body,
			compact,
		),
	)
	assertFixedHandlerError(t, second, http.StatusUnauthorized)
	if harness.replay.calls != 2 ||
		harness.store.calls() != 0 ||
		!reflect.DeepEqual(
			harness.events.values,
			[]string{"trust", "replay", "trust", "replay"},
		) {
		t.Fatalf("boundary order = %v", harness.events.values)
	}
}

func TestHandlerRejectsFramingBeforeTrustReplayAndStorage(t *testing.T) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "control_apply_service_jwt")
	body := canonicalPositiveObject(t, positive, "control_upsert")
	compact := publishedCompact(t, positive, "control_apply_service_jwt")

	tests := map[string]struct {
		status int
		mutate func(*http.Request)
	}{
		"unknown route": {
			status: http.StatusNotFound,
			mutate: func(request *http.Request) {
				request.URL.Path = "/internal/v1/xmtp-push/not-a9"
				request.RequestURI = request.URL.Path
			},
		},
		"wrong method": {
			status: http.StatusMethodNotAllowed,
			mutate: func(request *http.Request) {
				request.Method = http.MethodGet
			},
		},
		"no TLS": {
			status: http.StatusBadRequest,
			mutate: func(request *http.Request) {
				request.TLS = nil
			},
		},
		"query": {
			status: http.StatusBadRequest,
			mutate: func(request *http.Request) {
				request.URL.RawQuery = "debug=1"
				request.RequestURI = ControlApplyPath + "?debug=1"
			},
		},
		"empty query marker": {
			status: http.StatusBadRequest,
			mutate: func(request *http.Request) {
				request.URL.ForceQuery = true
				request.RequestURI = ControlApplyPath + "?"
			},
		},
		"escaped alias": {
			status: http.StatusBadRequest,
			mutate: func(request *http.Request) {
				request.URL.RawPath =
					"/internal/v1/xmtp-push/a9-authority%3Aapply"
				request.RequestURI = request.URL.RawPath
			},
		},
		"missing authorization": {
			status: http.StatusUnauthorized,
			mutate: func(request *http.Request) {
				request.Header.Del("Authorization")
			},
		},
		"duplicate authorization": {
			status: http.StatusUnauthorized,
			mutate: func(request *http.Request) {
				request.Header.Add(
					"Authorization",
					request.Header.Get("Authorization"),
				)
			},
		},
		"noncanonical bearer": {
			status: http.StatusUnauthorized,
			mutate: func(request *http.Request) {
				request.Header.Set(
					"Authorization",
					"bearer invalid.invalid.invalid",
				)
			},
		},
		"content type parameter": {
			status: http.StatusUnsupportedMediaType,
			mutate: func(request *http.Request) {
				request.Header.Set(
					"Content-Type",
					"application/json; charset=utf-8",
				)
			},
		},
		"duplicate content type": {
			status: http.StatusUnsupportedMediaType,
			mutate: func(request *http.Request) {
				request.Header.Add("Content-Type", "application/json")
			},
		},
		"content encoding": {
			status: http.StatusUnsupportedMediaType,
			mutate: func(request *http.Request) {
				request.Header.Set("Content-Encoding", "gzip")
			},
		},
		"empty body": {
			status: http.StatusBadRequest,
			mutate: func(request *http.Request) {
				request.Body = http.NoBody
				request.ContentLength = 0
			},
		},
		"declared oversized body": {
			status: http.StatusRequestEntityTooLarge,
			mutate: func(request *http.Request) {
				request.ContentLength = MaxRequestBodyBytes + 1
			},
		},
		"content length mismatch": {
			status: http.StatusBadRequest,
			mutate: func(request *http.Request) {
				request.ContentLength++
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			harness := newHandlerHarness(t, positive, now)
			request := exactHandlerRequest(
				http.MethodPost,
				ControlApplyPath,
				body,
				compact,
			)
			test.mutate(request)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			assertFixedHandlerError(t, response, test.status)
			if harness.trust.verifierCall != 0 ||
				harness.replay.calls != 0 ||
				harness.store.calls() != 0 ||
				harness.latch.calls != 0 ||
				len(harness.events.values) != 0 {
				t.Fatalf(
					"early rejection touched downstream state: %v",
					harness.events.values,
				)
			}
		})
	}
}

func TestHandlerFailsClosedAcrossTrustAuthReplayAndStoreFailures(
	t *testing.T,
) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "control_apply_service_jwt")
	body := canonicalPositiveObject(t, positive, "control_upsert")
	compact := publishedCompact(t, positive, "control_apply_service_jwt")

	t.Run("trust snapshot unavailable", func(t *testing.T) {
		harness := newHandlerHarness(t, positive, now)
		harness.trust.verifierErr = errors.New("unavailable")
		response := serveHandler(
			harness.handler,
			http.MethodPost,
			ControlApplyPath,
			body,
			compact,
		)
		assertFixedHandlerError(
			t,
			response,
			http.StatusServiceUnavailable,
		)
		if harness.replay.calls != 0 ||
			harness.store.calls() != 0 ||
			harness.latch.calls != 0 {
			t.Fatal("trust failure reached replay, storage, or artifact latch")
		}
	})

	t.Run("JWT body binding failure", func(t *testing.T) {
		harness := newHandlerHarness(t, positive, now)
		changed := append(append([]byte(nil), body...), ' ')
		response := serveHandler(
			harness.handler,
			http.MethodPost,
			ControlApplyPath,
			changed,
			compact,
		)
		assertFixedHandlerError(t, response, http.StatusUnauthorized)
		if harness.replay.calls != 0 ||
			harness.store.calls() != 0 ||
			harness.latch.calls != 0 {
			t.Fatal("invalid JWT reached replay, storage, or artifact latch")
		}
	})

	t.Run("replay store unavailable", func(t *testing.T) {
		harness := newHandlerHarness(t, positive, now)
		harness.replay.err = errors.New("unavailable")
		response := serveHandler(
			harness.handler,
			http.MethodPost,
			ControlApplyPath,
			body,
			compact,
		)
		assertFixedHandlerError(
			t,
			response,
			http.StatusServiceUnavailable,
		)
		if harness.replay.calls != 1 ||
			harness.store.calls() != 0 ||
			harness.latch.calls != 0 {
			t.Fatal("replay uncertainty did not fail before artifact storage")
		}
	})

	t.Run("vault unavailable", func(t *testing.T) {
		harness := newHandlerHarness(t, positive, now)
		harness.store.err = errors.New("unavailable")
		response := serveHandler(
			harness.handler,
			http.MethodPost,
			ControlApplyPath,
			body,
			compact,
		)
		assertFixedHandlerError(
			t,
			response,
			http.StatusServiceUnavailable,
		)
		if harness.replay.calls != 1 ||
			harness.store.controlCalls != 1 ||
			harness.latch.calls != 0 {
			t.Fatal("vault uncertainty did not preserve boundary ordering")
		}
	})

	t.Run("mismatched vault result identity", func(t *testing.T) {
		harness := newHandlerHarness(t, positive, now)
		override := validTestResult()
		harness.store.override = &override
		response := serveHandler(
			harness.handler,
			http.MethodPost,
			ControlApplyPath,
			body,
			compact,
		)
		assertFixedHandlerError(
			t,
			response,
			http.StatusServiceUnavailable,
		)
		if harness.store.controlCalls != 1 {
			t.Fatal("identity mismatch was not detected after the vault call")
		}
	})
}

func TestHandlerLatchesOnlyArtifactKeyStateVerdicts(t *testing.T) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "control_apply_service_jwt")
	control := cloneObject(
		t,
		objectValue(t, objectValue(t, positive["control_upsert"])["value"]),
	)
	control["signing_key_id"] =
		"ed25519-sha256:0000000000000000000000000000000000000000000000000000000000000000"
	body, err := a9trust.Canonicalize(control)
	if err != nil {
		t.Fatal(err)
	}
	compact := boundServiceJWT(
		t,
		positive,
		"control_apply_service_jwt",
		body,
		"00000000-0000-4000-8000-000000000102",
	)
	harness := newHandlerHarness(t, positive, now)
	harness.latch.err = errors.New("latch unavailable")
	response := serveHandler(
		harness.handler,
		http.MethodPost,
		ControlApplyPath,
		body,
		compact,
	)
	assertFixedHandlerError(t, response, http.StatusServiceUnavailable)
	if harness.replay.calls != 1 ||
		harness.store.calls() != 0 ||
		harness.latch.calls != 1 ||
		len(harness.latch.verdicts) != 1 ||
		!harness.latch.verdicts[0].RequiresKeysetUncertainty() ||
		!reflect.DeepEqual(
			harness.events.values,
			[]string{"trust", "replay", "latch"},
		) {
		t.Fatalf("artifact key-state order = %v", harness.events.values)
	}
}

func TestHandlerLatchesReplaceTopicKeyStateBeforeStorage(t *testing.T) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "service_jwt")
	body := []byte(stringValue(
		t,
		objectValue(t, positive["subscription_replace"])["canonical_body_utf8"],
	))
	harness := newHandlerHarness(t, positive, now)
	harness.trust.topicVerdict = a9trust.Inconclusive("KEY_STATE")
	response := serveHandler(
		harness.handler,
		http.MethodPut,
		SubscriptionsReplacePath,
		body,
		publishedCompact(t, positive, "service_jwt"),
	)
	assertFixedHandlerError(t, response, http.StatusServiceUnavailable)
	if harness.replay.calls != 1 ||
		harness.trust.topicCall != 1 ||
		harness.store.calls() != 0 ||
		harness.latch.calls != 1 ||
		!reflect.DeepEqual(
			harness.events.values,
			[]string{
				"trust", "replay", "lease", "topic",
				"lease_close", "latch",
			},
		) {
		t.Fatalf("topic key-state order = %v", harness.events.values)
	}
}

func TestHandlerDoesNotLatchTransientReplaceTrustFailure(
	t *testing.T,
) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "service_jwt")
	body := []byte(stringValue(
		t,
		objectValue(t, positive["subscription_replace"])["canonical_body_utf8"],
	))
	harness := newHandlerHarness(t, positive, now)
	harness.trust.topicVerdict =
		a9trust.Inconclusive("TRUST_UNAVAILABLE")
	response := serveHandler(
		harness.handler,
		http.MethodPut,
		SubscriptionsReplacePath,
		body,
		publishedCompact(t, positive, "service_jwt"),
	)
	assertFixedHandlerError(t, response, http.StatusServiceUnavailable)
	if harness.replay.calls != 1 ||
		harness.trust.topicCall != 1 ||
		harness.store.calls() != 0 ||
		harness.latch.calls != 0 ||
		!reflect.DeepEqual(
			harness.events.values,
			[]string{
				"trust", "replay", "lease", "topic",
				"lease_close",
			},
		) {
		t.Fatalf(
			"transient topic trust order = %v",
			harness.events.values,
		)
	}
}

func TestHandlerFailsClosedBeforeDecodeWhenTopicLeaseUnavailable(
	t *testing.T,
) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "service_jwt")
	body := []byte(stringValue(
		t,
		objectValue(t, positive["subscription_replace"])["canonical_body_utf8"],
	))
	harness := newHandlerHarness(t, positive, now)
	harness.trust.leaseErr = errors.New("durable currentness unavailable")
	response := serveHandler(
		harness.handler,
		http.MethodPut,
		SubscriptionsReplacePath,
		body,
		publishedCompact(t, positive, "service_jwt"),
	)
	assertFixedHandlerError(t, response, http.StatusServiceUnavailable)
	if harness.replay.calls != 1 ||
		harness.trust.leaseCall != 1 ||
		harness.trust.leaseClose != 0 ||
		harness.trust.topicCall != 0 ||
		harness.store.calls() != 0 ||
		harness.latch.calls != 0 ||
		!reflect.DeepEqual(
			harness.events.values,
			[]string{"trust", "replay", "lease"},
		) {
		t.Fatalf(
			"unavailable topic lease order = %v",
			harness.events.values,
		)
	}
}

func TestHandlerFailsClosedWhenVaultRejectsSampledKeysetReceipt(
	t *testing.T,
) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "service_jwt")
	body := []byte(stringValue(
		t,
		objectValue(t, positive["subscription_replace"])["canonical_body_utf8"],
	))
	harness := newHandlerHarness(t, positive, now)
	current, ok := keysetReceipt(harness.trust.keyset, "dev")
	if !ok {
		t.Fatal("published keyset did not produce a receipt")
	}
	advanced := current
	advanced.Sequence++
	harness.store.expectedReceipt = &advanced
	response := serveHandler(
		harness.handler,
		http.MethodPut,
		SubscriptionsReplacePath,
		body,
		publishedCompact(t, positive, "service_jwt"),
	)
	assertFixedHandlerError(
		t,
		response,
		http.StatusServiceUnavailable,
	)
	if harness.store.replaceCalls != 1 ||
		harness.store.replaceReceipt != current ||
		harness.store.lastResult != (Result{}) ||
		harness.latch.calls != 0 {
		t.Fatal("stale sampled keyset receipt did not fail closed at the vault")
	}
}

func TestKeysetReceiptMatchesPublishedSignedObject(t *testing.T) {
	positive := readPositive(t)
	keysetVector := objectValue(t, positive["keyset"])
	keyset := objectValue(t, keysetVector["value"])
	receipt, ok := keysetReceipt(keyset, "dev")
	if !ok {
		t.Fatal("published keyset did not produce a receipt")
	}
	wantHash, err := hex.DecodeString(
		stringValue(t, keysetVector["signed_object_sha256"]),
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Sequence != integerValue(t, keyset["keyset_sequence"]) ||
		!bytes.Equal(receipt.Hash[:], wantHash) {
		t.Fatal("keyset receipt did not match published provenance")
	}
}

func TestHandlerPersistsOnlySignatureValidUncertainWatermark(
	t *testing.T,
) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "watermark_apply_service_jwt")
	watermark := cloneObject(
		t,
		objectValue(t, objectValue(t, positive["watermark_current"])["value"]),
	)
	watermark["status"] = "UNCERTAIN"
	watermark["uncertainty_reason"] = "SOURCE_UNAVAILABLE"
	resignWatermarkForHandler(t, positive, watermark)
	body, err := a9trust.Canonicalize(watermark)
	if err != nil {
		t.Fatal(err)
	}
	compact := boundServiceJWT(
		t,
		positive,
		"watermark_apply_service_jwt",
		body,
		"00000000-0000-4000-8000-000000000103",
	)
	harness := newHandlerHarness(t, positive, now)
	response := serveHandler(
		harness.handler,
		http.MethodPost,
		WatermarkApplyPath,
		body,
		compact,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d", response.Code)
	}
	assertCanonicalHandlerResult(t, response, harness.store.lastResult)
	if harness.store.watermarkCalls != 1 ||
		harness.store.watermark.Status !=
			a9trust.WatermarkStatusUncertain ||
		harness.store.watermark.UncertaintyReason !=
			a9trust.WatermarkUncertaintySourceUnavailable ||
		harness.latch.calls != 0 {
		t.Fatal("valid signed uncertainty was not persisted exactly once")
	}

	t.Run("bad artifact signature", func(t *testing.T) {
		badWatermark := cloneObject(t, watermark)
		badWatermark["signature_base64url"] =
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		badBody, err := a9trust.Canonicalize(badWatermark)
		if err != nil {
			t.Fatal(err)
		}
		badCompact := boundServiceJWT(
			t,
			positive,
			"watermark_apply_service_jwt",
			badBody,
			"00000000-0000-4000-8000-000000000104",
		)
		badHarness := newHandlerHarness(t, positive, now)
		badResponse := serveHandler(
			badHarness.handler,
			http.MethodPost,
			WatermarkApplyPath,
			badBody,
			badCompact,
		)
		assertFixedHandlerError(t, badResponse, http.StatusBadRequest)
		if badHarness.replay.calls != 1 ||
			badHarness.store.calls() != 0 ||
			badHarness.latch.calls != 0 {
			t.Fatal("noneligible watermark reached storage or key latch")
		}
	})
}

func TestHandlerErasesReplacementIngressAfterVaultCall(t *testing.T) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "service_jwt")
	body := []byte(stringValue(
		t,
		objectValue(t, positive["subscription_replace"])["canonical_body_utf8"],
	))
	harness := newHandlerHarness(t, positive, now)
	response := serveHandler(
		harness.handler,
		http.MethodPut,
		SubscriptionsReplacePath,
		body,
		publishedCompact(t, positive, "service_jwt"),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d", response.Code)
	}
	retained := harness.store.retainedReplace
	if retained == nil ||
		retained.Environment != "" ||
		retained.PolicyControl != nil ||
		retained.Subscriptions != nil ||
		!allZero(retained.InstallationBindingID[:]) ||
		!allZero(retained.APNSToken[:]) ||
		!allZero(retained.RequestHash[:]) {
		t.Fatal("request-scoped replacement ingress was not erased")
	}
}

func TestHandlerAcceptsMaximumReplacementWithinDeadline(t *testing.T) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "service_jwt")
	fixture := maximumReplacementObject(
		t,
		positive,
		maximumReplacementSubscriptions,
	)
	body, err := a9trust.Canonicalize(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(body)) > MaxRequestBodyBytes {
		t.Fatalf(
			"maximum replacement body = %d bytes, limit = %d",
			len(body),
			MaxRequestBodyBytes,
		)
	}

	harness := newHandlerHarness(t, positive, now)
	binder := &deadlineCountingBinder{
		delegate: publishedTopicBinder(t, positive),
	}
	harness.trust.binder = binder
	compact := boundServiceJWT(
		t,
		positive,
		"service_jwt",
		body,
		"00000000-0000-4000-8000-000000002048",
	)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		maximumReplacementTestDeadline,
	)
	defer cancel()
	request := exactHandlerRequest(
		http.MethodPut,
		SubscriptionsReplacePath,
		body,
		compact,
	).WithContext(ctx)
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, body = %q", response.Code, response.Body)
	}
	if ctx.Err() != nil {
		t.Fatalf("maximum replacement exceeded its deadline: %v", ctx.Err())
	}
	if binder.calls != maximumReplacementSubscriptions ||
		harness.trust.topicCall != maximumReplacementSubscriptions {
		t.Fatalf(
			"topic-binding calls = %d/%d, want %d",
			binder.calls,
			harness.trust.topicCall,
			maximumReplacementSubscriptions,
		)
	}
	if harness.trust.leaseCall != 1 ||
		harness.trust.leaseClose != 1 ||
		harness.replay.calls != 1 ||
		harness.store.replaceCalls != 1 ||
		harness.store.calls() != 1 ||
		harness.latch.calls != 0 {
		t.Fatalf(
			"boundary counts lease=%d close=%d replay=%d replace=%d stores=%d latch=%d",
			harness.trust.leaseCall,
			harness.trust.leaseClose,
			harness.replay.calls,
			harness.store.replaceCalls,
			harness.store.calls(),
			harness.latch.calls,
		)
	}
}

func TestNewHandlerRequiresEveryFailClosedDependency(t *testing.T) {
	positive := readPositive(t)
	now := publishedJWTTime(t, positive, "service_jwt")
	valid := newHandlerHarness(t, positive, now)
	base := HandlerOptions{
		Environment: "dev",
		Trust:       valid.trust,
		ReplayStore: valid.replay,
		Store:       valid.store,
		KeyState:    valid.latch,
		Clock:       func() time.Time { return now },
	}
	tests := map[string]func(*HandlerOptions){
		"environment": func(options *HandlerOptions) {
			options.Environment = "staging"
		},
		"trust": func(options *HandlerOptions) {
			options.Trust = nil
		},
		"replay": func(options *HandlerOptions) {
			options.ReplayStore = nil
		},
		"store": func(options *HandlerOptions) {
			options.Store = nil
		},
		"key latch": func(options *HandlerOptions) {
			options.KeyState = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := base
			mutate(&options)
			if handler, err := NewHandler(options); handler != nil ||
				!errors.Is(err, ErrHandlerConfiguration) {
				t.Fatalf("handler = %v, error = %v", handler, err)
			}
		})
	}
}

func exactHandlerRequest(
	method string,
	path string,
	body []byte,
	compact string,
) *http.Request {
	request := httptest.NewRequest(
		method,
		"https://a9-bridge.invalid"+path,
		bytes.NewReader(body),
	)
	request.RequestURI = path
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+compact)
	return request
}

func serveHandler(
	handler *Handler,
	method string,
	path string,
	body []byte,
	compact string,
) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(
		response,
		exactHandlerRequest(method, path, body, compact),
	)
	return response
}

func assertFixedHandlerError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("HTTP status = %d, want %d", response.Code, status)
	}
	want := fixedRejectedBody
	if status == http.StatusUnauthorized {
		want = fixedAuthenticationBody
	}
	if status == http.StatusServiceUnavailable {
		want = fixedUnavailableBody
	}
	if response.Body.String() != want {
		t.Fatal("error response was not the fixed content-free body")
	}
	assertHandlerResponseHeaders(t, response)
}

func assertCanonicalHandlerResult(
	t *testing.T,
	response *httptest.ResponseRecorder,
	result Result,
) {
	t.Helper()
	raw := response.Body.Bytes()
	value, err := a9schema.Decode(a9schema.ResultKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := a9trust.Canonicalize(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		t.Fatal("handler result was not canonical")
	}
	want, err := result.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, raw) {
		t.Fatal("handler result did not match the committed vault result")
	}
	assertHandlerResponseHeaders(t, response)
}

func assertHandlerResponseHeaders(
	t *testing.T,
	response *httptest.ResponseRecorder,
) {
	t.Helper()
	if response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("handler response headers were not privacy hardened")
	}
}

func canonicalPositiveObject(
	t *testing.T,
	positive map[string]any,
	name string,
) []byte {
	t.Helper()
	raw, err := a9trust.Canonicalize(
		objectValue(t, objectValue(t, positive[name])["value"]),
	)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func publishedCompact(
	t *testing.T,
	positive map[string]any,
	name string,
) string {
	t.Helper()
	return stringValue(t, objectValue(t, positive[name])["compact"])
}

func publishedJWTTime(
	t *testing.T,
	positive map[string]any,
	name string,
) time.Time {
	t.Helper()
	claims := objectValue(t, objectValue(t, positive[name])["claims"])
	return time.Unix(int64(integerValue(t, claims["iat"])), 0).UTC()
}

func boundServiceJWT(
	t *testing.T,
	positive map[string]any,
	templateName string,
	body []byte,
	jti string,
) string {
	t.Helper()
	template := objectValue(t, positive[templateName])
	header := cloneObject(t, objectValue(t, template["header"]))
	claims := cloneObject(t, objectValue(t, template["claims"]))
	sum := sha256.Sum256(body)
	claims["request_sha256"] = hex.EncodeToString(sum[:])
	claims["jti"] = jti
	keys := objectValue(t, positive["test_keys"])
	seed, err := a9trust.DecodeBase64URL(
		stringValue(t, keys["service_auth_private_seed_base64url"]),
		32,
	)
	if err != nil {
		t.Fatal(err)
	}
	compact, _, err := a9trust.BuildJWT(header, claims, seed)
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func resignWatermarkForHandler(
	t *testing.T,
	positive map[string]any,
	watermark map[string]any,
) {
	t.Helper()
	keys := objectValue(t, positive["test_keys"])
	seed, err := a9trust.DecodeBase64URL(
		stringValue(t, keys["control_private_seed_base64url"]),
		32,
	)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := a9trust.SignObject(
		watermark,
		"signature_base64url",
		a9trust.WatermarkSignatureDomain,
		seed,
	)
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	watermark["signature_base64url"] = signature
}

var _ a9auth.ReplayStore = (*handlerReplayStore)(nil)
