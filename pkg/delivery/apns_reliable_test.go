package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sideshow/apns2"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type fixedAPNSClock struct {
	now time.Time
}

func (c *fixedAPNSClock) Now() time.Time {
	return c.now
}

func (c *fixedAPNSClock) After(time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

type advancingAPNSClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *advancingAPNSClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *advancingAPNSClock) After(delay time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.now = c.now.Add(delay)
	now := c.now
	c.mu.Unlock()
	result := make(chan time.Time, 1)
	result <- now
	return result
}

type fakeDeliveryJobStore struct {
	mu sync.Mutex

	recovered             bool
	erasuresRecovered     bool
	enqueueErr            error
	enqueued              []vault.SerializedDeliveryJob
	enqueuedIDs           [][]byte
	sourceEvents          []string
	claims                []vault.ClaimedDeliveryJob
	erasureClaims         []vault.ClaimedDeliveryJob
	claimErr              error
	claimPanic            any
	claimValidationDenied bool
	claimValidationErr    error
	claimValidations      [][]byte
	attemptRecordErr      error
	attemptRecords        [][]byte
	claimCalls            chan struct{}
	rescheduled           []rescheduledJob
	erasures              []rescheduledJob
	conversions           []invalidTokenConversion
	convertErr            error
	convertNoop           bool
	released              [][]byte
	deleted               [][]byte
	finalized             []finalizedJob
	observations          []vault.DeliveryObservation
}

type rescheduledJob struct {
	id        []byte
	attempts  int
	available time.Time
}

type invalidTokenConversion struct {
	id                 []byte
	installationLookup []byte
	deviceToken        string
	trafficClass       vault.DeliveryTrafficClass
	available          time.Time
}

type finalizedJob struct {
	id     []byte
	reason vault.DeliveryFinalReason
}

type fakeDeliveryAttemptGuard struct {
	store *fakeDeliveryJobStore
	jobID []byte
	job   vault.ClaimedDeliveryJob
	done  bool
}

func (g *fakeDeliveryAttemptGuard) Complete(
	_ context.Context,
	result vault.DeliveryAttemptResult,
) error {
	g.store.mu.Lock()
	defer g.store.mu.Unlock()
	if g.done {
		return vault.ErrDeliveryJobInvalid
	}
	g.done = true
	if g.store.attemptRecordErr != nil {
		return g.store.attemptRecordErr
	}
	g.store.attemptRecords = append(
		g.store.attemptRecords,
		append([]byte(nil), g.jobID...),
	)
	switch result.Outcome {
	case vault.DeliveryAttemptSent, vault.DeliveryAttemptRejected:
		g.store.deleted = append(
			g.store.deleted,
			append([]byte(nil), g.jobID...),
		)
	case vault.DeliveryAttemptTransient:
		if g.job.Attempts >= vault.MaxDeliveryAttempts ||
			!result.RetryAt.Before(g.job.ExpiresAt) {
			g.store.deleted = append(
				g.store.deleted,
				append([]byte(nil), g.jobID...),
			)
		} else {
			g.store.rescheduled = append(
				g.store.rescheduled,
				rescheduledJob{
					id:        append([]byte(nil), g.jobID...),
					attempts:  g.job.Attempts,
					available: result.RetryAt,
				},
			)
		}
	case vault.DeliveryAttemptInvalidToken:
		installationLookup := bytes.Repeat([]byte{8}, 32)
		g.store.conversions = append(
			g.store.conversions,
			invalidTokenConversion{
				id:                 append([]byte(nil), g.jobID...),
				installationLookup: installationLookup,
				deviceToken:        g.job.Job.DeviceToken,
				trafficClass:       g.job.Job.TrafficClass,
				available:          result.RetryAt,
			},
		)
		if g.store.convertErr != nil {
			return g.store.convertErr
		}
	default:
		return vault.ErrDeliveryJobInvalid
	}
	return nil
}

func (g *fakeDeliveryAttemptGuard) RecordAttempt(context.Context) error {
	g.store.mu.Lock()
	defer g.store.mu.Unlock()
	if g.done {
		return vault.ErrDeliveryJobInvalid
	}
	g.done = true
	if g.store.attemptRecordErr != nil {
		return g.store.attemptRecordErr
	}
	g.store.attemptRecords = append(
		g.store.attemptRecords,
		append([]byte(nil), g.jobID...),
	)
	return nil
}

func (g *fakeDeliveryAttemptGuard) Release() error {
	if g == nil {
		return nil
	}
	g.done = true
	return nil
}

func (s *fakeDeliveryJobStore) EnqueueDeliveryJob(
	_ context.Context,
	leaseID []byte,
	job vault.SerializedDeliveryJob,
	sourceEventID string,
	_ int,
) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enqueueErr != nil {
		return nil, s.enqueueErr
	}
	s.enqueued = append(s.enqueued, job)
	s.enqueuedIDs = append(s.enqueuedIDs, append([]byte(nil), leaseID...))
	s.sourceEvents = append(s.sourceEvents, sourceEventID)
	return bytes.Repeat([]byte{9}, 16), nil
}

func (s *fakeDeliveryJobStore) ValidateDeliveryClaim(
	_ context.Context,
	job vault.ClaimedDeliveryJob,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimValidations = append(
		s.claimValidations,
		append([]byte(nil), job.JobID...),
	)
	if s.claimValidationErr != nil {
		return false, s.claimValidationErr
	}
	return !s.claimValidationDenied, nil
}

func (s *fakeDeliveryJobStore) AcquireDeliveryAttempt(
	_ context.Context,
	job vault.ClaimedDeliveryJob,
) (vault.DeliveryAttemptGuard, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimValidations = append(
		s.claimValidations,
		append([]byte(nil), job.JobID...),
	)
	if s.claimValidationErr != nil {
		return nil, false, s.claimValidationErr
	}
	if s.claimValidationDenied {
		return nil, false, nil
	}
	return &fakeDeliveryAttemptGuard{
		store: s,
		jobID: append([]byte(nil), job.JobID...),
		job:   job,
	}, true, nil
}

func (s *fakeDeliveryJobStore) RecoverDeliveryJobs(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recovered = true
	return nil
}

func (s *fakeDeliveryJobStore) RecoverInvalidTokenErasures(
	context.Context,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.erasuresRecovered = true
	return nil
}

func (s *fakeDeliveryJobStore) ClaimDeliveryJobs(
	_ context.Context,
	limit int,
	_ time.Duration,
) ([]vault.ClaimedDeliveryJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimCalls != nil {
		select {
		case s.claimCalls <- struct{}{}:
		default:
		}
	}
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	if s.claimPanic != nil {
		panic(s.claimPanic)
	}
	if len(s.claims) == 0 {
		return nil, nil
	}
	if limit > len(s.claims) {
		limit = len(s.claims)
	}
	result := append([]vault.ClaimedDeliveryJob(nil), s.claims[:limit]...)
	s.claims = s.claims[limit:]
	return result, nil
}

func (s *fakeDeliveryJobStore) ClaimErasureJobs(
	_ context.Context,
	limit int,
	_ time.Duration,
) ([]vault.ClaimedDeliveryJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.erasureClaims) == 0 {
		return nil, nil
	}
	if limit > len(s.erasureClaims) {
		limit = len(s.erasureClaims)
	}
	result := append(
		[]vault.ClaimedDeliveryJob(nil),
		s.erasureClaims[:limit]...,
	)
	s.erasureClaims = s.erasureClaims[limit:]
	return result, nil
}

func (s *fakeDeliveryJobStore) RescheduleDeliveryJob(
	_ context.Context,
	jobID []byte,
	attempts int,
	availableAt time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rescheduled = append(s.rescheduled, rescheduledJob{
		id:        append([]byte(nil), jobID...),
		attempts:  attempts,
		available: availableAt,
	})
	return nil
}

func (s *fakeDeliveryJobStore) ConvertInvalidTokenToErasure(
	_ context.Context,
	jobID []byte,
	failedDeviceToken string,
	trafficClass vault.DeliveryTrafficClass,
	availableAt time.Time,
) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	installationLookup := bytes.Repeat([]byte{8}, 32)
	s.conversions = append(s.conversions, invalidTokenConversion{
		id:                 append([]byte(nil), jobID...),
		installationLookup: installationLookup,
		deviceToken:        failedDeviceToken,
		trafficClass:       trafficClass,
		available:          availableAt,
	})
	if s.convertErr != nil {
		return nil, s.convertErr
	}
	if s.convertNoop {
		return nil, nil
	}
	return append([]byte(nil), installationLookup...), nil
}

func (s *fakeDeliveryJobStore) RescheduleInvalidTokenErasure(
	_ context.Context,
	jobID []byte,
	availableAt time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.erasures = append(s.erasures, rescheduledJob{
		id:        append([]byte(nil), jobID...),
		available: availableAt,
	})
	return nil
}

func (s *fakeDeliveryJobStore) ReleaseDeliveryJob(
	_ context.Context,
	jobID []byte,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.released = append(s.released, append([]byte(nil), jobID...))
	return nil
}

func (s *fakeDeliveryJobStore) FinalizeDeliveryJob(
	_ context.Context,
	jobID []byte,
	reason vault.DeliveryFinalReason,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, append([]byte(nil), jobID...))
	s.finalized = append(s.finalized, finalizedJob{
		id:     append([]byte(nil), jobID...),
		reason: reason,
	})
	return nil
}

func (s *fakeDeliveryJobStore) DeleteErasureJob(
	_ context.Context,
	jobID []byte,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, append([]byte(nil), jobID...))
	return nil
}

func (s *fakeDeliveryJobStore) RecordDeliveryObservation(
	_ context.Context,
	observation vault.DeliveryObservation,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observations = append(s.observations, observation)
	return nil
}

type fakeInvalidTokenEraser struct {
	mu                  sync.Mutex
	installationLookups [][]byte
	deviceTokens        []string
	err                 error
	panicValue          any
}

func (e *fakeInvalidTokenEraser) EraseInvalidAPNSToken(
	_ context.Context,
	installationLookup []byte,
	failedDeviceToken string,
) error {
	if e.panicValue != nil {
		panic(e.panicValue)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.installationLookups = append(
		e.installationLookups,
		append([]byte(nil), installationLookup...),
	)
	e.deviceTokens = append(e.deviceTokens, failedDeviceToken)
	return e.err
}

type reliableFakeClient struct {
	mu            sync.Mutex
	responses     []*apns2.Response
	errs          []error
	notifications []*apns2.Notification
	block         <-chan struct{}
	started       chan<- struct{}
	active        int
	maxActive     int
}

func (c *reliableFakeClient) PushWithContext(
	ctx apns2.Context,
	notification *apns2.Notification,
) (*apns2.Response, error) {
	c.mu.Lock()
	index := len(c.notifications)
	c.notifications = append(c.notifications, notification)
	c.active++
	if c.active > c.maxActive {
		c.maxActive = c.active
	}
	var response *apns2.Response
	var err error
	if index < len(c.responses) {
		response = c.responses[index]
	}
	if index < len(c.errs) {
		err = c.errs[index]
	}
	c.mu.Unlock()
	if c.started != nil {
		c.started <- struct{}{}
	}
	if c.block != nil {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-c.block:
		}
	}
	c.mu.Lock()
	c.active--
	c.mu.Unlock()
	return response, err
}

func newReliabilityFixture(
	now time.Time,
	client apnsClient,
	store *fakeDeliveryJobStore,
) *ApnsDelivery {
	opts := options.ApnsOptions{
		SecureWrapperRequired: true,
		RatePerSecond:         100,
		RateBurst:             100,
		MaxConcurrency:        2,
		QueueCapacity:         10,
		QueuePollIntervalMs:   100,
		RequestTimeoutSeconds: 10,
		InitialRetryDelayMs:   1000,
		MaxRetryDelayMs:       10_000,
	}
	reliable := newAPNSReliability(zap.NewNop(), opts, store)
	clock := &fixedAPNSClock{now: now}
	reliable.clock = clock
	reliable.limiter = newAPNSTokenBucket(100, 100, now)
	reliable.jitter = bytes.NewReader([]byte{0, 0})
	reliable.workCtx, reliable.cancel = context.WithCancel(context.Background())
	return &ApnsDelivery{
		apnsClient: client,
		opts:       opts,
		now:        clock.Now,
		reliable:   reliable,
		logger:     zap.NewNop(),
	}
}

func claimedJobFixture(now time.Time, attempts int) vault.ClaimedDeliveryJob {
	return vault.ClaimedDeliveryJob{
		JobID:              bytes.Repeat([]byte{3}, 16),
		LeaseID:            bytes.Repeat([]byte{4}, 16),
		InstallationLookup: bytes.Repeat([]byte{8}, 32),
		Job: vault.SerializedDeliveryJob{
			DeviceToken:      strings.Repeat("ab", 32),
			Topic:            "com.example.app",
			Payload:          []byte(`{"aps":{"alert":"New message"},"hytch_wrapper":{"header":{"v":1},"ciphertext":"exact"}}`),
			PushType:         string(apns2.PushTypeAlert),
			Priority:         apns2.PriorityHigh,
			Expiration:       now.Add(15 * time.Minute),
			TrafficClass:     vault.DeliveryTrafficConversation,
			PolicyEpoch:      1,
			RouteKeyEpoch:    1,
			NoncePrefix:      0x01020304,
			DeliverySequence: 0,
			AliasDay:         gate8wrapper.UTCDay(now),
			RouteAlias: bytes.Repeat(
				[]byte{7},
				gate8wrapper.RouteAliasSize,
			),
		},
		Attempts:  attempts,
		ExpiresAt: now.Add(15 * time.Minute),
	}
}

func TestClassifyAPNSResponseUsesOnlyFixedOutcomes(t *testing.T) {
	tests := []struct {
		name     string
		response *apns2.Response
		err      error
		want     apnsOutcome
	}{
		{name: "success", response: &apns2.Response{StatusCode: 200}, want: apnsOutcomeSent},
		{name: "missing response", want: apnsOutcomeTransientNetwork},
		{name: "network", err: errors.New("sensitive network detail"), want: apnsOutcomeTransientNetwork},
		{name: "throttle", response: &apns2.Response{StatusCode: 429, Reason: apns2.ReasonTooManyRequests}, want: apnsOutcomeTransientThrottle},
		{name: "server", response: &apns2.Response{StatusCode: 503, Reason: apns2.ReasonShutdown}, want: apnsOutcomeTransientServer},
		{name: "bad token", response: &apns2.Response{StatusCode: 400, Reason: apns2.ReasonBadDeviceToken}, want: apnsOutcomeInvalidToken},
		{name: "response wins over transport detail", response: &apns2.Response{StatusCode: 410, Reason: apns2.ReasonUnregistered}, err: errors.New("transport detail"), want: apnsOutcomeInvalidToken},
		{name: "token topic mismatch", response: &apns2.Response{StatusCode: 400, Reason: apns2.ReasonDeviceTokenNotForTopic}, want: apnsOutcomeInvalidToken},
		{name: "expired token", response: &apns2.Response{StatusCode: 410, Reason: apns2.ReasonExpiredToken}, want: apnsOutcomeInvalidToken},
		{name: "unregistered", response: &apns2.Response{StatusCode: 410, Reason: apns2.ReasonUnregistered}, want: apnsOutcomeInvalidToken},
		{name: "terminal", response: &apns2.Response{StatusCode: 400, Reason: apns2.ReasonBadPriority}, want: apnsOutcomeRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, classifyAPNSResponse(test.response, test.err))
		})
	}
	require.EqualError(t, apnsOutcomeError(apnsOutcomeRejected), "APNS rejected notification")
	require.EqualError(t, apnsOutcomeError(apnsOutcomeTransientServer), "APNS delivery unavailable")
}

func TestReliableAPNSQueuesExactSerializedNotificationAndFailsClosedAtCap(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryJobStore{}
	delivery := newReliabilityFixture(
		now,
		&reliableFakeClient{},
		store,
	)
	delivery.reliable.started = true
	delivery.reliable.accepting = true
	payload := []byte(`{"aps":{"alert":"New message"},"hytch_wrapper":{"header":{"v":1,"nonce":"fixed"},"ciphertext":"fixed"}}`)
	notification := &apns2.Notification{
		DeviceToken: "opaque-device-token",
		Topic:       "com.example.app",
		Payload:     jsonRawMessage(payload),
		PushType:    apns2.PushTypeAlert,
		Priority:    apns2.PriorityHigh,
		Expiration:  now.Add(10 * time.Minute),
	}
	request := buildDeliveryRequest(t, 1)
	request.IdempotencyKey = "conversation-source-event"
	request.Subscription.SecureRoute = interfacesSecureRoute(bytes.Repeat([]byte{7}, 16))

	require.NoError(t, delivery.enqueueNotification(t.Context(), request, notification))
	require.Len(t, store.enqueued, 1)
	require.Equal(t, payload, store.enqueued[0].Payload)
	require.Equal(t, request.Subscription.SecureRoute.LeaseID, store.enqueuedIDs[0])
	require.Equal(t, []string{request.IdempotencyKey}, store.sourceEvents)
	roundTrip := notificationFromJob(store.enqueued[0])
	require.Equal(t, payload, []byte(roundTrip.Payload.(jsonRawMessage)))

	store.enqueueErr = vault.ErrDeliveryQueueFull
	require.ErrorIs(
		t,
		delivery.enqueueNotification(t.Context(), request, notification),
		ErrAPNSBackpressure,
	)

	boundary := *notification
	boundary.Payload = jsonRawMessage(
		bytes.Repeat([]byte{'x'}, maxAPNSPayloadBytes),
	)
	_, err := serializeAPNSNotification(&boundary)
	require.ErrorIs(t, err, ErrAPNSRejected)
}

func TestReliableAPNSBindsExactAuthorizedWelcomeTrafficClass(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryJobStore{}
	delivery := newReliabilityFixture(
		now,
		&reliableFakeClient{},
		store,
	)
	delivery.reliable.started = true
	delivery.reliable.accepting = true
	notification := &apns2.Notification{
		DeviceToken: strings.Repeat("ab", 32),
		Topic:       "com.example.app",
		Payload:     jsonRawMessage([]byte(`{"aps":{"content-available":1},"hytch_wrapper":{"header":{"v":1},"ciphertext":"fixed"}}`)),
		PushType:    apns2.PushTypeBackground,
		Priority:    apns2.PriorityLow,
		Expiration:  now.Add(30 * time.Second),
	}
	request := buildDeliveryRequest(t, 1)
	request.IdempotencyKey = "welcome-source-event"
	request.MessageContext.MessageType = topics.V3Welcome
	request.Subscription.SecureRoute = interfacesSecureRoute(
		bytes.Repeat([]byte{7}, 16),
	)
	request.Subscription.SecureRoute.WelcomeAuthorized = true

	require.NoError(t, delivery.enqueueNotification(t.Context(), request, notification))
	require.Len(t, store.enqueued, 1)
	require.Equal(
		t,
		vault.DeliveryTrafficWelcome,
		store.enqueued[0].TrafficClass,
	)

	request.Subscription.SecureRoute.WelcomeAuthorized = false
	require.ErrorIs(
		t,
		delivery.enqueueNotification(t.Context(), request, notification),
		ErrAPNSRejected,
	)
	require.Len(t, store.enqueued, 1)
}

func TestReliableAPNSRetriesExactBytesOnlyForTransientResults(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryJobStore{}
	client := &reliableFakeClient{
		responses: []*apns2.Response{
			{StatusCode: 503, Reason: apns2.ReasonServiceUnavailable},
			{StatusCode: 200},
		},
	}
	delivery := newReliabilityFixture(now, client, store)
	job := claimedJobFixture(now, 1)
	delivery.processClaimedJob(job)
	require.Len(t, store.rescheduled, 1)
	require.Len(t, store.attemptRecords, 1)
	require.Equal(t, 1, store.rescheduled[0].attempts)
	require.Equal(t, now.Add(750*time.Millisecond), store.rescheduled[0].available)
	require.Empty(t, store.deleted)

	retry := job
	retry.Attempts = 2
	delivery.reliable.jitter = bytes.NewReader([]byte{0, 0})
	delivery.processClaimedJob(retry)
	require.Len(t, store.deleted, 1)
	require.Len(t, store.attemptRecords, 2)
	require.Len(t, client.notifications, 2)
	require.Equal(
		t,
		[]byte(client.notifications[0].Payload.(jsonRawMessage)),
		[]byte(client.notifications[1].Payload.(jsonRawMessage)),
	)
	require.Equal(t, job.Job.Payload, []byte(client.notifications[1].Payload.(jsonRawMessage)))
}

func TestReliableAPNSDeletesAfterThirdTransientAttempt(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryJobStore{}
	client := &reliableFakeClient{errs: []error{errors.New("network detail")}}
	delivery := newReliabilityFixture(
		now,
		client,
		store,
	)
	delivery.processClaimedJob(claimedJobFixture(now, 3))
	require.Len(t, store.attemptRecords, 1)
	require.Empty(t, store.rescheduled)
	require.Len(t, store.deleted, 1)
}

func TestReliableAPNSRevalidatesClaimImmediatelyBeforeEgress(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryJobStore{claimValidationDenied: true}
	client := &reliableFakeClient{responses: []*apns2.Response{{
		StatusCode: 200,
	}}}
	delivery := newReliabilityFixture(now, client, store)
	job := claimedJobFixture(now, 1)

	delivery.processClaimedJob(job)

	require.Len(t, store.claimValidations, 1)
	require.Equal(t, job.JobID, store.claimValidations[0])
	require.Empty(t, store.attemptRecords)
	require.Empty(t, client.notifications)
	require.Len(t, store.deleted, 1)
	require.Len(t, store.finalized, 1)
	require.Equal(
		t,
		vault.DeliveryFinalSafetyInvalidated,
		store.finalized[0].reason,
	)
}

func TestReliableAPNSFinalizesExpiredClaimBeforeEgress(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryJobStore{}
	client := &reliableFakeClient{responses: []*apns2.Response{{
		StatusCode: 200,
	}}}
	delivery := newReliabilityFixture(now, client, store)
	job := claimedJobFixture(now, 1)
	job.ExpiresAt = now
	job.Job.Expiration = now

	delivery.processClaimedJob(job)

	require.Empty(t, store.claimValidations)
	require.Empty(t, store.attemptRecords)
	require.Empty(t, client.notifications)
	require.Len(t, store.finalized, 1)
	require.Equal(
		t,
		vault.DeliveryFinalTTLExpired,
		store.finalized[0].reason,
	)
}

func TestReliableAPNSInvalidTokenPersistsIndependentErasureMarker(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryJobStore{}
	client := &reliableFakeClient{responses: []*apns2.Response{{
		StatusCode: 410,
		Reason:     apns2.ReasonUnregistered,
		ApnsID:     "must-not-surface",
	}}}
	delivery := newReliabilityFixture(now, client, store)
	job := claimedJobFixture(now, 1)
	delivery.processClaimedJob(job)
	require.Len(t, client.notifications, 1)
	require.Len(t, store.attemptRecords, 1)
	require.Len(t, store.conversions, 1)
	require.Equal(t, job.JobID, store.conversions[0].id)
	require.Equal(t, job.Job.DeviceToken, store.conversions[0].deviceToken)
	require.Equal(t, job.Job.TrafficClass, store.conversions[0].trafficClass)
	require.Equal(t, now, store.conversions[0].available)
	require.Empty(t, store.erasures)
	require.Empty(t, store.rescheduled)
	require.Empty(t, store.deleted)
}

func TestReliableAPNSConversionFailureDoesNotReplayOrEraseOriginalClaim(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryJobStore{
		convertErr: vault.ErrDeliveryQueueUnavailable,
	}
	client := &reliableFakeClient{responses: []*apns2.Response{{
		StatusCode: 410,
		Reason:     apns2.ReasonUnregistered,
	}}}
	delivery := newReliabilityFixture(now, client, store)
	job := claimedJobFixture(now, 1)

	delivery.processClaimedJob(job)
	delivery.processClaimedJob(job)

	require.Len(t, client.notifications, 1)
	require.Len(t, store.attemptRecords, 1)
	require.Len(t, store.conversions, 2)
	require.Empty(t, store.rescheduled)
	require.Empty(t, store.erasures)
	require.Empty(t, store.deleted)
}

func TestReliableAPNSInvalidTokenFinalizationFailureStopsEgress(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryJobStore{
		convertErr: vault.ErrDeliveryFinalizationPending,
	}
	client := &reliableFakeClient{responses: []*apns2.Response{{
		StatusCode: 410,
		Reason:     apns2.ReasonUnregistered,
	}}}
	delivery := newReliabilityFixture(now, client, store)
	job := claimedJobFixture(now, 1)

	delivery.processClaimedJob(job)

	require.Len(t, client.notifications, 1)
	require.Len(t, store.conversions, 1)
	require.True(t, delivery.reliable.hasInvalidTokenClaim(job.JobID))
	select {
	case <-delivery.Failed():
	default:
		require.Fail(
			t,
			"committed invalid-token finalization failure did not stop egress",
		)
	}
}

func TestReliableAPNSAttemptRecordFailureLeavesClaimForCrashSafeRecovery(
	t *testing.T,
) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := &fakeDeliveryJobStore{
		attemptRecordErr: vault.ErrDeliveryQueueUnavailable,
	}
	client := &reliableFakeClient{responses: []*apns2.Response{{
		StatusCode: 200,
	}}}
	delivery := newReliabilityFixture(now, client, store)

	delivery.processClaimedJob(claimedJobFixture(now, 1))

	require.Len(t, client.notifications, 1)
	require.Empty(t, store.attemptRecords)
	require.Empty(t, store.rescheduled)
	require.Empty(t, store.deleted)
	select {
	case <-delivery.Failed():
	default:
		require.Fail(t, "terminal persistence failure did not stop APNS egress")
	}
}

func TestReliableAPNSRetentionFailureClaimsNothingAndSendsNothing(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	claimCalls := make(chan struct{}, 2)
	store := &fakeDeliveryJobStore{
		claims:     []vault.ClaimedDeliveryJob{claimedJobFixture(now, 1)},
		claimErr:   vault.ErrDeliveryQueueUnavailable,
		claimCalls: claimCalls,
	}
	client := &reliableFakeClient{}
	delivery := newReliabilityFixture(
		now,
		client,
		store,
	)

	require.NoError(t, delivery.Start(t.Context()))
	select {
	case <-claimCalls:
	case <-time.After(2 * time.Second):
		require.Fail(t, "worker did not attempt the retention-gated claim")
	}
	stopContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, delivery.Stop(stopContext))

	client.mu.Lock()
	defer client.mu.Unlock()
	require.Empty(t, client.notifications)
}

func TestReliableAPNSRecordsFixedRateDelayAndCancellation(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	t.Run("delayed", func(t *testing.T) {
		started := make(chan struct{}, 1)
		release := make(chan struct{})
		store := &fakeDeliveryJobStore{
			claims: []vault.ClaimedDeliveryJob{
				claimedJobFixture(now, 1),
			},
		}
		client := &reliableFakeClient{
			responses: []*apns2.Response{{StatusCode: 200}},
			started:   started,
			block:     release,
		}
		delivery := newReliabilityFixture(now, client, store)
		clock := &advancingAPNSClock{now: now}
		delivery.reliable.clock = clock
		delivery.reliable.limiter = newAPNSTokenBucket(1, 1, now)
		require.Zero(t, delivery.reliable.limiter.delay(now))
		delivery.reliable.wg.Add(1)
		go delivery.runReliableWorker()
		select {
		case <-started:
		case <-time.After(time.Second):
			require.Fail(t, "rate-delayed worker did not reach APNS")
		}
		store.mu.Lock()
		require.Equal(t, []vault.DeliveryObservation{{
			Event:           vault.DeliveryObservationRateLimit,
			Outcome:         vault.DeliveryOutcomeRateDelayed,
			TrafficClass:    vault.DeliveryTrafficConversation,
			ThresholdBucket: vault.DeliveryBucketMinimal,
			LatencyBucket:   vault.DeliveryBucketHigh,
		}}, store.observations)
		store.mu.Unlock()
		delivery.reliable.beginStop()
		close(release)
		delivery.reliable.wg.Wait()
	})

	t.Run("cancelled", func(t *testing.T) {
		store := &fakeDeliveryJobStore{
			claims: []vault.ClaimedDeliveryJob{
				claimedJobFixture(now, 1),
			},
		}
		client := &reliableFakeClient{}
		delivery := newReliabilityFixture(now, client, store)
		delivery.reliable.limiter = newAPNSTokenBucket(1, 1, now)
		require.Zero(t, delivery.reliable.limiter.delay(now))
		delivery.reliable.cancel()
		delivery.reliable.wg.Add(1)
		delivery.runReliableWorker()

		require.Equal(t, []vault.DeliveryObservation{{
			Event:           vault.DeliveryObservationRateLimit,
			Outcome:         vault.DeliveryOutcomeRateCancelled,
			TrafficClass:    vault.DeliveryTrafficConversation,
			ThresholdBucket: vault.DeliveryBucketMinimal,
			LatencyBucket:   vault.DeliveryBucketHigh,
		}}, store.observations)
		require.Len(t, store.released, 1)
		require.Empty(t, client.notifications)
	})
}

func TestReliableAPNSWorkerPanicIsFixedAndStopsEgress(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	claimCalls := make(chan struct{}, 1)
	const sensitivePanic = "sensitive-topic-and-device-token"
	store := &fakeDeliveryJobStore{
		claimPanic: sensitivePanic,
		claimCalls: claimCalls,
	}
	delivery := newReliabilityFixture(
		now,
		&reliableFakeClient{},
		store,
	)
	core, observed := observer.New(zapcore.DebugLevel)
	delivery.reliable.logger = zap.New(core)
	delivery.reliable.workers = 1

	require.NoError(t, delivery.Start(t.Context()))
	select {
	case <-claimCalls:
	case <-time.After(2 * time.Second):
		require.Fail(t, "worker did not reach panic canary")
	}
	require.Eventually(t, func() bool {
		delivery.reliable.mu.Lock()
		defer delivery.reliable.mu.Unlock()
		return !delivery.reliable.accepting
	}, time.Second, time.Millisecond)
	require.False(t, delivery.Ready())
	select {
	case <-delivery.Failed():
	default:
		require.Fail(t, "panic did not signal terminal APNS failure")
	}

	stopContext, cancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer cancel()
	require.NoError(t, delivery.Stop(stopContext))
	require.NotEmpty(t, observed.All())
	for _, entry := range observed.All() {
		require.NotContains(t, entry.Message, sensitivePanic)
	}
}

func TestReliableAPNSStartRecoversAndStopDrainsAtConcurrencyBound(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	release := make(chan struct{})
	started := make(chan struct{}, 3)
	store := &fakeDeliveryJobStore{
		claims: []vault.ClaimedDeliveryJob{
			claimedJobFixture(now, 1),
			claimedJobFixture(now, 1),
			claimedJobFixture(now, 1),
		},
	}
	store.claims[1].JobID = bytes.Repeat([]byte{5}, 16)
	store.claims[2].JobID = bytes.Repeat([]byte{6}, 16)
	client := &reliableFakeClient{
		responses: []*apns2.Response{{StatusCode: 200}, {StatusCode: 200}},
		block:     release,
		started:   started,
	}
	delivery := newReliabilityFixture(
		now,
		client,
		store,
	)
	require.NoError(t, delivery.Start(t.Context()))
	<-started
	<-started
	require.True(t, store.recovered)
	client.mu.Lock()
	require.Equal(t, 2, client.maxActive)
	client.mu.Unlock()

	stopDone := make(chan error, 1)
	go func() {
		stopContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stopDone <- delivery.Stop(stopContext)
	}()
	select {
	case err := <-stopDone:
		require.Failf(t, "Stop returned before in-flight sends drained", "error: %v", err)
	default:
	}
	close(release)
	require.NoError(t, <-stopDone)
	client.mu.Lock()
	require.Equal(t, 2, client.maxActive)
	client.mu.Unlock()
}

func TestAPNSTokenBucketIsBoundedAndDeterministic(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	bucket := newAPNSTokenBucket(2, 2, now)
	require.Zero(t, bucket.delay(now))
	require.Zero(t, bucket.delay(now))
	require.Equal(t, 500*time.Millisecond, bucket.delay(now))
	require.Zero(t, bucket.delay(now.Add(500*time.Millisecond)))
	require.Equal(t, 500*time.Millisecond, bucket.delay(now.Add(500*time.Millisecond)))
}

// Local aliases keep the exact-byte assertions readable without broadening
// production APIs solely for tests.
type jsonRawMessage = json.RawMessage

func interfacesSecureRoute(leaseID []byte) *interfaces.SecureRoute {
	return &interfaces.SecureRoute{
		LeaseID:                leaseID,
		AliasDay:               "2026-07-26",
		RouteAlias:             bytes.Repeat([]byte{7}, gate8wrapper.RouteAliasSize),
		WelcomeAuthorizationID: bytes.Repeat([]byte{8}, 16),
		WelcomeEnvelopeDigest:  bytes.Repeat([]byte{9}, 32),
	}
}
