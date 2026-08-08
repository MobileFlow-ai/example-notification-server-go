package delivery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/sideshow/apns2"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"go.uber.org/zap"
)

var (
	ErrAPNSBackpressure = errors.New("APNS delivery backpressure")
	ErrAPNSUnavailable  = errors.New("APNS delivery unavailable")
	ErrAPNSRejected     = errors.New("APNS rejected notification")
)

type apnsOutcome uint8

const (
	apnsOutcomeSent apnsOutcome = iota + 1
	apnsOutcomeTransientNetwork
	apnsOutcomeTransientThrottle
	apnsOutcomeTransientServer
	apnsOutcomeInvalidToken
	apnsOutcomeRejected
)

func (o apnsOutcome) transient() bool {
	return o == apnsOutcomeTransientNetwork ||
		o == apnsOutcomeTransientThrottle ||
		o == apnsOutcomeTransientServer
}

func classifyAPNSResponse(res *apns2.Response, _ error) apnsOutcome {
	if res == nil {
		return apnsOutcomeTransientNetwork
	}
	if res.Sent() {
		return apnsOutcomeSent
	}
	switch res.Reason {
	case apns2.ReasonBadDeviceToken,
		apns2.ReasonDeviceTokenNotForTopic,
		apns2.ReasonExpiredToken,
		apns2.ReasonUnregistered:
		return apnsOutcomeInvalidToken
	}
	if res.StatusCode == 429 {
		return apnsOutcomeTransientThrottle
	}
	if res.StatusCode >= 500 && res.StatusCode <= 599 {
		return apnsOutcomeTransientServer
	}
	return apnsOutcomeRejected
}

func apnsOutcomeError(outcome apnsOutcome) error {
	switch {
	case outcome == apnsOutcomeSent:
		return nil
	case outcome.transient():
		return ErrAPNSUnavailable
	default:
		return ErrAPNSRejected
	}
}

type apnsClock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type realAPNSClock struct{}

func (realAPNSClock) Now() time.Time {
	return time.Now().UTC()
}

func (realAPNSClock) After(delay time.Duration) <-chan time.Time {
	return time.After(delay)
}

type apnsReliability struct {
	store      vault.DeliveryJobStore
	logger     *zap.Logger
	clock      apnsClock
	jitter     io.Reader
	limiter    *apnsTokenBucket
	workers    int
	queueCap   int
	poll       time.Duration
	requestTTL time.Duration
	retryBase  time.Duration
	retryMax   time.Duration

	mu        sync.Mutex
	jitterMu  sync.Mutex
	invalidMu sync.Mutex
	errorLogs privacySafeErrorLimiter
	started   bool
	accepting bool
	failOnce  sync.Once
	stopOnce  sync.Once
	failed    chan struct{}
	stop      chan struct{}
	wake      chan struct{}
	workCtx   context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	// invalidTokenClaims keeps the claimed job in process only long enough to
	// retry APNS responses that proved a token invalid but whose atomic vault
	// conversion has not committed yet.
	// It prevents another worker in the same process from resubmitting the
	// original request if its database claim expires. A process crash between
	// Apple's response and the database transaction remains the documented
	// at-least-once ambiguity.
	invalidTokenClaims map[string]vault.ClaimedDeliveryJob
}

func NewReliableApnsDelivery(
	logger *zap.Logger,
	opts options.ApnsOptions,
	store vault.DeliveryJobStore,
) (*ApnsDelivery, error) {
	if store == nil || !opts.SecureWrapperRequired {
		return nil, ErrAPNSUnavailable
	}
	delivery, err := NewApnsDelivery(logger, opts)
	if err != nil {
		return nil, err
	}
	delivery.reliable = newAPNSReliability(logger, opts, store)
	return delivery, nil
}

func newAPNSReliability(
	logger *zap.Logger,
	opts options.ApnsOptions,
	store vault.DeliveryJobStore,
) *apnsReliability {
	if logger == nil {
		logger = zap.NewNop()
	}
	rate := boundedOption(opts.RatePerSecond, 50, 1, 10_000)
	burst := boundedOption(opts.RateBurst, 50, 1, 10_000)
	workers := boundedOption(opts.MaxConcurrency, 8, 1, 128)
	queueCap := boundedOption(opts.QueueCapacity, 5_000, 1, 1_000_000)
	pollMilliseconds := boundedOption(opts.QueuePollIntervalMs, 500, 10, 10_000)
	requestSeconds := boundedOption(opts.RequestTimeoutSeconds, 10, 1, 30)
	retryBaseMilliseconds := boundedOption(opts.InitialRetryDelayMs, 500, 10, 60_000)
	retryMaxMilliseconds := boundedOption(opts.MaxRetryDelayMs, 30_000, 10, 120_000)
	if retryMaxMilliseconds < retryBaseMilliseconds {
		retryMaxMilliseconds = retryBaseMilliseconds
	}
	clock := realAPNSClock{}
	return &apnsReliability{
		store:              store,
		logger:             logger,
		clock:              clock,
		jitter:             rand.Reader,
		limiter:            newAPNSTokenBucket(rate, burst, clock.Now()),
		workers:            workers,
		queueCap:           queueCap,
		poll:               time.Duration(pollMilliseconds) * time.Millisecond,
		requestTTL:         time.Duration(requestSeconds) * time.Second,
		retryBase:          time.Duration(retryBaseMilliseconds) * time.Millisecond,
		retryMax:           time.Duration(retryMaxMilliseconds) * time.Millisecond,
		failed:             make(chan struct{}),
		stop:               make(chan struct{}),
		wake:               make(chan struct{}, 1),
		invalidTokenClaims: make(map[string]vault.ClaimedDeliveryJob),
	}
}

func boundedOption(value, fallback, minimum, maximum int) int {
	if value <= 0 {
		return fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func (a *ApnsDelivery) Start(ctx context.Context) error {
	if a == nil || a.reliable == nil {
		return nil
	}
	r := a.reliable
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	if err := r.store.RecoverDeliveryJobs(ctx); err != nil {
		return ErrAPNSUnavailable
	}

	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return nil
	}
	r.workCtx, r.cancel = context.WithCancel(context.Background())
	r.started = true
	r.accepting = true
	r.mu.Unlock()

	for range r.workers {
		r.wg.Add(1)
		go a.runReliableWorker()
	}
	go func() {
		select {
		case <-ctx.Done():
			r.beginStop()
		case <-r.stop:
		}
	}()
	return nil
}

func (a *ApnsDelivery) Stop(ctx context.Context) error {
	if a == nil || a.reliable == nil {
		return nil
	}
	r := a.reliable
	r.mu.Lock()
	started := r.started
	r.mu.Unlock()
	if !started {
		return nil
	}
	r.beginStop()
	drained := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		r.mu.Lock()
		if r.cancel != nil {
			r.cancel()
		}
		r.mu.Unlock()
		return nil
	case <-ctx.Done():
		r.mu.Lock()
		if r.cancel != nil {
			r.cancel()
		}
		r.mu.Unlock()
		return ErrAPNSUnavailable
	}
}

func (a *ApnsDelivery) Ready() bool {
	if a == nil {
		return false
	}
	if a.reliable == nil {
		return true
	}
	r := a.reliable
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started &&
		r.accepting &&
		r.workCtx != nil &&
		r.workCtx.Err() == nil
}

func (a *ApnsDelivery) Failed() <-chan struct{} {
	if a == nil || a.reliable == nil {
		return nil
	}
	return a.reliable.failed
}

func (r *apnsReliability) beginStop() {
	r.mu.Lock()
	r.accepting = false
	r.mu.Unlock()
	r.stopOnce.Do(func() {
		close(r.stop)
	})
}

func (r *apnsReliability) fail() {
	if r == nil {
		return
	}
	r.failOnce.Do(func() {
		close(r.failed)
	})
	r.beginStop()
}

func (a *ApnsDelivery) enqueueNotification(
	ctx context.Context,
	req interfaces.SendRequest,
	notification *apns2.Notification,
) error {
	r := a.reliable
	if r == nil {
		return ErrAPNSUnavailable
	}
	r.mu.Lock()
	accepting := r.started && r.accepting
	r.mu.Unlock()
	if !accepting {
		return ErrAPNSBackpressure
	}
	job, err := serializeAPNSNotification(notification)
	if err != nil {
		return ErrAPNSRejected
	}
	secureRoute := req.Subscription.SecureRoute
	if secureRoute == nil {
		return ErrAPNSRejected
	}
	switch req.MessageContext.MessageType {
	case topics.V3Conversation:
		job.TrafficClass = vault.DeliveryTrafficConversation
	case topics.V3Welcome:
		if !secureRoute.WelcomeAuthorized {
			return ErrAPNSRejected
		}
		job.TrafficClass = vault.DeliveryTrafficWelcome
	default:
		return ErrAPNSRejected
	}
	job.PolicyEpoch = secureRoute.PolicyEpoch
	job.RouteKeyEpoch = secureRoute.RouteKeyEpoch
	job.NoncePrefix = secureRoute.NoncePrefix
	job.DeliverySequence = secureRoute.DeliverySequence
	job.AliasDay = secureRoute.AliasDay
	job.RouteAlias = append([]byte(nil), secureRoute.RouteAlias...)
	if job.TrafficClass == vault.DeliveryTrafficWelcome {
		job.WelcomeAuthorizationID = append(
			[]byte(nil),
			secureRoute.WelcomeAuthorizationID...,
		)
		job.WelcomeEnvelopeDigest = append(
			[]byte(nil),
			secureRoute.WelcomeEnvelopeDigest...,
		)
	}
	jobID, err := r.store.EnqueueDeliveryJob(
		ctx,
		secureRoute.LeaseID,
		job,
		req.IdempotencyKey,
		r.queueCap,
	)
	if errors.Is(err, vault.ErrDeliveryQueueFull) {
		return ErrAPNSBackpressure
	}
	if err != nil {
		return ErrAPNSUnavailable
	}
	if len(jobID) == 0 {
		return nil
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

func serializeAPNSNotification(
	notification *apns2.Notification,
) (vault.SerializedDeliveryJob, error) {
	if notification == nil {
		return vault.SerializedDeliveryJob{}, ErrAPNSRejected
	}
	payload, ok := notification.Payload.(json.RawMessage)
	if !ok || len(payload) == 0 || len(payload) >= maxAPNSPayloadBytes {
		return vault.SerializedDeliveryJob{}, ErrAPNSRejected
	}
	pushType := string(notification.PushType)
	if pushType != string(apns2.PushTypeAlert) &&
		pushType != string(apns2.PushTypeBackground) {
		return vault.SerializedDeliveryJob{}, ErrAPNSRejected
	}
	return vault.SerializedDeliveryJob{
		DeviceToken: notification.DeviceToken,
		Topic:       notification.Topic,
		Payload:     append([]byte(nil), payload...),
		PushType:    pushType,
		Priority:    notification.Priority,
		Expiration:  notification.Expiration.UTC(),
	}, nil
}

func notificationFromJob(job vault.SerializedDeliveryJob) *apns2.Notification {
	return &apns2.Notification{
		DeviceToken: job.DeviceToken,
		Topic:       job.Topic,
		Payload:     json.RawMessage(append([]byte(nil), job.Payload...)),
		PushType:    apns2.EPushType(job.PushType),
		Priority:    job.Priority,
		Expiration:  job.Expiration.UTC(),
	}
}

func (a *ApnsDelivery) runReliableWorker() {
	r := a.reliable
	defer r.wg.Done()
	defer func() {
		if recover() != nil {
			r.logWorkerError()
			r.fail()
		}
	}()
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		if invalidJob, exists := r.nextInvalidTokenClaim(); exists {
			a.persistAndProcessInvalidToken(invalidJob)
			if r.hasInvalidTokenClaim(invalidJob.JobID) &&
				!r.waitForWork() {
				return
			}
			continue
		}
		jobs, err := r.store.ClaimDeliveryJobs(
			r.workCtx,
			1,
			r.requestTTL+15*time.Second,
		)
		if err != nil {
			r.logWorkerError()
			if !r.waitForWork() {
				return
			}
			continue
		}
		if len(jobs) == 0 {
			if !r.waitForWork() {
				return
			}
			continue
		}
		job := jobs[0]
		select {
		case <-r.stop:
			a.releaseClaim(job.JobID)
			return
		default:
		}
		allowed, waitBucket := r.limiter.wait(r.workCtx, r.clock)
		if !allowed {
			r.recordDeliveryObservation(vault.DeliveryObservation{
				Event:           vault.DeliveryObservationRateLimit,
				Outcome:         vault.DeliveryOutcomeRateCancelled,
				TrafficClass:    job.Job.TrafficClass,
				ThresholdBucket: vault.DeliveryBucketMinimal,
				LatencyBucket:   waitBucket,
			})
			a.releaseClaim(job.JobID)
			return
		}
		if waitBucket != vault.DeliveryBucketMinimal {
			r.recordDeliveryObservation(vault.DeliveryObservation{
				Event:           vault.DeliveryObservationRateLimit,
				Outcome:         vault.DeliveryOutcomeRateDelayed,
				TrafficClass:    job.Job.TrafficClass,
				ThresholdBucket: vault.DeliveryBucketMinimal,
				LatencyBucket:   waitBucket,
			})
		}
		a.processClaimedJob(job)
	}
}

func (r *apnsReliability) recordDeliveryObservation(
	observation vault.DeliveryObservation,
) {
	recorder, ok := r.store.(vault.DeliveryObservationRecorder)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = recorder.RecordDeliveryObservation(ctx, observation)
}

func (r *apnsReliability) waitForWork() bool {
	select {
	case <-r.stop:
		return false
	case <-r.workCtx.Done():
		return false
	case <-r.wake:
		return true
	case <-r.clock.After(r.poll):
		return true
	}
}

func (a *ApnsDelivery) processClaimedJob(job vault.ClaimedDeliveryJob) {
	r := a.reliable
	now := r.clock.Now().UTC()
	if r.hasInvalidTokenClaim(job.JobID) {
		a.persistAndProcessInvalidToken(job)
		return
	}
	if !now.Before(job.ExpiresAt) {
		a.finalizeClaim(job.JobID, vault.DeliveryFinalTTLExpired)
		return
	}
	requestTTL := r.requestTTL
	if remaining := job.ExpiresAt.Sub(now); remaining < requestTTL {
		requestTTL = remaining
	}
	if requestTTL <= 0 {
		a.finalizeClaim(job.JobID, vault.DeliveryFinalTTLExpired)
		return
	}
	guardContext, guardCancel := context.WithTimeout(
		context.Background(),
		requestTTL+15*time.Second,
	)
	guard, valid, validationErr := r.store.AcquireDeliveryAttempt(
		guardContext,
		job,
	)
	if validationErr != nil {
		if guard != nil {
			_ = guard.Release()
		}
		guardCancel()
		r.logWorkerError()
		a.releaseClaim(job.JobID)
		return
	}
	if !valid {
		if guard != nil {
			_ = guard.Release()
		}
		guardCancel()
		a.finalizeClaim(job.JobID, vault.DeliveryFinalSafetyInvalidated)
		return
	}
	if guard == nil {
		guardCancel()
		r.logWorkerError()
		a.releaseClaim(job.JobID)
		return
	}
	defer func() {
		_ = guard.Release()
		guardCancel()
	}()
	requestContext, cancel := context.WithTimeout(r.workCtx, requestTTL)
	outcome := a.pushNotification(requestContext, notificationFromJob(job.Job))
	requestCancelled := requestContext.Err() != nil && r.workCtx.Err() != nil
	cancel()

	if requestCancelled {
		if err := guard.RecordAttempt(guardContext); err != nil {
			r.logWorkerError()
		}
		return
	}
	result := vault.DeliveryAttemptResult{}
	switch {
	case outcome == apnsOutcomeSent:
		result.Outcome = vault.DeliveryAttemptSent
	case outcome == apnsOutcomeInvalidToken:
		r.rememberInvalidTokenClaim(job)
		result.Outcome = vault.DeliveryAttemptInvalidToken
		result.RetryAt = r.clock.Now().UTC()
	case outcome.transient():
		delay := a.retryDelay(job.Attempts)
		result.Outcome = vault.DeliveryAttemptTransient
		result.RetryAt = r.clock.Now().UTC().Add(delay)
	default:
		result.Outcome = vault.DeliveryAttemptRejected
	}
	if err := guard.Complete(guardContext, result); err != nil {
		r.logWorkerError()
		if outcome != apnsOutcomeInvalidToken ||
			errors.Is(err, vault.ErrDeliveryFinalizationPending) {
			r.fail()
		}
		return
	}
	if outcome == apnsOutcomeInvalidToken {
		r.forgetInvalidTokenClaim(job.JobID)
	}
}

func (a *ApnsDelivery) persistAndProcessInvalidToken(job vault.ClaimedDeliveryJob) {
	r := a.reliable
	availableAt := r.clock.Now().UTC()
	updateContext, updateCancel := context.WithTimeout(context.Background(), 5*time.Second)
	installationLookup, updateErr := r.store.ConvertInvalidTokenToErasure(
		updateContext,
		job.JobID,
		job.Job.DeviceToken,
		job.Job.TrafficClass,
		availableAt,
	)
	updateCancel()
	if updateErr != nil {
		r.logWorkerError()
		if errors.Is(updateErr, vault.ErrDeliveryFinalizationPending) {
			r.fail()
		}
		return
	}
	if len(installationLookup) != 0 && len(installationLookup) != 32 {
		r.logWorkerError()
		return
	}
	r.forgetInvalidTokenClaim(job.JobID)
}

func (r *apnsReliability) rememberInvalidTokenClaim(
	job vault.ClaimedDeliveryJob,
) {
	r.invalidMu.Lock()
	defer r.invalidMu.Unlock()
	r.invalidTokenClaims[string(job.JobID)] = job
}

func (r *apnsReliability) hasInvalidTokenClaim(jobID []byte) bool {
	r.invalidMu.Lock()
	defer r.invalidMu.Unlock()
	_, exists := r.invalidTokenClaims[string(jobID)]
	return exists
}

func (r *apnsReliability) nextInvalidTokenClaim() (
	vault.ClaimedDeliveryJob,
	bool,
) {
	r.invalidMu.Lock()
	defer r.invalidMu.Unlock()
	for _, job := range r.invalidTokenClaims {
		return job, true
	}
	return vault.ClaimedDeliveryJob{}, false
}

func (r *apnsReliability) forgetInvalidTokenClaim(jobID []byte) {
	r.invalidMu.Lock()
	defer r.invalidMu.Unlock()
	delete(r.invalidTokenClaims, string(jobID))
}

func (a *ApnsDelivery) retryDelay(attempts int) time.Duration {
	r := a.reliable
	r.jitterMu.Lock()
	defer r.jitterMu.Unlock()
	return jitteredAPNSBackoff(
		r.retryBase,
		r.retryMax,
		attempts,
		r.jitter,
	)
}

func (a *ApnsDelivery) pushNotification(
	ctx context.Context,
	notification *apns2.Notification,
) apnsOutcome {
	if a == nil || a.apnsClient == nil || notification == nil {
		return apnsOutcomeRejected
	}
	response, err := a.apnsClient.PushWithContext(ctx, notification)
	return classifyAPNSResponse(response, err)
}

func (a *ApnsDelivery) releaseClaim(jobID []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.reliable.store.ReleaseDeliveryJob(ctx, jobID); err != nil {
		a.reliable.logWorkerError()
	}
}

func (a *ApnsDelivery) finalizeClaim(
	jobID []byte,
	reason vault.DeliveryFinalReason,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.reliable.store.FinalizeDeliveryJob(
		ctx,
		jobID,
		reason,
	); err != nil {
		a.reliable.logWorkerError()
		a.reliable.fail()
	}
}

func (r *apnsReliability) logWorkerError() {
	if r == nil {
		return
	}
	r.errorLogs.Log(
		r.logger,
		r.clock.Now().UTC(),
		"APNS worker degraded",
	)
}

func jitteredAPNSBackoff(
	initial time.Duration,
	maximum time.Duration,
	attempts int,
	entropy io.Reader,
) time.Duration {
	if initial <= 0 {
		initial = 500 * time.Millisecond
	}
	if maximum < initial {
		maximum = initial
	}
	if attempts < 1 {
		attempts = 1
	}
	base := initial
	for index := 1; index < attempts && base < maximum; index++ {
		if base > maximum/2 {
			base = maximum
			break
		}
		base *= 2
	}
	if base > maximum {
		base = maximum
	}
	var randomBytes [2]byte
	if entropy == nil {
		entropy = rand.Reader
	}
	multiplier := uint64(1000)
	if _, err := io.ReadFull(entropy, randomBytes[:]); err == nil {
		multiplier = 750 + uint64(binary.BigEndian.Uint16(randomBytes[:])%501)
	}
	delay := time.Duration((uint64(base) * multiplier) / 1000)
	if delay > maximum {
		return maximum
	}
	return delay
}

type apnsTokenBucket struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

func newAPNSTokenBucket(rate, burst int, now time.Time) *apnsTokenBucket {
	return &apnsTokenBucket{
		rate:     float64(rate),
		capacity: float64(burst),
		tokens:   float64(burst),
		last:     now.UTC(),
	}
}

func (b *apnsTokenBucket) wait(
	ctx context.Context,
	clock apnsClock,
) (bool, vault.DeliveryObservationBucket) {
	waitBucket := vault.DeliveryBucketMinimal
	for {
		delay := b.delay(clock.Now())
		if delay <= 0 {
			return true, waitBucket
		}
		if current := deliveryRateWaitBucket(delay); current > waitBucket {
			waitBucket = current
		}
		select {
		case <-ctx.Done():
			return false, waitBucket
		case <-clock.After(delay):
		}
	}
}

func deliveryRateWaitBucket(
	delay time.Duration,
) vault.DeliveryObservationBucket {
	switch {
	case delay <= 0:
		return vault.DeliveryBucketMinimal
	case delay <= 10*time.Millisecond:
		return vault.DeliveryBucketLow
	case delay <= 100*time.Millisecond:
		return vault.DeliveryBucketModerate
	case delay <= time.Second:
		return vault.DeliveryBucketHigh
	default:
		return vault.DeliveryBucketCritical
	}
}

func (b *apnsTokenBucket) delay(now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now = now.UTC()
	if now.After(b.last) {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	seconds := (1 - b.tokens) / b.rate
	return time.Duration(seconds * float64(time.Second))
}
