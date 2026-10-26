package xmtp

import (
	"context"
	"errors"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/delivery"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/pushpolicy"
)

const STARTING_SLEEP_TIME = 100 * time.Millisecond
const MAX_SLEEP_TIME = 30 * time.Second
const DELIVERY_TIMEOUT = 15 * time.Second
const ENVELOPE_RETRY_WINDOW = 30 * time.Second

// cappedBackoff doubles sleepTime up to MAX_SLEEP_TIME.
func cappedBackoff(sleepTime time.Duration) time.Duration {
	sleepTime *= 2
	if sleepTime > MAX_SLEEP_TIME {
		sleepTime = MAX_SLEEP_TIME
	}
	return sleepTime
}

// waitForReconnect bounds retry frequency, including graceful stream EOF,
// while allowing Stop to interrupt the longest backoff immediately.
func waitForReconnect(ctx context.Context, delay *time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	timer := time.NewTimer(*delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		*delay = cappedBackoff(*delay)
		return ctx.Err() == nil
	}
}

// NotificationListener is the interface implemented by both V3 and V4 listeners
type NotificationListener interface {
	Start()
	Stop()
	Ready() bool
	Failed() <-chan struct{}
	// SetNotificationQueue enables durable admission. It must be called
	// before Start, and only for the plaintext (non-vault) listener path.
	SetNotificationQueue(interfaces.NotificationQueue)
}

// runListenerGoroutine contains panics at XMTP listener goroutine boundaries.
// The recovered value is deliberately discarded because it may contain
// attacker-controlled envelope or topic data.
func runListenerGoroutine(work func(), failClosed func()) {
	defer func() {
		if recover() == nil {
			return
		}
		if failClosed != nil {
			failClosed()
		}
	}()
	work()
}

// deliveryDispatcher handles shared delivery logic for both V3 and V4 listeners
type deliveryDispatcher struct {
	ctx              context.Context
	deliveryServices []interfaces.Delivery
	invalidTokens    interfaces.TokenInvalidator
	queue            interfaces.NotificationQueue
}

func newDeliveryDispatcher(
	ctx context.Context,
	deliveryServices []interfaces.Delivery,
	invalidators ...interfaces.TokenInvalidator,
) deliveryDispatcher {
	return deliveryDispatcher{
		ctx:              ctx,
		deliveryServices: deliveryServices,
		invalidTokens:    firstInvalidator(invalidators),
	}
}

func firstInvalidator(
	invalidators []interfaces.TokenInvalidator,
) interfaces.TokenInvalidator {
	for _, invalidator := range invalidators {
		if invalidator != nil {
			return invalidator
		}
	}
	return nil
}

// dispatch is the single egress gate for every delivery mechanism.
func (d *deliveryDispatcher) dispatch(req interfaces.SendRequest) error {
	baseContext := d.ctx
	if baseContext == nil {
		baseContext = context.Background()
	}
	return d.dispatchContext(baseContext, req)
}

func (d *deliveryDispatcher) dispatchContext(
	baseContext context.Context,
	req interfaces.SendRequest,
) error {
	if baseContext == nil {
		baseContext = context.Background()
	}
	env := capturedEnvelope(baseContext)
	durable := d.queue != nil && env != nil
	var ticket string
	if durable {
		var done bool
		var err error
		ticket, done, err = d.queue.ClaimRecipient(
			baseContext,
			*env,
			req.Installation.Id,
		)
		if err != nil {
			return err
		}
		if done {
			// Already accepted or rejected, or not in this envelope's
			// initial recipient snapshot.
			return nil
		}
	}

	ctx, cancel := context.WithTimeout(baseContext, DELIVERY_TIMEOUT)
	defer cancel()

	authorizedContext, allowed := pushpolicy.AuthorizeDelivery(ctx, req)
	if !allowed {
		if durable {
			return d.finishRecipient(baseContext, *env, req, ticket, nil, "rejected", "suppressed")
		}
		return nil
	}

	matched, sendErr := d.send(baseContext, authorizedContext, req)
	if !durable {
		return sendErr
	}
	switch {
	case !matched:
		// The provider set is fixed for this process; retrying cannot help.
		return d.finishRecipient(baseContext, *env, req, ticket, nil, "rejected", "no_provider")
	case sendErr == nil:
		return d.finishRecipient(baseContext, *env, req, ticket, nil, "accepted", "")
	}
	var cleanup *tokenCleanupError
	switch {
	case errors.As(sendErr, &cleanup):
		return d.finishRecipient(baseContext, *env, req, ticket, sendErr, "pending", "token_cleanup")
	case delivery.IsPermanentFailure(sendErr):
		return d.finishRecipient(baseContext, *env, req, ticket, sendErr, "rejected", "provider_permanent")
	default:
		return d.finishRecipient(baseContext, *env, req, ticket, sendErr, "pending", "provider_transient")
	}
}

// finishRecipient persists one recipient outcome under the envelope and
// recipient leases. It uses its own deadline rather than the completed
// provider timeout, and it is not cancelled by listener shutdown: a provider
// acceptance that lands while the process stops is still recorded, so a
// restart does not resend it. The leases still fence the write. A failed
// write leaves the outcome uncertain, so the recipient stays pending and the
// envelope retries.
func (d *deliveryDispatcher) finishRecipient(
	baseContext context.Context,
	env interfaces.NotificationEnvelope,
	req interfaces.SendRequest,
	ticket string,
	sendErr error,
	status string,
	failureClass string,
) error {
	receiptContext, receiptCancel := context.WithTimeout(
		context.WithoutCancel(baseContext),
		DELIVERY_TIMEOUT,
	)
	defer receiptCancel()
	if err := d.queue.FinishRecipient(
		receiptContext,
		env,
		req.Installation.Id,
		ticket,
		status,
		failureClass,
	); err != nil {
		return errors.Join(sendErr, err)
	}
	if status == "pending" {
		return sendErr
	}
	return nil
}

// prepareRecipients records the complete initial eligible-recipient set for a
// durable envelope before any provider call. Retries intersect that snapshot
// with current subscriptions, so a device subscribed after admission does not
// receive an old message because another device needed a retry.
func (d *deliveryDispatcher) prepareRecipients(
	ctx context.Context,
	requests []interfaces.SendRequest,
) error {
	env := capturedEnvelope(ctx)
	if d.queue == nil || env == nil {
		return nil
	}
	ids := make([]string, 0, len(requests))
	for _, req := range requests {
		if _, allowed := pushpolicy.AuthorizeDelivery(ctx, req); allowed {
			ids = append(ids, req.Installation.Id)
		}
	}
	return d.queue.PrepareRecipients(ctx, *env, ids)
}

func retryEnvelopeProcessing(
	ctx context.Context,
	retryWindow time.Duration,
	process func(context.Context) error,
	onFailure func(),
) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if process == nil {
		return true
	}
	if retryWindow <= 0 {
		retryWindow = ENVELOPE_RETRY_WINDOW
	}
	retryContext, retryCancel := context.WithTimeout(
		ctx,
		retryWindow,
	)
	defer retryCancel()
	delay := STARTING_SLEEP_TIME
	for {
		if err := process(retryContext); err == nil {
			return true
		}
		if onFailure != nil {
			onFailure()
		}
		timer := time.NewTimer(delay)
		select {
		case <-retryContext.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
		delay = cappedBackoff(delay)
	}
}

func (d *deliveryDispatcher) deliver(
	ctx context.Context,
	req interfaces.SendRequest,
) error {
	_, err := d.send(ctx, ctx, req)
	return err
}

type tokenCleanupError struct{ cause error }

func (e *tokenCleanupError) Error() string { return "delivery token cleanup failed" }
func (e *tokenCleanupError) Unwrap() error { return e.cause }

// send delivers through the first matching provider and reports whether one
// matched. When the provider proves a plaintext token dead, it retires only
// the captured token version, under a fresh deadline derived from
// baseContext rather than the provider call's nearly spent one.
func (d *deliveryDispatcher) send(
	baseContext context.Context,
	providerContext context.Context,
	req interfaces.SendRequest,
) (bool, error) {
	for _, service := range d.deliveryServices {
		if !service.CanDeliver(req) {
			continue
		}
		sendErr := service.Send(providerContext, req)
		var rejection *delivery.ApnsRejection
		if d.invalidTokens != nil &&
			errors.As(sendErr, &rejection) &&
			rejection.InvalidToken &&
			!rejection.UnregisteredAt.IsZero() {
			cleanupContext, cleanupCancel := context.WithTimeout(
				baseContext,
				DELIVERY_TIMEOUT,
			)
			err := d.invalidTokens.InvalidateDeliveryToken(
				cleanupContext,
				req.Installation,
				rejection.UnregisteredAt,
			)
			cleanupCancel()
			if err != nil {
				sendErr = errors.Join(sendErr, &tokenCleanupError{cause: err})
			}
		}
		return true, sendErr
	}
	return false, nil
}
