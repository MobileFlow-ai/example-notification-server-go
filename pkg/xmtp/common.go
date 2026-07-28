package xmtp

import (
	"context"
	"time"

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

// NotificationListener is the interface implemented by both V3 and V4 listeners
type NotificationListener interface {
	Start()
	Stop()
	Ready() bool
	Failed() <-chan struct{}
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
}

func newDeliveryDispatcher(
	ctx context.Context,
	deliveryServices []interfaces.Delivery,
) deliveryDispatcher {
	return deliveryDispatcher{
		ctx:              ctx,
		deliveryServices: deliveryServices,
	}
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
	ctx, cancel := context.WithTimeout(baseContext, DELIVERY_TIMEOUT)
	defer cancel()

	authorizedContext, allowed := pushpolicy.AuthorizeDelivery(ctx, req)
	if !allowed {
		return nil
	}

	return d.deliver(authorizedContext, req)
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
	for _, service := range d.deliveryServices {
		if service.CanDeliver(req) {
			return service.Send(ctx, req)
		}
	}
	return nil
}
