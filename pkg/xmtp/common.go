package xmtp

import (
	"context"
	"errors"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/delivery"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"go.uber.org/zap"
)

const STARTING_SLEEP_TIME = 100 * time.Millisecond
const MAX_SLEEP_TIME = 30 * time.Second
const DELIVERY_TIMEOUT = 15 * time.Second

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
	SetNotificationQueue(interfaces.NotificationQueue)
}

// deliveryDispatcher handles shared delivery logic for both V3 and V4 listeners
type deliveryDispatcher struct {
	logger           *zap.Logger
	ctx              context.Context
	deliveryServices []interfaces.Delivery
	invalidTokens    interfaces.TokenInvalidator
	queue            interfaces.NotificationQueue
}

func (d *deliveryDispatcher) shouldDeliver(messageContext interfaces.MessageContext, subscription interfaces.Subscription) bool {
	if subscription.HmacKey != nil && len(subscription.HmacKey.Key) > 0 {
		isSender := messageContext.IsSender(subscription.HmacKey.Key)
		if isSender {
			return false
		}
	}
	if messageContext.ShouldPush != nil {
		shouldPush := messageContext.ShouldPush
		return *shouldPush
	}
	return true
}

type tokenCleanupError struct{ cause error }

func (e *tokenCleanupError) Error() string { return "delivery token cleanup failed" }
func (e *tokenCleanupError) Unwrap() error { return e.cause }

func (d *deliveryDispatcher) deliver(req interfaces.SendRequest) error {
	return d.deliverWithContext(d.ctx, req)
}

func (d *deliveryDispatcher) deliverWithContext(parent context.Context, req interfaces.SendRequest) error {
	var ticket string
	env := capturedEnvelope(parent)
	if d.queue != nil && env != nil {
		var done bool
		var err error
		ticket, done, err = d.queue.ClaimRecipient(parent, *env, req.Installation.Id)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	ctx, cancel := context.WithTimeout(parent, DELIVERY_TIMEOUT)
	defer cancel()
	var sendErr error
	matched := false
	for _, service := range d.deliveryServices {
		if !service.CanDeliver(req) {
			continue
		}
		matched = true
		sendErr = service.Send(ctx, req)
		var rejection *delivery.ApnsRejection
		if d.invalidTokens != nil && errors.As(sendErr, &rejection) && rejection.InvalidToken &&
			(rejection.StatusCode != 410 || !rejection.UnregisteredAt.IsZero()) {
			if err := d.invalidTokens.InvalidateDeliveryToken(ctx, req.Installation, rejection.UnregisteredAt); err != nil {
				sendErr = errors.Join(sendErr, &tokenCleanupError{cause: err})
			}
		}
		break
	}
	if !matched {
		sendErr = errors.New("no delivery service matches request")
	}
	if d.queue == nil || env == nil {
		return sendErr
	}
	status, class := "accepted", ""
	if sendErr != nil {
		status, class = "pending", "provider_transient"
		var cleanup *tokenCleanupError
		var rejection *delivery.ApnsRejection
		if errors.As(sendErr, &cleanup) {
			class = "token_cleanup"
		} else if errors.As(sendErr, &rejection) && rejection.Permanent {
			status, class = "rejected", "provider_permanent"
		}
	}
	// Use the envelope context for persistence, not the completed provider
	// timeout. Failure to persist an acknowledgment remains uncertain work.
	receiptCtx, receiptCancel := context.WithTimeout(parent, DELIVERY_TIMEOUT)
	defer receiptCancel()
	if err := d.queue.FinishRecipient(receiptCtx, *env, req.Installation.Id, ticket, status, class); err != nil {
		return errors.Join(sendErr, err)
	}
	if status == "rejected" {
		d.logger.Warn("notification permanently rejected by provider")
		return nil
	}
	return sendErr
}

func firstInvalidator(invalidators []interfaces.TokenInvalidator) interfaces.TokenInvalidator {
	if len(invalidators) > 0 {
		return invalidators[0]
	}
	return nil
}

func (d *deliveryDispatcher) prepareRecipients(ctx context.Context, requests []interfaces.SendRequest) error {
	env := capturedEnvelope(ctx)
	if d.queue == nil || env == nil {
		return nil
	}
	ids := make([]string, 0, len(requests))
	for _, req := range requests {
		if d.shouldDeliver(req.MessageContext, req.Subscription) {
			ids = append(ids, req.Installation.Id)
		}
	}
	return d.queue.PrepareRecipients(ctx, *env, ids)
}
