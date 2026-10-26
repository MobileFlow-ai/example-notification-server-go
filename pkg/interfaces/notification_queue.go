package interfaces

import (
	"context"
	"errors"
	"fmt"
)

var ErrInvalidNotificationEnvelope = errors.New("invalid notification envelope")

// ErrNotificationEnvelopeTooLarge reports a received frame above the durable
// admission limit. The queue keeps only its metadata; the listener skips the
// frame and keeps consuming.
var ErrNotificationEnvelopeTooLarge = fmt.Errorf(
	"%w: frame exceeds durable admission limit",
	ErrInvalidNotificationEnvelope,
)

// ErrNotificationRecipientLimit reports an envelope whose eligible recipient
// set exceeds the durable receipt limit; retrying cannot succeed.
var ErrNotificationRecipientLimit = errors.New(
	"notification recipient limit exceeded",
)

// NotificationEnvelope is persisted before it can enter a delivery worker.
// Payload contains the original encrypted network envelope, never decoded chat.
type NotificationEnvelope struct {
	ID         int64
	Listener   string
	MessageKey string
	Payload    []byte
	Attempts   int32
	LeaseID    string
}

type NotificationQueue interface {
	Enqueue(context.Context, string, string, []byte) error
	Claim(context.Context, string) (*NotificationEnvelope, error)
	Renew(context.Context, NotificationEnvelope) error
	Finish(context.Context, NotificationEnvelope, string, string) error
	PrepareRecipients(context.Context, NotificationEnvelope, []string) error
	ClaimRecipient(context.Context, NotificationEnvelope, string) (string, bool, error)
	FinishRecipient(context.Context, NotificationEnvelope, string, string, string, string) error
	Maintain(context.Context) error
}
