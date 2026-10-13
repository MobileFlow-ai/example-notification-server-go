package interfaces

import (
	"context"
	"errors"
)

var ErrInvalidNotificationEnvelope = errors.New("invalid notification envelope")

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
