// Package notificationqueue persists received encrypted envelopes and per-device
// acknowledgments. It cannot recover stream frames never delivered by XMTP.
package notificationqueue

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	"github.com/xmtp/example-notification-server-go/pkg/db/queries"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"go.uber.org/zap"
)

var ErrLeaseLost = errors.New("notification lease lost")
var ErrRecipientBusy = errors.New("notification recipient already leased")

const MaxAttempts = 12
const MaxEnvelopeBytes = 2 * 1024 * 1024
const MaxRecipients = 10000

type Store struct {
	db      *sql.DB
	queries *queries.Queries
	logger  *zap.Logger
}

func New(db *sql.DB, loggers ...*zap.Logger) *Store {
	logger := zap.NewNop()
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0].Named("notification-queue")
	}
	return &Store{db: db, queries: queries.New(db), logger: logger}
}

func (s *Store) Enqueue(ctx context.Context, listener, key string, payload []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if (listener != "v3" && listener != "v4") || key == "" || len(key) > 128 || len(payload) == 0 {
		return interfaces.ErrInvalidNotificationEnvelope
	}
	if len(payload) > MaxEnvelopeBytes {
		// Keep only metadata so queue health reports the frame and a replay
		// of the same frame stays deduplicated; never retain its bytes. A
		// database failure here pauses admission like any other write.
		if err := s.queries.RecordRejectedNotificationEnvelope(ctx, queries.RecordRejectedNotificationEnvelopeParams{Listener: listener, MessageKey: key, FailureClass: "oversized"}); err != nil {
			return err
		}
		return interfaces.ErrNotificationEnvelopeTooLarge
	}
	return database.RunInTx(ctx, s.db, func(q *queries.Queries) error {
		if err := q.LockNotificationAdmission(ctx); err != nil {
			return err
		}
		exists, err := q.NotificationEnvelopeExists(ctx, queries.NotificationEnvelopeExistsParams{Listener: listener, MessageKey: key})
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
		capacity, err := q.NotificationPendingCapacity(ctx)
		if err != nil {
			return err
		}
		if capacity.Count >= 100000 || capacity.Bytes+int64(len(payload)) > 512*1024*1024 {
			return errors.New("notification durable queue at capacity")
		}
		return q.EnqueueNotificationEnvelope(ctx, queries.EnqueueNotificationEnvelopeParams{Listener: listener, MessageKey: key, Payload: payload})
	})
}
func (s *Store) Claim(ctx context.Context, listener string) (*interfaces.NotificationEnvelope, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	row, err := s.queries.ClaimNotificationEnvelope(ctx, queries.ClaimNotificationEnvelopeParams{Listener: listener, LeaseID: uuid.NewString()})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &interfaces.NotificationEnvelope{ID: row.ID, Listener: row.Listener, MessageKey: row.MessageKey, Payload: row.Payload, Attempts: row.Attempts, LeaseID: row.LeaseID, RecipientsPrepared: row.RecipientsPrepared}, nil
}
func checkLease(rows int64, err error) error {
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrLeaseLost
	}
	return nil
}
func (s *Store) Renew(ctx context.Context, env interfaces.NotificationEnvelope) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return checkLease(s.queries.RenewNotificationLease(ctx, queries.RenewNotificationLeaseParams{ID: env.ID, LeaseID: env.LeaseID}))
}
func retryDelay(attempt int32) int32 {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > MaxAttempts {
		attempt = MaxAttempts
	}
	delay := int32(5) << uint(attempt-1)
	if delay > 3600 {
		return 3600
	}
	return delay
}
func (s *Store) Finish(ctx context.Context, env interfaces.NotificationEnvelope, outcome string, failureClass string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if outcome != "pending" && outcome != "complete" && outcome != "dead" {
		return errors.New("invalid notification outcome")
	}
	status := "pending"
	if outcome == "complete" {
		status = "complete"
		failureClass = ""
	} else if outcome == "dead" || env.Attempts >= MaxAttempts {
		status = "dead"
	}
	if !validFailureClass(failureClass) {
		return errors.New("invalid notification failure class")
	}
	return checkLease(s.queries.FinishNotificationEnvelope(ctx, queries.FinishNotificationEnvelopeParams{ID: env.ID, LeaseID: env.LeaseID, Status: status, DelaySeconds: retryDelay(env.Attempts), FailureClass: failureClass}))
}
func (s *Store) PrepareRecipients(ctx context.Context, env interfaces.NotificationEnvelope, ids []string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if env.RecipientsPrepared {
		// The snapshot from the first attempt is authoritative; a larger
		// current recipient set must not abandon it.
		return nil
	}
	if len(ids) > MaxRecipients {
		return interfaces.ErrNotificationRecipientLimit
	}
	return s.queries.PrepareNotificationRecipients(ctx, queries.PrepareNotificationRecipientsParams{EnvelopeID: env.ID, ExpectedEnvelopeLease: env.LeaseID, InstallationIds: ids})
}
func (s *Store) ClaimRecipient(ctx context.Context, env interfaces.NotificationEnvelope, installationID string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if installationID == "" {
		return "", false, errors.New("missing installation id")
	}
	ticket := uuid.NewString()
	_, err := s.queries.ClaimNotificationRecipient(ctx, queries.ClaimNotificationRecipientParams{EnvelopeID: env.ID, InstallationID: installationID, LeaseID: ticket, ExpectedEnvelopeLease: env.LeaseID})
	if err == nil {
		return ticket, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	status, err := s.queries.GetNotificationRecipientStatus(ctx, queries.GetNotificationRecipientStatusParams{EnvelopeID: env.ID, InstallationID: installationID})
	if errors.Is(err, sql.ErrNoRows) {
		return "", true, nil
	} // not in the initial recipient snapshot
	if err != nil {
		return "", false, err
	}
	if status == "accepted" || status == "rejected" {
		return "", true, nil
	}
	return "", false, ErrRecipientBusy
}
func (s *Store) FinishRecipient(ctx context.Context, env interfaces.NotificationEnvelope, installationID, ticket, status, failureClass string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if status != "pending" && status != "accepted" && status != "rejected" {
		return errors.New("invalid notification receipt status")
	}
	if !validFailureClass(failureClass) {
		return errors.New("invalid notification failure class")
	}
	return checkLease(s.queries.FinishNotificationRecipient(ctx, queries.FinishNotificationRecipientParams{EnvelopeID: env.ID, InstallationID: installationID, LeaseID: ticket, ExpectedEnvelopeLease: env.LeaseID, Status: status, FailureClass: failureClass}))
}
func validFailureClass(value string) bool {
	switch value {
	case "", "provider_transient", "provider_permanent", "token_cleanup", "processing",
		"invalid_envelope", "suppressed", "no_provider", "recipient_limit", "processing_panic":
		return true
	}
	return false
}
func (s *Store) Maintain(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := s.queries.ExpireNotificationEnvelopes(ctx); err != nil {
		return fmt.Errorf("expire notification queue: %w", err)
	}
	if err := s.queries.PurgeNotificationReceipts(ctx); err != nil {
		return err
	}
	rows, err := s.queries.NotificationQueueHealth(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		fields := []zap.Field{zap.String("listener", row.Listener), zap.String("status", row.Status), zap.Int64("count", row.Count), zap.Any("oldest_admission_at", row.OldestAt)}
		if row.Status == "dead" || row.Status == "recipient_rejected" {
			s.logger.Warn("notification queue has exhausted or expired work", fields...)
		} else {
			s.logger.Info("notification queue health", fields...)
		}
	}
	return nil
}
