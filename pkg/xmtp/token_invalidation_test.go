package xmtp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sideshow/apns2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/delivery"
	"github.com/xmtp/example-notification-server-go/pkg/installations"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/notificationqueue"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	"go.uber.org/zap"
)

type recordingInvalidator struct {
	calls        int
	installation interfaces.Installation
	at           time.Time
	err          error
}

func (r *recordingInvalidator) InvalidateDeliveryToken(_ context.Context, i interfaces.Installation, at time.Time) error {
	r.calls++
	r.installation = i
	r.at = at
	return r.err
}

func TestInvalidTokenCleanup_OnlyProviderTokenRejections(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		rejection *delivery.ApnsRejection
		cleanup   bool
	}{
		{"unregistered", &delivery.ApnsRejection{StatusCode: 410, InvalidToken: true, UnregisteredAt: at}, true},
		{"unregistered_without_timestamp", &delivery.ApnsRejection{StatusCode: 410, InvalidToken: true}, false},
		// Classification never marks BadDeviceToken invalid: Apple also
		// returns it for a sandbox/production environment mismatch.
		{"bad_token", &delivery.ApnsRejection{StatusCode: 400, Reason: "BadDeviceToken", Permanent: true}, false},
		{"wrong_topic", &delivery.ApnsRejection{StatusCode: 400, Reason: "DeviceTokenNotForTopic", Permanent: true}, false},
		{"credentials", &delivery.ApnsRejection{StatusCode: 403}, false},
		{"rate_limited", &delivery.ApnsRejection{StatusCode: 429}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := mocks.NewDelivery(t)
			provider.On("CanDeliver", mock.Anything).Return(true)
			provider.On("Send", mock.Anything, mock.Anything).Return(tc.rejection).Once()
			cleanup := &recordingInvalidator{}
			d := newDeliveryDispatcher(t.Context(), []interfaces.Delivery{provider}, cleanup)
			req := interfaces.SendRequest{Installation: interfaces.Installation{Id: "captured", DeliveryMechanism: interfaces.DeliveryMechanism{Kind: interfaces.APNS, Token: "captured-token", UpdatedAt: at.Add(-time.Hour)}}}
			require.ErrorIs(t, d.deliver(t.Context(), req), tc.rejection)
			if tc.cleanup {
				require.Equal(t, 1, cleanup.calls)
				require.Equal(t, req.Installation, cleanup.installation)
				require.Equal(t, tc.rejection.UnregisteredAt, cleanup.at)
			} else {
				require.Zero(t, cleanup.calls)
			}
		})
	}
}

func TestInvalidTokenCleanup_PreservesCleanupFailure(t *testing.T) {
	provider := mocks.NewDelivery(t)
	rejection := &delivery.ApnsRejection{StatusCode: 410, InvalidToken: true, UnregisteredAt: time.Now()}
	provider.On("CanDeliver", mock.Anything).Return(true)
	provider.On("Send", mock.Anything, mock.Anything).Return(rejection)
	cleanupErr := errors.New("database unavailable")
	cleanup := &recordingInvalidator{err: cleanupErr}
	d := newDeliveryDispatcher(t.Context(), []interfaces.Delivery{provider}, cleanup)
	err := d.deliver(t.Context(), interfaces.SendRequest{})
	require.ErrorIs(t, err, rejection)
	require.ErrorIs(t, err, cleanupErr)
}

// Cleanup must not inherit the provider call's nearly spent deadline.
func TestInvalidTokenCleanup_UsesFreshDeadline(t *testing.T) {
	provider := mocks.NewDelivery(t)
	provider.On("CanDeliver", mock.Anything).Return(true)
	provider.On("Send", mock.Anything, mock.Anything).Return(&delivery.ApnsRejection{StatusCode: 410, InvalidToken: true, UnregisteredAt: time.Now()})
	var cleanupErr error
	invalidator := invalidatorFunc(func(ctx context.Context) error {
		cleanupErr = ctx.Err()
		return nil
	})
	d := newDeliveryDispatcher(t.Context(), []interfaces.Delivery{provider}, invalidator)
	spent, cancel := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel()
	<-spent.Done()
	_, err := d.send(t.Context(), spent, interfaces.SendRequest{})
	require.Error(t, err)
	require.NoError(t, cleanupErr)
}

type invalidatorFunc func(context.Context) error

func (f invalidatorFunc) InvalidateDeliveryToken(ctx context.Context, _ interfaces.Installation, _ time.Time) error {
	return f(ctx)
}

type fixedAPNSResponseClient struct{ response *apns2.Response }

func (c fixedAPNSResponseClient) PushWithContext(apns2.Context, *apns2.Notification) (*apns2.Response, error) {
	return c.response, nil
}

// End to end through the real APNs adapter, the plaintext installation store
// and the durable queue: a sandbox/production mismatch (BadDeviceToken) and a
// topic mismatch reject the push without retiring the registration, while a
// timestamped 410 Unregistered retires exactly the captured token version.
func TestDurableDelivery_EnvironmentMismatchKeepsRegistration(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response func(time.Time) *apns2.Response
		status   string
		retained bool
	}{
		{"bad_device_token", func(time.Time) *apns2.Response {
			return &apns2.Response{StatusCode: 400, Reason: apns2.ReasonBadDeviceToken}
		}, "rejected", true},
		{"topic_mismatch", func(time.Time) *apns2.Response {
			return &apns2.Response{StatusCode: 400, Reason: apns2.ReasonDeviceTokenNotForTopic}
		}, "rejected", true},
		{"unregistered", func(registered time.Time) *apns2.Response {
			return &apns2.Response{StatusCode: 410, Reason: apns2.ReasonUnregistered, Timestamp: apns2.Time{Time: registered.Add(time.Hour)}}
		}, "rejected", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testutils.CreateTestDb(t)
			ctx := t.Context()
			installationsService := installations.NewInstallationsService(testutils.TestLogger(t), db)
			registered := time.Now().UTC().Truncate(time.Microsecond)
			_, err := installationsService.Register(ctx, interfaces.Installation{
				Id:                "device",
				DeliveryMechanism: interfaces.DeliveryMechanism{Kind: interfaces.APNS, Token: "production-token", UpdatedAt: registered},
			})
			require.NoError(t, err)
			current, err := installationsService.GetInstallations(ctx, []string{"device"})
			require.NoError(t, err)
			require.Len(t, current, 1)

			apns, err := delivery.NewApnsDeliveryWithClient(zap.NewNop(), options.ApnsOptions{Topic: "com.example.app", Mode: "development"}, fixedAPNSResponseClient{response: tc.response(registered)})
			require.NoError(t, err)
			store := notificationqueue.New(db)
			env := claimDurableTestEnvelope(t, store)
			dispatcher := newDeliveryDispatcher(ctx, []interfaces.Delivery{apns}, installationsService)
			dispatcher.queue = store
			req := durableTestRequest("device")
			req.Installation = current[0]
			attemptCtx := context.WithValue(ctx, envelopeContextKey{}, env)
			require.NoError(t, dispatcher.prepareRecipients(attemptCtx, []interfaces.SendRequest{req}))
			require.NoError(t, dispatcher.dispatchContext(attemptCtx, req))

			var status, class string
			require.NoError(t, db.QueryRowContext(ctx, "SELECT status, failure_class FROM notification_recipient_receipts WHERE envelope_id=$1 AND installation_id='device'", env.ID).Scan(&status, &class))
			require.Equal(t, tc.status, status)
			require.Equal(t, "provider_permanent", class)
			after, err := installationsService.GetInstallations(ctx, []string{"device"})
			require.NoError(t, err)
			if tc.retained {
				require.Len(t, after, 1, "the registration must survive a rejection that does not prove the token dead")
				require.Equal(t, "production-token", after[0].DeliveryMechanism.Token)
			} else {
				require.Empty(t, after, "a proven-dead token is retired")
			}
		})
	}
}
