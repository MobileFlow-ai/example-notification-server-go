package xmtp

import (
	"context"
	"errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/delivery"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	"testing"
	"time"
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
		{"bad_token", &delivery.ApnsRejection{StatusCode: 400, InvalidToken: true}, true},
		{"credentials", &delivery.ApnsRejection{StatusCode: 403, Permanent: true}, false},
		{"rate_limited", &delivery.ApnsRejection{StatusCode: 429}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := mocks.NewDelivery(t)
			provider.On("CanDeliver", mock.Anything).Return(true)
			provider.On("Send", mock.Anything, mock.Anything).Return(tc.rejection).Once()
			cleanup := &recordingInvalidator{}
			d := deliveryDispatcher{ctx: t.Context(), logger: testutils.TestLogger(t), deliveryServices: []interfaces.Delivery{provider}, invalidTokens: cleanup}
			req := interfaces.SendRequest{Installation: interfaces.Installation{Id: "captured", DeliveryMechanism: interfaces.DeliveryMechanism{Kind: interfaces.APNS, Token: "captured-token", UpdatedAt: at.Add(-time.Hour)}}}
			require.ErrorIs(t, d.deliver(req), tc.rejection)
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
	rejection := &delivery.ApnsRejection{StatusCode: 400, InvalidToken: true}
	provider.On("CanDeliver", mock.Anything).Return(true)
	provider.On("Send", mock.Anything, mock.Anything).Return(rejection)
	cleanupErr := errors.New("database unavailable")
	cleanup := &recordingInvalidator{err: cleanupErr}
	d := deliveryDispatcher{ctx: t.Context(), logger: testutils.TestLogger(t), deliveryServices: []interfaces.Delivery{provider}, invalidTokens: cleanup}
	err := d.deliver(interfaces.SendRequest{})
	require.ErrorIs(t, err, rejection)
	require.ErrorIs(t, err, cleanupErr)
}
