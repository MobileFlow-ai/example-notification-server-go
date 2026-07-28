package delivery

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestInvalidTokenErasureWorkerSynchronouslyRecoversWithoutAPNS(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	marker := erasureMarkerFixture(now, 1)
	store := &fakeDeliveryJobStore{
		erasureClaims: []vault.ClaimedDeliveryJob{marker},
	}
	eraser := &fakeInvalidTokenEraser{}
	worker, err := NewInvalidTokenErasureWorker(
		zap.NewNop(),
		store,
		eraser,
	)
	require.NoError(t, err)
	worker.clock = &fixedAPNSClock{now: now}

	require.NoError(t, worker.Start(t.Context()))
	require.True(t, store.erasuresRecovered)
	require.Equal(
		t,
		[][]byte{marker.InstallationLookup},
		eraser.installationLookups,
	)
	require.Equal(t, []string{marker.Job.DeviceToken}, eraser.deviceTokens)
	require.Equal(t, [][]byte{marker.JobID}, store.deleted)
	require.Empty(t, store.erasures)

	require.NoError(t, worker.Stop(t.Context()))
}

func TestInvalidTokenErasureWorkerPersistsBackoffBeyondAttemptThree(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	marker := erasureMarkerFixture(now, 8)
	store := &fakeDeliveryJobStore{
		erasureClaims: []vault.ClaimedDeliveryJob{marker},
	}
	eraser := &fakeInvalidTokenEraser{
		err: errors.New("vault unavailable"),
	}
	worker, err := NewInvalidTokenErasureWorker(
		zap.NewNop(),
		store,
		eraser,
	)
	require.NoError(t, err)
	worker.clock = &fixedAPNSClock{now: now}
	worker.jitter = bytes.NewReader([]byte{0, 0})

	require.NoError(t, worker.Start(t.Context()))
	require.True(t, store.erasuresRecovered)
	require.Len(t, eraser.installationLookups, 1)
	require.Len(t, store.erasures, 1)
	require.Equal(t, marker.JobID, store.erasures[0].id)
	require.GreaterOrEqual(
		t,
		store.erasures[0].available.Sub(now),
		20*time.Second,
	)
	require.Empty(t, store.deleted)

	require.NoError(t, worker.Stop(t.Context()))
}

func TestInvalidTokenErasurePanicIsFixedAndFailsStartupClosed(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	const sensitivePanic = "sensitive-device-token"
	store := &fakeDeliveryJobStore{
		erasureClaims: []vault.ClaimedDeliveryJob{
			erasureMarkerFixture(now, 1),
		},
	}
	eraser := &fakeInvalidTokenEraser{panicValue: sensitivePanic}
	core, observed := observer.New(zapcore.DebugLevel)
	worker, err := NewInvalidTokenErasureWorker(
		zap.New(core),
		store,
		eraser,
	)
	require.NoError(t, err)
	worker.clock = &fixedAPNSClock{now: now}

	require.ErrorIs(
		t,
		worker.Start(t.Context()),
		ErrInvalidTokenErasureUnavailable,
	)
	require.NotEmpty(t, observed.All())
	for _, entry := range observed.All() {
		require.NotContains(t, entry.Message, sensitivePanic)
	}
}

func erasureMarkerFixture(
	now time.Time,
	retryExponent int,
) vault.ClaimedDeliveryJob {
	return vault.ClaimedDeliveryJob{
		JobID:              bytes.Repeat([]byte{3}, 16),
		InstallationLookup: bytes.Repeat([]byte{8}, 32),
		Job: vault.SerializedDeliveryJob{
			DeviceToken:  "abababababababababababababababababababababababababababababababab",
			Expiration:   now.Add(-time.Minute),
			TrafficClass: vault.DeliveryTrafficConversation,
			EraseOnly:    true,
		},
		RetryExponent: retryExponent,
		ExpiresAt:     now.Add(-time.Minute),
	}
}
