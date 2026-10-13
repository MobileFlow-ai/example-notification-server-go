package installations

import (
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	"testing"
	"time"
)

func TestTokenInvalidation_VersionFenceAndNoFallback(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := NewInstallationsService(testutils.TestLogger(t), db)
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	register := func(token string, when time.Time) {
		req := buildInstallation("version-fenced", interfaces.APNS, token)
		req.DeliveryMechanism.UpdatedAt = when
		_, err := svc.Register(ctx, req)
		require.NoError(t, err)
	}
	current := func() []interfaces.Installation {
		rows, err := svc.GetInstallations(ctx, []string{"version-fenced"})
		require.NoError(t, err)
		return rows
	}
	register("older", at.Add(-time.Hour))
	register("current", at)
	captured := current()[0]
	// Provider invalidated the token before its latest registration: keep it.
	require.NoError(t, svc.InvalidateDeliveryToken(ctx, captured, at.Add(-time.Second)))
	require.Len(t, current(), 1)
	// Even an identical registration timestamp denotes a new token version.
	register("current", at)
	require.NoError(t, svc.InvalidateDeliveryToken(ctx, captured, at.Add(time.Hour)))
	require.Len(t, current(), 1)
	require.Greater(t, current()[0].DeliveryMechanism.RegistrationVersion, captured.DeliveryMechanism.RegistrationVersion)
	// Same token renewed while the provider response was in flight: keep it.
	register("current", at.Add(time.Minute))
	require.NoError(t, svc.InvalidateDeliveryToken(ctx, captured, at.Add(time.Hour)))
	require.Len(t, current(), 1)
	require.True(t, at.Add(time.Minute).Equal(current()[0].DeliveryMechanism.UpdatedAt))
	renewed := current()[0]
	require.NoError(t, svc.InvalidateDeliveryToken(ctx, renewed, at.Add(time.Hour)))
	require.Empty(t, current(), "invalid latest token must not fall back to an older registration")
	state := fetchInstallation(t, ctx, db, "version-fenced")
	require.False(t, state.DeletedAt.Valid, "token rejection must not delete installation")
	// An explicit later registration revives this token.
	register("current", at.Add(2*time.Minute))
	require.Len(t, current(), 1)
	// A different latest token is also unaffected by a delayed old rejection.
	old := current()[0]
	register("replacement", at.Add(3*time.Minute))
	require.NoError(t, svc.InvalidateDeliveryToken(ctx, old, time.Time{}))
	require.Equal(t, "replacement", current()[0].DeliveryMechanism.Token)
}

func TestTokenInvalidation_MissingSnapshotIsSafe(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := NewInstallationsService(testutils.TestLogger(t), db)
	req := buildInstallation("safe", interfaces.APNS, "token")
	_, err := svc.Register(ctx, req)
	require.NoError(t, err)
	require.NoError(t, svc.InvalidateDeliveryToken(ctx, req, time.Time{}))
	rows, err := svc.GetInstallations(ctx, []string{"safe"})
	require.NoError(t, err)
	require.Len(t, rows, 1)
}
