package vault

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/gate8wrapper"
)

func TestSerializedDeliveryJobRejectsExactAPNSBoundary(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	job := SerializedDeliveryJob{
		DeviceToken:      strings.Repeat("ab", 32),
		Topic:            "com.example.app",
		Payload:          make([]byte, 4096),
		PushType:         "alert",
		Priority:         10,
		Expiration:       now.Add(time.Minute),
		TrafficClass:     DeliveryTrafficConversation,
		PolicyEpoch:      1,
		RouteKeyEpoch:    1,
		NoncePrefix:      1,
		DeliverySequence: 1,
		AliasDay:         gate8wrapper.UTCDay(now),
		RouteAlias:       make([]byte, gate8wrapper.RouteAliasSize),
	}
	require.ErrorIs(
		t,
		validateSerializedDeliveryJob(job, now),
		ErrDeliveryJobInvalid,
	)
}
