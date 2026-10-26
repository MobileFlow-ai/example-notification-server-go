package xmtp

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/xmtpd/pkg/topic"
)

func TestDeliveryFailure_NilEnvelopes(t *testing.T) {
	require.Error(t, (&Listener{}).processEnvelope(nil))
	require.Error(t, (&V4Listener{}).processOriginatorEnvelope(nil))
}

// An early provider failure must not stop delivery to later recipients, and
// the envelope must still report failure so it is retried.
func TestDeliveryFailure_V4EarlyRecipientIsNotLost(t *testing.T) {
	fail := errors.New("provider temporarily unavailable")
	provider := mocks.NewDelivery(t)
	provider.On("CanDeliver", mock.Anything).Return(true)
	provider.On("Send", mock.Anything, mock.MatchedBy(func(r interfaces.SendRequest) bool { return r.Installation.Id == "early-a" })).Return(fail).Once()
	provider.On("Send", mock.Anything, mock.MatchedBy(func(r interfaces.SendRequest) bool { return r.Installation.Id == "early-b" })).Return(nil).Once()
	l := buildV4TestListener(t, provider)
	groupID := []byte{0x31, 0x32, 0x33, 0x34}
	groupTopic := topic.NewTopic(topic.TopicKindGroupMessagesV1, groupID)
	for _, id := range []string{"early-a", "early-b"} {
		registerV4Installation(t, l, id, interfaces.PayloadFormatV4)
		subscribeV4ToTopic(t, l, id, groupTopic)
	}
	env := buildGroupMessageOriginatorEnvelope(t, 1, 1, int64(time.Second), groupID, []byte("data"), nil, true)
	require.ErrorIs(t, l.processOriginatorEnvelope(env), fail)
	provider.AssertNumberOfCalls(t, "Send", 2)
}
