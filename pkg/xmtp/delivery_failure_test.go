package xmtp

import (
	"errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	"testing"
	"time"
)

func TestDeliveryFailure_MissingProvider(t *testing.T) {
	d := deliveryDispatcher{ctx: t.Context(), logger: testutils.TestLogger(t)}
	require.Error(t, d.deliver(interfaces.SendRequest{}))
}

func TestDeliveryFailure_NilEnvelopes(t *testing.T) {
	require.Error(t, (&Listener{}).processEnvelope(nil))
	require.Error(t, (&V4Listener{}).processOriginatorEnvelope(nil))
}

func TestDeliveryFailure_EarlyRecipientIsNotLost(t *testing.T) {
	for _, version := range []string{"v3", "v4"} {
		t.Run(version, func(t *testing.T) {
			fail := errors.New("provider temporarily unavailable")
			subs := mocks.NewSubscriptions(t)
			insts := mocks.NewInstallations(t)
			provider := mocks.NewDelivery(t)
			subs.On("GetSubscriptions", mock.Anything, mock.Anything, mock.Anything).Return([]interfaces.Subscription{{InstallationId: "a"}, {InstallationId: "b"}}, nil)
			insts.On("GetInstallations", mock.Anything, mock.Anything).Return([]interfaces.Installation{{Id: "a", PayloadFormat: interfaces.PayloadFormatV4}, {Id: "b", PayloadFormat: interfaces.PayloadFormatV4}}, nil)
			provider.On("CanDeliver", mock.Anything).Return(true)
			provider.On("Send", mock.Anything, mock.MatchedBy(func(r interfaces.SendRequest) bool { return r.Installation.Id == "a" })).Return(fail).Once()
			provider.On("Send", mock.Anything, mock.MatchedBy(func(r interfaces.SendRequest) bool { return r.Installation.Id == "b" })).Return(nil).Once()
			log := testutils.TestLogger(t)
			dispatcher := deliveryDispatcher{ctx: t.Context(), logger: log, deliveryServices: []interfaces.Delivery{provider}}
			var err error
			if version == "v3" {
				l := Listener{ctx: t.Context(), logger: log, subscriptions: subs, installations: insts, dispatcher: dispatcher}
				err = l.processEnvelope(&v1.Envelope{ContentTopic: TEST_TOPIC, Message: []byte("test"), TimestampNs: uint64(time.Now().UnixNano())})
			} else {
				l := V4Listener{ctx: t.Context(), logger: log, subscriptions: subs, installations: insts, dispatcher: dispatcher}
				env := buildGroupMessageOriginatorEnvelope(t, 1, 1, time.Now().UnixNano(), []byte("group-id"), []byte("test"), nil, true)
				err = l.processOriginatorEnvelope(env)
			}
			require.ErrorIs(t, err, fail)
			provider.AssertNumberOfCalls(t, "Send", 2)
		})
	}
}
