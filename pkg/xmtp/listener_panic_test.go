package xmtp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	topicutil "github.com/xmtp/example-notification-server-go/pkg/topics"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	envelopesProto "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/envelopes"
	"github.com/xmtp/xmtpd/pkg/topic"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type panicSubscriptions struct {
	value string
	err   error
}

func failureSignaled(failed <-chan struct{}) bool {
	select {
	case <-failed:
		return true
	default:
		return false
	}
}

func (s panicSubscriptions) Subscribe(
	context.Context,
	string,
	[]*topic.Topic,
) error {
	return nil
}

func (s panicSubscriptions) Unsubscribe(
	context.Context,
	string,
	[]*topic.Topic,
) error {
	return nil
}

func (s panicSubscriptions) GetSubscriptions(
	context.Context,
	*topic.Topic,
	int,
) ([]interfaces.Subscription, error) {
	if s.value != "" {
		panic(s.value)
	}
	return nil, s.err
}

func (s panicSubscriptions) SubscribeWithMetadata(
	context.Context,
	string,
	[]interfaces.SubscriptionInput,
) error {
	return nil
}

func TestV3WorkerPanicFailsClosedWithoutLoggingPanicValue(t *testing.T) {
	const canary = "PANIC_CANARY_RAW_V3_TOPIC_AND_ENVELOPE"
	core, observed := observer.New(zap.ErrorLevel)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	groupTopic := topic.NewTopic(
		topic.TopicKindGroupMessagesV1,
		[]byte("panic-boundary-v3"),
	)
	listener := &Listener{
		logger:         zap.New(core),
		ctx:            ctx,
		cancelFunc:     cancel,
		opts:           options.XmtpOptions{NumWorkers: 1},
		messageChannel: make(chan *v1.Envelope, 1),
		subscriptions:  panicSubscriptions{value: canary},
		dispatcher:     newDeliveryDispatcher(ctx, nil),
		failed:         make(chan struct{}),
	}
	listener.ready.Store(true)
	listener.startMessageWorkers()

	listener.messageChannel <- &v1.Envelope{
		ContentTopic: topicutil.TopicToString(groupTopic),
		TimestampNs:  uint64(time.Now().UnixNano()),
	}

	require.Eventually(t, func() bool {
		return listener.processingUnsafe.Load() &&
			ctx.Err() != nil &&
			failureSignaled(listener.Failed()) &&
			observed.Len() == 1
	}, time.Second, 10*time.Millisecond)
	require.False(t, listener.Ready())

	entries := observed.All()
	require.Len(t, entries, 1)
	require.Equal(t, "xmtp listener degraded", entries[0].Message)
	require.Empty(t, entries[0].Context)
	require.NotContains(t, entries[0].Message, canary)

	// A second terminal report must neither close the channel twice nor create
	// a failure-count side channel in the rate-limited operational log.
	listener.failClosed()
	require.Len(t, observed.All(), 1)
}

func TestV4WorkerPanicFailsClosedWithoutLoggingPanicValue(t *testing.T) {
	const canary = "PANIC_CANARY_RAW_V4_TOPIC_AND_ENVELOPE"
	core, observed := observer.New(zap.ErrorLevel)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	listener := &V4Listener{
		logger:          zap.New(core),
		ctx:             ctx,
		cancelFunc:      cancel,
		opts:            options.XmtpOptions{NumWorkers: 1},
		envelopeChannel: make(chan *envelopesProto.OriginatorEnvelope, 1),
		subscriptions:   panicSubscriptions{value: canary},
		dispatcher:      newDeliveryDispatcher(ctx, nil),
		failed:          make(chan struct{}),
	}
	listener.ready.Store(true)
	listener.startEnvelopeWorkers()

	listener.envelopeChannel <- buildGroupMessageOriginatorEnvelope(
		t,
		1,
		1,
		time.Now().UnixNano(),
		[]byte("panic-boundary-v4"),
		[]byte("data"),
		nil,
		true,
	)

	require.Eventually(t, func() bool {
		return listener.processingUnsafe.Load() &&
			ctx.Err() != nil &&
			failureSignaled(listener.Failed()) &&
			observed.Len() == 1
	}, time.Second, 10*time.Millisecond)
	require.False(t, listener.Ready())

	entries := observed.All()
	require.Len(t, entries, 1)
	require.Equal(t, "xmtp listener degraded", entries[0].Message)
	require.Empty(t, entries[0].Context)
	require.NotContains(t, entries[0].Message, canary)

	listener.failClosed()
	require.Len(t, observed.All(), 1)
}

func TestListenerStopDoesNotSignalFailure(t *testing.T) {
	t.Run("V3", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		listener := &Listener{
			ctx:        ctx,
			cancelFunc: cancel,
			failed:     make(chan struct{}),
		}

		listener.Stop()

		require.ErrorIs(t, ctx.Err(), context.Canceled)
		require.False(t, failureSignaled(listener.Failed()))
	})

	t.Run("V4", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		listener := &V4Listener{
			ctx:        ctx,
			cancelFunc: cancel,
			failed:     make(chan struct{}),
		}

		listener.Stop()

		require.ErrorIs(t, ctx.Err(), context.Canceled)
		require.False(t, failureSignaled(listener.Failed()))
	})
}

func TestWorkerChannelTerminalExitSignalsFailure(t *testing.T) {
	t.Run("V3", func(t *testing.T) {
		core, observed := observer.New(zap.ErrorLevel)
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		listener := &Listener{
			logger:         zap.New(core),
			ctx:            ctx,
			cancelFunc:     cancel,
			opts:           options.XmtpOptions{NumWorkers: 1},
			messageChannel: make(chan *v1.Envelope),
			failed:         make(chan struct{}),
		}
		listener.startMessageWorkers()

		close(listener.messageChannel)

		require.Eventually(t, func() bool {
			return failureSignaled(listener.Failed()) &&
				ctx.Err() != nil &&
				observed.Len() == 1
		}, time.Second, 10*time.Millisecond)
		require.Equal(t, "xmtp listener degraded", observed.All()[0].Message)
	})

	t.Run("V4", func(t *testing.T) {
		core, observed := observer.New(zap.ErrorLevel)
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		listener := &V4Listener{
			logger:          zap.New(core),
			ctx:             ctx,
			cancelFunc:      cancel,
			opts:            options.XmtpOptions{NumWorkers: 1},
			envelopeChannel: make(chan *envelopesProto.OriginatorEnvelope),
			failed:          make(chan struct{}),
		}
		listener.startEnvelopeWorkers()

		close(listener.envelopeChannel)

		require.Eventually(t, func() bool {
			return failureSignaled(listener.Failed()) &&
				ctx.Err() != nil &&
				observed.Len() == 1
		}, time.Second, 10*time.Millisecond)
		require.Equal(t, "xmtp listener degraded", observed.All()[0].Message)
	})
}

func TestEnvelopeRetryExhaustionSignalsFailure(t *testing.T) {
	dependencyError := errors.New("dependency unavailable")

	t.Run("V3", func(t *testing.T) {
		core, observed := observer.New(zap.ErrorLevel)
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		groupTopic := topic.NewTopic(
			topic.TopicKindGroupMessagesV1,
			[]byte("retry-boundary-v3"),
		)
		listener := &Listener{
			logger:         zap.New(core),
			ctx:            ctx,
			cancelFunc:     cancel,
			opts:           options.XmtpOptions{NumWorkers: 1},
			messageChannel: make(chan *v1.Envelope, 1),
			subscriptions:  panicSubscriptions{err: dependencyError},
			failed:         make(chan struct{}),
			retryWindow:    20 * time.Millisecond,
		}
		listener.startMessageWorkers()

		listener.messageChannel <- &v1.Envelope{
			ContentTopic: topicutil.TopicToString(groupTopic),
			TimestampNs:  uint64(time.Now().UnixNano()),
		}

		require.Eventually(t, func() bool {
			return failureSignaled(listener.Failed()) &&
				ctx.Err() != nil &&
				observed.Len() == 1
		}, time.Second, 10*time.Millisecond)
		require.True(t, listener.processingUnsafe.Load())
		require.Equal(t, "xmtp listener degraded", observed.All()[0].Message)
	})

	t.Run("V4", func(t *testing.T) {
		core, observed := observer.New(zap.ErrorLevel)
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		listener := &V4Listener{
			logger:          zap.New(core),
			ctx:             ctx,
			cancelFunc:      cancel,
			opts:            options.XmtpOptions{NumWorkers: 1},
			envelopeChannel: make(chan *envelopesProto.OriginatorEnvelope, 1),
			subscriptions:   panicSubscriptions{err: dependencyError},
			failed:          make(chan struct{}),
			retryWindow:     20 * time.Millisecond,
		}
		listener.startEnvelopeWorkers()

		listener.envelopeChannel <- buildGroupMessageOriginatorEnvelope(
			t,
			1,
			2,
			time.Now().UnixNano(),
			[]byte("retry-boundary-v4"),
			[]byte("data"),
			nil,
			true,
		)

		require.Eventually(t, func() bool {
			return failureSignaled(listener.Failed()) &&
				ctx.Err() != nil &&
				observed.Len() == 1
		}, time.Second, 10*time.Millisecond)
		require.True(t, listener.processingUnsafe.Load())
		require.Equal(t, "xmtp listener degraded", observed.All()[0].Message)
	})
}
