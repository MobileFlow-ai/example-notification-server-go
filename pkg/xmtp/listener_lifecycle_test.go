package xmtp

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	envelopesProto "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/envelopes"
	notificationApi "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/message_api"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

type closedV3Stream struct{ grpc.ClientStream }

func (closedV3Stream) Recv() (*v1.Envelope, error) { return nil, io.EOF }

type closedV4Stream struct{ grpc.ClientStream }

func (closedV4Stream) Recv() (*notificationApi.SubscribeEnvelopesResponse, error) {
	return nil, io.EOF
}

func TestV3ReconnectClosesEachPreviousConnectionAndStopClosesCurrent(t *testing.T) {
	listener, err := NewListener(t.Context(), zap.NewNop(), options.XmtpOptions{
		GrpcAddress: "localhost:1",
	}, nil, nil, nil, "test", "test")
	require.NoError(t, err)
	t.Cleanup(listener.Stop)
	for range 25 {
		previous := listener.xmtpConn
		require.NoError(t, listener.refreshClient())
		require.NotSame(t, previous, listener.xmtpConn)
		require.Equal(t, connectivity.Shutdown, previous.GetState())
	}
	current := listener.xmtpConn
	listener.Stop()
	require.Equal(t, connectivity.Shutdown, current.GetState())
	require.Nil(t, listener.xmtpConn)
	require.ErrorIs(t, listener.refreshClient(), context.Canceled)
	require.Nil(t, listener.xmtpConn)
}

func TestV4StoppedListenerCannotRecreateConnection(t *testing.T) {
	listener, err := NewV4Listener(t.Context(), zap.NewNop(), options.XmtpOptions{
		GrpcAddress: "localhost:1",
	}, nil, nil, nil, "test", "test")
	require.NoError(t, err)
	t.Cleanup(listener.Stop)
	current := listener.v4Conn
	listener.Stop()
	require.Equal(t, connectivity.Shutdown, current.GetState())
	require.ErrorIs(t, listener.refreshV4Client(), context.Canceled)
	require.Nil(t, listener.v4Conn)
}

func TestGracefullyClosedStreamsBackOffBeforeReconnecting(t *testing.T) {
	t.Run("v3", func(t *testing.T) {
		listener := &Listener{ctx: t.Context(), logger: zap.NewNop()}
		delay := 60 * time.Millisecond
		start := time.Now()
		require.False(t, listener.consumeMessageStream(closedV3Stream{}, &delay))
		require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
		require.Equal(t, 120*time.Millisecond, delay)
	})
	t.Run("v4", func(t *testing.T) {
		listener := &V4Listener{ctx: t.Context(), logger: zap.NewNop()}
		delay := 60 * time.Millisecond
		start := time.Now()
		require.False(t, listener.consumeEnvelopeStream(closedV4Stream{}, &delay))
		require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
		require.Equal(t, 120*time.Millisecond, delay)
	})
}

func TestStopInterruptsMaximumReconnectDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan bool, 1)
	delay := MAX_SLEEP_TIME
	go func() { done <- waitForReconnect(ctx, &delay) }()
	cancel()
	select {
	case live := <-done:
		require.False(t, live)
	case <-time.After(time.Second):
		t.Fatal("shutdown remained blocked by reconnect backoff")
	}
}

func TestConcurrentStopAndReconnectLeavesNoConnection(t *testing.T) {
	for _, version := range []string{"v3", "v4"} {
		t.Run(version, func(t *testing.T) {
			var stop func()
			var refresh func() error
			var check func()
			if version == "v3" {
				listener, err := NewListener(t.Context(), zap.NewNop(), options.XmtpOptions{
					GrpcAddress: "localhost:1",
				}, nil, nil, nil, "test", "test")
				require.NoError(t, err)
				stop, refresh = listener.Stop, listener.refreshClient
				check = func() { require.Nil(t, listener.xmtpConn) }
			} else {
				listener, err := NewV4Listener(t.Context(), zap.NewNop(), options.XmtpOptions{
					GrpcAddress: "localhost:1",
				}, nil, nil, nil, "test", "test")
				require.NoError(t, err)
				stop, refresh = listener.Stop, listener.refreshV4Client
				check = func() { require.Nil(t, listener.v4Conn) }
			}
			t.Cleanup(stop)
			var workers sync.WaitGroup
			workers.Go(func() {
				for range 100 {
					if refresh() != nil {
						return
					}
				}
			})
			workers.Go(stop)
			workers.Wait()
			check()
			require.ErrorIs(t, refresh(), context.Canceled)
			check()
		})
	}
}

// Observe real transports rather than a mocked Close call: every refused
// subscription causes reconnect, and Stop must release all of those sockets.
type listenerTransportCounter struct{ active atomic.Int32 }

func (c *listenerTransportCounter) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}
func (c *listenerTransportCounter) HandleConn(_ context.Context, event stats.ConnStats) {
	switch event.(type) {
	case *stats.ConnBegin:
		c.active.Add(1)
	case *stats.ConnEnd:
		c.active.Add(-1)
	}
}
func (*listenerTransportCounter) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}
func (*listenerTransportCounter) HandleRPC(context.Context, stats.RPCStats) {}

type unavailableMessageServer struct {
	v1.UnimplementedMessageApiServer
	calls atomic.Int32
}

func (s *unavailableMessageServer) SubscribeAll(*v1.SubscribeAllRequest, grpc.ServerStreamingServer[v1.Envelope]) error {
	s.calls.Add(1)
	return status.Error(codes.Unavailable, "synthetic reconnect probe")
}

func TestV3ListenerStopClosesTransportsAcrossReconnects(t *testing.T) {
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	counter := &listenerTransportCounter{}
	server := grpc.NewServer(grpc.StatsHandler(counter))
	messages := &unavailableMessageServer{}
	v1.RegisterMessageApiServer(server, messages)
	t.Cleanup(server.Stop)
	go func() { _ = server.Serve(socket) }()
	listener, err := NewListener(t.Context(), zap.NewNop(), options.XmtpOptions{
		GrpcAddress: socket.Addr().String(),
	}, nil, nil, nil, "test", "test")
	require.NoError(t, err)
	t.Cleanup(listener.Stop)
	listener.Start()
	require.Eventually(t, func() bool { return messages.calls.Load() >= 4 }, 5*time.Second, 5*time.Millisecond)
	listener.Stop()
	require.Eventually(t, func() bool { return counter.active.Load() == 0 }, time.Second, 5*time.Millisecond,
		"a replaced transport remains connected after listener shutdown")
}

func TestParentCancellationClosesListenerTransportWithoutExplicitStop(t *testing.T) {
	for _, version := range []string{"v3", "v4"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			var transport *grpc.ClientConn
			var start, stop func()
			if version == "v3" {
				listener, err := NewListener(ctx, zap.NewNop(), options.XmtpOptions{
					GrpcAddress: "localhost:1",
				}, nil, nil, nil, "test", "test")
				require.NoError(t, err)
				transport, start, stop = listener.xmtpConn, listener.Start, listener.Stop
			} else {
				listener, err := NewV4Listener(ctx, zap.NewNop(), options.XmtpOptions{
					GrpcAddress: "localhost:1",
				}, nil, nil, nil, "test", "test")
				require.NoError(t, err)
				transport, start, stop = listener.v4Conn, listener.Start, listener.Stop
			}
			t.Cleanup(stop)
			cancel()
			start()
			require.Eventually(t, func() bool { return transport.GetState() == connectivity.Shutdown },
				time.Second, 5*time.Millisecond)
		})
	}
}

// These probes exercise the consumer at its cancellation boundary, rather
// than testing a timer helper in isolation.
func TestCancellationInterruptsStreamReconnectBackoff(t *testing.T) {
	for _, version := range []string{"v3", "v4"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			core, _ := observer.New(zap.ErrorLevel)
			logger := zap.New(core, zap.Hooks(func(zapcore.Entry) error { cancel(); return nil }))
			delay := 1500 * time.Millisecond
			started := time.Now()
			var stopped bool
			if version == "v3" {
				listener := &Listener{ctx: ctx, logger: logger}
				stopped = listener.consumeMessageStream(&terminalV3Stream{}, &delay)
			} else {
				listener := &V4Listener{ctx: ctx, logger: logger}
				stopped = listener.consumeEnvelopeStream(&terminalV4Stream{}, &delay)
			}
			require.True(t, stopped, "cancellation must terminate the stream loop")
			require.Less(t, time.Since(started), 500*time.Millisecond)
		})
	}
}

type fullQueueV3Stream struct {
	grpc.ClientStream
	received chan struct{}
}

func (s fullQueueV3Stream) Recv() (*v1.Envelope, error) {
	close(s.received)
	return &v1.Envelope{}, nil
}

type fullQueueV4Stream struct {
	grpc.ClientStream
	received chan struct{}
}

func (s fullQueueV4Stream) Recv() (*notificationApi.SubscribeEnvelopesResponse, error) {
	close(s.received)
	return &notificationApi.SubscribeEnvelopesResponse{Envelopes: []*envelopesProto.OriginatorEnvelope{{}}}, nil
}

func TestCancellationReleasesFullListenerQueue(t *testing.T) {
	for _, version := range []string{"v3", "v4"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			received := make(chan struct{})
			done := make(chan bool, 1)
			delay := STARTING_SLEEP_TIME
			var drain func()
			var ready func() bool
			if version == "v3" {
				queue := make(chan *v1.Envelope, 1)
				queue <- &v1.Envelope{}
				listener := &Listener{ctx: ctx, logger: zap.NewNop(), messageChannel: queue}
				listener.ready.Store(true)
				ready = listener.Ready
				drain = func() { <-queue }
				go func() { done <- listener.consumeMessageStream(fullQueueV3Stream{received: received}, &delay) }()
			} else {
				queue := make(chan *envelopesProto.OriginatorEnvelope, 1)
				queue <- &envelopesProto.OriginatorEnvelope{}
				listener := &V4Listener{ctx: ctx, logger: zap.NewNop(), envelopeChannel: queue}
				listener.ready.Store(true)
				ready = listener.Ready
				drain = func() { <-queue }
				go func() { done <- listener.consumeEnvelopeStream(fullQueueV4Stream{received: received}, &delay) }()
			}
			<-received
			cancel()
			select {
			case stopped := <-done:
				require.True(t, stopped)
				require.False(t, ready())
			case <-time.After(500 * time.Millisecond):
				// Release the old blocked producer even on the negative baseline.
				drain()
				<-done
				t.Fatal("cancelled listener stayed blocked on its full worker queue")
			}
		})
	}
}
