package incidentaccess

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type gatedAcceptListener struct {
	net.Listener
	acceptStarted chan struct{}
	releaseAccept chan struct{}
	startOnce     sync.Once
}

func (l *gatedAcceptListener) Accept() (net.Conn, error) {
	l.startOnce.Do(func() {
		close(l.acceptStarted)
	})
	<-l.releaseAccept
	return l.Listener.Accept()
}

func TestServerAcceptsOnlyNumericLoopbackBind(t *testing.T) {
	handler := testHandler(t, &fakeGate{})
	for _, address := range []string{
		"",
		"localhost:9091",
		"0.0.0.0:9091",
		"[::]:9091",
		"192.168.1.8:9091",
		"127.0.0.1:0",
	} {
		server, err := NewServer(
			zap.NewNop(),
			handler,
			ServerOptions{
				BindAddress:    address,
				RequestTimeout: time.Second,
			},
		)
		require.Nil(t, server)
		require.ErrorIs(t, err, ErrInvalidConfiguration)
	}
	server, err := NewServer(
		zap.NewNop(),
		handler,
		ServerOptions{
			BindAddress:    "127.0.0.1:9091",
			RequestTimeout: time.Second,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, server)
}

func TestServerLifecycleUsesPreboundLoopbackListener(t *testing.T) {
	handler := testHandler(t, &fakeGate{})
	server, err := NewServer(
		zap.NewNop(),
		handler,
		ServerOptions{
			BindAddress:    "127.0.0.1:9091",
			RequestTimeout: time.Second,
		},
	)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, server.SetListener(listener))
	require.NoError(t, server.Prepare())
	require.NoError(t, server.Start())
	require.True(t, server.Ready())

	client := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   time.Second,
	}
	response, err := client.Get(
		"http://" + listener.Addr().String() + CreateRequestPath,
	)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, response.Body)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusMethodNotAllowed, response.StatusCode)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, server.Stop(ctx))
	require.False(t, server.Ready())
}

func TestServerDoesNotReportReadyBeforeServeAccepts(t *testing.T) {
	handler := testHandler(t, &fakeGate{})
	server, err := NewServer(
		zap.NewNop(),
		handler,
		ServerOptions{
			BindAddress:    "127.0.0.1:9091",
			RequestTimeout: time.Second,
		},
	)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	gated := &gatedAcceptListener{
		Listener:      listener,
		acceptStarted: make(chan struct{}),
		releaseAccept: make(chan struct{}),
	}
	defer func() {
		select {
		case <-gated.releaseAccept:
		default:
			close(gated.releaseAccept)
		}
		_ = listener.Close()
	}()
	require.NoError(t, server.SetListener(gated))
	started := make(chan error, 1)
	go func() {
		started <- server.Start()
	}()

	select {
	case <-gated.acceptStarted:
	case <-time.After(time.Second):
		t.Fatal("Serve did not attempt to accept a connection")
	}
	require.False(t, server.Ready())
	select {
	case startErr := <-started:
		require.Failf(
			t,
			"Start returned before Serve accepted",
			"unexpected error: %v",
			startErr,
		)
	default:
	}

	close(gated.releaseAccept)
	select {
	case startErr := <-started:
		require.NoError(t, startErr)
	case <-time.After(time.Second):
		t.Fatal("Start did not return after Serve accepted")
	}
	require.True(t, server.Ready())
	shutdownContext, shutdownCancel := context.WithTimeout(
		t.Context(),
		time.Second,
	)
	defer shutdownCancel()
	require.NoError(t, server.Stop(shutdownContext))
}

func TestServerStartFailsClosedWhenPreparedListenerIsClosed(t *testing.T) {
	handler := testHandler(t, &fakeGate{})
	server, err := NewServer(
		zap.NewNop(),
		handler,
		ServerOptions{
			BindAddress:    "127.0.0.1:9091",
			RequestTimeout: time.Second,
		},
	)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, server.SetListener(listener))
	require.NoError(t, server.Prepare())
	require.NoError(t, listener.Close())

	require.ErrorIs(t, server.Start(), ErrInvalidConfiguration)
	require.False(t, server.Ready())
	select {
	case <-server.Failed():
	default:
		t.Fatal("startup failure was not signaled before Start returned")
	}
}

func TestServerPanicBoundaryLogsAndReturnsOnlyFixedContent(
	t *testing.T,
) {
	const canary = "RAW_VAULT_PANIC_CANARY"
	core, observed := observer.New(zap.ErrorLevel)
	gate := &fakeGate{
		create: func(
			context.Context,
			vault.CreateIncidentAccessRequest,
		) (*vault.IncidentAccessStatus, error) {
			panic(canary)
		},
	}
	handler := testHandler(t, gate)
	server, err := NewServer(
		zap.New(core),
		handler,
		ServerOptions{
			BindAddress:    "127.0.0.1:9091",
			RequestTimeout: time.Second,
		},
	)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, server.SetListener(listener))
	require.NoError(t, server.Start())
	require.True(t, server.Ready())
	body := `{
	  "ticket_reference":"incident:ticket-001",
	  "hypothesis":1,
	  "window_start":"2026-07-27T17:00:00Z",
	  "window_end":"2026-07-27T18:00:00Z"
	}`
	request, err := http.NewRequest(
		http.MethodPost,
		"http://"+listener.Addr().String()+CreateRequestPath,
		strings.NewReader(body),
	)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+requesterSecret)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   time.Second,
	}
	response, err := client.Do(request)
	require.NoError(t, err)
	responseBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())

	require.Equal(t, http.StatusInternalServerError, response.StatusCode)
	require.JSONEq(t, `{"error":"internal_error"}`, string(responseBody))
	require.NotContains(t, string(responseBody), canary)
	require.False(t, server.Ready())
	select {
	case <-server.Failed():
	default:
		t.Fatal("handler panic was not signaled before the response completed")
	}
	shutdownContext, shutdownCancel := context.WithTimeout(
		t.Context(),
		time.Second,
	)
	defer shutdownCancel()
	require.NoError(t, server.Stop(shutdownContext))

	entries := observed.All()
	require.Len(t, entries, 1)
	require.Equal(t, "private incident request failed", entries[0].Message)
	require.Empty(t, entries[0].Context)
}
