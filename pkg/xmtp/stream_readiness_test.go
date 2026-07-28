package xmtp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	notificationApi "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/message_api"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
)

var errTerminalStream = errors.New("terminal stream failure")

type terminalV3Stream struct {
	grpc.ClientStream
}

func (*terminalV3Stream) Recv() (*v1.Envelope, error) {
	return nil, errTerminalStream
}

type terminalV4Stream struct {
	grpc.ClientStream
}

func (*terminalV4Stream) Recv() (
	*notificationApi.SubscribeEnvelopesResponse,
	error,
) {
	return nil, errTerminalStream
}

func TestV3StreamErrorDropsReadinessBeforeRecoveryWork(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var listener *Listener
	readyAtFailureLog := make(chan bool, 1)
	core, _ := observer.New(zap.ErrorLevel)
	logger := zap.New(core, zap.Hooks(func(zapcore.Entry) error {
		// The dependency log is emitted before backoff and refresh. Capturing
		// Ready here deterministically detects the old deferred-only reset.
		readyAtFailureLog <- listener.Ready()
		cancel()
		return nil
	}))
	listener = &Listener{
		ctx:    ctx,
		logger: logger,
	}
	listener.ready.Store(true)
	backoff := time.Duration(0)

	require.False(
		t,
		listener.consumeMessageStream(&terminalV3Stream{}, &backoff),
	)
	require.False(t, <-readyAtFailureLog)
	require.False(t, listener.Ready())
}

func TestV4StreamErrorDropsReadinessBeforeRecoveryWork(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var listener *V4Listener
	readyAtFailureLog := make(chan bool, 1)
	core, _ := observer.New(zap.ErrorLevel)
	logger := zap.New(core, zap.Hooks(func(zapcore.Entry) error {
		// The dependency log is emitted before backoff and refresh. Capturing
		// Ready here deterministically detects the old deferred-only reset.
		readyAtFailureLog <- listener.Ready()
		cancel()
		return nil
	}))
	listener = &V4Listener{
		ctx:    ctx,
		logger: logger,
	}
	listener.ready.Store(true)
	backoff := time.Duration(0)

	require.False(
		t,
		listener.consumeEnvelopeStream(&terminalV4Stream{}, &backoff),
	)
	require.False(t, <-readyAtFailureLog)
	require.False(t, listener.Ready())
}
