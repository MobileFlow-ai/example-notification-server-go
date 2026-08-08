package xmtp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	privacylog "github.com/xmtp/example-notification-server-go/pkg/logging"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type Listener struct {
	logger           *zap.Logger
	ctx              context.Context
	cancelFunc       func()
	connMu           sync.Mutex
	xmtpClient       v1.MessageApiClient
	xmtpConn         *grpc.ClientConn
	opts             options.XmtpOptions
	messageChannel   chan *v1.Envelope
	installations    interfaces.Installations
	subscriptions    interfaces.Subscriptions
	clientVersion    string
	appVersion       string
	dispatcher       deliveryDispatcher
	ready            atomic.Bool
	processing       atomic.Int32
	processingUnsafe atomic.Bool
	errorLogs        privacylog.FixedErrorLimiter
	failed           chan struct{}
	failedOnce       sync.Once
	retryWindow      time.Duration
}

func NewListener(
	ctx context.Context,
	logger *zap.Logger,
	opts options.XmtpOptions,
	installations interfaces.Installations,
	subscriptions interfaces.Subscriptions,
	deliveryServices []interfaces.Delivery,
	clientVersion string,
	appVersion string,
) (*Listener, error) {
	client, conn, err := NewClientWithConn(
		ctx,
		opts.GrpcAddress,
		opts.UseTls,
		clientVersion,
		appVersion,
	)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	namedLogger := logger.Named("xmtp-listener")

	return &Listener{
		ctx:            ctx,
		cancelFunc:     cancel,
		logger:         namedLogger,
		xmtpClient:     client,
		xmtpConn:       conn,
		opts:           opts,
		messageChannel: make(chan *v1.Envelope, 100),
		installations:  installations,
		subscriptions:  subscriptions,
		clientVersion:  clientVersion,
		appVersion:     appVersion,
		dispatcher:     newDeliveryDispatcher(ctx, deliveryServices),
		failed:         make(chan struct{}),
	}, nil
}

func (l *Listener) Start() {
	go runListenerGoroutine(l.startMessageListener, l.failClosed)
	l.startMessageWorkers()
}

func (l *Listener) Stop() {
	l.ready.Store(false)
	l.cancelFunc()
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if l.xmtpConn != nil {
		_ = l.xmtpConn.Close()
		l.xmtpConn = nil
	}
}

func (l *Listener) Ready() bool {
	return l.ready.Load() &&
		l.processing.Load() == 0 &&
		!l.processingUnsafe.Load()
}

func (l *Listener) Failed() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.failed
}

func (l *Listener) startMessageListener() {
	defer close(l.messageChannel)
	l.logger.Info("starting message listener")

	// Stream dependency failures retry indefinitely with capped backoff.
	// Transient broker outages degrade readiness but are not terminal listener
	// failures; internal panics and exhausted envelope processing are terminal.
	sleepTime := STARTING_SLEEP_TIME
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}

		stream, err := l.xmtpClient.SubscribeAll(l.ctx, &v1.SubscribeAllRequest{})
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}

			l.logDependencyFailure()
			time.Sleep(sleepTime)
			sleepTime = cappedBackoff(sleepTime)
			if err = l.refreshClient(); err != nil {
				l.logDependencyFailure()
			}
			continue
		}

		l.ready.Store(true)
		if l.consumeMessageStream(stream, &sleepTime) {
			return
		}
	}
}

func (l *Listener) consumeMessageStream(stream v1.MessageApi_SubscribeAllClient, sleepTime *time.Duration) bool {
	defer l.ready.Store(false)

	for {
		select {
		case <-l.ctx.Done():
			return true
		default:
			msg, err := stream.Recv()
			if err != nil {
				// Ready is wired to both /health/xmtp and /readyz. Drop it at
				// the stream-failure boundary, before backoff or connection
				// refresh can extend stale healthy state.
				l.ready.Store(false)
			}
			if err == io.EOF {
				l.logDependencyFailure()
				return false
			}

			if err != nil {
				l.logDependencyFailure()
				// Wait 100ms to avoid hammering the API and getting rate limited
				time.Sleep(*sleepTime)
				*sleepTime = cappedBackoff(*sleepTime)
				if err = l.refreshClient(); err != nil {
					l.logDependencyFailure()
				}
				return false
			}

			if msg != nil {
				// Reset the sleep time on first successful message
				*sleepTime = STARTING_SLEEP_TIME
				l.messageChannel <- msg
			}
		}
	}
}

func (l *Listener) startMessageWorkers() {
	for i := 0; i < l.opts.NumWorkers; i++ {
		go runListenerGoroutine(
			func() {
				for msg := range l.messageChannel {
					degraded := false
					recovered := retryEnvelopeProcessing(
						l.ctx,
						l.retryWindow,
						func(ctx context.Context) error {
							return l.processEnvelopeContext(ctx, msg)
						},
						func() {
							if !degraded {
								l.processing.Add(1)
								degraded = true
							}
							l.logDependencyFailure()
						},
					)
					if degraded {
						l.processing.Add(-1)
					}
					if !recovered {
						if l.ctx.Err() == nil {
							l.failClosed()
						}
						return
					}
				}
				if l.ctx.Err() == nil {
					l.failClosed()
				}
			},
			l.failClosed,
		)
	}
}

func (l *Listener) processEnvelope(env *v1.Envelope) error {
	return l.processEnvelopeContext(l.ctx, env)
}

func (l *Listener) processEnvelopeContext(
	ctx context.Context,
	env *v1.Envelope,
) error {
	// Fast-path: skip expensive parsing for topics that can't be V3
	if !strings.HasPrefix(env.ContentTopic, topics.V3_PREFIX) {
		return nil
	}

	t, err := topics.ParseV3Topic(env.ContentTopic)
	if err != nil {
		//nolint:nilerr
		return nil
	}
	if t.Kind() == topicpkg.TopicKindWelcomeMessagesV1 {
		return l.processWelcomeEnvelopeContext(ctx, env, t)
	}

	subs, err := l.subscriptions.GetSubscriptions(ctx, t, getThirtyDayPeriodsFromEpoch(env))
	if err != nil {
		return err
	}

	if len(subs) == 0 {
		return nil
	}

	installationIds := make([]string, len(subs))
	for i, sub := range subs {
		installationIds[i] = sub.InstallationId
	}

	installations, err := l.installations.GetInstallations(ctx, installationIds)
	if err != nil {
		return err
	}

	if len(installations) == 0 {
		return nil
	}

	sendRequests := buildSendRequests(env, t, installations, subs)
	var firstError error
	for _, request := range sendRequests {
		if err = l.dispatcher.dispatchContext(
			ctx,
			request,
		); err != nil && firstError == nil {
			firstError = err
		}
	}
	return firstError
}

func (l *Listener) processWelcomeEnvelopeContext(
	ctx context.Context,
	env *v1.Envelope,
	targetTopic *topicpkg.Topic,
) error {
	welcomeSubscriptions, supported := l.subscriptions.(interfaces.WelcomeSubscriptions)
	if !supported {
		return nil
	}
	envelopeDigest, err := V3WelcomeEnvelopeDigest(targetTopic, env.Message)
	if err != nil {
		//nolint:nilerr // Invalid external Welcome input is intentionally dropped.
		return nil
	}
	routes, err := welcomeSubscriptions.GetWelcomeSubscriptions(
		ctx,
		targetTopic,
		envelopeDigest[:],
	)
	if err != nil {
		return err
	}
	idempotencyKey := buildIdempotencyKey(env)
	messageContext := getContext(env, targetTopic)
	var firstError error
	for _, route := range routes {
		request := interfaces.SendRequest{
			IdempotencyKey:   idempotencyKey,
			Topic:            topics.TopicToString(targetTopic),
			EncryptedMessage: env.Message,
			PayloadFormat:    interfaces.PayloadFormatV3,
			MessageContext:   messageContext,
			Installation:     route.Installation,
			Subscription:     route.Subscription,
		}
		if err = l.dispatcher.dispatchContext(
			ctx,
			request,
		); err != nil && firstError == nil {
			firstError = err
		}
	}
	return firstError
}

func (l *Listener) logDependencyFailure() {
	if l == nil {
		return
	}
	l.errorLogs.Log(
		l.logger,
		time.Now().UTC(),
		"xmtp listener degraded",
	)
}

func (l *Listener) failClosed() {
	if l == nil {
		return
	}
	l.processingUnsafe.Store(true)
	l.ready.Store(false)
	if l.cancelFunc != nil {
		l.cancelFunc()
	}
	l.failedOnce.Do(func() {
		if l.failed != nil {
			close(l.failed)
		}
	})
	l.logDependencyFailure()
}

func (l *Listener) refreshClient() error {
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if err := l.ctx.Err(); err != nil {
		return err
	}
	if l.xmtpConn != nil {
		_ = l.xmtpConn.Close()
		l.xmtpConn = nil
	}
	client, conn, err := NewClientWithConn(
		l.ctx,
		l.opts.GrpcAddress,
		l.opts.UseTls,
		l.clientVersion,
		l.appVersion,
	)
	if err != nil {
		return err
	}
	l.xmtpClient = client
	l.xmtpConn = conn

	return nil
}

func buildIdempotencyKey(env *v1.Envelope) string {
	const sourceEventDomain = "Hytch V3 XMTP source event v1\x00"
	h := sha256.New()
	_, _ = h.Write([]byte(sourceEventDomain))
	_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(env.ContentTopic))))
	_, _ = h.Write([]byte(env.ContentTopic))
	_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(env.Message))))
	_, _ = h.Write(env.Message)
	_, _ = h.Write(binary.BigEndian.AppendUint64(nil, env.TimestampNs))

	return hex.EncodeToString(h.Sum(nil))
}

func buildSendRequests(envelope *v1.Envelope, t *topicpkg.Topic, installations []interfaces.Installation, subscriptions []interfaces.Subscription) []interfaces.SendRequest {
	idempotencyKey := buildIdempotencyKey(envelope)
	messageContext := getContext(envelope, t)
	out := make([]interfaces.SendRequest, 0, len(subscriptions))
	installationMap := make(map[string]interfaces.Installation)
	for _, installation := range installations {
		installationMap[installation.Id] = installation
	}

	for _, subscription := range subscriptions {
		if installation, exists := installationMap[subscription.InstallationId]; exists {
			out = append(out, interfaces.SendRequest{
				IdempotencyKey:   idempotencyKey,
				Topic:            topics.TopicToString(t),
				EncryptedMessage: envelope.Message,
				PayloadFormat:    interfaces.PayloadFormatV3,
				MessageContext:   messageContext,
				Installation:     installation,
				Subscription:     subscription,
			})
		}
	}

	return out
}
