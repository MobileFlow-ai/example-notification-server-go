package xmtp

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	privacylog "github.com/xmtp/example-notification-server-go/pkg/logging"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"github.com/xmtp/xmtpd/pkg/envelopes"
	mlsV1 "github.com/xmtp/xmtpd/pkg/proto/mls/api/v1"
	envelopesProto "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/envelopes"
	notificationApi "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/message_api"
	"github.com/xmtp/xmtpd/pkg/topic"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type V4Listener struct {
	dispatcher       deliveryDispatcher
	logger           *zap.Logger
	ctx              context.Context
	cancelFunc       func()
	connMu           sync.Mutex
	v4Client         notificationApi.NotificationApiClient
	v4Conn           *grpc.ClientConn
	opts             options.XmtpOptions
	envelopeChannel  chan *envelopesProto.OriginatorEnvelope
	installations    interfaces.Installations
	subscriptions    interfaces.Subscriptions
	clientVersion    string
	appVersion       string
	ready            atomic.Bool
	processing       atomic.Int32
	processingUnsafe atomic.Bool
	errorLogs        privacylog.FixedErrorLimiter
	failed           chan struct{}
	failedOnce       sync.Once
	retryWindow      time.Duration
}

func NewV4Listener(
	ctx context.Context,
	logger *zap.Logger,
	opts options.XmtpOptions,
	installations interfaces.Installations,
	subscriptions interfaces.Subscriptions,
	deliveryServices []interfaces.Delivery,
	clientVersion string,
	appVersion string,
) (*V4Listener, error) {
	client, conn, err := NewV4Client(ctx, opts.GrpcAddress, opts.UseTls, clientVersion, appVersion)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	namedLogger := logger.Named("xmtp-v4-listener")

	return &V4Listener{
		ctx:             ctx,
		cancelFunc:      cancel,
		logger:          namedLogger,
		v4Client:        client,
		v4Conn:          conn,
		opts:            opts,
		envelopeChannel: make(chan *envelopesProto.OriginatorEnvelope, 100),
		installations:   installations,
		subscriptions:   subscriptions,
		clientVersion:   clientVersion,
		appVersion:      appVersion,
		dispatcher:      newDeliveryDispatcher(ctx, deliveryServices),
		failed:          make(chan struct{}),
	}, nil
}

func (l *V4Listener) Start() {
	go runListenerGoroutine(l.startEnvelopeListener, l.failClosed)
	l.startEnvelopeWorkers()
}

func (l *V4Listener) Stop() {
	l.ready.Store(false)
	l.cancelFunc()
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if l.v4Conn != nil {
		_ = l.v4Conn.Close()
		l.v4Conn = nil
	}
}

func (l *V4Listener) Ready() bool {
	return l.ready.Load() &&
		l.processing.Load() == 0 &&
		!l.processingUnsafe.Load()
}

func (l *V4Listener) Failed() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.failed
}

func (l *V4Listener) startEnvelopeListener() {
	defer close(l.envelopeChannel)
	l.logger.Info("starting V4 envelope listener")

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

		stream, err := l.v4Client.SubscribeAllEnvelopes(l.ctx, &notificationApi.SubscribeAllEnvelopesRequest{})
		if err != nil {
			l.logDependencyFailure()
			time.Sleep(sleepTime)
			sleepTime = cappedBackoff(sleepTime)
			if err = l.refreshV4Client(); err != nil {
				l.logDependencyFailure()
			}
			continue
		}

		l.ready.Store(true)
		if l.consumeEnvelopeStream(stream, &sleepTime) {
			return
		}
	}
}

func (l *V4Listener) consumeEnvelopeStream(stream notificationApi.NotificationApi_SubscribeAllEnvelopesClient, sleepTime *time.Duration) bool {
	defer l.ready.Store(false)

	for {
		select {
		case <-l.ctx.Done():
			return true
		default:
			resp, err := stream.Recv()
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
				time.Sleep(*sleepTime)
				*sleepTime = cappedBackoff(*sleepTime)
				if err = l.refreshV4Client(); err != nil {
					l.logDependencyFailure()
				}
				return false
			}

			if resp != nil {
				*sleepTime = STARTING_SLEEP_TIME
				for _, env := range resp.GetEnvelopes() {
					l.envelopeChannel <- env
				}
			}
		}
	}
}

func (l *V4Listener) startEnvelopeWorkers() {
	for i := 0; i < l.opts.NumWorkers; i++ {
		go runListenerGoroutine(
			func() {
				for env := range l.envelopeChannel {
					degraded := false
					recovered := retryEnvelopeProcessing(
						l.ctx,
						l.retryWindow,
						func(ctx context.Context) error {
							return l.processOriginatorEnvelopeContext(ctx, env)
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

func (l *V4Listener) processOriginatorEnvelope(env *envelopesProto.OriginatorEnvelope) error {
	return l.processOriginatorEnvelopeContext(l.ctx, env)
}

func (l *V4Listener) processOriginatorEnvelopeContext(
	ctx context.Context,
	env *envelopesProto.OriginatorEnvelope,
) error {
	origEnv, err := envelopes.NewOriginatorEnvelope(env)
	if err != nil {
		//nolint:nilerr // Invalid external envelopes are intentionally dropped.
		return nil
	}

	clientEnvelope := origEnv.UnsignedOriginatorEnvelope.PayerEnvelope.ClientEnvelope
	targetTopic := clientEnvelope.TargetTopic()
	if targetTopic.Kind() == topic.TopicKindWelcomeMessagesV1 {
		return l.processWelcomeOriginatorEnvelopeContext(
			ctx,
			origEnv,
			&clientEnvelope,
			&targetTopic,
		)
	}
	thirtyDayPeriod := int(origEnv.OriginatorNs() / 1_000_000_000 / 60 / 60 / 24 / 30)

	var subs []interfaces.Subscription
	if subs, err = l.subscriptions.GetSubscriptions(ctx, &targetTopic, thirtyDayPeriod); err != nil {
		return err
	}

	if len(subs) == 0 {
		return nil
	}

	installationIds := make([]string, len(subs))
	for i, sub := range subs {
		installationIds[i] = sub.InstallationId
	}

	var insts []interfaces.Installation
	if insts, err = l.installations.GetInstallations(ctx, installationIds); err != nil {
		return err
	}

	if len(insts) == 0 {
		return nil
	}

	idempotencyKey := buildV4IdempotencyKey(origEnv)
	installationMap := make(map[string]interfaces.Installation, len(insts))
	for _, inst := range insts {
		installationMap[inst.Id] = inst
	}

	var firstError error
	for _, sub := range subs {
		inst, exists := installationMap[sub.InstallationId]
		if !exists {
			continue
		}
		var req interfaces.SendRequest
		switch inst.PayloadFormat {
		case interfaces.PayloadFormatV4:
			req, err = buildV4SendRequest(origEnv, &clientEnvelope, &targetTopic, idempotencyKey, inst, sub)
		default:
			req, err = buildV3SendRequest(origEnv, &clientEnvelope, &targetTopic, idempotencyKey, inst, sub)
		}

		if err != nil {
			continue
		}

		if err = l.dispatcher.dispatchContext(
			ctx,
			req,
		); err != nil && firstError == nil {
			firstError = err
		}
	}

	return firstError
}

func (l *V4Listener) processWelcomeOriginatorEnvelopeContext(
	ctx context.Context,
	origEnv *envelopes.OriginatorEnvelope,
	clientEnvelope *envelopes.ClientEnvelope,
	targetTopic *topic.Topic,
) error {
	welcomeSubscriptions, supported := l.subscriptions.(interfaces.WelcomeSubscriptions)
	if !supported {
		return nil
	}
	rawEnvelope, err := origEnv.Bytes()
	if err != nil {
		//nolint:nilerr // Unserializable external Welcome input is denied.
		return nil
	}
	envelopeDigest, err := V4WelcomeEnvelopeDigest(targetTopic, rawEnvelope)
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
	idempotencyKey := buildV4IdempotencyKey(origEnv)
	var firstError error
	for _, route := range routes {
		var request interfaces.SendRequest
		switch route.Installation.PayloadFormat {
		case interfaces.PayloadFormatV4:
			request, err = buildV4SendRequest(
				origEnv,
				clientEnvelope,
				targetTopic,
				idempotencyKey,
				route.Installation,
				route.Subscription,
			)
		default:
			request, err = buildV3SendRequest(
				origEnv,
				clientEnvelope,
				targetTopic,
				idempotencyKey,
				route.Installation,
				route.Subscription,
			)
		}
		if err != nil {
			continue
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

func (l *V4Listener) logDependencyFailure() {
	if l == nil {
		return
	}
	l.errorLogs.Log(
		l.logger,
		time.Now().UTC(),
		"xmtp listener degraded",
	)
}

func (l *V4Listener) failClosed() {
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

// buildV4SendRequest constructs a SendRequest for the given installation.
func buildV4SendRequest(
	origEnv *envelopes.OriginatorEnvelope,
	clientEnv *envelopes.ClientEnvelope,
	targetTopic *topic.Topic,
	idempotencyKey string,
	inst interfaces.Installation,
	sub interfaces.Subscription,
) (interfaces.SendRequest, error) {
	if !clientEnv.TopicMatchesPayload() {
		return interfaces.SendRequest{}, ErrTopicMismatch
	}
	// V4 format: deliver raw OriginatorEnvelope bytes
	envBytes, err := origEnv.Bytes()
	if err != nil {
		return interfaces.SendRequest{}, err
	}

	var messageContext interfaces.MessageContext
	switch payload := clientEnv.Payload().(type) {
	case *envelopesProto.ClientEnvelope_GroupMessage:
		v1Input := payload.GroupMessage.GetV1()
		messageContext = buildGroupMessageContext(v1Input)
	case *envelopesProto.ClientEnvelope_WelcomeMessage:
		messageContext = interfaces.MessageContext{MessageType: topics.V3Welcome}
	default:
		messageContext = interfaces.MessageContext{MessageType: topics.Unknown}
	}

	return interfaces.SendRequest{
		IdempotencyKey:   idempotencyKey,
		Topic:            topics.TopicToLegacy(targetTopic),
		TopicBytesB64:    topics.TopicToBase64(targetTopic),
		EncryptedMessage: envBytes,
		PayloadFormat:    interfaces.PayloadFormatV4,
		MessageContext:   messageContext,
		Installation:     inst,
		Subscription:     sub,
	}, nil
}

// buildV3SendRequest constructs a SendRequest for the given installation.
func buildV3SendRequest(
	origEnv *envelopes.OriginatorEnvelope,
	clientEnv *envelopes.ClientEnvelope,
	targetTopic *topic.Topic,
	idempotencyKey string,
	inst interfaces.Installation,
	sub interfaces.Subscription,
) (interfaces.SendRequest, error) {
	if !clientEnv.TopicMatchesPayload() {
		return interfaces.SendRequest{}, ErrTopicMismatch
	}

	legacyTopic := topics.TopicToLegacy(targetTopic)

	switch payload := clientEnv.Payload().(type) {
	case *envelopesProto.ClientEnvelope_GroupMessage:
		v1Input := payload.GroupMessage.GetV1()
		encryptedMsg, err := convertGroupMessageToV3(v1Input, origEnv, targetTopic)
		if err != nil {
			return interfaces.SendRequest{}, err
		}
		messageContext := buildGroupMessageContext(v1Input)
		return interfaces.SendRequest{
			IdempotencyKey:   idempotencyKey,
			Topic:            legacyTopic,
			EncryptedMessage: encryptedMsg,
			PayloadFormat:    interfaces.PayloadFormatV3,
			MessageContext:   messageContext,
			Installation:     inst,
			Subscription:     sub,
		}, nil

	case *envelopesProto.ClientEnvelope_WelcomeMessage:
		var encryptedMsg []byte
		var err error
		if v1Input := payload.WelcomeMessage.GetV1(); v1Input != nil {
			encryptedMsg, err = convertWelcomeMessageToV3(v1Input, origEnv)
		} else if wpInput := payload.WelcomeMessage.GetWelcomePointer(); wpInput != nil {
			encryptedMsg, err = convertWelcomePointerToV3(wpInput, origEnv)
		} else {
			return interfaces.SendRequest{}, ErrUnknownWelcomeVersion
		}
		if err != nil {
			return interfaces.SendRequest{}, err
		}
		return interfaces.SendRequest{
			IdempotencyKey:   idempotencyKey,
			Topic:            legacyTopic,
			EncryptedMessage: encryptedMsg,
			PayloadFormat:    interfaces.PayloadFormatV3,
			MessageContext:   interfaces.MessageContext{MessageType: topics.V3Welcome},
			Installation:     inst,
			Subscription:     sub,
		}, nil

	default:
		return interfaces.SendRequest{}, ErrUnknownPayloadType
	}
}

func buildGroupMessageContext(v1Input *mlsV1.GroupMessageInput_V1) interfaces.MessageContext {
	if v1Input == nil {
		return interfaces.MessageContext{MessageType: topics.V3Conversation}
	}
	shouldPush := v1Input.ShouldPush
	hmacInputs := cloneBytes(v1Input.Data)
	senderHmac := cloneBytes(v1Input.SenderHmac)
	mc := interfaces.MessageContext{
		MessageType: topics.V3Conversation,
		ShouldPush:  &shouldPush,
		HmacInputs:  &hmacInputs,
	}
	if len(senderHmac) > 0 {
		mc.SenderHmac = &senderHmac
	}
	return mc
}

func buildV4IdempotencyKey(env *envelopes.OriginatorEnvelope) string {
	return fmt.Sprintf("%d:%d", env.OriginatorNodeID(), env.OriginatorSequenceID())
}

func (l *V4Listener) refreshV4Client() error {
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if err := l.ctx.Err(); err != nil {
		return err
	}
	if l.v4Conn != nil {
		_ = l.v4Conn.Close()
	}
	client, conn, err := NewV4Client(l.ctx, l.opts.GrpcAddress, l.opts.UseTls, l.clientVersion, l.appVersion)
	if err != nil {
		return err
	}
	l.v4Client = client
	l.v4Conn = conn
	return nil
}
