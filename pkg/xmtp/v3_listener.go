package xmtp

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type Listener struct {
	logger         *zap.Logger
	ctx            context.Context
	cancelFunc     func()
	connMu         sync.Mutex
	v3Conn         *grpc.ClientConn
	xmtpClient     v1.MessageApiClient
	opts           options.XmtpOptions
	messageChannel chan *v1.Envelope
	installations  interfaces.Installations
	subscriptions  interfaces.Subscriptions
	clientVersion  string
	appVersion     string
	dispatcher     deliveryDispatcher
	ready          atomic.Bool
	queue          interfaces.NotificationQueue
	admissionReady atomic.Bool
	queueHealth    atomic.Pointer[durableWorkerHealth]
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
	invalidators ...interfaces.TokenInvalidator,
) (*Listener, error) {
	conn, err := newConn(opts.GrpcAddress, opts.UseTls, clientVersion, appVersion)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	namedLogger := logger.Named("xmtp-listener")

	return &Listener{
		ctx:            ctx,
		cancelFunc:     cancel,
		logger:         namedLogger,
		xmtpClient:     v1.NewMessageApiClient(conn),
		v3Conn:         conn,
		opts:           opts,
		messageChannel: make(chan *v1.Envelope, 100),
		installations:  installations,
		subscriptions:  subscriptions,
		clientVersion:  clientVersion,
		appVersion:     appVersion,
		dispatcher: deliveryDispatcher{
			logger:           namedLogger,
			ctx:              ctx,
			deliveryServices: deliveryServices,
			invalidTokens:    firstInvalidator(invalidators),
		},
	}, nil
}

func (l *Listener) Start() {
	l.startMessageWorkers()
	go l.startMessageListener()
}

func (l *Listener) Stop() {
	l.ready.Store(false)
	l.cancelFunc()
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if l.v3Conn != nil {
		_ = l.v3Conn.Close()
		l.v3Conn = nil
	}
}

func (l *Listener) Ready() bool {
	return l.ready.Load() && (l.queue == nil || (l.admissionReady.Load() && l.queueHealth.Load().Ready()))
}

func (l *Listener) startMessageListener() {
	l.logger.Info("starting message listener")
	defer close(l.messageChannel)
	defer l.Stop()

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

			l.logger.Error("error connecting to stream", zap.Error(err))
			if !waitForReconnect(l.ctx, &sleepTime) {
				return
			}
			if err = l.refreshClient(); err != nil {
				l.logger.Error("error refreshing client", zap.Error(err))
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
			if err == io.EOF {
				l.ready.Store(false)
				l.logger.Info("stream closed")
				return !waitForReconnect(l.ctx, sleepTime)
			}

			if err != nil {
				l.logger.Warn("error reading from stream", zap.Error(err))
				l.ready.Store(false)
				if !waitForReconnect(l.ctx, sleepTime) {
					return true
				}
				if err = l.refreshClient(); err != nil {
					l.logger.Error("error refreshing client", zap.Error(err))
				}
				return false
			}

			if msg != nil {
				// Reset the sleep time on first successful message
				*sleepTime = STARTING_SLEEP_TIME
				if l.queue != nil {
					if !strings.HasPrefix(msg.ContentTopic, topics.V3_PREFIX) {
						continue
					}
					parsed, err := topics.ParseV3Topic(msg.ContentTopic)
					if err != nil {
						continue
					}
					known, live := waitForKnownSubscriptions(l.ctx, &l.admissionReady, l.logger, func() (bool, error) {
						subs, err := l.subscriptions.GetSubscriptions(l.ctx, parsed, getThirtyDayPeriodsFromEpoch(msg))
						return len(subs) > 0, err
					})
					if !live {
						return true
					}
					if !known {
						continue
					}
					payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(msg)
					if err != nil {
						l.logger.Error("cannot encode received V3 envelope")
						return true
					}
					if !persistEnvelope(l.ctx, l.queue, "v3", buildIdempotencyKey(msg), payload, &l.admissionReady, l.logger) {
						return true
					}
				} else {
					select {
					case l.messageChannel <- msg:
					case <-l.ctx.Done():
						return true
					}
				}
			}
		}
	}
}

func (l *Listener) startMessageWorkers() {
	if l.queue != nil {
		l.queueHealth.Store(startDurableWorkers(l.ctx, l.queue, "v3", l.opts.NumWorkers, l.logger, func(ctx context.Context, raw []byte) error {
			env := &v1.Envelope{}
			if err := proto.Unmarshal(raw, env); err != nil {
				return &invalidEnvelopeError{cause: err}
			}
			return l.processEnvelopeWithContext(ctx, env)
		}))
		return
	}

	for i := 0; i < l.opts.NumWorkers; i++ {
		go func() {
			var err error
			for msg := range l.messageChannel {
				err = l.processEnvelope(msg)
				if err != nil {
					l.logger.Error("error processing envelope", zap.String("v3_topic", msg.ContentTopic), zap.Error(err))
					continue
				}
			}
		}()
	}
}

func (l *Listener) processEnvelope(env *v1.Envelope) error {
	return l.processEnvelopeWithContext(l.ctx, env)
}

func (l *Listener) processEnvelopeWithContext(ctx context.Context, env *v1.Envelope) error {
	if env == nil {
		return errors.New("missing V3 envelope")
	}
	// Fast-path: skip expensive parsing for topics that can't be V3
	if !strings.HasPrefix(env.ContentTopic, topics.V3_PREFIX) {
		l.logger.Debug("ignoring message", zap.String("v3_topic", env.ContentTopic))
		return nil
	}

	t, err := topics.ParseV3Topic(env.ContentTopic)
	if err != nil {
		l.logger.Warn("ignoring message with unsupported topic format", zap.String("v3_topic", env.ContentTopic))
		//nolint:nilerr
		return nil
	}

	logger := l.logger.With(zap.String("topic", t.String()))
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
		logger.Debug("No matching installations found for topic")
		return nil
	}

	sendRequests := buildSendRequests(env, t, installations, subs)
	if err := l.dispatcher.prepareRecipients(ctx, sendRequests); err != nil {
		return err
	}
	var deliveryErrors []error
	for _, request := range sendRequests {
		if !l.dispatcher.shouldDeliver(request.MessageContext, request.Subscription) {
			logger.Debug("Skipping delivery of request",
				zap.Any("message_context", request.MessageContext),
				zap.Bool("subscription_has_hmac_key", request.Subscription.HmacKey != nil),
			)
			continue
		}
		if err = l.dispatcher.deliverWithContext(ctx, request); err != nil {
			logger.Error("error delivering request", zap.Error(err))
			deliveryErrors = append(deliveryErrors, err)
		}
	}
	return errors.Join(deliveryErrors...)
}

func (l *Listener) refreshClient() error {
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if err := l.ctx.Err(); err != nil {
		return err
	}
	conn, err := newConn(l.opts.GrpcAddress, l.opts.UseTls, l.clientVersion, l.appVersion)
	if err != nil {
		return err
	}
	if l.v3Conn != nil {
		_ = l.v3Conn.Close()
	}
	l.v3Conn = conn
	l.xmtpClient = v1.NewMessageApiClient(conn)
	return nil
}

func buildIdempotencyKey(env *v1.Envelope) string {
	h := sha1.New()
	h.Write([]byte(env.ContentTopic))
	h.Write(env.Message)
	h.Write(binary.BigEndian.AppendUint64(nil, env.TimestampNs))

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

func (l *Listener) SetNotificationQueue(queue interfaces.NotificationQueue) {
	l.queue = queue
	l.dispatcher.queue = queue
	l.admissionReady.Store(true)
}
