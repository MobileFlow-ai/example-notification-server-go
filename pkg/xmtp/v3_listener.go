package xmtp

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
	"go.uber.org/zap"
)

type Listener struct {
	logger         *zap.Logger
	ctx            context.Context
	cancelFunc     func()
	xmtpClient     v1.MessageApiClient
	opts           options.XmtpOptions
	messageChannel chan *v1.Envelope
	installations  interfaces.Installations
	subscriptions  interfaces.Subscriptions
	clientVersion  string
	appVersion     string
	dispatcher     deliveryDispatcher
	ready          atomic.Bool
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
	client, err := NewClient(ctx, opts.GrpcAddress, opts.UseTls, clientVersion, appVersion)
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
		opts:           opts,
		messageChannel: make(chan *v1.Envelope, 100),
		installations:  installations,
		subscriptions:  subscriptions,
		clientVersion:  clientVersion,
		appVersion:     appVersion,
		dispatcher:     newDeliveryDispatcher(ctx, deliveryServices),
	}, nil
}

func (l *Listener) Start() {
	go l.startMessageListener()
	l.startMessageWorkers()
}

func (l *Listener) Stop() {
	l.ready.Store(false)
	l.cancelFunc()
}

func (l *Listener) Ready() bool {
	return l.ready.Load()
}

func (l *Listener) startMessageListener() {
	l.logger.Info("starting message listener")
	defer close(l.messageChannel)

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
			time.Sleep(sleepTime)
			sleepTime = cappedBackoff(sleepTime)
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
				l.logger.Info("stream closed")
				return false
			}

			if err != nil {
				l.logger.Warn("error reading from stream", zap.Error(err))
				// Wait 100ms to avoid hammering the API and getting rate limited
				time.Sleep(*sleepTime)
				*sleepTime = cappedBackoff(*sleepTime)
				if err = l.refreshClient(); err != nil {
					l.logger.Error("error refreshing client", zap.Error(err))
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
		go func() {
			for msg := range l.messageChannel {
				_ = l.processEnvelope(msg)
			}
		}()
	}
}

func (l *Listener) processEnvelope(env *v1.Envelope) error {
	// Fast-path: skip expensive parsing for topics that can't be V3
	if !strings.HasPrefix(env.ContentTopic, topics.V3_PREFIX) {
		return nil
	}

	t, err := topics.ParseV3Topic(env.ContentTopic)
	if err != nil {
		//nolint:nilerr
		return nil
	}

	subs, err := l.subscriptions.GetSubscriptions(l.ctx, t, getThirtyDayPeriodsFromEpoch(env))
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

	installations, err := l.installations.GetInstallations(l.ctx, installationIds)
	if err != nil {
		return err
	}

	if len(installations) == 0 {
		return nil
	}

	sendRequests := buildSendRequests(env, t, installations, subs)
	var firstError error
	for _, request := range sendRequests {
		if err = l.dispatcher.dispatch(request); err != nil && firstError == nil {
			firstError = err
		}
	}
	return firstError
}

func (l *Listener) refreshClient() error {
	client, err := NewClient(l.ctx, l.opts.GrpcAddress, l.opts.UseTls, l.clientVersion, l.appVersion)
	if err != nil {
		return err
	}
	l.xmtpClient = client

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
