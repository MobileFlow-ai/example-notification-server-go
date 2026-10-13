package xmtp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"github.com/xmtp/xmtpd/pkg/envelopes"
	mlsV1 "github.com/xmtp/xmtpd/pkg/proto/mls/api/v1"
	envelopesProto "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/envelopes"
	notificationApi "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/message_api"
	"github.com/xmtp/xmtpd/pkg/topic"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type V4Listener struct {
	dispatcher      deliveryDispatcher
	logger          *zap.Logger
	ctx             context.Context
	cancelFunc      func()
	connMu          sync.Mutex
	v4Client        notificationApi.NotificationApiClient
	v4Conn          *grpc.ClientConn
	opts            options.XmtpOptions
	envelopeChannel chan *envelopesProto.OriginatorEnvelope
	installations   interfaces.Installations
	subscriptions   interfaces.Subscriptions
	clientVersion   string
	appVersion      string
	ready           atomic.Bool
	queue           interfaces.NotificationQueue
	admissionReady  atomic.Bool
	queueHealth     atomic.Pointer[durableWorkerHealth]
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
	invalidators ...interfaces.TokenInvalidator,
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
		dispatcher: deliveryDispatcher{
			logger:           namedLogger,
			ctx:              ctx,
			deliveryServices: deliveryServices,
			invalidTokens:    firstInvalidator(invalidators),
		},
	}, nil
}

func (l *V4Listener) Start() {
	l.startEnvelopeWorkers()
	go l.startEnvelopeListener()
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
	return l.ready.Load() && (l.queue == nil || (l.admissionReady.Load() && l.queueHealth.Load().Ready()))
}

func (l *V4Listener) startEnvelopeListener() {
	l.logger.Info("starting V4 envelope listener")
	sleepTime := STARTING_SLEEP_TIME
	for {
		select {
		case <-l.ctx.Done():
			close(l.envelopeChannel)
			return
		default:
		}

		stream, err := l.v4Client.SubscribeAllEnvelopes(l.ctx, &notificationApi.SubscribeAllEnvelopesRequest{})
		if err != nil {
			l.logger.Error("error connecting to V4 stream", zap.Error(err))
			time.Sleep(sleepTime)
			sleepTime = cappedBackoff(sleepTime)
			if err = l.refreshV4Client(); err != nil {
				l.logger.Error("error refreshing V4 client", zap.Error(err))
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
			close(l.envelopeChannel)
			return true
		default:
			resp, err := stream.Recv()
			if err == io.EOF {
				l.logger.Info("V4 stream closed")
				return false
			}

			if err != nil {
				l.logger.Error("error reading from V4 stream", zap.Error(err))
				time.Sleep(*sleepTime)
				*sleepTime = cappedBackoff(*sleepTime)
				if err = l.refreshV4Client(); err != nil {
					l.logger.Error("error refreshing V4 client", zap.Error(err))
				}
				return false
			}

			if resp != nil {
				*sleepTime = STARTING_SLEEP_TIME
				for _, env := range resp.GetEnvelopes() {
					if l.queue != nil {
						orig, err := envelopes.NewOriginatorEnvelope(env)
						if err != nil {
							l.logger.Warn("ignoring malformed received V4 envelope")
							continue
						}
						target := orig.UnsignedOriginatorEnvelope.PayerEnvelope.ClientEnvelope.TargetTopic()
						known, live := waitForKnownSubscriptions(l.ctx, &l.admissionReady, l.logger, func() (bool, error) {
							subs, err := l.subscriptions.GetSubscriptions(l.ctx, &target, int(orig.OriginatorNs()/1_000_000_000/60/60/24/30))
							return len(subs) > 0, err
						})
						if !live {
							return true
						}
						if !known {
							continue
						}
						payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(env)
						if err != nil {
							l.logger.Error("cannot encode received V4 envelope")
							return true
						}
						if !persistEnvelope(l.ctx, l.queue, "v4", buildV4IdempotencyKey(orig), payload, &l.admissionReady, l.logger) {
							return true
						}
					} else {
						select {
						case l.envelopeChannel <- env:
						case <-l.ctx.Done():
							close(l.envelopeChannel)
							return true
						}
					}
				}
			}
		}
	}
}

func (l *V4Listener) startEnvelopeWorkers() {
	if l.queue != nil {
		l.queueHealth.Store(startDurableWorkers(l.ctx, l.queue, "v4", l.opts.NumWorkers, l.logger, func(ctx context.Context, raw []byte) error {
			env := &envelopesProto.OriginatorEnvelope{}
			if err := proto.Unmarshal(raw, env); err != nil {
				return &invalidEnvelopeError{cause: err}
			}
			return l.processOriginatorEnvelopeWithContext(ctx, env)
		}))
		return
	}

	for i := 0; i < l.opts.NumWorkers; i++ {
		go func() {
			for env := range l.envelopeChannel {
				if err := l.processOriginatorEnvelope(env); err != nil {
					l.logger.Error("error processing originator envelope", zap.Error(err))
				}
			}
		}()
	}
}

func (l *V4Listener) processOriginatorEnvelope(env *envelopesProto.OriginatorEnvelope) error {
	return l.processOriginatorEnvelopeWithContext(l.ctx, env)
}

func (l *V4Listener) processOriginatorEnvelopeWithContext(ctx context.Context, env *envelopesProto.OriginatorEnvelope) error {
	if env == nil {
		return errors.New("missing V4 envelope")
	}
	origEnv, err := envelopes.NewOriginatorEnvelope(env)
	if err != nil {
		l.logger.Info("skipping envelope: failed to parse originator envelope", zap.Error(err))
		return nil
	}

	clientEnvelope := origEnv.UnsignedOriginatorEnvelope.PayerEnvelope.ClientEnvelope
	targetTopic := clientEnvelope.TargetTopic()
	thirtyDayPeriod := int(origEnv.OriginatorNs() / 1_000_000_000 / 60 / 60 / 24 / 30)

	logger := l.logger.With(zap.String("topic", targetTopic.String()), zap.Uint32("node_id", origEnv.OriginatorNodeID()), zap.Uint64("sequence_id", origEnv.OriginatorSequenceID()))

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

	requests := make([]interfaces.SendRequest, 0, len(subs))
	for _, sub := range subs {
		inst, exists := installationMap[sub.InstallationId]
		if !exists {
			continue
		}
		var req interfaces.SendRequest
		switch inst.PayloadFormat {
		case interfaces.PayloadFormatV4:
			req, err = buildV4SendRequest(logger, origEnv, &clientEnvelope, &targetTopic, idempotencyKey, inst, sub)
		default:
			req, err = buildV3SendRequest(logger, origEnv, &clientEnvelope, &targetTopic, idempotencyKey, inst, sub)
		}

		if err != nil {
			logger.Warn("error building send request", zap.Error(err), zap.String("payload_format", inst.PayloadFormat.String()))
			continue
		}

		requests = append(requests, req)
	}
	if err := l.dispatcher.prepareRecipients(ctx, requests); err != nil {
		return err
	}
	var deliveryErrors []error
	for _, req := range requests {
		if !l.dispatcher.shouldDeliver(req.MessageContext, req.Subscription) {
			logger.Debug("skipping delivery of V4 request",
				zap.Any("message_context", req.MessageContext),
				zap.Bool("subscription_has_hmac_key", req.Subscription.HmacKey != nil),
			)
			continue
		}
		logger.Info("delivering notification")
		if err = l.dispatcher.deliverWithContext(ctx, req); err != nil {
			logger.Error("error delivering V4 request", zap.Error(err))
			deliveryErrors = append(deliveryErrors, err)
		}
	}

	return errors.Join(deliveryErrors...)
}

// buildV4SendRequest constructs a SendRequest for the given installation.
// Returns (request, true) if the request should be be delivered, (request, false) otherwise.
func buildV4SendRequest(
	logger *zap.Logger,
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
// Returns (request, true) if the request should be be delivered, (request, false) otherwise.
func buildV3SendRequest(
	logger *zap.Logger,
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

func (l *V4Listener) SetNotificationQueue(queue interfaces.NotificationQueue) {
	l.queue = queue
	l.dispatcher.queue = queue
	l.admissionReady.Store(true)
}
