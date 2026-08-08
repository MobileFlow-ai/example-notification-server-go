package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	privacylog "github.com/xmtp/example-notification-server-go/pkg/logging"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	proto "github.com/xmtp/example-notification-server-go/pkg/proto/notifications/v1"
	"github.com/xmtp/example-notification-server-go/pkg/proto/notifications/v1/notificationsv1connect"
	"github.com/xmtp/example-notification-server-go/pkg/registration"
	topicutil "github.com/xmtp/example-notification-server-go/pkg/topics"
	"github.com/xmtp/xmtpd/pkg/topic"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/types/known/emptypb"
)

type ApiServer struct {
	logger         *zap.Logger
	installations  interfaces.Installations
	subscriptions  interfaces.Subscriptions
	httpServer     *http.Server
	port           int
	listener       net.Listener
	prepared       bool
	listenerType   interfaces.ListenerType
	readyCheck     func() bool
	xmtpReadyCheck func() bool
	secureRefresh  *registration.Handler
	secureMode     bool
	failureOnce    sync.Once
	failed         chan struct{}
}

var ErrAPIUnavailable = errors.New("api server unavailable")

func NewApiServer(logger *zap.Logger, opts options.ApiOptions, installations interfaces.Installations, subscriptions interfaces.Subscriptions, listenerType interfaces.ListenerType) *ApiServer {
	return &ApiServer{
		logger:        logger.Named("api"),
		installations: installations,
		subscriptions: subscriptions,
		port:          opts.Port,
		listenerType:  listenerType,
		failed:        make(chan struct{}),
	}
}

func (s *ApiServer) SetListener(listener net.Listener) error {
	if s.httpServer != nil || s.prepared {
		return errors.New("api server already started")
	}

	s.listener = listener
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		s.port = tcpAddr.Port
	}

	return nil
}

// Prepare reserves the API port synchronously without serving requests. Main
// calls it before enabling XMTP or APNS egress so a bind failure terminates
// startup rather than leaving a headless delivery process.
func (s *ApiServer) Prepare() error {
	if s == nil {
		return ErrAPIUnavailable
	}
	if s.prepared {
		return nil
	}
	if s.listener == nil {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
		if err != nil {
			return ErrAPIUnavailable
		}
		s.listener = listener
	}
	if tcpAddr, ok := s.listener.Addr().(*net.TCPAddr); ok {
		s.port = tcpAddr.Port
	}
	s.prepared = true
	return nil
}

func (s *ApiServer) SetReadyCheck(readyCheck func() bool) {
	s.readyCheck = readyCheck
}

// SetXMTPReadyCheck keeps the dependency-specific probe independent from
// aggregate service readiness (which can also include retention and storage).
func (s *ApiServer) SetXMTPReadyCheck(readyCheck func() bool) {
	s.xmtpReadyCheck = readyCheck
}

func (s *ApiServer) EnableSecureRegistration(handler *registration.Handler) {
	s.secureMode = true
	s.secureRefresh = handler
}

func (s *ApiServer) Start() error {
	if s.httpServer != nil {
		return nil
	}
	if err := s.Prepare(); err != nil {
		return err
	}
	mux := http.NewServeMux()
	path, handler := notificationsv1connect.NewNotificationsHandler(s)
	mux.Handle(path, handler)
	if s.secureRefresh != nil {
		mux.Handle(registration.RefreshPath, s.secureRefresh)
		mux.HandleFunc(registration.PolicyPath, s.secureRefresh.ServePolicyHTTP)
		mux.HandleFunc(registration.WelcomePath, s.secureRefresh.ServeWelcomeHTTP)
	}
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/livez", s.handleLive)
	mux.HandleFunc("/health/xmtp", s.handleXMTPHealth)

	listener := s.listener
	addr := listener.Addr().String()
	s.httpServer = &http.Server{
		Addr: addr,
		Handler: privacySafeHTTPHandler(
			s.logger,
			h2c.NewHandler(mux, &http2.Server{}),
		),
		// net/http's default error logger includes the remote address and a
		// stack trace when a handler panics. The recovery boundary above owns
		// handler failures; suppress the fallback path so a raw provider IP,
		// token, or topic can never be emitted by the standard library.
		ErrorLog:          log.New(io.Discard, "", 0),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	s.logger.Info("api server started")

	go func() {
		defer func() {
			if recover() != nil {
				s.logger.Error("api server stopped")
				s.signalFailure()
			}
		}()
		err := s.httpServer.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("api server stopped")
			s.signalFailure()
			return
		}
		s.logger.Info("api server stopped")
	}()
	return nil
}

func (s *ApiServer) signalFailure() {
	if s == nil {
		return
	}
	s.failureOnce.Do(func() {
		close(s.failed)
	})
}

func (s *ApiServer) Failed() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.failed
}

func privacySafeHTTPHandler(
	logger *zap.Logger,
	next http.Handler,
) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	var errorLogs privacylog.FixedErrorLimiter
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		defer func() {
			if recovered := recover(); recovered != nil {
				errorLogs.Log(
					logger,
					time.Now().UTC(),
					"api request failed",
				)
				http.Error(
					writer,
					"internal_error",
					http.StatusInternalServerError,
				)
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

func (s *ApiServer) Stop() {
	s.logger.Info("server shutting down")
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Fatal("server failed to shutdown")
		}
	}

	s.logger.Info("server stopped")
}

func (s *ApiServer) RegisterInstallation(
	ctx context.Context,
	req *connect.Request[proto.RegisterInstallationRequest],
) (*connect.Response[proto.RegisterInstallationResponse], error) {
	if s.secureMode {
		return nil, legacyRegistrationDisabled()
	}
	mechanism := convertDeliveryMechanism(req.Msg.DeliveryMechanism)
	if mechanism == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("missing delivery mechanism"))
	}

	payloadFormat := interfaces.PayloadFormatFromProto(req.Msg.PayloadFormat)
	payloadFormat = interfaces.NormalizePayloadFormat(payloadFormat)
	if err := payloadFormat.ValidateForListener(s.listenerType); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	result, err := s.installations.Register(
		ctx,
		interfaces.Installation{
			Id:                req.Msg.InstallationId,
			DeliveryMechanism: *mechanism,
			PayloadFormat:     payloadFormat,
		},
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&proto.RegisterInstallationResponse{
		InstallationId: req.Msg.InstallationId,
		ValidUntil:     uint64(result.ValidUntil.UnixMilli()),
	}), nil
}

func (s *ApiServer) DeleteInstallation(
	ctx context.Context,
	req *connect.Request[proto.DeleteInstallationRequest],
) (*connect.Response[emptypb.Empty], error) {
	if s.secureMode {
		return nil, legacyRegistrationDisabled()
	}
	err := s.installations.Delete(ctx, req.Msg.InstallationId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *ApiServer) Subscribe(
	ctx context.Context,
	req *connect.Request[proto.SubscribeRequest],
) (*connect.Response[emptypb.Empty], error) {
	if s.secureMode {
		return nil, legacyRegistrationDisabled()
	}
	topics, err := normalizeTopics(req.Msg.Topics, req.Msg.TopicsBytes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	err = s.subscriptions.Subscribe(ctx, req.Msg.InstallationId, topics)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *ApiServer) Unsubscribe(
	ctx context.Context,
	req *connect.Request[proto.UnsubscribeRequest],
) (*connect.Response[emptypb.Empty], error) {
	if s.secureMode {
		return nil, legacyRegistrationDisabled()
	}
	topics, err := normalizeTopics(req.Msg.Topics, req.Msg.TopicsBytes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	err = s.subscriptions.Unsubscribe(ctx, req.Msg.InstallationId, topics)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *ApiServer) SubscribeWithMetadata(ctx context.Context, req *connect.Request[proto.SubscribeWithMetadataRequest]) (*connect.Response[emptypb.Empty], error) {
	if s.secureMode {
		return nil, legacyRegistrationDisabled()
	}
	inputs, err := normalizeSubscriptionInputs(req.Msg.Subscriptions)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	err = s.subscriptions.SubscribeWithMetadata(ctx, req.Msg.InstallationId, inputs)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func legacyRegistrationDisabled() *connect.Error {
	return connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("legacy registration disabled"),
	)
}

func normalizeTopics(stringTopics []string, bytesTopics [][]byte) ([]*topic.Topic, error) {
	seen := make(map[string]struct{})
	var result []*topic.Topic

	for _, s := range stringTopics {
		t, err := topicutil.ParseV3Topic(s)
		if err != nil {
			return nil, errors.New("invalid topic")
		}
		key := string(t.Bytes())
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, t)
		}
	}

	for _, b := range bytesTopics {
		t, err := topic.ParseTopic(b)
		if err != nil {
			return nil, errors.New("invalid binary topic")
		}
		key := string(t.Bytes())
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, t)
		}
	}

	return result, nil
}

func normalizeSubscriptionInputs(subs []*proto.Subscription) ([]interfaces.SubscriptionInput, error) {
	out := make([]interfaces.SubscriptionInput, len(subs))
	for idx, sub := range subs {
		var t *topic.Topic
		var err error
		if len(sub.TopicBytes) > 0 {
			t, err = topic.ParseTopic(sub.TopicBytes)
			if err != nil {
				return nil, errors.New("invalid binary topic")
			}
		} else if sub.Topic != "" {
			t, err = topicutil.ParseV3Topic(sub.Topic)
			if err != nil {
				return nil, errors.New("invalid topic")
			}
		} else {
			return nil, fmt.Errorf("subscription at index %d has no topic", idx)
		}
		out[idx] = interfaces.SubscriptionInput{
			Topic:    t,
			IsSilent: sub.IsSilent,
			HmacKeys: buildHmacKeys(sub.HmacKeys),
		}
	}
	return out, nil
}

func buildHmacKeys(protoKeys []*proto.Subscription_HmacKey) []interfaces.HmacKey {
	out := make([]interfaces.HmacKey, len(protoKeys))
	for idx, key := range protoKeys {
		out[idx] = interfaces.HmacKey{
			ThirtyDayPeriodsSinceEpoch: int(key.ThirtyDayPeriodsSinceEpoch),
			Key:                        key.Key,
		}
	}
	return out
}

func convertDeliveryMechanism(mechanism *proto.DeliveryMechanism) *interfaces.DeliveryMechanism {
	if mechanism == nil {
		return nil
	}
	apnsToken := mechanism.GetApnsDeviceToken()
	fcmToken := mechanism.GetFirebaseDeviceToken()
	if apnsToken != "" {
		return &interfaces.DeliveryMechanism{Kind: interfaces.APNS, Token: apnsToken}
	} else {
		return &interfaces.DeliveryMechanism{Kind: interfaces.FCM, Token: fcmToken}
	}
}

func (s *ApiServer) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.readyCheck != nil && !s.readyCheck() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "not_ready")
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

// handleLive deliberately reports process health without coupling Railway's
// restart policy to XMTP availability. The dependency-specific endpoint below
// remains fail-closed for modern-api and operator readiness checks.
func (s *ApiServer) handleLive(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

func (s *ApiServer) handleXMTPHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.xmtpReadyCheck == nil || !s.xmtpReadyCheck() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "xmtp_unavailable")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}
