package incidentaccess

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	privacylog "github.com/xmtp/example-notification-server-go/pkg/logging"
	"go.uber.org/zap"
)

const (
	defaultReadHeaderTimeout = 5 * time.Second
	defaultIdleTimeout       = 30 * time.Second
	startupProbeTimeout      = 2 * time.Second
	maxHeaderBytes           = 8 * 1024
)

type ServerOptions struct {
	BindAddress    string
	RequestTimeout time.Duration
}

type Server struct {
	logger         *zap.Logger
	handler        http.Handler
	bindAddress    string
	requestTimeout time.Duration
	listener       net.Listener
	httpServer     *http.Server
	prepared       bool
	failureOnce    sync.Once
	failed         chan struct{}
	ready          atomic.Bool
}

func NewServer(
	logger *zap.Logger,
	handler *Handler,
	options ServerOptions,
) (*Server, error) {
	if handler == nil ||
		!validLoopbackAddress(options.BindAddress) ||
		options.RequestTimeout <= 0 ||
		options.RequestTimeout > 30*time.Second {
		return nil, ErrInvalidConfiguration
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Server{
		logger:         logger.Named("incident-access"),
		handler:        handler.Mux(),
		bindAddress:    options.BindAddress,
		requestTimeout: options.RequestTimeout,
		failed:         make(chan struct{}),
	}, nil
}

func (s *Server) SetListener(listener net.Listener) error {
	if s == nil ||
		listener == nil ||
		s.prepared ||
		s.httpServer != nil ||
		!loopbackListener(listener) {
		return ErrInvalidConfiguration
	}
	s.listener = listener
	return nil
}

func (s *Server) Prepare() error {
	if s == nil {
		return ErrInvalidConfiguration
	}
	if s.prepared {
		return nil
	}
	if s.listener == nil {
		listener, err := net.Listen("tcp", s.bindAddress)
		if err != nil {
			return ErrInvalidConfiguration
		}
		s.listener = listener
	}
	if !loopbackListener(s.listener) {
		_ = s.listener.Close()
		s.listener = nil
		return ErrInvalidConfiguration
	}
	s.prepared = true
	return nil
}

func (s *Server) Start() error {
	if s == nil {
		return ErrInvalidConfiguration
	}
	if s.httpServer != nil {
		if s.Ready() {
			return nil
		}
		return ErrInvalidConfiguration
	}
	if err := s.Prepare(); err != nil {
		return err
	}
	listener := s.listener
	handler := s.privacyBoundary(
		s.withRequestDeadline(s.handler),
	)
	servingListener := &startupListener{
		Listener: listener,
		accepted: make(chan struct{}),
	}
	s.httpServer = &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           handler,
		ErrorLog:          log.New(io.Discard, "", 0),
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       s.requestTimeout + 2*time.Second,
		WriteTimeout:      s.requestTimeout + 2*time.Second,
		IdleTimeout:       defaultIdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	go func() {
		defer func() {
			if recover() != nil {
				s.ready.Store(false)
				s.logger.Error("private incident access listener stopped")
				s.signalFailure()
			}
		}()
		err := s.httpServer.Serve(servingListener)
		s.ready.Store(false)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("private incident access listener stopped")
			s.signalFailure()
			return
		}
		s.logger.Info("private incident access listener stopped")
	}()
	if err := s.requireServing(servingListener); err != nil {
		s.ready.Store(false)
		_ = s.httpServer.Close()
		s.signalFailure()
		return ErrInvalidConfiguration
	}
	select {
	case <-s.failed:
		return ErrInvalidConfiguration
	default:
	}
	s.ready.Store(true)
	select {
	case <-s.failed:
		s.ready.Store(false)
		return ErrInvalidConfiguration
	default:
	}
	s.logger.Info("private incident access listener started")
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return nil
	}
	if ctx == nil {
		return ErrInvalidConfiguration
	}
	s.ready.Store(false)
	err := s.httpServer.Shutdown(ctx)
	if err != nil {
		return ErrInvalidConfiguration
	}
	return nil
}

func (s *Server) Failed() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.failed
}

func (s *Server) Ready() bool {
	return s != nil && s.ready.Load()
}

func (s *Server) signalFailure() {
	if s == nil {
		return
	}
	s.failureOnce.Do(func() {
		close(s.failed)
	})
}

func (s *Server) withRequestDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		ctx, cancel := context.WithTimeout(
			request.Context(),
			s.requestTimeout,
		)
		defer cancel()
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func (s *Server) privacyBoundary(next http.Handler) http.Handler {
	var errorLogs privacylog.FixedErrorLimiter
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		defer func() {
			if recover() != nil {
				s.ready.Store(false)
				// Let the fixed response finish before the runtime monitor begins
				// shutdown. The deferred signal still runs if response writing
				// itself panics.
				defer s.signalFailure()
				errorLogs.Log(
					s.logger,
					time.Now().UTC(),
					"private incident request failed",
				)
				prepareResponse(writer)
				writeFixedError(
					writer,
					http.StatusInternalServerError,
					"internal_error",
				)
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

type startupListener struct {
	net.Listener
	accepted   chan struct{}
	acceptOnce sync.Once
}

func (l *startupListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.acceptOnce.Do(func() {
			close(l.accepted)
		})
	}
	return connection, err
}

func (s *Server) requireServing(listener *startupListener) error {
	if s == nil ||
		listener == nil ||
		listener.Listener == nil ||
		listener.accepted == nil ||
		s.httpServer == nil {
		return ErrInvalidConfiguration
	}
	probeContext, probeCancel := context.WithTimeout(
		context.Background(),
		startupProbeTimeout,
	)
	defer probeCancel()
	connection, err := (&net.Dialer{}).DialContext(
		probeContext,
		"tcp",
		listener.Addr().String(),
	)
	if err != nil {
		return ErrInvalidConfiguration
	}
	defer func() {
		_ = connection.Close()
	}()
	select {
	case <-listener.accepted:
		return nil
	case <-s.failed:
		return ErrInvalidConfiguration
	case <-probeContext.Done():
		return ErrInvalidConfiguration
	}
}

func validLoopbackAddress(address string) bool {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	return err == nil &&
		ip != nil &&
		ip.IsLoopback() &&
		port >= 1 &&
		port <= 65535
}

func loopbackListener(listener net.Listener) bool {
	if listener == nil {
		return false
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	return ok &&
		address.IP != nil &&
		address.IP.IsLoopback() &&
		address.Port >= 1 &&
		address.Port <= 65535
}
