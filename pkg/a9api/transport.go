package a9api

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var (
	ErrPrivateServerConfiguration = errors.New(
		"a9 private server configuration invalid",
	)
	ErrPrivateServerUnavailable = errors.New(
		"a9 private server unavailable",
	)
)

const (
	minPrivateReadHeaderTimeout       = time.Second
	maxPrivateReadHeaderTimeout       = 10 * time.Second
	minPrivateRequestTimeout          = time.Second
	maxPrivateRequestTimeout          = 30 * time.Second
	minPrivateIdleTimeout             = time.Second
	maxPrivateIdleTimeout             = 60 * time.Second
	minPrivateHeaderBytes             = 4 * 1024
	maxPrivateHeaderBytes             = 32 * 1024
	maxPrivateTLSPEMBytes       int64 = 1024 * 1024
)

// PrivateServerOptions are the complete transport settings for the dedicated
// A9 listener. Certificate material is accepted only through explicit files;
// no plaintext, inline-key, h2c, or proxy-header mode exists.
type PrivateServerOptions struct {
	BindAddress          string
	AllowUnspecifiedBind bool
	CertificatePath      string
	PrivateKeyPath       string
	ReadHeaderTimeout    time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	MaxHeaderBytes       int
}

// ValidatePrivateServerOptions validates bounded transport settings without
// reading certificate material or opening a listener.
func ValidatePrivateServerOptions(options PrivateServerOptions) error {
	if !validPrivateBindAddress(
		options.BindAddress,
		options.AllowUnspecifiedBind,
	) ||
		!filepath.IsAbs(options.CertificatePath) ||
		!filepath.IsAbs(options.PrivateKeyPath) ||
		options.ReadHeaderTimeout < minPrivateReadHeaderTimeout ||
		options.ReadHeaderTimeout > maxPrivateReadHeaderTimeout ||
		options.ReadTimeout < minPrivateRequestTimeout ||
		options.ReadTimeout > maxPrivateRequestTimeout ||
		options.ReadTimeout < options.ReadHeaderTimeout ||
		options.WriteTimeout < minPrivateRequestTimeout ||
		options.WriteTimeout > maxPrivateRequestTimeout ||
		options.IdleTimeout < minPrivateIdleTimeout ||
		options.IdleTimeout > maxPrivateIdleTimeout ||
		options.MaxHeaderBytes < minPrivateHeaderBytes ||
		options.MaxHeaderBytes > maxPrivateHeaderBytes {
		return ErrPrivateServerConfiguration
	}
	return nil
}

// PrivateTLSServer is a TLS-only net/http server primitive. It intentionally
// exposes no plaintext ListenAndServe path.
type PrivateTLSServer struct {
	bindAddress          string
	allowUnspecifiedBind bool
	tlsConfig            *tls.Config
	httpServer           *http.Server
	requestTimeout       time.Duration
	failureOnce          sync.Once
	failed               chan struct{}
}

// NewPrivateTLSServer loads a matching certificate pair from checked regular
// files and constructs a TLS 1.3 server. The returned server supports HTTP/2
// and HTTP/1.1 over TLS with identical handler semantics; unencrypted HTTP/2
// is explicitly disabled.
func NewPrivateTLSServer(
	handler http.Handler,
	options PrivateServerOptions,
) (*PrivateTLSServer, error) {
	if handler == nil ||
		ValidatePrivateServerOptions(options) != nil {
		return nil, ErrPrivateServerConfiguration
	}
	certificatePEM, err := readPrivateTransportFile(
		options.CertificatePath,
		false,
	)
	if err != nil {
		return nil, ErrPrivateServerConfiguration
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := readPrivateTransportFile(
		options.PrivateKeyPath,
		true,
	)
	if err != nil {
		return nil, ErrPrivateServerConfiguration
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(
		certificatePEM,
		privateKeyPEM,
	)
	if err != nil {
		return nil, ErrPrivateServerConfiguration
	}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(false)
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	requestTimeout := options.ReadTimeout
	if options.WriteTimeout < requestTimeout {
		requestTimeout = options.WriteTimeout
	}
	server := &PrivateTLSServer{
		bindAddress:          options.BindAddress,
		allowUnspecifiedBind: options.AllowUnspecifiedBind,
		tlsConfig:            tlsConfig,
		requestTimeout:       requestTimeout,
		failed:               make(chan struct{}),
	}
	httpServer := &http.Server{
		Addr: options.BindAddress,
		Handler: server.failClosedRequestBoundary(
			stripForwardingHeaders(handler),
		),
		TLSConfig:         tlsConfig,
		Protocols:         protocols,
		ErrorLog:          log.New(io.Discard, "", 0),
		ReadHeaderTimeout: options.ReadHeaderTimeout,
		ReadTimeout:       options.ReadTimeout,
		WriteTimeout:      options.WriteTimeout,
		IdleTimeout:       options.IdleTimeout,
		MaxHeaderBytes:    options.MaxHeaderBytes,
	}
	server.httpServer = httpServer
	return server, nil
}

// ListenAndServe opens only the configured TLS listener.
func (server *PrivateTLSServer) ListenAndServe() error {
	if server == nil || server.httpServer == nil ||
		server.tlsConfig == nil {
		return ErrPrivateServerConfiguration
	}
	listener, err := net.Listen("tcp", server.bindAddress)
	if err != nil {
		return ErrPrivateServerUnavailable
	}
	return server.Serve(listener)
}

// Serve accepts an already-bound listener but always wraps it in TLS before
// passing connections to net/http.
func (server *PrivateTLSServer) Serve(listener net.Listener) error {
	if server == nil || server.httpServer == nil ||
		server.tlsConfig == nil ||
		!validPrivateListener(
			listener,
			server.allowUnspecifiedBind,
		) {
		return ErrPrivateServerConfiguration
	}
	tlsListener := tls.NewListener(
		listener,
		server.tlsConfig.Clone(),
	)
	err := server.httpServer.Serve(tlsListener)
	if errors.Is(err, http.ErrServerClosed) {
		return http.ErrServerClosed
	}
	if err != nil {
		return ErrPrivateServerUnavailable
	}
	return nil
}

func (server *PrivateTLSServer) Shutdown(ctx context.Context) error {
	if server == nil || server.httpServer == nil || ctx == nil {
		return ErrPrivateServerConfiguration
	}
	if err := server.httpServer.Shutdown(ctx); err != nil {
		return ErrPrivateServerUnavailable
	}
	return nil
}

// Failed closes after a recovered request panic. The runtime treats any such
// panic as a fail-stop event instead of allowing net/http to keep the private
// authority surface apparently healthy.
func (server *PrivateTLSServer) Failed() <-chan struct{} {
	if server == nil {
		return nil
	}
	return server.failed
}

func (server *PrivateTLSServer) signalFailure() {
	if server == nil {
		return
	}
	server.failureOnce.Do(func() {
		close(server.failed)
	})
}

func (server *PrivateTLSServer) failClosedRequestBoundary(
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		defer func() {
			if recover() != nil {
				// Signal only after attempting the fixed response, so runtime
				// shutdown cannot race the response write. The deferred signal
				// still runs if the writer itself panics.
				defer server.signalFailure()
				writeFixedError(
					writer,
					http.StatusServiceUnavailable,
				)
			}
		}()
		ctx, cancel := context.WithTimeout(
			request.Context(),
			server.requestTimeout,
		)
		defer cancel()
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func validPrivateBindAddress(
	address string,
	allowUnspecified bool,
) bool {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if err != nil || ip == nil || port < 1 || port > 65535 {
		return false
	}
	return validPrivateIP(ip, allowUnspecified)
}

func validPrivateListener(
	listener net.Listener,
	allowUnspecified bool,
) bool {
	if listener == nil {
		return false
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	return ok &&
		address.Port >= 1 &&
		address.Port <= 65535 &&
		validPrivateIP(address.IP, allowUnspecified)
}

func validPrivateIP(
	ip net.IP,
	allowUnspecified bool,
) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() {
		return allowUnspecified
	}
	return !allowUnspecified &&
		(ip.IsLoopback() ||
			ip.IsPrivate() ||
			ip.IsLinkLocalUnicast())
}

var forwardingHeaders = []string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Port",
	"X-Forwarded-Proto",
	"X-Forwarded-Ssl",
	"X-Real-Ip",
	"X-Original-Forwarded-For",
	"True-Client-Ip",
	"Cf-Connecting-Ip",
}

func stripForwardingHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		for _, header := range forwardingHeaders {
			request.Header.Del(header)
		}
		next.ServeHTTP(writer, request)
	})
}

func readPrivateTransportFile(
	path string,
	private bool,
) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrPrivateServerConfiguration
	}
	before, err := os.Lstat(path)
	if err != nil ||
		!validTransportFileInfo(before, private) {
		return nil, ErrPrivateServerConfiguration
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrPrivateServerConfiguration
	}
	opened, err := file.Stat()
	if err != nil ||
		!validTransportFileInfo(opened, private) ||
		!os.SameFile(before, opened) {
		_ = file.Close()
		return nil, ErrPrivateServerConfiguration
	}
	afterOpen, err := os.Lstat(path)
	if err != nil ||
		!validTransportFileInfo(afterOpen, private) ||
		!os.SameFile(opened, afterOpen) ||
		afterOpen.Size() != opened.Size() {
		_ = file.Close()
		return nil, ErrPrivateServerConfiguration
	}

	raw, err := io.ReadAll(io.LimitReader(
		file,
		maxPrivateTLSPEMBytes+1,
	))
	if err != nil {
		clear(raw)
		_ = file.Close()
		return nil, ErrPrivateServerConfiguration
	}
	finalOpened, statErr := file.Stat()
	afterRead, pathErr := os.Lstat(path)
	closeErr := file.Close()
	if statErr != nil ||
		pathErr != nil ||
		closeErr != nil ||
		!validTransportFileInfo(finalOpened, private) ||
		!validTransportFileInfo(afterRead, private) ||
		!os.SameFile(opened, finalOpened) ||
		!os.SameFile(finalOpened, afterRead) ||
		finalOpened.Size() != opened.Size() ||
		afterRead.Size() != opened.Size() ||
		int64(len(raw)) != opened.Size() {
		clear(raw)
		return nil, ErrPrivateServerConfiguration
	}
	return raw, nil
}

func validTransportFileInfo(
	info os.FileInfo,
	private bool,
) bool {
	if info == nil ||
		!info.Mode().IsRegular() ||
		info.Size() < 1 ||
		info.Size() > maxPrivateTLSPEMBytes ||
		info.Mode()&(os.ModeSymlink|
			os.ModeSetuid|
			os.ModeSetgid|
			os.ModeSticky) != 0 {
		return false
	}
	permissions := info.Mode().Perm()
	if permissions&0o111 != 0 ||
		permissions&0o400 == 0 {
		return false
	}
	if private {
		return permissions&0o077 == 0
	}
	return permissions&0o022 == 0
}

// TransportFileMetadataValid exposes the exact content-free TLS file metadata
// contract used by the private A9 runtime. One-shot preflight uses this helper
// so a preflight pass cannot accept a file that runtime startup rejects.
func TransportFileMetadataValid(info os.FileInfo, private bool) bool {
	return validTransportFileInfo(info, private)
}
