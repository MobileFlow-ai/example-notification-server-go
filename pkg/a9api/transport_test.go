package a9api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type privateRequestObservation struct {
	protocol   string
	tlsVersion uint16
	remoteAddr string
	forwarded  map[string]string
}

type publicTestListener struct{}

func (publicTestListener) Accept() (net.Conn, error) {
	return nil, errors.New("unexpected accept")
}

func (publicTestListener) Close() error {
	return nil
}

func (publicTestListener) Addr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("203.0.113.8"),
		Port: 9443,
	}
}

func TestPrivateTLSServerUsesBoundedTLS13OnlyConfiguration(
	t *testing.T,
) {
	certificatePath, privateKeyPath, _ := writePrivateServerPair(t)
	options := testPrivateServerOptions(
		certificatePath,
		privateKeyPath,
	)
	server, err := NewPrivateTLSServer(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		options,
	)
	require.NoError(t, err)
	require.NotNil(t, server)
	require.Equal(t, uint16(tls.VersionTLS13), server.tlsConfig.MinVersion)
	require.Equal(t, uint16(tls.VersionTLS13), server.tlsConfig.MaxVersion)
	require.Equal(t, []string{"h2", "http/1.1"}, server.tlsConfig.NextProtos)
	require.True(t, server.httpServer.Protocols.HTTP1())
	require.True(t, server.httpServer.Protocols.HTTP2())
	require.False(t, server.httpServer.Protocols.UnencryptedHTTP2())
	require.Equal(t, options.ReadHeaderTimeout, server.httpServer.ReadHeaderTimeout)
	require.Equal(t, options.ReadTimeout, server.httpServer.ReadTimeout)
	require.Equal(t, options.WriteTimeout, server.httpServer.WriteTimeout)
	require.Equal(t, options.IdleTimeout, server.httpServer.IdleTimeout)
	require.Equal(t, options.MaxHeaderBytes, server.httpServer.MaxHeaderBytes)
	require.NotNil(t, server.httpServer.ErrorLog)
}

func TestPrivateTLSServerRejectsInvalidOptionsAndFileSurfaces(
	t *testing.T,
) {
	certificatePath, privateKeyPath, _ := writePrivateServerPair(t)
	valid := testPrivateServerOptions(certificatePath, privateKeyPath)
	tests := map[string]func(*PrivateServerOptions){
		"hostname bind": func(options *PrivateServerOptions) {
			options.BindAddress = "localhost:9443"
		},
		"public bind": func(options *PrivateServerOptions) {
			options.BindAddress = "203.0.113.8:9443"
		},
		"unspecified IPv4 bind": func(options *PrivateServerOptions) {
			options.BindAddress = "0.0.0.0:9443"
		},
		"unspecified IPv6 bind": func(options *PrivateServerOptions) {
			options.BindAddress = "[::]:9443"
		},
		"zero port": func(options *PrivateServerOptions) {
			options.BindAddress = "127.0.0.1:0"
		},
		"relative certificate": func(options *PrivateServerOptions) {
			options.CertificatePath = "server.pem"
		},
		"relative private key": func(options *PrivateServerOptions) {
			options.PrivateKeyPath = "server-key.pem"
		},
		"short header timeout": func(options *PrivateServerOptions) {
			options.ReadHeaderTimeout = 0
		},
		"long header timeout": func(options *PrivateServerOptions) {
			options.ReadHeaderTimeout =
				maxPrivateReadHeaderTimeout + time.Second
		},
		"read below header timeout": func(options *PrivateServerOptions) {
			options.ReadTimeout = options.ReadHeaderTimeout - time.Millisecond
		},
		"long read timeout": func(options *PrivateServerOptions) {
			options.ReadTimeout = maxPrivateRequestTimeout + time.Second
		},
		"short write timeout": func(options *PrivateServerOptions) {
			options.WriteTimeout = 0
		},
		"long idle timeout": func(options *PrivateServerOptions) {
			options.IdleTimeout = maxPrivateIdleTimeout + time.Second
		},
		"small header limit": func(options *PrivateServerOptions) {
			options.MaxHeaderBytes = minPrivateHeaderBytes - 1
		},
		"large header limit": func(options *PrivateServerOptions) {
			options.MaxHeaderBytes = maxPrivateHeaderBytes + 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			require.ErrorIs(
				t,
				ValidatePrivateServerOptions(candidate),
				ErrPrivateServerConfiguration,
			)
			server, err := NewPrivateTLSServer(
				http.HandlerFunc(func(
					http.ResponseWriter,
					*http.Request,
				) {
				}),
				candidate,
			)
			require.Nil(t, server)
			require.ErrorIs(t, err, ErrPrivateServerConfiguration)
		})
	}

	server, err := NewPrivateTLSServer(nil, valid)
	require.Nil(t, server)
	require.ErrorIs(t, err, ErrPrivateServerConfiguration)

	require.NoError(t, os.Chmod(privateKeyPath, 0o640))
	server, err = NewPrivateTLSServer(
		http.NotFoundHandler(),
		valid,
	)
	require.Nil(t, server)
	require.ErrorIs(t, err, ErrPrivateServerConfiguration)
	require.NoError(t, os.Chmod(privateKeyPath, 0o600))

	require.NoError(t, os.Chmod(certificatePath, 0o664))
	server, err = NewPrivateTLSServer(
		http.NotFoundHandler(),
		valid,
	)
	require.Nil(t, server)
	require.ErrorIs(t, err, ErrPrivateServerConfiguration)
	require.NoError(t, os.Chmod(certificatePath, 0o644))

	symlinkPath := filepath.Join(t.TempDir(), "certificate-link.pem")
	require.NoError(t, os.Symlink(certificatePath, symlinkPath))
	symlinkOptions := valid
	symlinkOptions.CertificatePath = symlinkPath
	server, err = NewPrivateTLSServer(
		http.NotFoundHandler(),
		symlinkOptions,
	)
	require.Nil(t, server)
	require.ErrorIs(t, err, ErrPrivateServerConfiguration)

	oversizedPath := filepath.Join(t.TempDir(), "oversized-key.pem")
	require.NoError(t, os.WriteFile(
		oversizedPath,
		make([]byte, maxPrivateTLSPEMBytes+1),
		0o600,
	))
	oversizedOptions := valid
	oversizedOptions.PrivateKeyPath = oversizedPath
	server, err = NewPrivateTLSServer(
		http.NotFoundHandler(),
		oversizedOptions,
	)
	require.Nil(t, server)
	require.ErrorIs(t, err, ErrPrivateServerConfiguration)
}

func TestPrivateTLSServerRequiresExactWildcardIsolationOptIn(
	t *testing.T,
) {
	certificatePath, privateKeyPath, _ := writePrivateServerPair(t)
	valid := testPrivateServerOptions(certificatePath, privateKeyPath)

	for _, address := range []string{"0.0.0.0:9443", "[::]:9443"} {
		options := valid
		options.BindAddress = address
		require.ErrorIs(
			t,
			ValidatePrivateServerOptions(options),
			ErrPrivateServerConfiguration,
		)

		options.AllowUnspecifiedBind = true
		require.NoError(t, ValidatePrivateServerOptions(options))
		server, err := NewPrivateTLSServer(
			http.NotFoundHandler(),
			options,
		)
		require.NoError(t, err)
		require.NotNil(t, server)
		require.True(t, server.allowUnspecifiedBind)
	}

	loopbackWithRelaxation := valid
	loopbackWithRelaxation.AllowUnspecifiedBind = true
	require.ErrorIs(
		t,
		ValidatePrivateServerOptions(loopbackWithRelaxation),
		ErrPrivateServerConfiguration,
	)
}

func TestPrivateTLSServerBoundsHandlerContext(t *testing.T) {
	certificatePath, privateKeyPath, _ := writePrivateServerPair(t)
	contextResult := make(chan error, 1)
	server, err := NewPrivateTLSServer(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			<-request.Context().Done()
			contextResult <- request.Context().Err()
			writer.WriteHeader(http.StatusServiceUnavailable)
		}),
		testPrivateServerOptions(certificatePath, privateKeyPath),
	)
	require.NoError(t, err)
	server.requestTimeout = 20 * time.Millisecond

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "https://a9.test/", nil)
	started := time.Now()
	server.httpServer.Handler.ServeHTTP(recorder, request)

	require.ErrorIs(t, <-contextResult, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 500*time.Millisecond)
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	select {
	case <-server.Failed():
		t.Fatal("ordinary request deadline signaled runtime failure")
	default:
	}
}

func TestPrivateTLSServerPanicFailsRuntimeWithFixedResponse(
	t *testing.T,
) {
	const canary = "A9_PRIVATE_HANDLER_PANIC_CANARY"
	certificatePath, privateKeyPath, _ := writePrivateServerPair(t)
	server, err := NewPrivateTLSServer(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(canary)
		}),
		testPrivateServerOptions(certificatePath, privateKeyPath),
	)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "https://a9.test/", nil)
	server.httpServer.Handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	require.JSONEq(t, fixedUnavailableBody, recorder.Body.String())
	require.NotContains(t, recorder.Body.String(), canary)
	select {
	case <-server.Failed():
	default:
		t.Fatal("handler panic did not signal runtime failure")
	}
}

func TestPrivateTLSServerServesHTTP1AndHTTP2WithoutProxyTrust(
	t *testing.T,
) {
	certificatePath, privateKeyPath, certificatePEM :=
		writePrivateServerPair(t)
	observations := make(chan privateRequestObservation, 2)
	var handled atomic.Int32
	handler := http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		handled.Add(1)
		forwarded := make(map[string]string, len(forwardingHeaders))
		for _, header := range forwardingHeaders {
			forwarded[header] = request.Header.Get(header)
		}
		observations <- privateRequestObservation{
			protocol:   request.Proto,
			tlsVersion: request.TLS.Version,
			remoteAddr: request.RemoteAddr,
			forwarded:  forwarded,
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	server, err := NewPrivateTLSServer(
		handler,
		testPrivateServerOptions(certificatePath, privateKeyPath),
	)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(certificatePEM))
	for _, test := range []struct {
		name           string
		nextProtocols  []string
		forceHTTP2     bool
		wantProtoMajor string
	}{
		{
			name:           "HTTP1",
			nextProtocols:  []string{"http/1.1"},
			wantProtoMajor: "HTTP/1.1",
		},
		{
			name:           "HTTP2",
			forceHTTP2:     true,
			wantProtoMajor: "HTTP/2.0",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientTLS := &tls.Config{
				RootCAs:    roots,
				MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS13,
				NextProtos: append(
					[]string(nil),
					test.nextProtocols...,
				),
			}
			transport := &http.Transport{
				Proxy:             nil,
				TLSClientConfig:   clientTLS,
				ForceAttemptHTTP2: test.forceHTTP2,
			}
			client := &http.Client{
				Transport: transport,
				Timeout:   2 * time.Second,
			}
			request, err := http.NewRequest(
				http.MethodGet,
				"https://"+listener.Addr().String()+"/probe",
				nil,
			)
			require.NoError(t, err)
			for _, header := range forwardingHeaders {
				request.Header.Set(header, "spoofed")
			}
			response, err := client.Do(request)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, http.StatusNoContent, response.StatusCode)
			observation := <-observations
			require.Equal(t, test.wantProtoMajor, observation.protocol)
			require.Equal(t, uint16(tls.VersionTLS13), observation.tlsVersion)
			require.NotEmpty(t, observation.remoteAddr)
			require.NotContains(t, observation.remoteAddr, "spoofed")
			for _, value := range observation.forwarded {
				require.Empty(t, value)
			}
			transport.CloseIdleConnections()
		})
	}

	tls12Transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
		},
	}
	tls12Client := &http.Client{
		Transport: tls12Transport,
		Timeout:   time.Second,
	}
	_, err = tls12Client.Get(
		"https://" + listener.Addr().String() + "/tls12",
	)
	require.Error(t, err)
	tls12Transport.CloseIdleConnections()

	plaintext, err := net.DialTimeout(
		"tcp",
		listener.Addr().String(),
		time.Second,
	)
	require.NoError(t, err)
	require.NoError(t, plaintext.SetDeadline(time.Now().Add(time.Second)))
	_, err = plaintext.Write([]byte(
		"GET /h2c HTTP/1.1\r\n" +
			"Host: private.invalid\r\n" +
			"Connection: Upgrade\r\n" +
			"Upgrade: h2c\r\n\r\n",
	))
	require.NoError(t, err)
	buffer := make([]byte, 1)
	_, _ = plaintext.Read(buffer)
	require.NoError(t, plaintext.Close())
	require.Equal(t, int32(2), handled.Load())

	shutdownContext, cancel := context.WithTimeout(
		t.Context(),
		2*time.Second,
	)
	defer cancel()
	require.NoError(t, server.Shutdown(shutdownContext))
	require.ErrorIs(t, <-serveResult, http.ErrServerClosed)
}

func TestPrivateTLSServerLifecycleRejectsNilState(t *testing.T) {
	var server *PrivateTLSServer
	require.ErrorIs(
		t,
		server.Serve(nil),
		ErrPrivateServerConfiguration,
	)
	require.ErrorIs(
		t,
		server.Serve(publicTestListener{}),
		ErrPrivateServerConfiguration,
	)
	require.ErrorIs(
		t,
		server.ListenAndServe(),
		ErrPrivateServerConfiguration,
	)
	require.ErrorIs(
		t,
		server.Shutdown(t.Context()),
		ErrPrivateServerConfiguration,
	)

	certificatePath, privateKeyPath, _ := writePrivateServerPair(t)
	server, err := NewPrivateTLSServer(
		http.NotFoundHandler(),
		testPrivateServerOptions(certificatePath, privateKeyPath),
	)
	require.NoError(t, err)
	require.ErrorIs(
		t,
		server.Serve(nil),
		ErrPrivateServerConfiguration,
	)
	require.NoError(t, server.Shutdown(context.Background()))
}

func testPrivateServerOptions(
	certificatePath string,
	privateKeyPath string,
) PrivateServerOptions {
	return PrivateServerOptions{
		BindAddress:       "127.0.0.1:9443",
		CertificatePath:   certificatePath,
		PrivateKeyPath:    privateKeyPath,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
}

func writePrivateServerPair(
	t *testing.T,
) (string, string, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "a9-private.test",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	require.NoError(t, err)
	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	})
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "server-cert.pem")
	privateKeyPath := filepath.Join(directory, "server-key.pem")
	require.NoError(t, os.WriteFile(
		certificatePath,
		certificatePEM,
		0o644,
	))
	require.NoError(t, os.WriteFile(
		privateKeyPath,
		privateKeyPEM,
		0o600,
	))
	require.NoError(t, os.Chmod(certificatePath, 0o644))
	require.NoError(t, os.Chmod(privateKeyPath, 0o600))
	return certificatePath, privateKeyPath, certificatePEM
}
