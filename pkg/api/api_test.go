package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	proto "github.com/xmtp/example-notification-server-go/pkg/proto/notifications/v1"
	protoconnect "github.com/xmtp/example-notification-server-go/pkg/proto/notifications/v1/notificationsv1connect"
	"github.com/xmtp/example-notification-server-go/pkg/registration"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

const INSTALLATION_ID = "install1"
const testGroupTopic = "/xmtp/mls/1/g-24ce39d660600b3a98adff3075b6d1f4/proto"
const testWelcomeTopic = "/xmtp/mls/1/w-abcdef0123456789/proto"

type testContext struct {
	client            protoconnect.NotificationsClient
	ctx               context.Context
	httpClient        *http.Client
	installationsMock *mocks.Installations
	subscriptionsMock *mocks.Subscriptions
	apiServer         *ApiServer
}

type failingListener struct {
	err error
}

func (l *failingListener) Accept() (net.Conn, error) {
	return nil, l.err
}

func (l *failingListener) Close() error {
	return nil
}

func (l *failingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func matchTopics(expected ...*topicpkg.Topic) interface{} {
	return mock.MatchedBy(func(actual []*topicpkg.Topic) bool {
		if len(actual) != len(expected) {
			return false
		}
		for i := range expected {
			if actual[i] == nil || expected[i] == nil {
				if actual[i] != expected[i] {
					return false
				}
				continue
			}
			if actual[i].Kind() != expected[i].Kind() || !bytes.Equal(actual[i].Bytes(), expected[i].Bytes()) {
				return false
			}
		}
		return true
	})
}

func matchSubscriptionInputs(expected ...interfaces.SubscriptionInput) interface{} {
	return mock.MatchedBy(func(actual []interfaces.SubscriptionInput) bool {
		if len(actual) != len(expected) {
			return false
		}
		for i := range expected {
			exp := expected[i]
			got := actual[i]
			if (got.Topic == nil) != (exp.Topic == nil) {
				return false
			}
			if got.Topic != nil {
				if got.Topic.Kind() != exp.Topic.Kind() || !bytes.Equal(got.Topic.Bytes(), exp.Topic.Bytes()) {
					return false
				}
			}
			if got.IsSilent != exp.IsSilent {
				return false
			}
			if len(got.HmacKeys) != len(exp.HmacKeys) {
				return false
			}
			for j := range exp.HmacKeys {
				if got.HmacKeys[j].ThirtyDayPeriodsSinceEpoch != exp.HmacKeys[j].ThirtyDayPeriodsSinceEpoch {
					return false
				}
				if !bytes.Equal(got.HmacKeys[j].Key, exp.HmacKeys[j].Key) {
					return false
				}
			}
		}
		return true
	})
}

func setupTest(t *testing.T) testContext {
	t.Helper()
	return setupTestWithListenerType(t, interfaces.ListenerTypeV3)
}

func setupTestWithListenerType(t *testing.T, listenerType interfaces.ListenerType) testContext {
	t.Helper()
	ctx := t.Context()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	installationsMock := mocks.NewInstallations(t)
	subscriptionsMock := mocks.NewSubscriptions(t)
	httpClient := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	apiServer := NewApiServer(testutils.TestLogger(t), options.ApiOptions{Port: port}, installationsMock, subscriptionsMock, listenerType)
	require.NoError(t, apiServer.SetListener(listener))
	require.NoError(t, apiServer.Start())
	time.Sleep(50 * time.Millisecond)

	t.Cleanup(func() {
		httpClient.CloseIdleConnections()
		apiServer.Stop()
	})

	return testContext{
		client:            protoconnect.NewNotificationsClient(httpClient, fmt.Sprintf("http://127.0.0.1:%d", port)),
		ctx:               ctx,
		httpClient:        httpClient,
		installationsMock: installationsMock,
		subscriptionsMock: subscriptionsMock,
		apiServer:         apiServer,
	}
}

func Test_SetListenerAfterStartReturnsError(t *testing.T) {
	apiServer := NewApiServer(
		testutils.TestLogger(t),
		options.ApiOptions{Port: 18081},
		mocks.NewInstallations(t),
		mocks.NewSubscriptions(t),
		interfaces.ListenerTypeV3,
	)
	require.NoError(t, apiServer.Start())
	defer apiServer.Stop()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, listener.Close())
	}()

	err = apiServer.SetListener(listener)
	require.EqualError(t, err, "api server already started")
}

func Test_StartFailsSynchronouslyWhenPortIsOccupied(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, occupied.Close())
	}()
	port := occupied.Addr().(*net.TCPAddr).Port
	server := NewApiServer(
		testutils.TestLogger(t),
		options.ApiOptions{Port: port},
		mocks.NewInstallations(t),
		mocks.NewSubscriptions(t),
		interfaces.ListenerTypeV3,
	)

	err = server.Start()
	require.ErrorIs(t, err, ErrAPIUnavailable)
	require.Nil(t, server.httpServer)
	require.False(t, server.prepared)
}

func TestUnexpectedServeFailureSignalsWithoutLoggingCause(t *testing.T) {
	const sensitiveCause = "sensitive-listener-address-or-token"
	observedCore, logs := observer.New(zap.DebugLevel)
	server := NewApiServer(
		zap.New(observedCore),
		options.ApiOptions{},
		mocks.NewInstallations(t),
		mocks.NewSubscriptions(t),
		interfaces.ListenerTypeV3,
	)
	require.NoError(t, server.SetListener(&failingListener{
		err: errors.New(sensitiveCause),
	}))
	require.NoError(t, server.Start())
	t.Cleanup(server.Stop)

	select {
	case <-server.Failed():
	case <-time.After(time.Second):
		t.Fatal("API failure was not signaled")
	}
	for _, entry := range logs.All() {
		rendered := fmt.Sprintf("%s %#v", entry.Message, entry.ContextMap())
		require.NotContains(t, rendered, sensitiveCause)
	}
}

func Test_RegisterInstallation(t *testing.T) {
	ctx := setupTest(t)

	deviceToken := "foo"
	validUntil := time.Now()

	ctx.installationsMock.On(
		"Register",
		mock.Anything,
		mock.MatchedBy(func(inst interfaces.Installation) bool {
			return inst.Id == INSTALLATION_ID &&
				inst.DeliveryMechanism.Kind == interfaces.APNS &&
				inst.DeliveryMechanism.Token == deviceToken &&
				inst.PayloadFormat == interfaces.PayloadFormatV3
		}),
	).Return(&interfaces.RegisterResponse{
		InstallationId: INSTALLATION_ID,
		ValidUntil:     validUntil,
	}, nil)

	result, err := ctx.client.RegisterInstallation(
		ctx.ctx,
		connect.NewRequest(&proto.RegisterInstallationRequest{
			InstallationId: INSTALLATION_ID,
			DeliveryMechanism: &proto.DeliveryMechanism{
				DeliveryMechanismType: &proto.DeliveryMechanism_ApnsDeviceToken{ApnsDeviceToken: deviceToken},
			},
		}),
	)

	require.NoError(t, err)
	require.Equal(t, result.Msg.InstallationId, INSTALLATION_ID)
	require.Equal(t, result.Msg.ValidUntil, uint64(validUntil.UnixMilli()))
}

func TestApiLogsRedactRegistrationAndSubscriptionSecrets(t *testing.T) {
	const (
		installationID = "sensitive-installation-id"
		deviceToken    = "sensitive-device-token"
		rawTopic       = "/xmtp/mls/1/g-feedfacefeedfacefeedfacefeedface/proto"
		hmacSecret     = "sensitive-hmac-secret"
	)
	observedCore, logs := observer.New(zap.DebugLevel)
	installationsMock := mocks.NewInstallations(t)
	subscriptionsMock := mocks.NewSubscriptions(t)
	server := NewApiServer(
		zap.New(observedCore),
		options.ApiOptions{},
		installationsMock,
		subscriptionsMock,
		interfaces.ListenerTypeV3,
	)

	installationsMock.On("Register", mock.Anything, mock.Anything).
		Return(&interfaces.RegisterResponse{ValidUntil: time.Now()}, nil)
	_, err := server.RegisterInstallation(
		t.Context(),
		connect.NewRequest(&proto.RegisterInstallationRequest{
			InstallationId: installationID,
			DeliveryMechanism: &proto.DeliveryMechanism{
				DeliveryMechanismType: &proto.DeliveryMechanism_ApnsDeviceToken{
					ApnsDeviceToken: deviceToken,
				},
			},
		}),
	)
	require.NoError(t, err)

	subscriptionsMock.On("SubscribeWithMetadata", mock.Anything, installationID, mock.Anything).
		Return(nil)
	_, err = server.SubscribeWithMetadata(
		t.Context(),
		connect.NewRequest(&proto.SubscribeWithMetadataRequest{
			InstallationId: installationID,
			Subscriptions: []*proto.Subscription{{
				Topic: rawTopic,
				HmacKeys: []*proto.Subscription_HmacKey{{
					Key: []byte(hmacSecret),
				}},
			}},
		}),
	)
	require.NoError(t, err)

	for _, entry := range logs.All() {
		rendered := fmt.Sprintf("%s %#v", entry.Message, entry.ContextMap())
		require.NotContains(t, rendered, installationID)
		require.NotContains(t, rendered, deviceToken)
		require.NotContains(t, rendered, rawTopic)
		require.NotContains(t, rendered, hmacSecret)
	}
}

func TestPrivacySafeHTTPHandlerRedactsPanicAndRemoteAddress(t *testing.T) {
	const (
		sensitiveRemote = "203.0.113.42:49152"
		sensitiveNeedle = "sensitive-topic-token-installation"
	)
	observedCore, logs := observer.New(zap.DebugLevel)
	handler := privacySafeHTTPHandler(
		zap.New(observedCore),
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(sensitiveNeedle)
		}),
	)
	request := httptest.NewRequest(
		http.MethodPost,
		"https://bridge.invalid/refresh?secret="+sensitiveNeedle,
		strings.NewReader(sensitiveNeedle),
	)
	request.RemoteAddr = sensitiveRemote
	recorder := httptest.NewRecorder()

	require.NotPanics(t, func() {
		handler.ServeHTTP(recorder, request)
	})
	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Equal(t, "internal_error\n", recorder.Body.String())
	require.Len(t, logs.All(), 1)

	secondRecorder := httptest.NewRecorder()
	require.NotPanics(t, func() {
		handler.ServeHTTP(secondRecorder, request)
	})
	require.Equal(t, http.StatusInternalServerError, secondRecorder.Code)
	require.Len(t, logs.All(), 1)

	for _, entry := range logs.All() {
		rendered := fmt.Sprintf("%s %#v", entry.Message, entry.ContextMap())
		require.NotContains(t, rendered, sensitiveRemote)
		require.NotContains(t, rendered, sensitiveNeedle)
	}
}

func Test_RegisterInstallationError(t *testing.T) {
	ctx := setupTest(t)

	ctx.installationsMock.On(
		"Register",
		mock.Anything,
		mock.Anything,
	).Return(nil, errors.New("err"))

	result, err := ctx.client.RegisterInstallation(
		ctx.ctx,
		connect.NewRequest(&proto.RegisterInstallationRequest{
			InstallationId: INSTALLATION_ID,
			DeliveryMechanism: &proto.DeliveryMechanism{
				DeliveryMechanismType: &proto.DeliveryMechanism_ApnsDeviceToken{ApnsDeviceToken: "foo"},
			},
		}),
	)

	require.Equal(t, err.Error(), "internal: err")
	require.Nil(t, result)
}

func Test_DeleteInstallation(t *testing.T) {
	ctx := setupTest(t)

	ctx.installationsMock.On("Delete", mock.Anything, mock.Anything).
		Return(nil)

	_, err := ctx.client.DeleteInstallation(
		ctx.ctx,
		connect.NewRequest(&proto.DeleteInstallationRequest{
			InstallationId: INSTALLATION_ID,
		}),
	)

	require.NoError(t, err)
	ctx.installationsMock.AssertCalled(
		t,
		"Delete",
		mock.Anything,
		INSTALLATION_ID,
	)
}

func Test_Subscribe(t *testing.T) {
	ctx := setupTest(t)

	parsed := testutils.MustParseTopic(t, testGroupTopic)

	ctx.subscriptionsMock.On(
		"Subscribe",
		mock.Anything,
		INSTALLATION_ID,
		matchTopics(parsed),
	).Return(nil)

	_, err := ctx.client.Subscribe(
		ctx.ctx,
		connect.NewRequest(&proto.SubscribeRequest{
			InstallationId: INSTALLATION_ID,
			Topics:         []string{testGroupTopic},
		}),
	)

	require.NoError(t, err)
}

func Test_SubscribeError(t *testing.T) {
	ctx := setupTest(t)

	ctx.subscriptionsMock.On(
		"Subscribe",
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(errors.New("test"))

	_, err := ctx.client.Subscribe(
		ctx.ctx,
		connect.NewRequest(&proto.SubscribeRequest{
			InstallationId: INSTALLATION_ID,
			Topics:         []string{"/xmtp/mls/1/g-24ce39d660600b3a98adff3075b6d1f4/proto"},
		}),
	)

	require.Error(t, err)
	require.Equal(t, err.Error(), "internal: test")
}

func Test_Unsubscribe(t *testing.T) {
	ctx := setupTest(t)

	parsed := testutils.MustParseTopic(t, testGroupTopic)

	ctx.subscriptionsMock.On(
		"Unsubscribe",
		mock.Anything,
		INSTALLATION_ID,
		matchTopics(parsed),
	).Return(nil)

	_, err := ctx.client.Unsubscribe(
		ctx.ctx,
		connect.NewRequest(&proto.UnsubscribeRequest{
			InstallationId: INSTALLATION_ID,
			Topics:         []string{testGroupTopic},
		}),
	)

	require.NoError(t, err)
}

func Test_Subscribe_BytesTopics(t *testing.T) {
	ctx := setupTest(t)

	parsed := testutils.MustParseTopic(t, testGroupTopic)
	ctx.subscriptionsMock.On("Subscribe", mock.Anything, INSTALLATION_ID, matchTopics(parsed)).Return(nil)
	_, err := ctx.client.Subscribe(ctx.ctx, connect.NewRequest(&proto.SubscribeRequest{
		InstallationId: INSTALLATION_ID,
		TopicsBytes:    [][]byte{parsed.Bytes()},
	}))
	require.NoError(t, err)
}

func Test_Subscribe_InvalidStringTopic(t *testing.T) {
	ctx := setupTest(t)

	_, err := ctx.client.Subscribe(ctx.ctx, connect.NewRequest(&proto.SubscribeRequest{
		InstallationId: INSTALLATION_ID,
		Topics:         []string{"invalid-topic"},
	}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid")
}

func Test_Subscribe_InvalidBytesTopics(t *testing.T) {
	ctx := setupTest(t)

	_, err := ctx.client.Subscribe(ctx.ctx, connect.NewRequest(&proto.SubscribeRequest{
		InstallationId: INSTALLATION_ID,
		TopicsBytes:    [][]byte{{0xFF}}, // Too short, invalid kind
	}))
	require.Error(t, err)
}

func Test_Subscribe_MergedTopics(t *testing.T) {
	ctx := setupTest(t)

	parsed := testutils.MustParseTopic(t, testGroupTopic)
	ctx.subscriptionsMock.On("Subscribe", mock.Anything, INSTALLATION_ID, matchTopics(parsed)).Return(nil)
	_, err := ctx.client.Subscribe(ctx.ctx, connect.NewRequest(&proto.SubscribeRequest{
		InstallationId: INSTALLATION_ID,
		Topics:         []string{testGroupTopic},
		TopicsBytes:    [][]byte{parsed.Bytes()},
	}))
	require.NoError(t, err)
}

func Test_Subscribe_EmptyTopics(t *testing.T) {
	ctx := setupTest(t)

	ctx.subscriptionsMock.On("Subscribe", mock.Anything, INSTALLATION_ID, matchTopics()).Return(nil)
	_, err := ctx.client.Subscribe(ctx.ctx, connect.NewRequest(&proto.SubscribeRequest{
		InstallationId: INSTALLATION_ID,
	}))
	require.NoError(t, err)
}

func Test_Unsubscribe_BytesTopics(t *testing.T) {
	ctx := setupTest(t)

	parsed := testutils.MustParseTopic(t, testGroupTopic)
	ctx.subscriptionsMock.On("Unsubscribe", mock.Anything, INSTALLATION_ID, matchTopics(parsed)).Return(nil)
	_, err := ctx.client.Unsubscribe(ctx.ctx, connect.NewRequest(&proto.UnsubscribeRequest{
		InstallationId: INSTALLATION_ID,
		TopicsBytes:    [][]byte{parsed.Bytes()},
	}))
	require.NoError(t, err)
}

func Test_SubscribeWithMetadata_StringTopic(t *testing.T) {
	ctx := setupTest(t)

	ctx.subscriptionsMock.On(
		"SubscribeWithMetadata",
		mock.Anything,
		INSTALLATION_ID,
		matchSubscriptionInputs(interfaces.SubscriptionInput{
			Topic:    testutils.MustParseTopic(t, testGroupTopic),
			IsSilent: true,
		}),
	).Return(nil)
	_, err := ctx.client.SubscribeWithMetadata(ctx.ctx, connect.NewRequest(&proto.SubscribeWithMetadataRequest{
		InstallationId: INSTALLATION_ID,
		Subscriptions: []*proto.Subscription{{
			Topic:    testGroupTopic,
			IsSilent: true,
		}},
	}))
	require.NoError(t, err)
}

func Test_SubscribeWithMetadata_BytesTakesPrecedence(t *testing.T) {
	ctx := setupTest(t)

	parsed := testutils.MustParseTopic(t, testWelcomeTopic)
	ctx.subscriptionsMock.On(
		"SubscribeWithMetadata",
		mock.Anything,
		INSTALLATION_ID,
		matchSubscriptionInputs(interfaces.SubscriptionInput{
			Topic: parsed,
		}),
	).Return(nil)
	_, err := ctx.client.SubscribeWithMetadata(ctx.ctx, connect.NewRequest(&proto.SubscribeWithMetadataRequest{
		InstallationId: INSTALLATION_ID,
		Subscriptions: []*proto.Subscription{{
			Topic:      testGroupTopic,
			TopicBytes: parsed.Bytes(),
		}},
	}))
	require.NoError(t, err)
}

func Test_SubscribeWithMetadata_InvalidTopic(t *testing.T) {
	ctx := setupTest(t)

	_, err := ctx.client.SubscribeWithMetadata(ctx.ctx, connect.NewRequest(&proto.SubscribeWithMetadataRequest{
		InstallationId: INSTALLATION_ID,
		Subscriptions: []*proto.Subscription{{
			Topic: "not-a-valid-topic",
		}},
	}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid")
}

func Test_SubscribeWithMetadata_EmptyTopic(t *testing.T) {
	ctx := setupTest(t)

	_, err := ctx.client.SubscribeWithMetadata(ctx.ctx, connect.NewRequest(&proto.SubscribeWithMetadataRequest{
		InstallationId: INSTALLATION_ID,
		Subscriptions:  []*proto.Subscription{{}},
	}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "no topic")
}

func TestRegisterInstallation_WithPayloadFormatV4_OnV3Listener_ReturnsError(t *testing.T) {
	ctx := setupTestWithListenerType(t, interfaces.ListenerTypeV3)

	_, err := ctx.client.RegisterInstallation(
		ctx.ctx,
		connect.NewRequest(&proto.RegisterInstallationRequest{
			InstallationId: INSTALLATION_ID,
			DeliveryMechanism: &proto.DeliveryMechanism{
				DeliveryMechanismType: &proto.DeliveryMechanism_ApnsDeviceToken{ApnsDeviceToken: "token"},
			},
			PayloadFormat: proto.PayloadFormat_PAYLOAD_FORMAT_V4,
		}),
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid_argument")
}

func TestRegisterInstallation_WithPayloadFormatV4_OnV4Listener_Succeeds(t *testing.T) {
	ctx := setupTestWithListenerType(t, interfaces.ListenerTypeV4)

	validUntil := time.Now()
	ctx.installationsMock.On(
		"Register",
		mock.Anything,
		mock.MatchedBy(func(inst interfaces.Installation) bool {
			return inst.Id == INSTALLATION_ID &&
				inst.DeliveryMechanism.Kind == interfaces.APNS &&
				inst.DeliveryMechanism.Token == "token" &&
				inst.PayloadFormat == interfaces.PayloadFormatV4
		}),
	).Return(&interfaces.RegisterResponse{
		InstallationId: INSTALLATION_ID,
		ValidUntil:     validUntil,
	}, nil)

	result, err := ctx.client.RegisterInstallation(
		ctx.ctx,
		connect.NewRequest(&proto.RegisterInstallationRequest{
			InstallationId: INSTALLATION_ID,
			DeliveryMechanism: &proto.DeliveryMechanism{
				DeliveryMechanismType: &proto.DeliveryMechanism_ApnsDeviceToken{ApnsDeviceToken: "token"},
			},
			PayloadFormat: proto.PayloadFormat_PAYLOAD_FORMAT_V4,
		}),
	)

	require.NoError(t, err)
	require.Equal(t, INSTALLATION_ID, result.Msg.InstallationId)
}

func TestRegisterInstallation_WithUnspecified_DefaultsToV3(t *testing.T) {
	ctx := setupTest(t)

	validUntil := time.Now()
	ctx.installationsMock.On(
		"Register",
		mock.Anything,
		mock.MatchedBy(func(inst interfaces.Installation) bool {
			return inst.Id == INSTALLATION_ID &&
				inst.DeliveryMechanism.Kind == interfaces.APNS &&
				inst.DeliveryMechanism.Token == "token" &&
				inst.PayloadFormat == interfaces.PayloadFormatV3
		}),
	).Return(&interfaces.RegisterResponse{
		InstallationId: INSTALLATION_ID,
		ValidUntil:     validUntil,
	}, nil)

	result, err := ctx.client.RegisterInstallation(
		ctx.ctx,
		connect.NewRequest(&proto.RegisterInstallationRequest{
			InstallationId: INSTALLATION_ID,
			DeliveryMechanism: &proto.DeliveryMechanism{
				DeliveryMechanismType: &proto.DeliveryMechanism_ApnsDeviceToken{ApnsDeviceToken: "token"},
			},
			PayloadFormat: proto.PayloadFormat_PAYLOAD_FORMAT_UNSPECIFIED,
		}),
	)

	require.NoError(t, err)
	require.Equal(t, INSTALLATION_ID, result.Msg.InstallationId)
}

func Test_Readyz_DefaultsToOk(t *testing.T) {
	ctx := setupTest(t)

	resp, err := ctx.httpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/readyz", ctx.apiServer.port))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "ok", string(body))
}

func Test_Readyz_ReflectsReadyCheck(t *testing.T) {
	ctx := setupTest(t)
	ctx.apiServer.SetReadyCheck(func() bool { return false })

	resp, err := ctx.httpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/readyz", ctx.apiServer.port))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "not_ready", string(body))
}

func Test_Livez_DoesNotRestartForXMTPOutage(t *testing.T) {
	ctx := setupTest(t)
	ctx.apiServer.SetReadyCheck(func() bool { return false })

	resp, err := ctx.httpClient.Get(
		fmt.Sprintf("http://127.0.0.1:%d/livez", ctx.apiServer.port),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "ok", string(body))
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
}

func Test_XMTPHealth_FailsClosedWhileDisconnected(t *testing.T) {
	ctx := setupTest(t)
	// Aggregate storage/retention readiness is not evidence that an XMTP
	// listener exists or is connected.
	ctx.apiServer.SetReadyCheck(func() bool { return true })

	resp, err := ctx.httpClient.Get(
		fmt.Sprintf("http://127.0.0.1:%d/health/xmtp", ctx.apiServer.port),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "xmtp_unavailable", string(body))
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
}

func Test_XMTPHealth_ReportsConnected(t *testing.T) {
	ctx := setupTest(t)
	ctx.apiServer.SetXMTPReadyCheck(func() bool { return true })

	resp, err := ctx.httpClient.Get(
		fmt.Sprintf("http://127.0.0.1:%d/health/xmtp", ctx.apiServer.port),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "ok", string(body))
}

func Test_XMTPHealth_IsIndependentFromAggregateReadiness(t *testing.T) {
	ctx := setupTest(t)
	ctx.apiServer.SetReadyCheck(func() bool { return false })
	ctx.apiServer.SetXMTPReadyCheck(func() bool { return true })

	readyResponse, err := ctx.httpClient.Get(
		fmt.Sprintf("http://127.0.0.1:%d/readyz", ctx.apiServer.port),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, readyResponse.Body.Close())
	}()
	require.Equal(t, http.StatusServiceUnavailable, readyResponse.StatusCode)

	xmtpResponse, err := ctx.httpClient.Get(
		fmt.Sprintf("http://127.0.0.1:%d/health/xmtp", ctx.apiServer.port),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, xmtpResponse.Body.Close())
	}()
	require.Equal(t, http.StatusOK, xmtpResponse.StatusCode)
}

type secureMountBackend struct {
	welcomeCalls int
}

func (b *secureMountBackend) Refresh(
	context.Context,
	vault.RefreshRequest,
) (*vault.RefreshResult, error) {
	return &vault.RefreshResult{}, nil
}

func (b *secureMountBackend) AuthorizeWelcome(
	context.Context,
	vault.WelcomeAuthorizationRequest,
) error {
	b.welcomeCalls++
	return nil
}

func TestSecureRegistrationMountsWelcomeAuthorizationEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	backend := &secureMountBackend{}
	handler, err := registration.NewHandler(
		backend,
		"0123456789abcdef0123456789abcdef",
	)
	require.NoError(t, err)
	server := NewApiServer(
		testutils.TestLogger(t),
		options.ApiOptions{Port: port},
		mocks.NewInstallations(t),
		mocks.NewSubscriptions(t),
		interfaces.ListenerTypeV3,
	)
	server.EnableSecureRegistration(handler)
	require.NoError(t, server.SetListener(listener))
	require.NoError(t, server.Start())
	t.Cleanup(server.Stop)
	time.Sleep(50 * time.Millisecond)

	body := strings.NewReader(`{
		"schema_version":1,
		"topic_b64":"AAE",
		"authorization":{"schema_version":1}
	}`)
	request, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf(
			"http://127.0.0.1:%d%s",
			port,
			registration.WelcomePath,
		),
		body,
	)
	require.NoError(t, err)
	request.Header.Set(
		"Authorization",
		"Bearer 0123456789abcdef0123456789abcdef",
	)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, response.Body.Close())
	}()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, 1, backend.welcomeCalls)
}
