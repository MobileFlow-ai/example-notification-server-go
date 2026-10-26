package delivery

import (
	"net/http"
	"net/http/httptest"
	"testing"

	firebase "firebase.google.com/go/v4"
	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"google.golang.org/api/option"
)

func loopbackFcmDelivery(t *testing.T, status int, body string) FcmDelivery {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	app, err := firebase.NewApp(t.Context(), &firebase.Config{ProjectID: "test-project"},
		option.WithEndpoint(server.URL), option.WithoutAuthentication(), option.WithHTTPClient(server.Client()))
	require.NoError(t, err)
	client, err := app.Messaging(t.Context())
	require.NoError(t, err)
	return FcmDelivery{client: client}
}

func fcmErrorBody(status, errorCode string) string {
	return `{"error":{"code":400,"message":"rejected","status":"` + status +
		`","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"` +
		errorCode + `"}]}}`
}

func TestFcm_ProviderFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		permanent bool
	}{
		{"accepted", http.StatusOK, `{"name":"projects/test-project/messages/1"}`, false},
		{"unregistered", http.StatusNotFound, fcmErrorBody("NOT_FOUND", "UNREGISTERED"), true},
		{"invalid_argument", http.StatusBadRequest, fcmErrorBody("INVALID_ARGUMENT", "INVALID_ARGUMENT"), true},
		{"sender_mismatch", http.StatusForbidden, fcmErrorBody("PERMISSION_DENIED", "SENDER_ID_MISMATCH"), true},
		{"quota", http.StatusTooManyRequests, fcmErrorBody("RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED"), false},
		// 5xx (UNAVAILABLE, INTERNAL) is retried inside the SDK with
		// backoff and is never classified permanent; omitted to keep the
		// test fast.
		{"apns_credentials", http.StatusUnauthorized, fcmErrorBody("UNAUTHENTICATED", "THIRD_PARTY_AUTH_ERROR"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := loopbackFcmDelivery(t, tc.status, tc.body)
			req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)
			req.Installation.DeliveryMechanism = interfaces.DeliveryMechanism{Kind: interfaces.FCM, Token: "fcm-token"}
			ctx, req := authorizeTestDeliveryRequest(t, t.Context(), req)
			err := f.Send(ctx, req)
			if tc.status == http.StatusOK {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Equal(t, tc.permanent, IsPermanentFailure(err))
		})
	}
}
