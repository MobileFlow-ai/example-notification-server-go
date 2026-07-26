package delivery

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/pushpolicy"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
)

func TestFcm_DataIncludesPayloadFormat(t *testing.T) {
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)

	data := buildFcmData(req)
	require.Equal(t, "v3", data["payloadFormat"])
}

func Test_BuildFcmData_TopicField(t *testing.T) {
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)

	data := buildFcmData(req)
	require.Equal(t, deliveryTestTopic, data["topic"])
	require.NotContains(t, data, "topicBytesB64")
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("test")), data["encryptedMessage"])
	require.Equal(t, "v3-conversation", data["messageType"])
}

func Test_BuildFcmData_V4TopicBytesB64(t *testing.T) {
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV4)

	data := buildFcmData(req)
	require.Equal(t, deliveryTestTopic, data["topic"])
	require.Equal(t, req.TopicBytesB64, data["topicBytesB64"])
	require.Equal(t, "v4", data["payloadFormat"])
}

func Test_BuildFcmData_WelcomeIsCompact(t *testing.T) {
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV4)
	req.MessageContext = interfaces.MessageContext{MessageType: topics.V3Welcome}
	req.EncryptedMessage = make([]byte, 8_192)

	data := buildFcmData(req)
	require.NotContains(t, data, "encryptedMessage")
	require.NotContains(t, buildFcmApnsCustomData(req, data), "encryptedMessage")
}

func TestFcmDelivery_UnsealedRequestReturnsUnauthorized(t *testing.T) {
	req := buildDeliveryRequest(t, interfaces.PayloadFormatV3)
	require.ErrorIs(t, (FcmDelivery{}).Send(t.Context(), req), pushpolicy.ErrUnauthorized)
}
