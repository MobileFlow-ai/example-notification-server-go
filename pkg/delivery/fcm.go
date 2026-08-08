package delivery

import (
	"context"
	"encoding/base64"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"github.com/pkg/errors"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/pushpolicy"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"go.uber.org/zap"
	"google.golang.org/api/option"
)

type FcmDelivery struct {
	client *messaging.Client
}

func NewFcmDelivery(ctx context.Context, _ *zap.Logger, opts options.FcmOptions) (*FcmDelivery, error) {
	creds := option.WithCredentialsJSON([]byte(opts.CredentialsJson))
	app, err := firebase.NewApp(ctx, &firebase.Config{
		ProjectID: opts.ProjectId,
	}, creds)

	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize firebase app")
	}

	// Use the auth method to validate the credentials
	_, err = app.Auth(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "firebase credentials failed to validate")
	}

	messaging, err := app.Messaging(ctx)
	if err != nil {
		return nil, err
	}

	return &FcmDelivery{
		client: messaging,
	}, nil
}

func (f FcmDelivery) CanDeliver(req interfaces.SendRequest) bool {
	return req.Installation.DeliveryMechanism.Kind == interfaces.FCM && req.Installation.DeliveryMechanism.Token != ""
}

func (f FcmDelivery) Send(ctx context.Context, req interfaces.SendRequest) error {
	if !pushpolicy.AllowsDelivery(ctx, req) {
		return pushpolicy.ErrUnauthorized
	}

	data := buildFcmData(req)

	apnsHeaders := map[string]string{}
	androidPriority := "high"

	if req.Subscription.IsSilent {
		apnsHeaders["apns-push-type"] = "background"
		apnsHeaders["apns-priority"] = "5"
		androidPriority = "normal"
	}

	_, err := f.client.Send(ctx, &messaging.Message{
		Token: req.Installation.DeliveryMechanism.Token,
		Data:  data,
		Android: &messaging.AndroidConfig{
			Data:     data,
			Priority: androidPriority,
		},
		Webpush: &messaging.WebpushConfig{
			Data: data,
			Notification: &messaging.WebpushNotification{
				Title: "New message from XMTP",
			},
		},
		APNS: &messaging.APNSConfig{
			Headers: apnsHeaders,
			Payload: &messaging.APNSPayload{
				CustomData: buildFcmApnsCustomData(req, data),
				Aps: &messaging.Aps{
					ContentAvailable: req.Subscription.IsSilent,
					MutableContent:   !req.Subscription.IsSilent,
				},
			},
		},
	})

	return err
}

func buildFcmApnsCustomData(req interfaces.SendRequest, data map[string]string) map[string]interface{} {
	customData := map[string]interface{}{
		"topic":         req.Topic,
		"messageType":   data["messageType"],
		"payloadFormat": data["payloadFormat"],
	}
	if encryptedMessage, ok := data["encryptedMessage"]; ok {
		customData["encryptedMessage"] = encryptedMessage
	}
	if req.TopicBytesB64 != "" {
		customData["topicBytesB64"] = req.TopicBytesB64
	}
	return customData
}

func buildFcmData(req interfaces.SendRequest) map[string]string {
	data := map[string]string{
		"topic":         req.Topic,
		"messageType":   string(req.MessageContext.MessageType),
		"payloadFormat": req.PayloadFormat.String(),
	}
	if req.MessageContext.MessageType != topics.V3Welcome {
		data["encryptedMessage"] = base64.StdEncoding.EncodeToString(req.EncryptedMessage)
	}
	if req.TopicBytesB64 != "" {
		data["topicBytesB64"] = req.TopicBytesB64
	}
	return data
}
