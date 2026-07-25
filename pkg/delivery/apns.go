package delivery

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"go.uber.org/zap"
)

type ApnsDelivery struct {
	logger     *zap.Logger
	apnsClient *apns2.Client
	opts       options.ApnsOptions
}

func NewApnsDelivery(logger *zap.Logger, opts options.ApnsOptions) (*ApnsDelivery, error) {
	bytes, err := loadApnsCertificate(opts)
	if err != nil {
		return nil, err
	}

	client, err := getApnsClient(bytes, opts.KeyId, opts.TeamId)
	if err != nil {
		return nil, err
	}

	switch opts.Mode {
	case "production":
		client.Production()
	case "development":
		client.Development()
	default:
		return nil, errors.New("invalid APNS mode")
	}

	return &ApnsDelivery{
		logger:     logger.Named("delivery-service"),
		apnsClient: client,
		opts:       opts,
	}, nil
}

func loadApnsCertificate(opts options.ApnsOptions) ([]byte, error) {
	switch {
	case opts.P8Certificate != "":
		return []byte(strings.ReplaceAll(opts.P8Certificate, "\\n", "\n")), nil
	case opts.P8CertificateBase64 != "":
		bytes, err := base64.StdEncoding.DecodeString(
			strings.TrimSpace(opts.P8CertificateBase64),
		)
		if err != nil {
			return nil, fmt.Errorf("decode APNS .p8 certificate base64: %w", err)
		}
		return bytes, nil
	case opts.P8CertificateFilePath != "":
		return os.ReadFile(opts.P8CertificateFilePath)
	default:
		return nil, errors.New("APNS .p8 certificate is not configured")
	}
}

func (a ApnsDelivery) CanDeliver(req interfaces.SendRequest) bool {
	return req.Installation.DeliveryMechanism.Kind == interfaces.APNS
}

func (a ApnsDelivery) Send(ctx context.Context, req interfaces.SendRequest) error {
	notification := a.buildNotification(req)

	res, err := a.apnsClient.PushWithContext(ctx, notification)
	if res != nil {
		a.logger.Info(
			"Sent notification",
			zap.String("apns_id", res.ApnsID),
			zap.Int("status_code", res.StatusCode),
			zap.String("reason", res.Reason),
		)
	}

	if err != nil {
		return err
	}

	return apnsResponseError(res)
}

func (a ApnsDelivery) buildNotification(req interfaces.SendRequest) *apns2.Notification {
	notificationPayload := payload.NewPayload().
		Custom("topic", req.Topic).
		Custom("encryptedMessage", req.EncryptedMessage).
		Custom("messageKind", string(req.MessageContext.MessageType)).
		Custom("payloadFormat", req.PayloadFormat.String())

	if req.TopicBytesB64 != "" {
		notificationPayload = notificationPayload.Custom("topicBytesB64", req.TopicBytesB64)
	}

	pushType := apns2.PushTypeAlert
	priority := apns2.PriorityHigh
	if req.Subscription.IsSilent {
		notificationPayload = notificationPayload.ContentAvailable()
		pushType = apns2.PushTypeBackground
		priority = apns2.PriorityLow
	} else {
		notificationPayload = notificationPayload.
			Alert("New message from XMTP").
			MutableContent()
	}

	return &apns2.Notification{
		DeviceToken: req.Installation.DeliveryMechanism.Token,
		Topic:       a.opts.Topic,
		Payload:     notificationPayload,
		PushType:    pushType,
		Priority:    priority,
	}
}

func apnsResponseError(res *apns2.Response) error {
	if res == nil || res.Sent() {
		return nil
	}

	return fmt.Errorf(
		"APNS rejected notification: status=%d reason=%s apns_id=%s",
		res.StatusCode,
		res.Reason,
		res.ApnsID,
	)
}

func getApnsClient(authKey []byte, keyId, teamId string) (*apns2.Client, error) {
	key, err := token.AuthKeyFromBytes(authKey)
	if err != nil {
		return nil, err
	}

	authToken := &token.Token{
		AuthKey: key,
		KeyID:   keyId,
		TeamID:  teamId,
	}

	return apns2.NewTokenClient(authToken), nil
}
