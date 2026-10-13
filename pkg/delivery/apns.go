package delivery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"go.uber.org/zap"
)

type apnsSender interface {
	PushWithContext(apns2.Context, *apns2.Notification) (*apns2.Response, error)
}

// ApnsRejection preserves provider failure classification for durable dispatch.
// InvalidToken is deliberately narrower than Permanent: bad credentials or a
// malformed payload must never delete a user's installation.
type ApnsRejection struct {
	StatusCode   int
	Reason       string
	InvalidToken bool
	Permanent    bool
}

func (e *ApnsRejection) Error() string {
	return fmt.Sprintf("APNs rejected notification: status %d, reason %s", e.StatusCode, e.Reason)
}

func classifyApnsResponse(res *apns2.Response) error {
	if res == nil {
		return errors.New("APNs returned no response")
	}
	if res.StatusCode == http.StatusOK {
		return nil
	}
	return &ApnsRejection{
		StatusCode: res.StatusCode,
		Reason:     res.Reason,
		InvalidToken: (res.StatusCode == http.StatusGone && res.Reason == "Unregistered") ||
			(res.StatusCode == http.StatusBadRequest && (res.Reason == "BadDeviceToken" || res.Reason == "DeviceTokenNotForTopic")),
		Permanent: res.StatusCode >= 400 && res.StatusCode < 500 &&
			res.StatusCode != http.StatusTooManyRequests && res.Reason != "ExpiredProviderToken",
	}
}

type ApnsDelivery struct {
	logger     *zap.Logger
	apnsClient apnsSender
	opts       options.ApnsOptions
}

func NewApnsDelivery(logger *zap.Logger, opts options.ApnsOptions) (*ApnsDelivery, error) {
	var bytes []byte
	var err error

	if opts.P8Certificate == "" {
		bytes, err = os.ReadFile(opts.P8CertificateFilePath)

		if err != nil {
			return nil, err
		}
	} else {
		bytes = []byte(strings.ReplaceAll(opts.P8Certificate, "\\n", "\n"))
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

func (a ApnsDelivery) CanDeliver(req interfaces.SendRequest) bool {
	return req.Installation.DeliveryMechanism.Kind == interfaces.APNS
}

func (a ApnsDelivery) Send(ctx context.Context, req interfaces.SendRequest) error {
	notification := a.buildNotification(req)

	res, err := a.apnsClient.PushWithContext(ctx, notification)
	if err != nil {
		return err
	}
	if err = classifyApnsResponse(res); err != nil {
		a.logger.Warn("APNs notification rejected", zap.Error(err))
		return err
	}
	if res != nil {
		a.logger.Info(
			"Sent notification",
			zap.String("apns_id", res.ApnsID),
			zap.Int("status_code", res.StatusCode),
			zap.String("reason", res.Reason),
		)
	}

	return nil
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

	if req.Subscription.IsSilent {
		notificationPayload = notificationPayload.ContentAvailable()
	} else {
		notificationPayload = notificationPayload.
			Alert("New message from XMTP").
			MutableContent()
	}

	return &apns2.Notification{
		DeviceToken: req.Installation.DeliveryMechanism.Token,
		Topic:       a.opts.Topic,
		Payload:     notificationPayload,
	}
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
