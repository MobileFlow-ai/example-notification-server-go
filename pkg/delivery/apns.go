package delivery

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/pushpolicy"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"go.uber.org/zap"
)

type ApnsDelivery struct {
	apnsClient apnsClient
	opts       options.ApnsOptions
	now        func() time.Time
	random     io.Reader
	logger     *zap.Logger
	reliable   *apnsReliability
}

// APNSPushClient is the narrow provider boundary used by ApnsDelivery.
// Exposing only PushWithContext permits deterministic provider substitution
// without exposing credentials or the concrete APNS client implementation.
type APNSPushClient interface {
	PushWithContext(apns2.Context, *apns2.Notification) (*apns2.Response, error)
}

type apnsClient = APNSPushClient

var _ APNSPushClient = (*apns2.Client)(nil)

// NewApnsDeliveryWithClient constructs APNS delivery around an already
// configured provider client. The normal credential-loading constructor remains
// the production default; this seam is intentionally limited to provider
// substitution.
func NewApnsDeliveryWithClient(
	logger *zap.Logger,
	opts options.ApnsOptions,
	client APNSPushClient,
) (*ApnsDelivery, error) {
	if client == nil || opts.Topic == "" ||
		(opts.Mode != "development" && opts.Mode != "production") {
		return nil, errors.New("APNS provider configuration invalid")
	}
	if err := validateSecureAPNSOptions(opts); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ApnsDelivery{
		apnsClient: client,
		opts:       opts,
		now:        time.Now,
		random:     rand.Reader,
		logger:     logger,
	}, nil
}

func NewApnsDelivery(logger *zap.Logger, opts options.ApnsOptions) (*ApnsDelivery, error) {
	if err := validateSecureAPNSOptions(opts); err != nil {
		return nil, err
	}
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
		apnsClient: client,
		opts:       opts,
		now:        time.Now,
		random:     rand.Reader,
		logger:     logger,
	}, nil
}

func validateSecureAPNSOptions(opts options.ApnsOptions) error {
	if !opts.SecureWrapperRequired {
		return nil
	}
	if opts.P8CertificateBase64 == "" ||
		opts.P8Certificate != "" ||
		opts.P8CertificateFilePath != "" ||
		opts.KeyId == "" ||
		opts.TeamId == "" ||
		opts.Topic == "" ||
		opts.SecureEnvironment == "" ||
		opts.SecureEnvironment != opts.Mode {
		return errors.New("secure APNS configuration invalid")
	}
	return nil
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

func (a *ApnsDelivery) Send(ctx context.Context, req interfaces.SendRequest) error {
	if !pushpolicy.AllowsDelivery(ctx, req) {
		return pushpolicy.ErrUnauthorized
	}

	notification, err := a.buildNotification(req)
	if err != nil {
		return err
	}

	if a.reliable != nil {
		return a.enqueueNotification(ctx, req, notification)
	}

	outcome := a.pushNotification(ctx, notification)
	return apnsOutcomeError(outcome)
}

func (a ApnsDelivery) buildNotification(
	req interfaces.SendRequest,
) (*apns2.Notification, error) {
	if req.Subscription.SecureRoute != nil {
		return a.buildSecureNotification(req)
	}
	if a.opts.SecureWrapperRequired {
		return nil, ErrSecurePayloadInvalid
	}

	notificationPayload := payload.NewPayload().
		Custom("topic", req.Topic).
		Custom("messageKind", string(req.MessageContext.MessageType)).
		Custom("payloadFormat", req.PayloadFormat.String())

	// MLS welcome envelopes routinely exceed APNs' 4 KiB payload limit. The
	// welcome topic itself is enough to wake the NSE, which then syncs and
	// processes the welcome from XMTP. Conversation envelopes remain inline so
	// the NSE can decrypt and render them without an extra network read.
	if req.MessageContext.MessageType != topics.V3Welcome {
		notificationPayload = notificationPayload.Custom(
			"encryptedMessage",
			req.EncryptedMessage,
		)
	}

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
	}, nil
}

func apnsResponseError(res *apns2.Response) error {
	return apnsOutcomeError(classifyAPNSResponse(res, nil))
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
