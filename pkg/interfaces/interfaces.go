package interfaces

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	proto "github.com/xmtp/example-notification-server-go/pkg/proto/notifications/v1"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
	"github.com/xmtp/xmtpd/pkg/topic"
)

type DeliveryMechanismKind string

const (
	APNS DeliveryMechanismKind = "apns"
	FCM  DeliveryMechanismKind = "fcm"
)

type DeliveryMechanism struct {
	Kind      DeliveryMechanismKind `json:"kind"`
	Token     string                `json:"token"`
	UpdatedAt time.Time             `json:"-"`
}

type PayloadFormat int

const (
	PayloadFormatUnspecified PayloadFormat = 0
	PayloadFormatV3          PayloadFormat = 1
	PayloadFormatV4          PayloadFormat = 2
)

func PayloadFormatFromProto(p proto.PayloadFormat) PayloadFormat {
	switch p {
	case proto.PayloadFormat_PAYLOAD_FORMAT_V3:
		return PayloadFormatV3
	case proto.PayloadFormat_PAYLOAD_FORMAT_V4:
		return PayloadFormatV4
	default:
		return PayloadFormatUnspecified
	}
}

func (p PayloadFormat) ToProto() proto.PayloadFormat {
	switch p {
	case PayloadFormatV3:
		return proto.PayloadFormat_PAYLOAD_FORMAT_V3
	case PayloadFormatV4:
		return proto.PayloadFormat_PAYLOAD_FORMAT_V4
	default:
		return proto.PayloadFormat_PAYLOAD_FORMAT_UNSPECIFIED
	}
}

func (p PayloadFormat) String() string {
	switch p {
	case PayloadFormatV3:
		return "v3"
	case PayloadFormatV4:
		return "v4"
	default:
		return "unspecified"
	}
}

func (p PayloadFormat) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

type ListenerType string

const (
	ListenerTypeV3 ListenerType = "v3"
	ListenerTypeV4 ListenerType = "v4"
)

func NormalizePayloadFormat(format PayloadFormat) PayloadFormat {
	if format == PayloadFormatUnspecified {
		return PayloadFormatV3
	}
	return format
}

func (p PayloadFormat) ValidateForListener(listenerType ListenerType) error {
	normalized := NormalizePayloadFormat(p)
	if listenerType == ListenerTypeV3 && normalized == PayloadFormatV4 {
		return fmt.Errorf("payload format %q is not supported by listener type %q", normalized.String(), listenerType)
	}
	return nil
}

type RegisterResponse struct {
	InstallationId string
	ValidUntil     time.Time
}

/*
*
An installation represents an app installed on a device. If the app is reinstalled, or installed onto
a new device it is expected to generate a fresh installation_id.
*/
type Installation struct {
	Id                string            `json:"id"`
	DeliveryMechanism DeliveryMechanism `json:"delivery_mechanism"`
	PayloadFormat     PayloadFormat     `json:"payload_format"`
}

type Subscription struct {
	Id                    int64        `json:"-"`
	CreatedAt             time.Time    `json:"created_at"`
	InstallationId        string       `json:"-"`
	Topic                 string       `json:"topic"`
	TopicV4               *topic.Topic `json:"-"`
	IsActive              bool         `json:"-"`
	IsSilent              bool         `json:"is_silent"`
	ExpectedHmacKeyPeriod *int         `json:"-"`
	HmacKey               *HmacKey     `json:"-"`
	SecureRoute           *SecureRoute `json:"-"`
}

// A9RouteSnapshot is the exact A9 authority provenance selected with a route.
// It is current-operation material only: callers may carry it into the
// encrypted delivery job, but must never serialize it outside that boundary
// or emit it to logs, traces, metrics, or errors.
type A9RouteSnapshot struct {
	InstallationBindingID  [16]byte  `json:"installation_binding_id"`
	SequencerEpoch         [16]byte  `json:"sequencer_epoch"`
	SubscriptionGeneration uint64    `json:"subscription_generation"`
	BindingID               [16]byte  `json:"binding_id"`
	BindingVersion          uint64    `json:"binding_version"`
	AssertionHash           [32]byte  `json:"assertion_hash"`
	AssertionStreamSequence uint64    `json:"assertion_stream_sequence"`
	AssertionExpiresAt      time.Time `json:"assertion_expires_at"`
	TopicKeyEpoch           uint32    `json:"topic_key_epoch"`
	TopicBinding            [32]byte  `json:"topic_binding"`
	RouteKeyEpoch           uint32    `json:"route_key_epoch"`
	KeysetSequence          uint64    `json:"keyset_sequence"`
	KeysetHash              [32]byte  `json:"keyset_hash"`
	WatermarkSequence       uint64    `json:"watermark_sequence"`
}

// SecureRoute contains only current-operation material decrypted inside the
// Gate-8 vault boundary. It must never be serialized or logged.
type SecureRoute struct {
	LeaseID           []byte
	RouteKey          []byte
	RouteKeyEpoch     uint32
	NoncePrefix       uint32
	DeliverySequence  uint64
	AliasDay          string
	RouteAlias        []byte
	ReceiveCapability []byte
	LeaseExpiresAt    time.Time
	ControlExpiresAt  time.Time
	PolicyEpoch       uint64
	WelcomeAuthorized bool
	// WelcomeAuthorizationID and WelcomeEnvelopeDigest are opaque reservation
	// material. They are finalized atomically with durable Welcome enqueue and
	// must never be serialized outside the encrypted job.
	WelcomeAuthorizationID []byte
	WelcomeEnvelopeDigest  []byte
	A9                     *A9RouteSnapshot
}

type SendRequest struct {
	IdempotencyKey   string         `json:"-"`
	Topic            string         `json:"-"`
	TopicBytesB64    string         `json:"-"`
	EncryptedMessage []byte         `json:"-"`
	PayloadFormat    PayloadFormat  `json:"-"`
	MessageContext   MessageContext `json:"-"`
	Installation     Installation   `json:"-"`
	Subscription     Subscription   `json:"-"`
}

// sendRequestJSON is the HTTP delivery JSON format, preserving backward
// compatibility with the original V3 envelope-based payload shape.
type sendRequestJSON struct {
	IdempotencyKey string `json:"idempotency_key"`
	Message        struct {
		ContentTopic string `json:"content_topic"`
		Message      []byte `json:"message,omitempty"`
	} `json:"message"`
	MessageContext MessageContext `json:"message_context"`
	Installation   Installation   `json:"installation"`
	Subscription   Subscription   `json:"subscription"`
	PayloadFormat  PayloadFormat  `json:"payload_format,omitempty"`
	TopicBytesB64  string         `json:"topicBytesB64,omitempty"`
}

func (r SendRequest) MarshalJSON() ([]byte, error) {
	out := sendRequestJSON{
		IdempotencyKey: r.IdempotencyKey,
		MessageContext: r.MessageContext,
		Installation:   r.Installation,
		Subscription:   r.Subscription,
		PayloadFormat:  r.PayloadFormat,
		TopicBytesB64:  r.TopicBytesB64,
	}
	out.Message.ContentTopic = r.Topic
	if r.MessageContext.MessageType != topics.V3Welcome {
		out.Message.Message = r.EncryptedMessage
	}
	return json.Marshal(out)
}

type MessageContext struct {
	MessageType topics.MessageType `json:"message_type"`
	ShouldPush  *bool              `json:"should_push,omitempty"`
	HmacInputs  *[]byte            `json:"-"`
	SenderHmac  *[]byte            `json:"-"`
}

func (m MessageContext) IsSender(hmacKey []byte) bool {
	if !m.HasValidSenderHmac() || len(hmacKey) != sha256.Size {
		return false
	}
	hmacHash := hmac.New(sha256.New, hmacKey)
	hmacHash.Write(*m.HmacInputs)
	expectedHmac := hmacHash.Sum(nil)
	return hmac.Equal(*m.SenderHmac, expectedHmac)
}

func (m MessageContext) HasValidSenderHmac() bool {
	return m.SenderHmac != nil &&
		len(*m.SenderHmac) == sha256.Size &&
		m.HmacInputs != nil
}

type HmacKey struct {
	ThirtyDayPeriodsSinceEpoch int
	Key                        []byte
}

func (k HmacKey) IsValid() bool {
	const maxDatabasePeriod = int64(1<<31 - 1)
	return k.ThirtyDayPeriodsSinceEpoch >= 0 &&
		int64(k.ThirtyDayPeriodsSinceEpoch) <= maxDatabasePeriod &&
		len(k.Key) == sha256.Size
}

type SubscriptionInput struct {
	Topic    *topic.Topic
	IsSilent bool
	HmacKeys []HmacKey
}

// Pluggable Installation Service interface
//
//go:generate mockery --dir ../interfaces --name Installations --output ../../mocks --outpkg mocks
type Installations interface {
	Register(ctx context.Context, installation Installation) (*RegisterResponse, error)
	Delete(ctx context.Context, installationId string) error
	GetInstallations(ctx context.Context, installationIds []string) ([]Installation, error)
}

// This interface is not expected to be pluggable
//
//go:generate mockery --dir ../interfaces --name Subscriptions --output ../../mocks --outpkg mocks
type Subscriptions interface {
	Subscribe(ctx context.Context, installationId string, topics []*topic.Topic) error
	Unsubscribe(ctx context.Context, installationId string, topics []*topic.Topic) error
	GetSubscriptions(ctx context.Context, t *topic.Topic, thirtyDayPeriod int) ([]Subscription, error)
	SubscribeWithMetadata(ctx context.Context, installationId string, subscriptions []SubscriptionInput) error
}

// WelcomeSubscriptions is deliberately separate from Subscriptions. A
// listener only asks for a Welcome route when its backing store explicitly
// implements exact, one-use outer-envelope correlation. Legacy implementations
// therefore remain closed without a permissive compatibility path.
type WelcomeSubscriptions interface {
	GetWelcomeSubscriptions(
		ctx context.Context,
		t *topic.Topic,
		outerEnvelopeDigest []byte,
	) ([]WelcomeSubscription, error)
}

// WelcomeSubscription is returned as one atomic routing decision. It avoids a
// second installation lookup after the authorization has been consumed.
type WelcomeSubscription struct {
	Installation Installation
	Subscription Subscription
}

// Pluggable interface for sending push notifications
//
//go:generate mockery --dir ../interfaces --name Delivery --output ../../mocks --outpkg mocks
type Delivery interface {
	CanDeliver(req SendRequest) bool
	Send(ctx context.Context, req SendRequest) error
}
