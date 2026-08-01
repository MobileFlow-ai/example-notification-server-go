// Package a9api implements the private, fail-closed A9 control-plane HTTP
// boundary. It never enables provider egress or Welcome routing by itself.
package a9api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9schema"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

var ErrInvalidReplace = errors.New("a9 replacement invalid")

const maxSafeInteger = uint64(9007199254740991)

type TopicBinder interface {
	TopicBindingForEpoch(
		ctx context.Context,
		topic []byte,
		epoch uint32,
		now time.Time,
		assertionExpiresAt time.Time,
		alreadyAccepted bool,
	) ([]byte, a9trust.Verdict)
}

type RouteHMACKey struct {
	ThirtyDayPeriodsSinceEpoch uint32
	Key                        [32]byte
}

type Subscription struct {
	BindingID               [16]byte
	BindingVersion          uint64
	AssertionHash           [32]byte
	TopicBinding            [32]byte
	TopicKeyEpoch           uint32
	RouteKeyEpoch           uint32
	Topic                   [33]byte
	TransportConversationID [32]byte
	RouteKey                [32]byte
	HMACKeys                []RouteHMACKey
	ReceiveCapability       []byte
}

type ReplaceRequest struct {
	Environment                    string
	InstallationBindingID          [16]byte
	SequencerEpoch                 [16]byte
	SubscriptionGeneration         uint64
	ExpectedSubscriptionGeneration uint64
	IdempotencyKey                 [16]byte
	LegacyInstallationID           [32]byte
	AccountIncarnationID           [16]byte
	APNSToken                      [32]byte
	PayloadSchema                  string
	PolicyControl                  []byte
	Subscriptions                  []Subscription
	RequestHash                    [32]byte
}

// DecodeReplace must be called only after service JWT verification and durable
// JTI consumption. It requires the exact JCS request spelling, normalizes
// sensitive values into zeroable byte storage, verifies topic resolution and
// keyed topic binding, and enforces complete-replacement ordering.
func DecodeReplace(
	ctx context.Context,
	raw []byte,
	expectedEnvironment string,
	binder TopicBinder,
	now time.Time,
) (*ReplaceRequest, error) {
	if ctx == nil ||
		binder == nil ||
		(expectedEnvironment != "dev" &&
			expectedEnvironment != "production") ||
		now.IsZero() {
		return nil, ErrInvalidReplace
	}
	object, err := a9schema.Decode(
		a9schema.SubscriptionsReplaceKind,
		raw,
	)
	if err != nil {
		return nil, ErrInvalidReplace
	}
	canonical, err := a9trust.Canonicalize(object)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrInvalidReplace
	}
	if stringField(object, "environment") != expectedEnvironment {
		return nil, ErrInvalidReplace
	}

	request := &ReplaceRequest{
		Environment:   expectedEnvironment,
		PayloadSchema: stringField(object, "payload_schema"),
		RequestHash:   sha256.Sum256(raw),
	}
	valid := false
	defer func() {
		if !valid {
			request.Close()
		}
	}()

	if !decodeFixed(
		stringField(object, "installation_binding_id"),
		request.InstallationBindingID[:],
	) ||
		!decodeFixed(
			stringField(object, "sequencer_epoch"),
			request.SequencerEpoch[:],
		) ||
		!decodeUUID(
			stringField(object, "idempotency_key"),
			request.IdempotencyKey[:],
		) ||
		!decodeLowerHex(
			stringField(object, "legacy_installation_id"),
			request.LegacyInstallationID[:],
		) ||
		!decodeUUID(
			stringField(object, "account_incarnation_id"),
			request.AccountIncarnationID[:],
		) ||
		!decodeFixed(
			stringField(object, "apns_token_base64url"),
			request.APNSToken[:],
		) {
		return nil, ErrInvalidReplace
	}
	request.SubscriptionGeneration, err = safeInteger(
		object["subscription_generation"],
		true,
	)
	if err != nil {
		return nil, ErrInvalidReplace
	}
	request.ExpectedSubscriptionGeneration, err = safeInteger(
		object["expected_subscription_generation"],
		false,
	)
	if err != nil ||
		request.ExpectedSubscriptionGeneration == maxSafeInteger ||
		request.SubscriptionGeneration !=
			request.ExpectedSubscriptionGeneration+1 {
		return nil, ErrInvalidReplace
	}
	request.PolicyControl, err = decodeVariable(
		stringField(object, "policy_control_base64url"),
	)
	if err != nil {
		return nil, ErrInvalidReplace
	}

	items, ok := object["subscriptions"].([]any)
	if !ok {
		return nil, ErrInvalidReplace
	}
	request.Subscriptions = make([]Subscription, len(items))
	seenBindings := make(map[[16]byte]bool, len(items))
	seenRouteCAS := make(map[string]bool, len(items))
	for index, item := range items {
		subscriptionObject, ok := item.(map[string]any)
		if !ok {
			return nil, ErrInvalidReplace
		}
		subscription := &request.Subscriptions[index]
		if err := decodeSubscription(
			ctx,
			subscription,
			subscriptionObject,
			binder,
			now.UTC(),
		); err != nil {
			return nil, ErrInvalidReplace
		}
		if seenBindings[subscription.BindingID] {
			return nil, ErrInvalidReplace
		}
		seenBindings[subscription.BindingID] = true
		casKey := routeCASKey(
			subscription.TopicKeyEpoch,
			subscription.TopicBinding,
		)
		if seenRouteCAS[casKey] {
			return nil, ErrInvalidReplace
		}
		seenRouteCAS[casKey] = true
		if index > 0 && !subscriptionAfter(
			&request.Subscriptions[index-1],
			subscription,
		) {
			return nil, ErrInvalidReplace
		}
	}

	valid = true
	return request, nil
}

func decodeSubscription(
	ctx context.Context,
	subscription *Subscription,
	object map[string]any,
	binder TopicBinder,
	now time.Time,
) error {
	if subscription == nil ||
		!decodeFixed(
			stringField(object, "binding_id"),
			subscription.BindingID[:],
		) ||
		!decodeFixed(
			stringField(object, "assertion_hash"),
			subscription.AssertionHash[:],
		) ||
		!decodeFixed(
			stringField(object, "topic_binding"),
			subscription.TopicBinding[:],
		) ||
		!decodeFixed(
			stringField(object, "topic_base64url"),
			subscription.Topic[:],
		) ||
		!decodeLowerHex(
			stringField(object, "transport_conversation_id"),
			subscription.TransportConversationID[:],
		) ||
		!decodeFixed(
			stringField(object, "route_key_base64url"),
			subscription.RouteKey[:],
		) {
		return ErrInvalidReplace
	}
	var err error
	subscription.BindingVersion, err = safeInteger(
		object["binding_version"],
		true,
	)
	if err != nil {
		return ErrInvalidReplace
	}
	topicEpoch, err := safeInteger(object["topic_key_epoch"], true)
	if err != nil || topicEpoch > uint64(^uint32(0)) {
		return ErrInvalidReplace
	}
	subscription.TopicKeyEpoch = uint32(topicEpoch)
	routeEpoch, err := safeInteger(object["route_key_epoch"], true)
	if err != nil || routeEpoch > uint64(^uint32(0)) {
		return ErrInvalidReplace
	}
	subscription.RouteKeyEpoch = uint32(routeEpoch)

	resolved, err := a9trust.ResolveTopic(
		stringField(object, "transport_conversation_id"),
	)
	if err != nil ||
		!a9trust.EqualBinding(resolved.Bytes, subscription.Topic[:]) {
		return ErrInvalidReplace
	}
	// The vault transaction must still prove the referenced assertion was
	// already accepted and remains unexpired. This request-boundary check only
	// verifies that the declared binding can correspond to the exact topic and
	// epoch during the allowed current/previous period.
	recomputed, verdict := binder.TopicBindingForEpoch(
		ctx,
		subscription.Topic[:],
		subscription.TopicKeyEpoch,
		now,
		now.Add(time.Nanosecond),
		true,
	)
	if !verdict.IsEligible() ||
		!a9trust.EqualBinding(
			recomputed,
			subscription.TopicBinding[:],
		) {
		return ErrInvalidReplace
	}

	hmacItems, ok := object["hmac_keys"].([]any)
	if !ok {
		return ErrInvalidReplace
	}
	subscription.HMACKeys = make([]RouteHMACKey, len(hmacItems))
	var previousPeriod uint32
	for index, item := range hmacItems {
		keyObject, ok := item.(map[string]any)
		if !ok {
			return ErrInvalidReplace
		}
		period, err := safeInteger(
			keyObject["thirty_day_periods_since_epoch"],
			false,
		)
		if err != nil || period > uint64(^uint32(0)>>1) {
			return ErrInvalidReplace
		}
		if index > 0 && uint32(period) <= previousPeriod {
			return ErrInvalidReplace
		}
		previousPeriod = uint32(period)
		subscription.HMACKeys[index].ThirtyDayPeriodsSinceEpoch =
			uint32(period)
		if !decodeFixed(
			stringField(keyObject, "key_base64url"),
			subscription.HMACKeys[index].Key[:],
		) {
			return ErrInvalidReplace
		}
	}
	subscription.ReceiveCapability, err = decodeVariable(
		stringField(object, "receive_capability_base64url"),
	)
	return err
}

func (request *ReplaceRequest) Close() {
	if request == nil {
		return
	}
	clear(request.InstallationBindingID[:])
	clear(request.SequencerEpoch[:])
	clear(request.IdempotencyKey[:])
	clear(request.LegacyInstallationID[:])
	clear(request.AccountIncarnationID[:])
	clear(request.APNSToken[:])
	clear(request.PolicyControl)
	for index := range request.Subscriptions {
		subscription := &request.Subscriptions[index]
		clear(subscription.BindingID[:])
		clear(subscription.AssertionHash[:])
		clear(subscription.TopicBinding[:])
		clear(subscription.Topic[:])
		clear(subscription.TransportConversationID[:])
		clear(subscription.RouteKey[:])
		for keyIndex := range subscription.HMACKeys {
			clear(subscription.HMACKeys[keyIndex].Key[:])
		}
		clear(subscription.HMACKeys)
		subscription.HMACKeys = nil
		clear(subscription.ReceiveCapability)
		subscription.ReceiveCapability = nil
		subscription.BindingVersion = 0
		subscription.TopicKeyEpoch = 0
		subscription.RouteKeyEpoch = 0
	}
	clear(request.Subscriptions)
	request.Subscriptions = nil
	request.PolicyControl = nil
	clear(request.RequestHash[:])
	request.Environment = ""
	request.PayloadSchema = ""
	request.SubscriptionGeneration = 0
	request.ExpectedSubscriptionGeneration = 0
}

func decodeFixed(value string, destination []byte) bool {
	decoded, err := a9trust.DecodeBase64URL(value, len(destination))
	if err != nil {
		return false
	}
	defer clear(decoded)
	copy(destination, decoded)
	return true
}

func decodeVariable(value string) ([]byte, error) {
	// The schema already bounds this value. DecodeBase64URL intentionally
	// requires a fixed length, so use the strict round-trip decoder here.
	if value == "" {
		return nil, ErrInvalidReplace
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		clear(decoded)
		return nil, ErrInvalidReplace
	}
	return decoded, nil
}

func safeInteger(value any, positive bool) (uint64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, ErrInvalidReplace
	}
	raw := number.String()
	if raw == "" {
		return 0, ErrInvalidReplace
	}
	parsed, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || parsed > maxSafeInteger ||
		(positive && parsed == 0) {
		return 0, ErrInvalidReplace
	}
	return parsed, nil
}

func stringField(object map[string]any, field string) string {
	value, _ := object[field].(string)
	return value
}

func decodeUUID(value string, destination []byte) bool {
	decoded, err := a9trust.ParseCanonicalUUID(value)
	if err != nil || len(decoded) != len(destination) {
		clear(decoded)
		return false
	}
	defer clear(decoded)
	copy(destination, decoded)
	return true
}

func decodeLowerHex(value string, destination []byte) bool {
	if len(value) != len(destination)*2 {
		return false
	}
	for index := range value {
		if (value[index] < '0' || value[index] > '9') &&
			(value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(destination) {
		clear(decoded)
		return false
	}
	defer clear(decoded)
	copy(destination, decoded)
	return true
}

func routeCASKey(epoch uint32, binding [32]byte) string {
	var prefix [4]byte
	prefix[0] = byte(epoch >> 24)
	prefix[1] = byte(epoch >> 16)
	prefix[2] = byte(epoch >> 8)
	prefix[3] = byte(epoch)
	return string(prefix[:]) + string(binding[:])
}

func subscriptionAfter(previous, current *Subscription) bool {
	if previous == nil || current == nil {
		return false
	}
	switch comparison := bytes.Compare(
		previous.TopicBinding[:],
		current.TopicBinding[:],
	); {
	case comparison < 0:
		return true
	case comparison > 0:
		return false
	default:
		return bytes.Compare(
			previous.BindingID[:],
			current.BindingID[:],
		) < 0
	}
}
