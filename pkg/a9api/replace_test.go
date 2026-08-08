package a9api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

const (
	maximumReplacementSubscriptions = 2048
	maximumReplacementTestDeadline  = 10 * time.Second
)

type fixtureBinder struct {
	keys map[uint32][32]byte
}

func (binder fixtureBinder) TopicBindingForEpoch(
	_ context.Context,
	topic []byte,
	epoch uint32,
	_ time.Time,
	_ time.Time,
	_ bool,
) ([]byte, a9trust.Verdict) {
	key, ok := binder.keys[epoch]
	if !ok {
		return nil, a9trust.Invalid("TOPIC_KEY_EPOCH")
	}
	binding, err := a9trust.TopicBinding(key[:], topic)
	if err != nil {
		return nil, a9trust.Invalid("TOPIC_RESOLVER")
	}
	return binding, a9trust.Eligible()
}

type deadlineCountingBinder struct {
	delegate TopicBinder
	calls    int
}

func (binder *deadlineCountingBinder) TopicBindingForEpoch(
	ctx context.Context,
	topic []byte,
	epoch uint32,
	now time.Time,
	assertionExpiresAt time.Time,
	alreadyAccepted bool,
) ([]byte, a9trust.Verdict) {
	binder.calls++
	if ctx == nil || ctx.Err() != nil || binder.delegate == nil {
		return nil, a9trust.Inconclusive("TRUST_UNAVAILABLE")
	}
	return binder.delegate.TopicBindingForEpoch(
		ctx,
		topic,
		epoch,
		now,
		assertionExpiresAt,
		alreadyAccepted,
	)
}

func TestDecodeReplaceNormalizesPublishedCanonicalRequest(t *testing.T) {
	positive := readPositive(t)
	replace := objectValue(t, positive["subscription_replace"])
	raw := []byte(
		stringValue(t, replace["canonical_body_utf8"]),
	)
	binder := publishedTopicBinder(t, positive)
	request, err := DecodeReplace(
		context.Background(),
		raw,
		"dev",
		binder,
		wireTime(
			t,
			objectValue(
				t,
				objectValue(t, positive["assertion"])["value"],
			)["issued_at"],
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.Environment != "dev" ||
		request.SubscriptionGeneration != 12 ||
		request.ExpectedSubscriptionGeneration != 11 ||
		len(request.Subscriptions) != 1 {
		t.Fatalf("unexpected normalized request: %+v", request)
	}
	if request.RequestHash != sha256.Sum256(raw) {
		t.Fatal("request hash did not bind the exact canonical bytes")
	}
	if got := hexString(request.RequestHash[:]); got !=
		stringValue(t, replace["canonical_body_sha256"]) {
		t.Fatalf("request hash = %s", got)
	}
	subscription := &request.Subscriptions[0]
	if subscription.Topic[0] != 0 ||
		len(subscription.HMACKeys) == 0 ||
		len(subscription.ReceiveCapability) == 0 ||
		len(request.PolicyControl) == 0 {
		t.Fatal("sensitive ingress material was not normalized")
	}

	request.Close()
	if request.Environment != "" ||
		request.Subscriptions != nil ||
		request.PolicyControl != nil ||
		!allZero(request.APNSToken[:]) ||
		!allZero(request.RequestHash[:]) {
		t.Fatal("Close did not erase request-owned sensitive state")
	}
}

func TestDecodeReplaceAcceptsMaximumSubscriptionsWithinDeadline(
	t *testing.T,
) {
	positive := readPositive(t)
	fixture := maximumReplacementObject(
		t,
		positive,
		maximumReplacementSubscriptions,
	)
	raw, err := a9trust.Canonicalize(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(raw)) > MaxRequestBodyBytes {
		t.Fatalf(
			"maximum replacement body = %d bytes, limit = %d",
			len(raw),
			MaxRequestBodyBytes,
		)
	}
	binder := &deadlineCountingBinder{
		delegate: publishedTopicBinder(t, positive),
	}
	now := wireTime(
		t,
		objectValue(
			t,
			objectValue(t, positive["assertion"])["value"],
		)["issued_at"],
	)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		maximumReplacementTestDeadline,
	)
	defer cancel()

	request, err := DecodeReplace(ctx, raw, "dev", binder, now)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	if ctx.Err() != nil {
		t.Fatalf("maximum replacement exceeded its deadline: %v", ctx.Err())
	}
	if len(request.Subscriptions) != maximumReplacementSubscriptions {
		t.Fatalf(
			"subscriptions = %d, want %d",
			len(request.Subscriptions),
			maximumReplacementSubscriptions,
		)
	}
	if binder.calls != maximumReplacementSubscriptions {
		t.Fatalf(
			"topic-binding calls = %d, want %d",
			binder.calls,
			maximumReplacementSubscriptions,
		)
	}
}

func TestDecodeReplaceFailsClosedOnCrossFieldAndCanonicalViolations(
	t *testing.T,
) {
	positive := readPositive(t)
	fixture := objectValue(
		t,
		objectValue(t, positive["subscription_replace"])["value"],
	)
	now := wireTime(
		t,
		objectValue(
			t,
			objectValue(t, positive["assertion"])["value"],
		)["issued_at"],
	)
	binder := publishedTopicBinder(t, positive)

	tests := map[string]func(map[string]any){
		"generation equation": func(object map[string]any) {
			object["subscription_generation"] = json.Number("2")
		},
		"wrong environment": func(object map[string]any) {
			object["environment"] = "production"
		},
		"transport topic mismatch": func(object map[string]any) {
			subscription := firstSubscription(t, object)
			subscription["transport_conversation_id"] =
				"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		"topic binding mismatch": func(object map[string]any) {
			subscription := firstSubscription(t, object)
			subscription["topic_binding"] =
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		"unsorted hmac periods": func(object map[string]any) {
			subscription := firstSubscription(t, object)
			first := objectValue(
				t,
				arrayValue(t, subscription["hmac_keys"])[0],
			)
			second := cloneObject(t, first)
			first["thirty_day_periods_since_epoch"] = json.Number("2")
			second["thirty_day_periods_since_epoch"] = json.Number("1")
			subscription["hmac_keys"] = []any{first, second}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			object := cloneObject(t, fixture)
			mutate(object)
			raw, err := a9trust.Canonicalize(object)
			if err != nil {
				t.Fatal(err)
			}
			request, err := DecodeReplace(
				context.Background(),
				raw,
				"dev",
				binder,
				now,
			)
			if request != nil {
				request.Close()
			}
			if !errors.Is(err, ErrInvalidReplace) {
				t.Fatalf("error = %v, want ErrInvalidReplace", err)
			}
		})
	}

	canonical, err := a9trust.Canonicalize(fixture)
	if err != nil {
		t.Fatal(err)
	}
	noncanonical := append([]byte(" "), canonical...)
	request, err := DecodeReplace(
		context.Background(),
		noncanonical,
		"dev",
		binder,
		now,
	)
	if request != nil {
		request.Close()
	}
	if !errors.Is(err, ErrInvalidReplace) {
		t.Fatalf("noncanonical error = %v", err)
	}
}

func TestDecodeReplaceRequiresCurrentTopicKeyProof(t *testing.T) {
	positive := readPositive(t)
	fixture := objectValue(
		t,
		objectValue(t, positive["subscription_replace"])["value"],
	)
	raw, err := a9trust.Canonicalize(fixture)
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeReplace(
		context.Background(),
		raw,
		"dev",
		fixtureBinder{keys: map[uint32][32]byte{}},
		time.Now().UTC(),
	)
	if request != nil {
		request.Close()
	}
	if !errors.Is(err, ErrInvalidReplace) {
		t.Fatalf("error = %v, want ErrInvalidReplace", err)
	}
}

func TestSubscriptionOrderingUsesDecodedTopicBindingThenBindingID(
	t *testing.T,
) {
	compareWithoutValueCopy := subscriptionAfter
	var first, second Subscription
	first.TopicBinding[31] = 1
	second.TopicBinding[31] = 2
	if !compareWithoutValueCopy(&first, &second) ||
		compareWithoutValueCopy(&second, &first) {
		t.Fatal("topic-binding ordering failed")
	}
	second.TopicBinding = first.TopicBinding
	first.BindingID[15] = 1
	second.BindingID[15] = 2
	if !compareWithoutValueCopy(&first, &second) ||
		compareWithoutValueCopy(&second, &first) ||
		compareWithoutValueCopy(&first, &first) ||
		compareWithoutValueCopy(nil, &first) ||
		compareWithoutValueCopy(&first, nil) {
		t.Fatal("binding-id tiebreak ordering failed")
	}
}

func readPositive(t *testing.T) map[string]any {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	raw, err := os.ReadFile(filepath.Join(
		root,
		"contracts",
		"xmtp_push",
		"a9_adapter",
		"v1",
		"vectors",
		"positive.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	value, err := a9trust.ParseStrictJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return objectValue(t, value)
}

func publishedTopicBinder(
	t *testing.T,
	positive map[string]any,
) fixtureBinder {
	t.Helper()
	keys := objectValue(t, positive["test_keys"])
	commitments := objectValue(t, positive["commitments"])
	epoch := uint32(integerValue(t, commitments["topic_key_epoch"]))
	key, err := a9trust.DecodeBase64URL(
		stringValue(t, keys["topic_hmac_key_base64url"]),
		32,
	)
	if err != nil {
		t.Fatal(err)
	}
	var fixed [32]byte
	copy(fixed[:], key)
	return fixtureBinder{keys: map[uint32][32]byte{epoch: fixed}}
}

type maximumSubscriptionItem struct {
	object       map[string]any
	topicBinding [32]byte
}

func maximumReplacementObject(
	t *testing.T,
	positive map[string]any,
	count int,
) map[string]any {
	t.Helper()
	if count < 0 || count > maximumReplacementSubscriptions {
		t.Fatalf("invalid maximum replacement count %d", count)
	}
	replacement := cloneObject(
		t,
		objectValue(
			t,
			objectValue(t, positive["subscription_replace"])["value"],
		),
	)
	template := firstSubscription(t, replacement)
	epoch := uint32(integerValue(t, template["topic_key_epoch"]))
	key, ok := publishedTopicBinder(t, positive).keys[epoch]
	if !ok {
		t.Fatalf("published TOPIC key epoch %d is absent", epoch)
	}

	entries := make([]maximumSubscriptionItem, count)
	seenBindings := make(map[[32]byte]bool, count)
	for index := range entries {
		subscription := cloneObject(t, template)
		var groupID [32]byte
		binary.BigEndian.PutUint32(
			groupID[len(groupID)-4:],
			uint32(index+1),
		)
		var topic [33]byte
		copy(topic[1:], groupID[:])
		binding, err := a9trust.TopicBinding(key[:], topic[:])
		if err != nil || len(binding) != len(entries[index].topicBinding) {
			t.Fatalf("topic binding %d: %v", index, err)
		}
		copy(entries[index].topicBinding[:], binding)
		if seenBindings[entries[index].topicBinding] {
			t.Fatalf("duplicate generated topic binding at %d", index)
		}
		seenBindings[entries[index].topicBinding] = true

		var bindingID [16]byte
		binary.BigEndian.PutUint32(
			bindingID[len(bindingID)-4:],
			uint32(index+1),
		)
		subscription["binding_id"] = a9trust.EncodeBase64URL(bindingID[:])
		subscription["transport_conversation_id"] = hexString(groupID[:])
		subscription["topic_base64url"] = a9trust.EncodeBase64URL(topic[:])
		subscription["topic_binding"] = a9trust.EncodeBase64URL(binding)
		entries[index].object = subscription
	}
	sort.Slice(entries, func(left, right int) bool {
		return bytes.Compare(
			entries[left].topicBinding[:],
			entries[right].topicBinding[:],
		) < 0
	})
	subscriptions := make([]any, len(entries))
	for index := range entries {
		subscriptions[index] = entries[index].object
	}
	replacement["subscriptions"] = subscriptions
	return replacement
}

func firstSubscription(
	t *testing.T,
	object map[string]any,
) map[string]any {
	t.Helper()
	return objectValue(t, arrayValue(t, object["subscriptions"])[0])
}

func cloneObject(t *testing.T, object map[string]any) map[string]any {
	t.Helper()
	canonical, err := a9trust.Canonicalize(object)
	if err != nil {
		t.Fatal(err)
	}
	value, err := a9trust.ParseStrictJSON(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return objectValue(t, value)
}

func objectValue(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("got %T, want object", value)
	}
	return object
}

func arrayValue(t *testing.T, value any) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("got %T, want array", value)
	}
	return array
}

func stringValue(t *testing.T, value any) string {
	t.Helper()
	result, ok := value.(string)
	if !ok {
		t.Fatalf("got %T, want string", value)
	}
	return result
}

func integerValue(t *testing.T, value any) uint64 {
	t.Helper()
	number, ok := value.(json.Number)
	if !ok {
		t.Fatalf("got %T, want json.Number", value)
	}
	parsed, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func wireTime(t *testing.T, value any) time.Time {
	t.Helper()
	parsed, err := time.Parse(
		"2006-01-02T15:04:05.000Z",
		stringValue(t, value),
	)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func allZero(value []byte) bool {
	return bytes.Equal(value, make([]byte, len(value)))
}

func hexString(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = digits[item>>4]
		result[index*2+1] = digits[item&0x0f]
	}
	return string(result)
}
