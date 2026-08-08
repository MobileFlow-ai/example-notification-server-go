package a9schema

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var (
	assertionFields = []string{
		"protocol", "schema_version", "audience", "purpose", "environment",
		"binding_id", "installation_binding_id", "lease_id", "binding_version",
		"stream_sequence", "tuple_commitment", "tuple_commitment_key_id",
		"roster_commitment", "roster_commitment_key_id", "topic_binding",
		"topic_key_epoch", "conversation_generation", "roster_version", "state",
		"issued_at", "expires_at", "signing_key_id", "signature_algorithm",
		"signature_base64url",
	}
	controlFields = []string{
		"protocol", "schema_version", "audience", "environment",
		"idempotency_key", "installation_binding_id", "sequencer_epoch",
		"stream_sequence", "expected_previous_sequence", "binding_id",
		"binding_version", "expected_binding_version", "action", "assertion",
		"assertion_hash", "reason_code", "issued_at", "expires_at",
		"signing_key_id", "signature_algorithm", "signature_base64url",
	}
	keysetFields = []string{
		"protocol", "schema_version", "environment", "keyset_sequence",
		"issued_at", "expires_at", "keys", "commitment_keys",
		"root_signing_key_id", "root_signature_algorithm",
		"root_signature_base64url",
	}
	publicKeyFields = []string{
		"key_id", "use", "public_key_base64url", "not_before", "not_after",
		"state",
	}
	commitmentKeyFields = []string{
		"purpose", "key_id", "topic_key_epoch", "not_before", "not_after",
	}
	resultFields = []string{
		"protocol", "schema_version", "environment",
		"installation_binding_id", "sequencer_epoch", "subscription_generation",
		"state", "outcome", "accepted_stream_sequence", "idempotent_replay",
	}
	subscriptionsReplaceFields = []string{
		"protocol", "schema_version", "environment", "installation_binding_id",
		"sequencer_epoch", "subscription_generation",
		"expected_subscription_generation", "idempotency_key",
		"legacy_installation_id", "account_incarnation_id",
		"apns_token_base64url", "payload_schema", "policy_control_base64url",
		"subscriptions",
	}
	subscriptionFields = []string{
		"binding_id", "binding_version", "assertion_hash", "topic_binding",
		"topic_key_epoch", "route_key_epoch", "topic_base64url",
		"transport_conversation_id", "route_key_base64url", "hmac_keys",
		"receive_capability_base64url",
	}
	hmacKeyFields = []string{
		"thirty_day_periods_since_epoch", "key_base64url",
	}
	watermarkFields = []string{
		"protocol", "schema_version", "audience", "environment",
		"installation_binding_id", "sequencer_epoch", "watermark_sequence",
		"committed_through_stream_sequence", "status", "uncertainty_reason",
		"issued_at", "expires_at", "signing_key_id", "signature_algorithm",
		"signature_base64url",
	}
)

// Decode strictly parses raw and validates it against one closed A9 v1 schema.
func Decode(kind Kind, raw []byte) (Object, error) {
	value, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := Validate(kind, value); err != nil {
		return nil, err
	}
	return value.(Object), nil
}

// Validate applies a closed A9 v1 schema to a value returned by Parse.
func Validate(kind Kind, value any) error {
	switch kind {
	case AssertionKind:
		return validateAssertion(value, "$")
	case ControlEventKind:
		return validateControl(value, "$")
	case KeysetKind:
		return validateKeyset(value, "$")
	case ResultKind:
		return validateResult(value, "$")
	case SubscriptionsReplaceKind:
		return validateSubscriptionsReplace(value, "$")
	case WatermarkKind:
		return validateWatermark(value, "$")
	default:
		return failure(ReasonFieldDomain, "$")
	}
}

func validateAssertion(value any, path string) error {
	object, err := closedObject(value, path, assertionFields)
	if err != nil {
		return err
	}
	if err := fixedString(object, "protocol", "hytch.a9-bridge-assertion", path, ReasonFieldDomain); err != nil {
		return err
	}
	if err := fixedInteger(object, "schema_version", 1, path); err != nil {
		return err
	}
	if err := fixedString(object, "audience", "hytch.xmtp-push-bridge.a9-control", path, ReasonWrongAudience); err != nil {
		return err
	}
	purpose, err := stringField(object, "purpose", path)
	if err != nil {
		return err
	}
	if purpose != "conversation_message_push" {
		if strings.Contains(strings.ToLower(purpose), "welcome") {
			return failure(ReasonWelcomeClosed, objectPath(path, "purpose"))
		}
		return failure(ReasonFieldDomain, objectPath(path, "purpose"))
	}
	if err := environmentField(object, "environment", path); err != nil {
		return err
	}
	for _, field := range []string{"binding_id", "installation_binding_id", "lease_id"} {
		if _, err := base64URLField(object, field, path, 16, ReasonNoncanonicalBase64URL); err != nil {
			return err
		}
	}
	for _, field := range []string{"binding_version", "stream_sequence"} {
		if _, err := integerField(object, field, path, 1, maxSafeInteger); err != nil {
			return err
		}
	}
	for _, field := range []string{"tuple_commitment", "roster_commitment", "topic_binding"} {
		if _, err := base64URLField(object, field, path, 32, ReasonNoncanonicalBase64URL); err != nil {
			return err
		}
	}
	for _, field := range []string{"tuple_commitment_key_id", "roster_commitment_key_id"} {
		if err := keyIDField(object, field, path, "hmac-sha256:"); err != nil {
			return err
		}
	}
	if _, err := integerField(object, "topic_key_epoch", path, 1, 4294967295); err != nil {
		return err
	}
	for _, field := range []string{"conversation_generation", "roster_version"} {
		if _, err := integerField(object, field, path, 1, 2147483647); err != nil {
			return err
		}
	}
	if err := fixedString(object, "state", "ACTIVE", path, ReasonFieldDomain); err != nil {
		return err
	}
	for _, field := range []string{"issued_at", "expires_at"} {
		if err := timestampField(object, field, path); err != nil {
			return err
		}
	}
	if err := keyIDField(object, "signing_key_id", path, "ed25519-sha256:"); err != nil {
		return err
	}
	if err := fixedString(object, "signature_algorithm", "Ed25519", path, ReasonFieldDomain); err != nil {
		return err
	}
	_, err = base64URLField(object, "signature_base64url", path, 64, ReasonNoncanonicalBase64URL)
	return err
}

func validateControl(value any, path string) error {
	object, err := closedObject(value, path, controlFields)
	if err != nil {
		return err
	}
	if err := fixedString(object, "protocol", "hytch.a9-bridge-control", path, ReasonFieldDomain); err != nil {
		return err
	}
	if err := fixedInteger(object, "schema_version", 1, path); err != nil {
		return err
	}
	if err := fixedString(object, "audience", "hytch.xmtp-push-bridge.a9-control", path, ReasonWrongAudience); err != nil {
		return err
	}
	if err := environmentField(object, "environment", path); err != nil {
		return err
	}
	if err := uuidField(object, "idempotency_key", path); err != nil {
		return err
	}
	for _, field := range []string{"installation_binding_id", "sequencer_epoch", "binding_id"} {
		if _, err := base64URLField(object, field, path, 16, ReasonNoncanonicalBase64URL); err != nil {
			return err
		}
	}
	for _, field := range []string{"stream_sequence", "binding_version"} {
		if _, err := integerField(object, field, path, 1, maxSafeInteger); err != nil {
			return err
		}
	}
	for _, field := range []string{"expected_previous_sequence", "expected_binding_version"} {
		if _, err := integerField(object, field, path, 0, maxSafeInteger); err != nil {
			return err
		}
	}
	action, err := enumStringField(object, "action", path, "UPSERT", "REVOKE")
	if err != nil {
		return err
	}
	if _, err := base64URLField(object, "assertion_hash", path, 32, ReasonNoncanonicalBase64URL); err != nil {
		return err
	}
	if action == "UPSERT" {
		if object["assertion"] == nil {
			return failure(ReasonFieldDomain, objectPath(path, "assertion"))
		}
		if err := validateAssertion(object["assertion"], objectPath(path, "assertion")); err != nil {
			return err
		}
		if object["reason_code"] != nil {
			return failure(ReasonFieldDomain, objectPath(path, "reason_code"))
		}
	} else {
		if object["assertion"] != nil {
			return failure(ReasonFieldDomain, objectPath(path, "assertion"))
		}
		if _, err := enumStringField(
			object,
			"reason_code",
			path,
			"authority_revoked",
			"authority_expired",
			"authority_replaced",
		); err != nil {
			return err
		}
	}
	for _, field := range []string{"issued_at", "expires_at"} {
		if err := timestampField(object, field, path); err != nil {
			return err
		}
	}
	if err := keyIDField(object, "signing_key_id", path, "ed25519-sha256:"); err != nil {
		return err
	}
	if err := fixedString(object, "signature_algorithm", "Ed25519", path, ReasonFieldDomain); err != nil {
		return err
	}
	_, err = base64URLField(object, "signature_base64url", path, 64, ReasonNoncanonicalBase64URL)
	return err
}

func validateKeyset(value any, path string) error {
	object, err := closedObject(value, path, keysetFields)
	if err != nil {
		return err
	}
	if err := fixedString(object, "protocol", "hytch.a9-bridge-keyset", path, ReasonFieldDomain); err != nil {
		return err
	}
	if err := fixedInteger(object, "schema_version", 1, path); err != nil {
		return err
	}
	if err := environmentField(object, "environment", path); err != nil {
		return err
	}
	if _, err := integerField(object, "keyset_sequence", path, 1, maxSafeInteger); err != nil {
		return err
	}
	for _, field := range []string{"issued_at", "expires_at"} {
		if err := timestampField(object, field, path); err != nil {
			return err
		}
	}

	keys, err := arrayField(object, "keys", path, 2, 4)
	if err != nil {
		return err
	}
	if err := uniqueItems(keys, objectPath(path, "keys"), ReasonFieldDomain); err != nil {
		return err
	}
	signCounts := map[string]int{"A9_CONTROL": 0, "SERVICE_AUTH": 0}
	for index, entry := range keys {
		entryPath := arrayPath(objectPath(path, "keys"), index)
		key, err := closedObject(entry, entryPath, publicKeyFields)
		if err != nil {
			return err
		}
		if err := keyIDField(key, "key_id", entryPath, "ed25519-sha256:"); err != nil {
			return err
		}
		use, err := enumStringField(key, "use", entryPath, "A9_CONTROL", "SERVICE_AUTH")
		if err != nil {
			return err
		}
		if _, err := base64URLField(key, "public_key_base64url", entryPath, 32, ReasonNoncanonicalBase64URL); err != nil {
			return err
		}
		for _, field := range []string{"not_before", "not_after"} {
			if err := timestampField(key, field, entryPath); err != nil {
				return err
			}
		}
		state, err := enumStringField(key, "state", entryPath, "SIGN", "VERIFY_ONLY")
		if err != nil {
			return err
		}
		if state == "SIGN" {
			signCounts[use]++
		}
	}
	for _, count := range signCounts {
		if count != 1 {
			return failure(ReasonFieldDomain, objectPath(path, "keys"))
		}
	}

	commitmentKeys, err := arrayField(object, "commitment_keys", path, 3, 6)
	if err != nil {
		return err
	}
	if err := uniqueItems(commitmentKeys, objectPath(path, "commitment_keys"), ReasonFieldDomain); err != nil {
		return err
	}
	purposeCounts := map[string]int{"ROSTER": 0, "TUPLE": 0, "TOPIC": 0}
	for index, entry := range commitmentKeys {
		entryPath := arrayPath(objectPath(path, "commitment_keys"), index)
		key, err := closedObject(entry, entryPath, commitmentKeyFields)
		if err != nil {
			return err
		}
		purpose, err := enumStringField(key, "purpose", entryPath, "ROSTER", "TUPLE", "TOPIC")
		if err != nil {
			return err
		}
		purposeCounts[purpose]++
		if err := keyIDField(key, "key_id", entryPath, "hmac-sha256:"); err != nil {
			return err
		}
		if purpose == "TOPIC" {
			if _, err := integerField(key, "topic_key_epoch", entryPath, 1, 4294967295); err != nil {
				return err
			}
		} else if key["topic_key_epoch"] != nil {
			return failure(ReasonFieldDomain, objectPath(entryPath, "topic_key_epoch"))
		}
		for _, field := range []string{"not_before", "not_after"} {
			if err := timestampField(key, field, entryPath); err != nil {
				return err
			}
		}
	}
	for _, count := range purposeCounts {
		if count < 1 || count > 2 {
			return failure(ReasonFieldDomain, objectPath(path, "commitment_keys"))
		}
	}

	if err := keyIDField(object, "root_signing_key_id", path, "ed25519-sha256:"); err != nil {
		return err
	}
	if err := fixedString(object, "root_signature_algorithm", "Ed25519", path, ReasonFieldDomain); err != nil {
		return err
	}
	_, err = base64URLField(object, "root_signature_base64url", path, 64, ReasonNoncanonicalBase64URL)
	return err
}

func validateResult(value any, path string) error {
	object, err := closedObject(value, path, resultFields)
	if err != nil {
		return err
	}
	if err := fixedString(object, "protocol", "hytch.a9-vault-cas-result", path, ReasonFieldDomain); err != nil {
		return err
	}
	if err := fixedInteger(object, "schema_version", 1, path); err != nil {
		return err
	}
	if err := environmentField(object, "environment", path); err != nil {
		return err
	}
	for _, field := range []string{"installation_binding_id", "sequencer_epoch"} {
		if _, err := base64URLField(object, field, path, 16, ReasonNoncanonicalBase64URL); err != nil {
			return err
		}
	}
	for _, field := range []string{"subscription_generation", "accepted_stream_sequence"} {
		if _, err := integerField(object, field, path, 0, maxSafeInteger); err != nil {
			return err
		}
	}
	if _, err := enumStringField(object, "state", path, "ACTIVE", "REVOKED", "UNCERTAIN"); err != nil {
		return err
	}
	outcome, err := enumStringField(
		object,
		"outcome",
		path,
		"APPLIED",
		"REPLAY",
		"STALE",
		"GAP",
		"CONFLICT",
		"INCONCLUSIVE",
	)
	if err != nil {
		return err
	}
	replay, ok := object["idempotent_replay"].(bool)
	if !ok || replay != (outcome == "REPLAY") {
		return failure(ReasonFieldDomain, objectPath(path, "idempotent_replay"))
	}
	return nil
}

func validateSubscriptionsReplace(value any, path string) error {
	object, err := closedObject(value, path, subscriptionsReplaceFields)
	if err != nil {
		return err
	}
	if err := fixedString(object, "protocol", "hytch.a9-subscription-replace", path, ReasonFieldDomain); err != nil {
		return err
	}
	if err := fixedInteger(object, "schema_version", 1, path); err != nil {
		return err
	}
	if err := environmentField(object, "environment", path); err != nil {
		return err
	}
	for _, field := range []string{"installation_binding_id", "sequencer_epoch"} {
		if _, err := base64URLField(object, field, path, 16, ReasonNoncanonicalBase64URL); err != nil {
			return err
		}
	}
	if _, err := integerField(object, "subscription_generation", path, 1, maxSafeInteger); err != nil {
		return err
	}
	if _, err := integerField(object, "expected_subscription_generation", path, 0, maxSafeInteger); err != nil {
		return err
	}
	if err := uuidField(object, "idempotency_key", path); err != nil {
		return err
	}
	if err := lowerHexField(object, "legacy_installation_id", path, 64, ReasonFieldDomain); err != nil {
		return err
	}
	if err := uuidField(object, "account_incarnation_id", path); err != nil {
		return err
	}
	if _, err := base64URLField(object, "apns_token_base64url", path, 32, ReasonNoncanonicalBase64URL); err != nil {
		return err
	}
	if err := fixedString(object, "payload_schema", "hytch_push_wrapper_v1", path, ReasonFieldDomain); err != nil {
		return err
	}
	if _, err := boundedBase64URLField(object, "policy_control_base64url", path); err != nil {
		return err
	}

	subscriptions, err := arrayField(object, "subscriptions", path, 0, 2048)
	if err != nil {
		return err
	}
	if err := uniqueCanonicalItems(
		subscriptions,
		objectPath(path, "subscriptions"),
		ReasonDuplicateSubscription,
	); err != nil {
		return err
	}
	for index, entry := range subscriptions {
		entryPath := arrayPath(objectPath(path, "subscriptions"), index)
		subscription, err := closedObject(entry, entryPath, subscriptionFields)
		if err != nil {
			return err
		}
		if _, err := base64URLField(subscription, "binding_id", entryPath, 16, ReasonNoncanonicalBase64URL); err != nil {
			return err
		}
		if _, err := integerField(subscription, "binding_version", entryPath, 1, maxSafeInteger); err != nil {
			return err
		}
		for _, field := range []string{"assertion_hash", "topic_binding", "route_key_base64url"} {
			if _, err := base64URLField(subscription, field, entryPath, 32, ReasonNoncanonicalBase64URL); err != nil {
				return err
			}
		}
		for _, field := range []string{"topic_key_epoch", "route_key_epoch"} {
			if _, err := integerField(subscription, field, entryPath, 1, 4294967295); err != nil {
				return err
			}
		}
		topicBytes, err := base64URLField(subscription, "topic_base64url", entryPath, 33, ReasonTopicResolver)
		if err != nil {
			return err
		}
		if topicBytes[0] != 0 {
			return failure(ReasonWelcomeClosed, objectPath(entryPath, "topic_base64url"))
		}
		if err := lowerHexField(
			subscription,
			"transport_conversation_id",
			entryPath,
			64,
			ReasonTopicResolver,
		); err != nil {
			return err
		}

		hmacKeys, err := arrayField(subscription, "hmac_keys", entryPath, 1, 3)
		if err != nil {
			return err
		}
		if err := uniqueItems(hmacKeys, objectPath(entryPath, "hmac_keys"), ReasonFieldDomain); err != nil {
			return err
		}
		for hmacIndex, hmacEntry := range hmacKeys {
			hmacPath := arrayPath(objectPath(entryPath, "hmac_keys"), hmacIndex)
			hmacKey, err := closedObject(hmacEntry, hmacPath, hmacKeyFields)
			if err != nil {
				return err
			}
			if _, err := integerField(
				hmacKey,
				"thirty_day_periods_since_epoch",
				hmacPath,
				0,
				2147483647,
			); err != nil {
				return err
			}
			if _, err := base64URLField(hmacKey, "key_base64url", hmacPath, 32, ReasonNoncanonicalBase64URL); err != nil {
				return err
			}
		}
		if _, err := boundedBase64URLField(subscription, "receive_capability_base64url", entryPath); err != nil {
			return err
		}
	}
	return nil
}

func validateWatermark(value any, path string) error {
	object, err := closedObject(value, path, watermarkFields)
	if err != nil {
		return err
	}
	if err := fixedString(object, "protocol", "hytch.a9-control-watermark", path, ReasonFieldDomain); err != nil {
		return err
	}
	if err := fixedInteger(object, "schema_version", 1, path); err != nil {
		return err
	}
	if err := fixedString(object, "audience", "hytch.xmtp-push-bridge.a9-control", path, ReasonWrongAudience); err != nil {
		return err
	}
	if err := environmentField(object, "environment", path); err != nil {
		return err
	}
	for _, field := range []string{"installation_binding_id", "sequencer_epoch"} {
		if _, err := base64URLField(object, field, path, 16, ReasonNoncanonicalBase64URL); err != nil {
			return err
		}
	}
	if _, err := integerField(object, "watermark_sequence", path, 1, maxSafeInteger); err != nil {
		return err
	}
	if _, err := integerField(object, "committed_through_stream_sequence", path, 0, maxSafeInteger); err != nil {
		return err
	}
	status, err := enumStringField(object, "status", path, "CURRENT", "UNCERTAIN")
	if err != nil {
		return err
	}
	if status == "CURRENT" {
		if err := fixedString(object, "uncertainty_reason", "NONE", path, ReasonFieldDomain); err != nil {
			return err
		}
	} else if _, err := enumStringField(
		object,
		"uncertainty_reason",
		path,
		"SOURCE_UNAVAILABLE",
		"OUTBOX_GAP",
		"REPLICA_AMBIGUITY",
		"OVERFLOW",
		"CLOCK_UNCERTAIN",
	); err != nil {
		return err
	}
	for _, field := range []string{"issued_at", "expires_at"} {
		if err := timestampField(object, field, path); err != nil {
			return err
		}
	}
	if err := keyIDField(object, "signing_key_id", path, "ed25519-sha256:"); err != nil {
		return err
	}
	if err := fixedString(object, "signature_algorithm", "Ed25519", path, ReasonFieldDomain); err != nil {
		return err
	}
	_, err = base64URLField(object, "signature_base64url", path, 64, ReasonNoncanonicalBase64URL)
	return err
}

func closedObject(value any, path string, required []string) (Object, error) {
	object, ok := value.(Object)
	if !ok {
		return nil, failure(ReasonFieldDomain, path)
	}
	allowed := make(map[string]struct{}, len(required))
	for _, field := range required {
		allowed[field] = struct{}{}
	}
	for field := range object {
		if _, ok := allowed[field]; ok {
			continue
		}
		if field == "roster_digest" {
			return nil, failure(ReasonUnknownFieldRawRosterForbidden, objectPath(path, "<forbidden>"))
		}
		return nil, failure(ReasonFieldDomain, objectPath(path, "<unknown>"))
	}
	for _, field := range required {
		if _, ok := object[field]; !ok {
			return nil, failure(ReasonFieldDomain, objectPath(path, field))
		}
	}
	return object, nil
}

func stringField(object Object, field, path string) (string, error) {
	value, ok := object[field].(string)
	if !ok {
		return "", failure(ReasonFieldDomain, objectPath(path, field))
	}
	return value, nil
}

func fixedString(
	object Object,
	field string,
	expected string,
	path string,
	reason Reason,
) error {
	value, err := stringField(object, field, path)
	if err != nil {
		return err
	}
	if value != expected {
		return failure(reason, objectPath(path, field))
	}
	return nil
}

func enumStringField(
	object Object,
	field string,
	path string,
	allowed ...string,
) (string, error) {
	value, err := stringField(object, field, path)
	if err != nil {
		return "", err
	}
	for _, candidate := range allowed {
		if value == candidate {
			return value, nil
		}
	}
	return "", failure(ReasonFieldDomain, objectPath(path, field))
}

func fixedInteger(object Object, field string, expected int64, path string) error {
	value, err := integerField(object, field, path, expected, expected)
	if err != nil {
		return err
	}
	if value != expected {
		return failure(ReasonFieldDomain, objectPath(path, field))
	}
	return nil
}

func integerField(
	object Object,
	field string,
	path string,
	minimum int64,
	maximum int64,
) (int64, error) {
	number, ok := object[field].(json.Number)
	if !ok {
		return 0, failure(ReasonFieldDomain, objectPath(path, field))
	}
	value, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, failure(ReasonIntegerRange, objectPath(path, field))
	}
	return value, nil
}

func environmentField(object Object, field, path string) error {
	_, err := enumStringField(object, field, path, "dev", "production")
	return err
}

func base64URLField(
	object Object,
	field string,
	path string,
	byteLength int,
	reason Reason,
) ([]byte, error) {
	value, err := stringField(object, field, path)
	if err != nil {
		return nil, err
	}
	expectedLength := (byteLength*8 + 5) / 6
	if len(value) != expectedLength {
		return nil, failure(reason, objectPath(path, field))
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil ||
		len(decoded) != byteLength ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, failure(reason, objectPath(path, field))
	}
	return decoded, nil
}

func boundedBase64URLField(object Object, field, path string) ([]byte, error) {
	value, err := stringField(object, field, path)
	if err != nil {
		return nil, err
	}
	if len(value) < 2 || len(value) > 4096 {
		return nil, failure(ReasonNoncanonicalBase64URL, objectPath(path, field))
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, failure(ReasonNoncanonicalBase64URL, objectPath(path, field))
	}
	return decoded, nil
}

func uuidField(object Object, field, path string) error {
	value, err := stringField(object, field, path)
	if err != nil {
		return err
	}
	if len(value) != 36 {
		return failure(ReasonFieldDomain, objectPath(path, field))
	}
	for index := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value[index] != '-' {
				return failure(ReasonFieldDomain, objectPath(path, field))
			}
			continue
		}
		if !isLowerHex(value[index]) {
			return failure(ReasonFieldDomain, objectPath(path, field))
		}
	}
	return nil
}

func timestampField(object Object, field, path string) error {
	value, err := stringField(object, field, path)
	if err != nil {
		return err
	}
	const timestampLayout = "2006-01-02T15:04:05.000Z"
	if len(value) != len(timestampLayout) {
		return failure(ReasonNoncanonicalTime, objectPath(path, field))
	}
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || parsed.Format(timestampLayout) != value {
		return failure(ReasonNoncanonicalTime, objectPath(path, field))
	}
	return nil
}

func keyIDField(object Object, field, path, prefix string) error {
	value, err := stringField(object, field, path)
	if err != nil {
		return err
	}
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return failure(ReasonFieldDomain, objectPath(path, field))
	}
	for index := len(prefix); index < len(value); index++ {
		if !isLowerHex(value[index]) {
			return failure(ReasonFieldDomain, objectPath(path, field))
		}
	}
	return nil
}

func lowerHexField(
	object Object,
	field string,
	path string,
	length int,
	reason Reason,
) error {
	value, err := stringField(object, field, path)
	if err != nil {
		return err
	}
	if len(value) != length {
		return failure(reason, objectPath(path, field))
	}
	for index := range value {
		if !isLowerHex(value[index]) {
			return failure(reason, objectPath(path, field))
		}
	}
	return nil
}

func isLowerHex(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')
}

func arrayField(
	object Object,
	field string,
	path string,
	minimum int,
	maximum int,
) ([]any, error) {
	value, ok := object[field].([]any)
	if !ok || len(value) < minimum || len(value) > maximum {
		return nil, failure(ReasonFieldDomain, objectPath(path, field))
	}
	return value, nil
}

func uniqueItems(values []any, path string, reason Reason) error {
	for left := range values {
		for right := 0; right < left; right++ {
			if reflect.DeepEqual(values[left], values[right]) {
				return failure(reason, arrayPath(path, left))
			}
		}
	}
	return nil
}

// uniqueCanonicalItems preserves exact JSON-value equality without the
// quadratic pairwise scan used for the keyset's small fixed arrays. Values
// originate from Parse, so json.Marshal provides a deterministic, injective
// encoding for the supported null/bool/string/integer/array/object domain.
func uniqueCanonicalItems(values []any, path string, reason Reason) error {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		canonical, err := json.Marshal(value)
		if err != nil {
			return failure(ReasonFieldDomain, arrayPath(path, index))
		}
		key := string(canonical)
		if _, duplicate := seen[key]; duplicate {
			return failure(reason, arrayPath(path, index))
		}
		seen[key] = struct{}{}
	}
	return nil
}
