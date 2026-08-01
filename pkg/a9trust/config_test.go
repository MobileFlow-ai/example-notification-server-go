package a9trust

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestRootPinAndTopicSecretsReconcileWithPublishedKeyset(t *testing.T) {
	corpus := loadCorpus(t)
	keys := mustObject(t, corpus.positive["test_keys"])
	keyset := mustObject(
		t,
		mustObject(t, corpus.positive["keyset"])["value"],
	)

	pin, err := ParseRootPin(
		mustString(t, keys["root_public_key_base64url"]),
		mustString(t, keys["root_signing_key_id"]),
	)
	if err != nil {
		t.Fatal(err)
	}
	if pin.KeyID != mustString(t, keyset["root_signing_key_id"]) {
		t.Fatal("root pin did not match the signed keyset")
	}

	set := mustTopicKeySet(t, keyset, keys)
	defer set.Close()
	assertVerdict(
		t,
		set.Reconcile(
			keyset,
			mustWireTime(t, keyset["issued_at"]),
		),
		Eligible(),
	)
	assertVerdict(t, ValidateTopicKeySchedule(keyset), Eligible())

	topic := mustB64(
		t,
		mustObject(t, corpus.positive["topic_resolver"]),
		"topic_bytes_base64url",
		33,
	)
	commitments := mustObject(t, corpus.positive["commitments"])
	epoch := uint32(mustUint(t, commitments["topic_key_epoch"]))
	issuedAt := mustWireTime(t, keyset["issued_at"])
	binding, verdict := set.BindingForEpoch(
		topic,
		epoch,
		issuedAt,
		issuedAt.Add(30*time.Second),
		false,
	)
	assertVerdict(t, verdict, Eligible())
	want, err := DecodeBase64URL(
		mustString(t, commitments["topic_binding_base64url"]),
		32,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !EqualBinding(binding, want) {
		t.Fatal("topic binding did not match the published vector")
	}
}

func TestTopicSecretPreviousEpochRequiresAcceptedUnexpiredAssertion(t *testing.T) {
	corpus := loadCorpus(t)
	keys := mustObject(t, corpus.positive["test_keys"])
	keyset := mustObject(
		t,
		mustObject(t, corpus.positive["keyset"])["value"],
	)
	set := mustTopicKeySet(t, keyset, keys)
	defer set.Close()

	topic := mustB64(
		t,
		mustObject(t, corpus.positive["topic_resolver"]),
		"topic_bytes_base64url",
		33,
	)
	boundary := mustObject(t, corpus.positive["topic_epoch_boundary"])
	oldAssertion := mustObject(
		t,
		mustObject(t, boundary["old_epoch_assertion"])["value"],
	)
	epoch := uint32(mustUint(t, oldAssertion["topic_key_epoch"]))
	expiresAt := mustWireTime(t, oldAssertion["expires_at"])
	afterBoundary := mustWireTime(t, boundary["boundary_at"]).
		Add(20 * time.Second)

	_, verdict := set.BindingForEpoch(
		topic,
		epoch,
		afterBoundary,
		expiresAt,
		false,
	)
	assertVerdict(t, verdict, Invalid("TOPIC_KEY_EPOCH"))

	binding, verdict := set.BindingForEpoch(
		topic,
		epoch,
		afterBoundary,
		expiresAt,
		true,
	)
	assertVerdict(t, verdict, Eligible())
	want, err := DecodeBase64URL(
		mustString(t, oldAssertion["topic_binding"]),
		32,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !EqualBinding(binding, want) {
		t.Fatal("previous-period binding did not match")
	}

	_, verdict = set.BindingForEpoch(
		topic,
		epoch,
		expiresAt,
		expiresAt,
		true,
	)
	assertVerdict(t, verdict, Invalid("TOPIC_KEY_EPOCH"))
}

func TestTopicSecretConfigurationFailsClosed(t *testing.T) {
	corpus := loadCorpus(t)
	keys := mustObject(t, corpus.positive["test_keys"])
	keyset := mustObject(
		t,
		mustObject(t, corpus.positive["keyset"])["value"],
	)
	valid := topicKeyConfig(t, keyset, keys)

	tests := map[string]string{
		"not array":        `{}`,
		"empty":            `[]`,
		"duplicate member": `[{"environment":"dev","environment":"dev"}]`,
		"unknown field": mutateTopicKeyConfig(
			t,
			valid,
			func(record map[string]any) { record["secret"] = "forbidden" },
		),
		"wrong environment": mutateTopicKeyConfig(
			t,
			valid,
			func(record map[string]any) { record["environment"] = "production" },
		),
		"wrong purpose": mutateTopicKeyConfig(
			t,
			valid,
			func(record map[string]any) { record["purpose"] = "ROSTER" },
		),
		"padded key": mutateTopicKeyConfig(
			t,
			valid,
			func(record map[string]any) {
				record["key_base64url"] =
					record["key_base64url"].(string) + "="
			},
		),
		"mismatched key id": mutateTopicKeyConfig(
			t,
			valid,
			func(record map[string]any) {
				record["key_id"] =
					"hmac-sha256:" +
						"0000000000000000000000000000000000000000000000000000000000000000"
			},
		),
		"noncanonical time": mutateTopicKeyConfig(
			t,
			valid,
			func(record map[string]any) {
				record["not_before"] = "2026-07-29T16:55:00Z"
			},
		),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			set, err := ParseTopicKeySetBytes([]byte(raw), "dev")
			if set != nil {
				set.Close()
			}
			if !errors.Is(err, ErrConfiguration) {
				t.Fatalf("error = %v, want ErrConfiguration", err)
			}
		})
	}

	set, err := ParseTopicKeySetBytes([]byte(valid), "dev")
	if err != nil {
		t.Fatal(err)
	}
	set.Close()
	if descriptors := set.Descriptors(); descriptors != nil {
		t.Fatalf("descriptors survived Close: %v", descriptors)
	}
}

func TestRootPinFailsClosed(t *testing.T) {
	corpus := loadCorpus(t)
	keys := mustObject(t, corpus.positive["test_keys"])
	publicKey := mustString(t, keys["root_public_key_base64url"])
	keyID := mustString(t, keys["root_signing_key_id"])
	for name, mutate := range map[string]func() (string, string){
		"padded": func() (string, string) {
			return publicKey + "=", keyID
		},
		"wrong length": func() (string, string) {
			return publicKey[1:], keyID
		},
		"wrong id": func() (string, string) {
			return publicKey,
				"ed25519-sha256:" +
					"0000000000000000000000000000000000000000000000000000000000000000"
		},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, id := mutate()
			_, err := ParseRootPin(encoded, id)
			if !errors.Is(err, ErrConfiguration) {
				t.Fatalf("error = %v, want ErrConfiguration", err)
			}
		})
	}
}

func mustTopicKeySet(
	t *testing.T,
	keyset map[string]any,
	keys map[string]any,
) *TopicKeySet {
	t.Helper()
	set, err := parseTopicKeySetBytes(
		[]byte(topicKeyConfig(t, keyset, keys)),
		"dev",
		func() time.Time {
			return mustWireTime(t, keyset["issued_at"])
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func topicKeyConfig(
	t *testing.T,
	keyset map[string]any,
	keys map[string]any,
) string {
	t.Helper()
	secretByID := map[string]string{
		mustString(t, keys["topic_hmac_key_id"]):      mustString(t, keys["topic_hmac_key_base64url"]),
		mustString(t, keys["next_topic_hmac_key_id"]): mustString(t, keys["next_topic_hmac_key_base64url"]),
	}
	var records []any
	for _, item := range mustArray(t, keyset["commitment_keys"]) {
		descriptor := mustObject(t, item)
		if mustString(t, descriptor["purpose"]) != "TOPIC" {
			continue
		}
		keyID := mustString(t, descriptor["key_id"])
		records = append(records, map[string]any{
			"environment":     "dev",
			"purpose":         "TOPIC",
			"key_id":          keyID,
			"topic_key_epoch": descriptor["topic_key_epoch"],
			"key_base64url":   secretByID[keyID],
			"not_before":      descriptor["not_before"],
			"not_after":       descriptor["not_after"],
		})
	}
	raw, err := Canonicalize(records)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func mutateTopicKeyConfig(
	t *testing.T,
	raw string,
	mutate func(map[string]any),
) string {
	t.Helper()
	var records []map[string]any
	if err := json.Unmarshal([]byte(raw), &records); err != nil {
		t.Fatal(err)
	}
	mutate(records[0])
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
