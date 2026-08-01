package a9trust

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestVerifyControlPublishedPositiveVector(t *testing.T) {
	corpus := loadCorpus(t)
	vector := mustObject(t, corpus.positive["control_upsert"])
	control := mustObject(t, vector["value"])
	keysetVector := mustObject(t, corpus.positive["keyset"])
	keyset := mustObject(t, keysetVector["value"])
	evaluationTime := mustWireTime(t, control["issued_at"])

	verified, verdict := VerifyControl(
		mustCanonical(t, control),
		ControlExpectations{
			Environment:    "dev",
			EvaluationTime: evaluationTime,
			Keyset:         keyset,
		},
	)
	assertVerdict(t, verdict, Eligible())

	if verified.Environment != "dev" ||
		verified.IdempotencyKey !=
			mustString(t, control["idempotency_key"]) ||
		verified.StreamSequence != 7 ||
		verified.ExpectedPreviousSequence != 6 ||
		verified.BindingVersion != 4 ||
		verified.ExpectedBindingVersion != 3 ||
		verified.Action != ControlActionUpsert ||
		verified.Reason != ControlReasonNone ||
		verified.Assertion == nil {
		t.Fatalf("unexpected verified control projection: %+v", verified)
	}
	assertFixedBytes(
		t,
		verified.InstallationBindingID[:],
		mustB64(t, control, "installation_binding_id", 16),
	)
	assertFixedBytes(
		t,
		verified.SequencerEpoch[:],
		mustB64(t, control, "sequencer_epoch", 16),
	)
	assertFixedBytes(
		t,
		verified.BindingID[:],
		mustB64(t, control, "binding_id", 16),
	)
	assertFixedBytes(
		t,
		verified.AssertionHash[:],
		mustB64(t, control, "assertion_hash", 32),
	)
	assertDigestHex(
		t,
		verified.SignedObjectHash,
		mustString(t, vector["signed_object_sha256"]),
	)
	assertDigestHex(
		t,
		verified.KeysetHash,
		mustString(t, keysetVector["signed_object_sha256"]),
	)
	if verified.KeysetSequence !=
		mustUint(t, keyset["keyset_sequence"]) {
		t.Fatalf(
			"keyset sequence = %d, want %d",
			verified.KeysetSequence,
			mustUint(t, keyset["keyset_sequence"]),
		)
	}

	assertionVector := mustObject(t, corpus.positive["assertion"])
	assertion := mustObject(t, assertionVector["value"])
	projection := verified.Assertion
	assertFixedBytes(
		t,
		projection.Hash[:],
		mustB64(
			t,
			assertionVector,
			"assertion_hash_base64url",
			32,
		),
	)
	assertFixedBytes(
		t,
		projection.TopicBinding[:],
		mustB64(t, assertion, "topic_binding", 32),
	)
	assertFixedBytes(
		t,
		projection.RosterCommitment[:],
		mustB64(t, assertion, "roster_commitment", 32),
	)
	assertFixedBytes(
		t,
		projection.TupleCommitment[:],
		mustB64(t, assertion, "tuple_commitment", 32),
	)
	if projection.StreamSequence != verified.StreamSequence ||
		projection.BindingVersion != verified.BindingVersion ||
		projection.TopicKeyEpoch != 688 ||
		projection.ConversationGeneration != 3 ||
		projection.RosterVersion != 9 ||
		projection.IssuedAt != evaluationTime ||
		projection.KeysetHash != verified.KeysetHash {
		t.Fatalf(
			"unexpected verified assertion projection: %+v",
			*projection,
		)
	}
}

func TestVerifyControlPublishedNegativeVectors(t *testing.T) {
	corpus := loadCorpus(t)
	base := mustObject(
		t,
		mustObject(t, corpus.positive["control_upsert"])["value"],
	)
	keyset := mustObject(
		t,
		mustObject(t, corpus.positive["keyset"])["value"],
	)
	keys := mustObject(t, corpus.positive["test_keys"])
	expectations := ControlExpectations{
		Environment:    "dev",
		EvaluationTime: mustWireTime(t, base["issued_at"]),
		Keyset:         keyset,
	}

	t.Run("control_upsert_shape_mismatch", func(t *testing.T) {
		vector := corpus.negatives["control_upsert_shape_mismatch"]
		mutated := cloneViaJCS(t, base)
		applyVectorPatch(t, mutated, mustObject(t, vector["mutation"]))
		_, verdict := VerifyControl(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVectorVerdict(t, vector, verdict)
	})

	t.Run("duplicate_json_key", func(t *testing.T) {
		vector := corpus.negatives["duplicate_json_key"]
		raw := []byte(
			mustString(
				t,
				mustObject(t, vector["mutation"])["raw_utf8"],
			),
		)
		_, verdict := VerifyControl(raw, expectations)
		assertVectorVerdict(t, vector, verdict)
	})

	t.Run("expired_assertion", func(t *testing.T) {
		vector := corpus.negatives["expired_assertion"]
		expired := expectations
		expired.EvaluationTime = mustWireTime(
			t,
			mustObject(t, vector["mutation"])["evaluation_time"],
		)
		_, verdict := VerifyControl(
			mustCanonical(t, base),
			expired,
		)
		assertVectorVerdict(t, vector, verdict)
	})

	t.Run("assertion_signature_one_byte", func(t *testing.T) {
		vector := corpus.negatives["assertion_signature_one_byte"]
		mutated := cloneViaJCS(t, base)
		assertion := mustObject(t, mutated["assertion"])
		applyVectorPatch(t, assertion, mustObject(t, vector["mutation"]))
		resignControl(t, mutated, keys)
		_, verdict := VerifyControl(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVectorVerdict(t, vector, verdict)
	})

	t.Run("unknown_signer", func(t *testing.T) {
		vector := corpus.negatives["unknown_signer"]
		mutated := cloneViaJCS(t, base)
		assertion := mustObject(t, mutated["assertion"])
		applyVectorPatch(t, assertion, mustObject(t, vector["mutation"]))
		hash, err := AssertionHash(assertion)
		if err != nil {
			t.Fatal(err)
		}
		mutated["assertion_hash"] = hash
		resignControl(t, mutated, keys)
		_, verdict := VerifyControl(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVectorVerdict(t, vector, verdict)
	})
}

func TestVerifyControlEquationsOverflowAndAssertionPairing(t *testing.T) {
	corpus := loadCorpus(t)
	base := mustObject(
		t,
		mustObject(t, corpus.positive["control_upsert"])["value"],
	)
	keys := mustObject(t, corpus.positive["test_keys"])
	expectations := controlVectorExpectations(t, corpus, base)

	for name, mutation := range map[string]func(map[string]any){
		"stream equation": func(control map[string]any) {
			control["expected_previous_sequence"] = json.Number("5")
		},
		"binding equation": func(control map[string]any) {
			control["expected_binding_version"] = json.Number("2")
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneViaJCS(t, base)
			mutation(mutated)
			resignControl(t, mutated, keys)
			_, verdict := VerifyControl(
				mustCanonical(t, mutated),
				expectations,
			)
			assertVerdict(t, verdict, Invalid("FIELD_DOMAIN"))
		})
	}

	for name, field := range map[string]string{
		"stream overflow":  "expected_previous_sequence",
		"binding overflow": "expected_binding_version",
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneViaJCS(t, base)
			mutated[field] = json.Number("9007199254740991")
			resignControl(t, mutated, keys)
			_, verdict := VerifyControl(
				mustCanonical(t, mutated),
				expectations,
			)
			assertVerdict(t, verdict, Invalid("INTEGER_RANGE"))
		})
	}

	t.Run("safe-integer maximum is accepted without overflow", func(t *testing.T) {
		mutated := cloneViaJCS(t, base)
		assertion := mustObject(t, mutated["assertion"])
		assertion["stream_sequence"] =
			json.Number("9007199254740991")
		resignAssertion(t, assertion, keys)
		hash, err := AssertionHash(assertion)
		if err != nil {
			t.Fatal(err)
		}
		mutated["assertion_hash"] = hash
		mutated["stream_sequence"] =
			json.Number("9007199254740991")
		mutated["expected_previous_sequence"] =
			json.Number("9007199254740990")
		resignControl(t, mutated, keys)

		verified, verdict := VerifyControl(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVerdict(t, verdict, Eligible())
		if verified.StreamSequence != maxIJSONInteger ||
			verified.Assertion == nil ||
			verified.Assertion.StreamSequence != maxIJSONInteger {
			t.Fatalf(
				"maximum sequence was not preserved: %+v",
				verified,
			)
		}
	})

	t.Run("assertion hash mismatch", func(t *testing.T) {
		vector := corpus.negatives["cross_topic_assertion_hash"]
		mutated := cloneViaJCS(t, base)
		mutated["assertion_hash"] =
			mustObject(t, vector["mutation"])["value"]
		resignControl(t, mutated, keys)
		_, verdict := VerifyControl(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVectorVerdict(t, vector, verdict)
	})

	for name, field := range map[string]string{
		"binding ID":      "binding_id",
		"binding version": "binding_version",
		"stream sequence": "stream_sequence",
	} {
		t.Run("assertion "+name+" mismatch", func(t *testing.T) {
			mutated := cloneViaJCS(t, base)
			assertion := mustObject(t, mutated["assertion"])
			switch field {
			case "binding_id":
				assertion[field] = "ICEiIyQlJicoKSorLC0uLw"
			default:
				assertion[field] = json.Number("5")
			}
			resignAssertion(t, assertion, keys)
			hash, err := AssertionHash(assertion)
			if err != nil {
				t.Fatal(err)
			}
			mutated["assertion_hash"] = hash
			resignControl(t, mutated, keys)
			_, verdict := VerifyControl(
				mustCanonical(t, mutated),
				expectations,
			)
			assertVerdict(t, verdict, Invalid("FIELD_DOMAIN"))
		})
	}

	t.Run("installation mismatch", func(t *testing.T) {
		vector := corpus.negatives["cross_installation_assertion"]
		mutated := cloneViaJCS(t, base)
		assertion := mustObject(t, mutated["assertion"])
		assertion["installation_binding_id"] =
			"ICEiIyQlJicoKSorLC0uLw"
		resignAssertion(t, assertion, keys)
		hash, err := AssertionHash(assertion)
		if err != nil {
			t.Fatal(err)
		}
		mutated["assertion_hash"] = hash
		resignControl(t, mutated, keys)
		_, verdict := VerifyControl(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVectorVerdict(t, vector, verdict)
	})
}

func TestVerifyControlTimeBoundsAndDenialOnlyRevoke(t *testing.T) {
	corpus := loadCorpus(t)
	base := mustObject(
		t,
		mustObject(t, corpus.positive["control_upsert"])["value"],
	)
	keys := mustObject(t, corpus.positive["test_keys"])
	expectations := controlVectorExpectations(t, corpus, base)
	issued := mustWireTime(t, base["issued_at"])
	expires := mustWireTime(t, base["expires_at"])

	for name, test := range map[string]struct {
		at   time.Time
		want Verdict
	}{
		"issued inclusive": {
			at:   issued,
			want: Eligible(),
		},
		"one millisecond before expiry": {
			at:   expires.Add(-time.Millisecond),
			want: Eligible(),
		},
		"expiry exclusive": {
			at:   expires,
			want: Invalid("EXPIRED"),
		},
		"before issuance": {
			at:   issued.Add(-time.Millisecond),
			want: Inconclusive("CLOCK_UNCERTAIN"),
		},
		"missing evaluation clock": {
			at:   time.Time{},
			want: Inconclusive("CLOCK_UNCERTAIN"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := expectations
			input.EvaluationTime = test.at
			_, verdict := VerifyControl(
				mustCanonical(t, base),
				input,
			)
			assertVerdict(t, verdict, test.want)
		})
	}

	t.Run("validity interval over 30 seconds", func(t *testing.T) {
		mutated := cloneViaJCS(t, base)
		mutated["expires_at"] = issued.Add(
			30*time.Second + time.Millisecond,
		).Format("2006-01-02T15:04:05.000Z")
		resignControl(t, mutated, keys)
		_, verdict := VerifyControl(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVerdict(t, verdict, Invalid("FIELD_DOMAIN"))
	})

	t.Run("wire object must use exact JCS spelling", func(t *testing.T) {
		raw := append([]byte(" "), mustCanonical(t, base)...)
		_, verdict := VerifyControl(raw, expectations)
		assertVerdict(t, verdict, Invalid("FIELD_DOMAIN"))
	})

	for reason, expectedReason := range map[string]ControlReason{
		"authority_revoked":  ControlReasonAuthorityRevoked,
		"authority_expired":  ControlReasonAuthorityExpired,
		"authority_replaced": ControlReasonAuthorityReplaced,
	} {
		t.Run("denial-only "+reason, func(t *testing.T) {
			revoke := cloneViaJCS(t, base)
			revoke["action"] = "REVOKE"
			revoke["assertion"] = nil
			revoke["reason_code"] = reason
			resignControl(t, revoke, keys)

			verified, verdict := VerifyControl(
				mustCanonical(t, revoke),
				expectations,
			)
			assertVerdict(t, verdict, Eligible())
			if verified.Action != ControlActionRevoke ||
				verified.Reason != expectedReason ||
				verified.Assertion != nil {
				t.Fatalf(
					"REVOKE synthesized positive authority: %+v",
					verified,
				)
			}
		})
	}
}

func TestVerifyControlLeavesPublishedDurableStateToVault(t *testing.T) {
	corpus := loadCorpus(t)
	base := mustObject(
		t,
		mustObject(t, corpus.positive["control_upsert"])["value"],
	)
	expectations := controlVectorExpectations(t, corpus, base)

	for _, id := range []string{
		"control_gap_upsert",
		"control_sequence_regression",
		"idempotency_key_different_body",
		"upsert_after_tombstone",
	} {
		t.Run(id, func(t *testing.T) {
			if _, ok := corpus.negatives[id]; !ok {
				t.Fatalf("published negative %q is missing", id)
			}
			verified, verdict := VerifyControl(
				mustCanonical(t, base),
				expectations,
			)
			assertVerdict(t, verdict, Eligible())
			if verified.StreamSequence == 0 ||
				verified.SignedObjectHash == ([32]byte{}) {
				t.Fatalf(
					"vault projection is incomplete: %+v",
					verified,
				)
			}
		})
	}
}

func TestVerifiedControlTypesCannotRetainSignedBodies(t *testing.T) {
	for _, target := range []reflect.Type{
		reflect.TypeOf(VerifiedControl{}),
		reflect.TypeOf(VerifiedAssertion{}),
	} {
		for index := 0; index < target.NumField(); index++ {
			field := target.Field(index)
			switch field.Name {
			case "CanonicalSignedObject", "SignedBody", "Signature",
				"SignatureBase64URL", "Raw":
				t.Fatalf(
					"%s unexpectedly exposes %s",
					target.Name(),
					field.Name,
				)
			}
			if field.Type == reflect.TypeOf([]byte(nil)) {
				t.Fatalf(
					"%s.%s is an unbounded byte slice",
					target.Name(),
					field.Name,
				)
			}
		}
	}
}

func controlVectorExpectations(
	t *testing.T,
	corpus vectorCorpus,
	control map[string]any,
) ControlExpectations {
	t.Helper()
	return ControlExpectations{
		Environment:    "dev",
		EvaluationTime: mustWireTime(t, control["issued_at"]),
		Keyset: mustObject(
			t,
			mustObject(t, corpus.positive["keyset"])["value"],
		),
	}
}

func resignAssertion(
	t *testing.T,
	assertion map[string]any,
	keys map[string]any,
) {
	t.Helper()
	signature, err := SignObject(
		assertion,
		"signature_base64url",
		AssertionSignatureDomain,
		mustB64(
			t,
			keys,
			"control_private_seed_base64url",
			ed25519.SeedSize,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertion["signature_base64url"] = signature
}

func resignControl(
	t *testing.T,
	control map[string]any,
	keys map[string]any,
) {
	t.Helper()
	signature, err := SignObject(
		control,
		"signature_base64url",
		ControlSignatureDomain,
		mustB64(
			t,
			keys,
			"control_private_seed_base64url",
			ed25519.SeedSize,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	control["signature_base64url"] = signature
}

func assertDigestHex(t *testing.T, actual [32]byte, expected string) {
	t.Helper()
	decoded, err := hex.DecodeString(expected)
	if err != nil {
		t.Fatal(err)
	}
	assertFixedBytes(t, actual[:], decoded)
}

func assertFixedBytes(t *testing.T, actual, expected []byte) {
	t.Helper()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf(
			"bytes = %x, want %x",
			actual,
			expected,
		)
	}
}
