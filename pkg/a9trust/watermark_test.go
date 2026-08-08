package a9trust

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestVerifyWatermarkPublishedPositiveVector(t *testing.T) {
	corpus := loadCorpus(t)
	vector := mustObject(t, corpus.positive["watermark_current"])
	watermark := mustObject(t, vector["value"])
	keysetVector := mustObject(t, corpus.positive["keyset"])
	keyset := mustObject(t, keysetVector["value"])

	verified, verdict := VerifyWatermark(
		mustCanonical(t, watermark),
		WatermarkExpectations{
			Environment:    "dev",
			EvaluationTime: mustWireTime(t, watermark["issued_at"]),
			Keyset:         keyset,
		},
	)
	assertVerdict(t, verdict, Eligible())
	if verified.Environment != "dev" ||
		verified.WatermarkSequence != 41 ||
		verified.CommittedThroughStreamSequence != 7 ||
		verified.Status != WatermarkStatusCurrent ||
		verified.UncertaintyReason != WatermarkUncertaintyNone {
		t.Fatalf(
			"unexpected verified watermark projection: %+v",
			verified,
		)
	}
	assertFixedBytes(
		t,
		verified.InstallationBindingID[:],
		mustB64(t, watermark, "installation_binding_id", 16),
	)
	assertFixedBytes(
		t,
		verified.SequencerEpoch[:],
		mustB64(t, watermark, "sequencer_epoch", 16),
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
}

func TestVerifyWatermarkPublishedNegativeVectors(t *testing.T) {
	corpus := loadCorpus(t)
	base := mustObject(
		t,
		mustObject(t, corpus.positive["watermark_current"])["value"],
	)
	keys := mustObject(t, corpus.positive["test_keys"])
	expectations := watermarkVectorExpectations(t, corpus, base)

	t.Run("watermark_expired", func(t *testing.T) {
		vector := corpus.negatives["watermark_expired"]
		expired := expectations
		expired.EvaluationTime = mustWireTime(
			t,
			mustObject(t, vector["mutation"])["evaluation_time"],
		)
		_, verdict := VerifyWatermark(
			mustCanonical(t, base),
			expired,
		)
		assertVectorVerdict(t, vector, verdict)
	})

	t.Run("watermark_uncertain", func(t *testing.T) {
		vector := corpus.negatives["watermark_uncertain"]
		mutated := cloneViaJCS(t, base)
		mutation := mustObject(t, vector["mutation"])
		mutated["status"] = mutation["status"]
		mutated["uncertainty_reason"] =
			mutation["uncertainty_reason"]
		resignWatermark(t, mutated, keys, WatermarkSignatureDomain)

		verified, verdict := VerifyWatermark(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVectorVerdict(t, vector, verdict)
		if verified.Status != WatermarkStatusUncertain ||
			verified.UncertaintyReason !=
				WatermarkUncertaintySourceUnavailable ||
			verified.SignedObjectHash == ([32]byte{}) {
			t.Fatalf(
				"verified uncertainty was not retained: %+v",
				verified,
			)
		}
	})

	t.Run("unknown signer", func(t *testing.T) {
		vector := corpus.negatives["unknown_signer"]
		mutated := cloneViaJCS(t, base)
		mutated["signing_key_id"] =
			mustObject(t, vector["mutation"])["value"]
		resignWatermark(t, mutated, keys, WatermarkSignatureDomain)
		_, verdict := VerifyWatermark(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVectorVerdict(t, vector, verdict)
	})
}

func TestVerifyWatermarkStatusShapeSignatureAndReasons(t *testing.T) {
	corpus := loadCorpus(t)
	base := mustObject(
		t,
		mustObject(t, corpus.positive["watermark_current"])["value"],
	)
	keys := mustObject(t, corpus.positive["test_keys"])
	expectations := watermarkVectorExpectations(t, corpus, base)

	for name, mutation := range map[string]func(map[string]any){
		"CURRENT with uncertainty": func(watermark map[string]any) {
			watermark["uncertainty_reason"] = "OUTBOX_GAP"
		},
		"UNCERTAIN with NONE": func(watermark map[string]any) {
			watermark["status"] = "UNCERTAIN"
			watermark["uncertainty_reason"] = "NONE"
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneViaJCS(t, base)
			mutation(mutated)
			resignWatermark(
				t,
				mutated,
				keys,
				WatermarkSignatureDomain,
			)
			_, verdict := VerifyWatermark(
				mustCanonical(t, mutated),
				expectations,
			)
			assertVerdict(t, verdict, Invalid("FIELD_DOMAIN"))
		})
	}

	t.Run("wrong signature domain", func(t *testing.T) {
		mutated := cloneViaJCS(t, base)
		resignWatermark(t, mutated, keys, ControlSignatureDomain)
		_, verdict := VerifyWatermark(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVerdict(t, verdict, Invalid("BAD_SIGNATURE"))
	})

	t.Run("signature byte mutation", func(t *testing.T) {
		mutated := cloneViaJCS(t, base)
		signature := mustString(
			t,
			mutated["signature_base64url"],
		)
		if signature[0] == 'A' {
			mutated["signature_base64url"] = "B" + signature[1:]
		} else {
			mutated["signature_base64url"] = "A" + signature[1:]
		}
		_, verdict := VerifyWatermark(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVerdict(t, verdict, Invalid("BAD_SIGNATURE"))
	})

	for reason, expectedReason := range map[string]WatermarkUncertaintyReason{
		"SOURCE_UNAVAILABLE": WatermarkUncertaintySourceUnavailable,
		"OUTBOX_GAP":         WatermarkUncertaintyOutboxGap,
		"REPLICA_AMBIGUITY":  WatermarkUncertaintyReplicaAmbiguity,
		"OVERFLOW":           WatermarkUncertaintyOverflow,
		"CLOCK_UNCERTAIN":    WatermarkUncertaintyClock,
	} {
		t.Run(reason, func(t *testing.T) {
			mutated := cloneViaJCS(t, base)
			mutated["status"] = "UNCERTAIN"
			mutated["uncertainty_reason"] = reason
			resignWatermark(
				t,
				mutated,
				keys,
				WatermarkSignatureDomain,
			)
			verified, verdict := VerifyWatermark(
				mustCanonical(t, mutated),
				expectations,
			)
			assertVerdict(t, verdict, Inconclusive(reason))
			if verified.Status != WatermarkStatusUncertain ||
				verified.UncertaintyReason != expectedReason {
				t.Fatalf(
					"uncertainty projection = %+v",
					verified,
				)
			}
		})
	}
}

func TestVerifyWatermarkTimeAndIntegerBounds(t *testing.T) {
	corpus := loadCorpus(t)
	base := mustObject(
		t,
		mustObject(t, corpus.positive["watermark_current"])["value"],
	)
	keys := mustObject(t, corpus.positive["test_keys"])
	expectations := watermarkVectorExpectations(t, corpus, base)
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
			want: Inconclusive("WATERMARK_EXPIRED"),
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
			_, verdict := VerifyWatermark(
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
		resignWatermark(
			t,
			mutated,
			keys,
			WatermarkSignatureDomain,
		)
		_, verdict := VerifyWatermark(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVerdict(t, verdict, Invalid("FIELD_DOMAIN"))
	})

	t.Run("wire object must use exact JCS spelling", func(t *testing.T) {
		raw := append([]byte(" "), mustCanonical(t, base)...)
		_, verdict := VerifyWatermark(raw, expectations)
		assertVerdict(t, verdict, Invalid("FIELD_DOMAIN"))
	})

	t.Run("safe-integer maximum survives projection", func(t *testing.T) {
		mutated := cloneViaJCS(t, base)
		mutated["watermark_sequence"] =
			json.Number("9007199254740991")
		mutated["committed_through_stream_sequence"] =
			json.Number("9007199254740991")
		resignWatermark(
			t,
			mutated,
			keys,
			WatermarkSignatureDomain,
		)
		verified, verdict := VerifyWatermark(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVerdict(t, verdict, Eligible())
		if verified.WatermarkSequence != maxIJSONInteger ||
			verified.CommittedThroughStreamSequence !=
				maxIJSONInteger {
			t.Fatalf(
				"maximum integers were not preserved: %+v",
				verified,
			)
		}
	})
}

func TestVerifyWatermarkLeavesPublishedStreamStateToVault(t *testing.T) {
	corpus := loadCorpus(t)
	base := mustObject(
		t,
		mustObject(t, corpus.positive["watermark_current"])["value"],
	)
	keys := mustObject(t, corpus.positive["test_keys"])
	expectations := watermarkVectorExpectations(t, corpus, base)

	for _, id := range []string{
		"watermark_max_seen_with_gap",
		"watermark_sequence_rollback",
	} {
		t.Run(id, func(t *testing.T) {
			if _, ok := corpus.negatives[id]; !ok {
				t.Fatalf("published negative %q is missing", id)
			}
			_, verdict := VerifyWatermark(
				mustCanonical(t, base),
				expectations,
			)
			assertVerdict(t, verdict, Eligible())
		})
	}

	t.Run("sequencer_epoch_change", func(t *testing.T) {
		vector := corpus.negatives["sequencer_epoch_change"]
		mutated := cloneViaJCS(t, base)
		mutated["sequencer_epoch"] =
			mustObject(t, vector["mutation"])["sequencer_epoch"]
		resignWatermark(
			t,
			mutated,
			keys,
			WatermarkSignatureDomain,
		)
		verified, verdict := VerifyWatermark(
			mustCanonical(t, mutated),
			expectations,
		)
		assertVerdict(t, verdict, Eligible())
		if verified.SequencerEpoch ==
			mustFixed16(t, base, "sequencer_epoch") {
			t.Fatal("mutated epoch was not preserved for vault comparison")
		}
	})
}

func TestVerifiedWatermarkCannotRetainSignedBody(t *testing.T) {
	target := reflect.TypeOf(VerifiedWatermark{})
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

func watermarkVectorExpectations(
	t *testing.T,
	corpus vectorCorpus,
	watermark map[string]any,
) WatermarkExpectations {
	t.Helper()
	return WatermarkExpectations{
		Environment:    "dev",
		EvaluationTime: mustWireTime(t, watermark["issued_at"]),
		Keyset: mustObject(
			t,
			mustObject(t, corpus.positive["keyset"])["value"],
		),
	}
}

func resignWatermark(
	t *testing.T,
	watermark map[string]any,
	keys map[string]any,
	domain []byte,
) {
	t.Helper()
	signature, err := SignObject(
		watermark,
		"signature_base64url",
		domain,
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
	watermark["signature_base64url"] = signature
}

func mustFixed16(
	t *testing.T,
	object map[string]any,
	field string,
) [16]byte {
	t.Helper()
	decoded := mustB64(t, object, field, 16)
	var fixed [16]byte
	copy(fixed[:], decoded)
	return fixed
}
