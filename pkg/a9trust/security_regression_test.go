package a9trust

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func TestValidateAssertionRequiresCurrentCommitmentMetadata(t *testing.T) {
	corpus := loadCorpus(t)
	baseAssertion := mustObject(
		t,
		mustObject(t, corpus.positive["assertion"])["value"],
	)
	baseKeyset := mustObject(
		t,
		mustObject(t, corpus.positive["keyset"])["value"],
	)
	keys := mustObject(t, corpus.positive["test_keys"])

	for _, field := range []string{
		"roster_commitment_key_id",
		"tuple_commitment_key_id",
	} {
		t.Run(field+" unknown after valid signature", func(t *testing.T) {
			assertion := cloneViaJCS(t, baseAssertion)
			assertion[field] = "hmac-sha256:" +
				"0000000000000000000000000000000000000000000000000000000000000000"
			resignAssertionForTrustTest(t, assertion, keys)

			verdict := ValidateAssertion(
				assertion,
				assertionExpectationsForTest(t, assertion, baseKeyset),
			)
			assertVerdict(t, verdict, Inconclusive("KEY_STATE"))
			if !verdict.RequiresKeysetUncertainty() {
				t.Fatal("unknown commitment metadata did not request a durable keyset latch")
			}
		})

		t.Run(field+" is not trusted before signature verification", func(t *testing.T) {
			assertion := cloneViaJCS(t, baseAssertion)
			assertion[field] = "hmac-sha256:" +
				"0000000000000000000000000000000000000000000000000000000000000000"

			verdict := ValidateAssertion(
				assertion,
				assertionExpectationsForTest(t, assertion, baseKeyset),
			)
			assertVerdict(t, verdict, Invalid("BAD_SIGNATURE"))
			if verdict.RequiresKeysetUncertainty() {
				t.Fatal("an unverified artifact requested a durable keyset latch")
			}
		})
	}
}

func TestValidateAssertionCommitmentMetadataCoversArtifactLifetime(t *testing.T) {
	corpus := loadCorpus(t)
	assertion := mustObject(
		t,
		mustObject(t, corpus.positive["assertion"])["value"],
	)
	baseKeyset := mustObject(
		t,
		mustObject(t, corpus.positive["keyset"])["value"],
	)
	keys := mustObject(t, corpus.positive["test_keys"])
	expires := mustWireTime(t, assertion["expires_at"])

	for _, purpose := range []string{"ROSTER", "TOPIC", "TUPLE"} {
		t.Run(purpose+" ends before assertion", func(t *testing.T) {
			keyset := cloneViaJCS(t, baseKeyset)
			descriptor := commitmentDescriptorForTest(t, keyset, purpose)
			descriptor["not_after"] = expires.Add(-time.Millisecond).
				Format("2006-01-02T15:04:05.000Z")
			resignKeysetForTrustTest(t, keyset, keys)

			verdict := ValidateAssertion(
				assertion,
				assertionExpectationsForTest(t, assertion, keyset),
			)
			assertVerdict(t, verdict, Inconclusive("KEY_STATE"))
			if !verdict.RequiresKeysetUncertainty() {
				t.Fatal("short commitment lifetime did not request a durable keyset latch")
			}
		})

		t.Run(purpose+" exact assertion expiry", func(t *testing.T) {
			keyset := cloneViaJCS(t, baseKeyset)
			descriptor := commitmentDescriptorForTest(t, keyset, purpose)
			descriptor["not_after"] = expires.
				Format("2006-01-02T15:04:05.000Z")
			resignKeysetForTrustTest(t, keyset, keys)

			assertVerdict(
				t,
				ValidateAssertion(
					assertion,
					assertionExpectationsForTest(t, assertion, keyset),
				),
				Eligible(),
			)
		})
	}
}

func TestValidateAssertionRejectsEvaluationBeforeIssuedAt(t *testing.T) {
	corpus := loadCorpus(t)
	assertion := mustObject(
		t,
		mustObject(t, corpus.positive["assertion"])["value"],
	)
	keyset := mustObject(
		t,
		mustObject(t, corpus.positive["keyset"])["value"],
	)
	issued := mustWireTime(t, assertion["issued_at"])

	expected := assertionExpectationsForTest(t, assertion, keyset)
	expected.EvaluationTime = issued.Add(-time.Nanosecond)
	assertVerdict(
		t,
		ValidateAssertion(assertion, expected),
		Inconclusive("CLOCK_UNCERTAIN"),
	)

	expected.EvaluationTime = issued
	assertVerdict(t, ValidateAssertion(assertion, expected), Eligible())
}

func TestValidateOnlineRotationIndependentlyStagesServiceAuth(t *testing.T) {
	transitionIssued := time.Date(2026, 7, 29, 17, 0, 0, 0, time.UTC)
	cutoverIssued := transitionIssued.Add(24 * time.Hour)

	a9Public := bytes.Repeat([]byte{0x11}, 32)
	serviceOldPublic := bytes.Repeat([]byte{0x22}, 32)
	serviceNewPublic := bytes.Repeat([]byte{0x33}, 32)
	a9NotBefore := transitionIssued.Add(-time.Hour)
	a9NotAfter := cutoverIssued.Add(24 * time.Hour)
	serviceNotBefore := transitionIssued.Add(-time.Hour)
	serviceOldNotAfter := cutoverIssued.Add(125 * time.Second)
	serviceNewNotAfter := cutoverIssued.Add(24 * time.Hour)

	transition := rotationKeysetForTest(
		1,
		transitionIssued,
		onlineKeyForTest(
			t,
			a9Public,
			"A9_CONTROL",
			"SIGN",
			a9NotBefore,
			a9NotAfter,
		),
		onlineKeyForTest(
			t,
			serviceOldPublic,
			"SERVICE_AUTH",
			"SIGN",
			serviceNotBefore,
			serviceOldNotAfter,
		),
		onlineKeyForTest(
			t,
			serviceNewPublic,
			"SERVICE_AUTH",
			"VERIFY_ONLY",
			cutoverIssued,
			serviceNewNotAfter,
		),
	)
	cutover := rotationKeysetForTest(
		2,
		cutoverIssued,
		onlineKeyForTest(
			t,
			a9Public,
			"A9_CONTROL",
			"SIGN",
			a9NotBefore,
			a9NotAfter,
		),
		onlineKeyForTest(
			t,
			serviceNewPublic,
			"SERVICE_AUTH",
			"SIGN",
			cutoverIssued,
			serviceNewNotAfter,
		),
		onlineKeyForTest(
			t,
			serviceOldPublic,
			"SERVICE_AUTH",
			"VERIFY_ONLY",
			serviceNotBefore,
			serviceOldNotAfter,
		),
	)

	assertVerdict(t, ValidateOnlineRotation(transition, cutover), Eligible())

	t.Run("old service key retention covers JWT skew plus 60 seconds", func(t *testing.T) {
		tooShortTransition := cloneViaJCS(t, transition)
		tooShort := cloneViaJCS(t, cutover)
		shortNotAfter := cutoverIssued.Add(125*time.Second - time.Millisecond).
			Format("2006-01-02T15:04:05.000Z")
		oldSign := onlineDescriptorForTest(
			t,
			tooShortTransition,
			"SERVICE_AUTH",
			"SIGN",
		)
		oldSign["not_after"] = shortNotAfter
		oldVerify := onlineDescriptorForTest(
			t,
			tooShort,
			"SERVICE_AUTH",
			"VERIFY_ONLY",
		)
		oldVerify["not_after"] = shortNotAfter
		assertVerdict(
			t,
			ValidateOnlineRotation(tooShortTransition, tooShort),
			Inconclusive("KEY_STATE"),
		)
	})

	t.Run("new service key must have been staged", func(t *testing.T) {
		notStaged := cloneViaJCS(t, transition)
		items := notStaged["keys"].([]any)
		notStaged["keys"] = items[:2]
		assertVerdict(
			t,
			ValidateOnlineRotation(notStaged, cutover),
			Inconclusive("KEY_STATE"),
		)
	})

	t.Run("retired service key cannot disappear before its horizon", func(t *testing.T) {
		tooEarly := keysetWithoutOnlineDescriptorForTest(
			t,
			cutover,
			"SERVICE_AUTH",
			"VERIFY_ONLY",
		)
		tooEarly["keyset_sequence"] = json.Number("3")
		tooEarly["issued_at"] = cutoverIssued.Add(60 * time.Second).
			Format("2006-01-02T15:04:05.000Z")
		assertVerdict(
			t,
			ValidateOnlineRotation(cutover, tooEarly),
			Inconclusive("KEY_STATE"),
		)

		atHorizon := keysetWithoutOnlineDescriptorForTest(
			t,
			cutover,
			"SERVICE_AUTH",
			"VERIFY_ONLY",
		)
		atHorizon["keyset_sequence"] = json.Number("3")
		atHorizon["issued_at"] = serviceOldNotAfter.
			Format("2006-01-02T15:04:05.000Z")
		assertVerdict(
			t,
			ValidateOnlineRotation(cutover, atHorizon),
			Eligible(),
		)
	})

	t.Run("staging must cover a full 24 hours", func(t *testing.T) {
		tooLate := cloneViaJCS(t, transition)
		tooLateCutover := cloneViaJCS(t, cutover)
		lateNotBefore := cutoverIssued.Add(-time.Millisecond).
			Format("2006-01-02T15:04:05.000Z")
		staged := onlineDescriptorForTest(
			t,
			tooLate,
			"SERVICE_AUTH",
			"VERIFY_ONLY",
		)
		staged["not_before"] = lateNotBefore
		newSign := onlineDescriptorForTest(
			t,
			tooLateCutover,
			"SERVICE_AUTH",
			"SIGN",
		)
		newSign["not_before"] = lateNotBefore
		assertVerdict(
			t,
			ValidateOnlineRotation(tooLate, tooLateCutover),
			Inconclusive("KEY_STATE"),
		)
	})
}

func TestValidateOnlineRotationRequiresA9ControlRetentionHorizon(t *testing.T) {
	corpus := loadCorpus(t)
	rotation := mustObject(t, corpus.positive["online_signer_rotation"])
	transition := cloneViaJCS(
		t,
		mustObject(t, mustObject(t, rotation["transition_keyset"])["value"]),
	)
	cutover := cloneViaJCS(
		t,
		mustObject(t, mustObject(t, rotation["cutover_keyset"])["value"]),
	)
	activation := mustWireTime(t, rotation["activation_at"])
	shortNotAfter := activation.Add(90*time.Second - time.Millisecond).
		Format("2006-01-02T15:04:05.000Z")
	oldSign := onlineDescriptorForTest(
		t,
		transition,
		"A9_CONTROL",
		"SIGN",
	)
	oldVerify := onlineDescriptorForTest(
		t,
		cutover,
		"A9_CONTROL",
		"VERIFY_ONLY",
	)
	oldSign["not_after"] = shortNotAfter
	oldVerify["not_after"] = shortNotAfter

	assertVerdict(
		t,
		ValidateOnlineRotation(transition, cutover),
		Inconclusive("KEY_STATE"),
	)
}

func assertionExpectationsForTest(
	t *testing.T,
	assertion map[string]any,
	keyset map[string]any,
) AssertionExpectations {
	t.Helper()
	return AssertionExpectations{
		Environment:           "dev",
		InstallationBindingID: mustString(t, assertion["installation_binding_id"]),
		RosterCommitment:      mustString(t, assertion["roster_commitment"]),
		TupleCommitment:       mustString(t, assertion["tuple_commitment"]),
		TopicBinding:          mustString(t, assertion["topic_binding"]),
		TopicKeyEpoch:         uint32(mustUint(t, assertion["topic_key_epoch"])),
		EvaluationTime:        mustWireTime(t, assertion["issued_at"]),
		Keyset:                keyset,
	}
}

func commitmentDescriptorForTest(
	t *testing.T,
	keyset map[string]any,
	purpose string,
) map[string]any {
	t.Helper()
	for _, value := range keyset["commitment_keys"].([]any) {
		descriptor := value.(map[string]any)
		if descriptor["purpose"] == purpose {
			return descriptor
		}
	}
	t.Fatalf("missing %s commitment descriptor", purpose)
	return nil
}

func resignAssertionForTrustTest(
	t *testing.T,
	assertion map[string]any,
	keys map[string]any,
) {
	t.Helper()
	signature, err := SignObject(
		assertion,
		"signature_base64url",
		AssertionSignatureDomain,
		mustB64(t, keys, "control_private_seed_base64url", 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertion["signature_base64url"] = signature
}

func resignKeysetForTrustTest(
	t *testing.T,
	keyset map[string]any,
	keys map[string]any,
) {
	t.Helper()
	signature, err := SignObject(
		keyset,
		"root_signature_base64url",
		KeysetSignatureDomain,
		mustB64(t, keys, "root_private_seed_base64url", 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	keyset["root_signature_base64url"] = signature
}

func onlineKeyForTest(
	t *testing.T,
	publicKey []byte,
	use string,
	state string,
	notBefore time.Time,
	notAfter time.Time,
) map[string]any {
	t.Helper()
	keyID, err := Ed25519KeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"key_id":               keyID,
		"use":                  use,
		"public_key_base64url": EncodeBase64URL(publicKey),
		"not_before": notBefore.UTC().
			Format("2006-01-02T15:04:05.000Z"),
		"not_after": notAfter.UTC().
			Format("2006-01-02T15:04:05.000Z"),
		"state": state,
	}
}

func rotationKeysetForTest(
	sequence uint64,
	issued time.Time,
	keys ...map[string]any,
) map[string]any {
	items := make([]any, len(keys))
	for index := range keys {
		items[index] = keys[index]
	}
	return map[string]any{
		"keyset_sequence": json.Number(strconv.FormatUint(sequence, 10)),
		"issued_at": issued.UTC().
			Format("2006-01-02T15:04:05.000Z"),
		"keys": items,
	}
}

func onlineDescriptorForTest(
	t *testing.T,
	keyset map[string]any,
	use string,
	state string,
) map[string]any {
	t.Helper()
	for _, value := range keyset["keys"].([]any) {
		descriptor := value.(map[string]any)
		if descriptor["use"] == use && descriptor["state"] == state {
			return descriptor
		}
	}
	t.Fatalf("missing %s/%s online descriptor", use, state)
	return nil
}

func keysetWithoutOnlineDescriptorForTest(
	t *testing.T,
	keyset map[string]any,
	use string,
	state string,
) map[string]any {
	t.Helper()
	cloned := cloneViaJCS(t, keyset)
	items := cloned["keys"].([]any)
	filtered := make([]any, 0, len(items))
	removed := false
	for _, value := range items {
		descriptor := value.(map[string]any)
		if !removed &&
			descriptor["use"] == use &&
			descriptor["state"] == state {
			removed = true
			continue
		}
		filtered = append(filtered, descriptor)
	}
	if !removed {
		t.Fatalf("missing %s/%s online descriptor", use, state)
	}
	cloned["keys"] = filtered
	return cloned
}
