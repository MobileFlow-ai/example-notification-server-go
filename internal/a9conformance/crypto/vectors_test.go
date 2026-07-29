package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type vectorCorpus struct {
	positive  map[string]any
	negatives map[string]map[string]any
}

func loadCorpus(t *testing.T) vectorCorpus {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	read := func(name string) map[string]any {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, "contracts", "xmtp_push", "a9_adapter", "v1", "vectors", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		value, err := ParseStrictJSON(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		object, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("%s is not an object", name)
		}
		return object
	}
	positive := read("positive.json")
	negativeRoot := read("negative.json")
	negativeList := mustArray(t, negativeRoot["vectors"])
	negatives := make(map[string]map[string]any, len(negativeList))
	for _, item := range negativeList {
		vector := mustObject(t, item)
		negatives[mustString(t, vector["id"])] = vector
	}
	return vectorCorpus{positive: positive, negatives: negatives}
}

func TestPositiveCryptographicTranscripts(t *testing.T) {
	corpus := loadCorpus(t)
	keys := mustObject(t, corpus.positive["test_keys"])
	controlSeed := mustB64(t, keys, "control_private_seed_base64url", 32)
	controlPublic := mustB64(t, keys, "control_public_key_base64url", 32)
	nextControlSeed := mustB64(t, keys, "next_control_private_seed_base64url", 32)
	nextControlPublic := mustB64(t, keys, "next_control_public_key_base64url", 32)
	rootSeed := mustB64(t, keys, "root_private_seed_base64url", 32)
	rootPublic := mustB64(t, keys, "root_public_key_base64url", 32)

	type signedFixture struct {
		name, signatureField string
		vector               map[string]any
		domain, seed, public []byte
	}
	rotation := mustObject(t, corpus.positive["online_signer_rotation"])
	boundary := mustObject(t, corpus.positive["topic_epoch_boundary"])
	fixtures := []signedFixture{
		{"assertion", "signature_base64url", mustObject(t, corpus.positive["assertion"]), AssertionSignatureDomain, controlSeed, controlPublic},
		{"control", "signature_base64url", mustObject(t, corpus.positive["control_upsert"]), ControlSignatureDomain, controlSeed, controlPublic},
		{"watermark", "signature_base64url", mustObject(t, corpus.positive["watermark_current"]), WatermarkSignatureDomain, controlSeed, controlPublic},
		{"base keyset", "root_signature_base64url", mustObject(t, corpus.positive["keyset"]), KeysetSignatureDomain, rootSeed, rootPublic},
		{"online transition keyset", "root_signature_base64url", mustObject(t, rotation["transition_keyset"]), KeysetSignatureDomain, rootSeed, rootPublic},
		{"online cutover keyset", "root_signature_base64url", mustObject(t, rotation["cutover_keyset"]), KeysetSignatureDomain, rootSeed, rootPublic},
		{"topic transition keyset", "root_signature_base64url", mustObject(t, boundary["transition_keyset"]), KeysetSignatureDomain, rootSeed, rootPublic},
		{"old epoch assertion", "signature_base64url", mustObject(t, boundary["old_epoch_assertion"]), AssertionSignatureDomain, nextControlSeed, nextControlPublic},
		{"new epoch assertion", "signature_base64url", mustObject(t, boundary["new_epoch_assertion"]), AssertionSignatureDomain, nextControlSeed, nextControlPublic},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			value := mustObject(t, fixture.vector["value"])
			canonical, signingInput, err := SignedTranscript(value, fixture.signatureField, fixture.domain)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := string(canonical), mustString(t, fixture.vector["canonical_unsigned_utf8"]); got != want {
				t.Fatalf("canonical unsigned mismatch\n got: %s\nwant: %s", got, want)
			}
			if got, want := SHA256LowerHex(canonical), mustString(t, fixture.vector["canonical_unsigned_sha256"]); got != want {
				t.Fatalf("canonical hash = %s, want %s", got, want)
			}
			if got, want := hex.EncodeToString(signingInput), mustString(t, fixture.vector["signing_input_hex"]); got != want {
				t.Fatalf("signing input mismatch: got %s want %s", got, want)
			}
			signature, err := SignObject(value, fixture.signatureField, fixture.domain, fixture.seed)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := signature, mustString(t, value[fixture.signatureField]); got != want {
				t.Fatalf("signature mismatch: got %s want %s", got, want)
			}
			assertVerdict(t, VerifyObject(value, fixture.signatureField, fixture.domain, fixture.public), Eligible())
			complete, err := Canonicalize(value)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := SHA256LowerHex(complete), mustString(t, fixture.vector["signed_object_sha256"]); got != want {
				t.Fatalf("signed object hash = %s, want %s", got, want)
			}
		})
	}

	assertionVector := mustObject(t, corpus.positive["assertion"])
	assertion := mustObject(t, assertionVector["value"])
	hash, err := AssertionHash(assertion)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustString(t, assertionVector["assertion_hash_base64url"]); hash != want {
		t.Fatalf("assertion hash = %s, want %s", hash, want)
	}
	commitments := mustObject(t, corpus.positive["commitments"])
	assertVerdict(t, ValidateAssertion(assertion, AssertionExpectations{
		Environment:           "dev",
		InstallationBindingID: mustString(t, assertion["installation_binding_id"]),
		RosterCommitment:      mustString(t, commitments["roster_commitment_base64url"]),
		TupleCommitment:       mustString(t, commitments["tuple_commitment_base64url"]),
		TopicBinding:          mustString(t, commitments["topic_binding_base64url"]),
		TopicKeyEpoch:         uint32(mustUint(t, commitments["topic_key_epoch"])),
		EvaluationTime:        mustWireTime(t, assertion["issued_at"]),
		Keyset:                mustObject(t, mustObject(t, corpus.positive["keyset"])["value"]),
	}), Eligible())
}

func TestPositiveKeyIDsCommitmentsAndResolver(t *testing.T) {
	corpus := loadCorpus(t)
	keys := mustObject(t, corpus.positive["test_keys"])
	keyPairs := []struct {
		material, expected string
		ed25519            bool
	}{
		{"control_public_key_base64url", "control_signing_key_id", true},
		{"next_control_public_key_base64url", "next_control_signing_key_id", true},
		{"root_public_key_base64url", "root_signing_key_id", true},
		{"service_auth_public_key_base64url", "service_auth_signing_key_id", true},
		{"roster_hmac_key_base64url", "roster_hmac_key_id", false},
		{"tuple_hmac_key_base64url", "tuple_hmac_key_id", false},
		{"topic_hmac_key_base64url", "topic_hmac_key_id", false},
		{"next_topic_hmac_key_base64url", "next_topic_hmac_key_id", false},
	}
	for _, pair := range keyPairs {
		t.Run(pair.expected, func(t *testing.T) {
			material := mustB64(t, keys, pair.material, 32)
			var got string
			var err error
			if pair.ed25519 {
				got, err = Ed25519KeyID(material)
			} else {
				got, err = HMACKeyID(material)
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := mustString(t, keys[pair.expected]); got != want {
				t.Fatalf("key ID = %s, want %s", got, want)
			}
		})
	}

	source := mustObject(t, corpus.positive["source_tuple"])
	commitments := mustObject(t, corpus.positive["commitments"])
	resolver := mustObject(t, corpus.positive["topic_resolver"])
	resolved, err := ResolveTopic(mustString(t, source["transport_conversation_id"]))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(resolved.GroupID), mustString(t, resolver["group_identifier_hex"]); got != want {
		t.Fatalf("group ID = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(resolved.Bytes), mustString(t, resolver["topic_bytes_hex"]); got != want {
		t.Fatalf("topic bytes = %s, want %s", got, want)
	}
	if got, want := EncodeBase64URL(resolved.Bytes), mustString(t, resolver["topic_bytes_base64url"]); got != want {
		t.Fatalf("topic Base64url = %s, want %s", got, want)
	}
	if got, want := SHA256LowerHex(resolved.Bytes), mustString(t, resolver["topic_bytes_sha256"]); got != want {
		t.Fatalf("topic hash = %s, want %s", got, want)
	}

	rosterDigest, err := DecodeBase64URL(mustString(t, source["roster_digest_base64url"]), 32)
	if err != nil {
		t.Fatal(err)
	}
	roster, err := RosterCommitment(
		mustB64(t, keys, "roster_hmac_key_base64url", 32),
		mustString(t, source["environment"]),
		rosterDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := EncodeBase64URL(roster), mustString(t, commitments["roster_commitment_base64url"]); got != want {
		t.Fatalf("roster commitment = %s, want %s", got, want)
	}
	topic, err := TopicBinding(mustB64(t, keys, "topic_hmac_key_base64url", 32), resolved.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := EncodeBase64URL(topic), mustString(t, commitments["topic_binding_base64url"]); got != want {
		t.Fatalf("topic binding = %s, want %s", got, want)
	}
	generation := uint32(mustUint(t, source["conversation_generation"]))
	rosterVersion := uint32(mustUint(t, source["roster_version"]))
	tuple, err := TupleCommitment(mustB64(t, keys, "tuple_hmac_key_base64url", 32), TupleInput{
		Environment:             mustString(t, source["environment"]),
		AccountIncarnationID:    mustString(t, source["account_incarnation_id"]),
		HytchConversationID:     mustString(t, source["hytch_conversation_id"]),
		ConversationGeneration:  generation,
		RosterVersion:           rosterVersion,
		RosterCommitment:        roster,
		TransportConversationID: mustString(t, source["transport_conversation_id"]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := EncodeBase64URL(tuple), mustString(t, commitments["tuple_commitment_base64url"]); got != want {
		t.Fatalf("tuple commitment = %s, want %s", got, want)
	}
}

func TestPositiveKeyRotationAndTopicBoundary(t *testing.T) {
	corpus := loadCorpus(t)
	keys := mustObject(t, corpus.positive["test_keys"])
	rootPublic := mustB64(t, keys, "root_public_key_base64url", 32)
	rootID := mustString(t, keys["root_signing_key_id"])
	baseKeyset := mustObject(t, mustObject(t, corpus.positive["keyset"])["value"])
	rotation := mustObject(t, corpus.positive["online_signer_rotation"])
	transition := mustObject(t, mustObject(t, rotation["transition_keyset"])["value"])
	cutover := mustObject(t, mustObject(t, rotation["cutover_keyset"])["value"])
	topicBoundary := mustObject(t, corpus.positive["topic_epoch_boundary"])
	topicTransition := mustObject(t, mustObject(t, topicBoundary["transition_keyset"])["value"])

	for name, keyset := range map[string]map[string]any{
		"base": baseKeyset, "online transition": transition,
		"online cutover": cutover, "topic transition": topicTransition,
	} {
		t.Run(name, func(t *testing.T) {
			issued := mustWireTime(t, keyset["issued_at"])
			assertVerdict(t, ValidateKeyset(keyset, rootPublic, rootID, "dev", issued), Eligible())
		})
	}
	assertVerdict(t, ValidateOnlineRotation(transition, cutover), Eligible())

	initial := mustWireTime(t, transition["issued_at"])
	activation := mustWireTime(t, rotation["activation_at"])
	oldID := mustString(t, keys["control_signing_key_id"])
	nextID := mustString(t, keys["next_control_signing_key_id"])
	signing, verdict := SigningKeyAt(transition, "A9_CONTROL", initial)
	assertVerdict(t, verdict, Eligible())
	if signing.KeyID != oldID {
		t.Fatalf("transition signer = %s, want %s", signing.KeyID, oldID)
	}
	signing, verdict = SigningKeyAt(cutover, "A9_CONTROL", activation)
	assertVerdict(t, verdict, Eligible())
	if signing.KeyID != nextID {
		t.Fatalf("cutover signer = %s, want %s", signing.KeyID, nextID)
	}

	assertVerdict(t, ValidateTopicTransition(topicTransition), Eligible())
	boundary := mustWireTime(t, topicBoundary["boundary_at"])
	oldEpoch := TopicEpoch(boundary.Add(-time.Second))
	newEpoch := TopicEpoch(boundary)
	if newEpoch != oldEpoch+1 {
		t.Fatalf("epoch did not advance at boundary: %d to %d", oldEpoch, newEpoch)
	}
	if !TopicEpochUsable(oldEpoch, boundary.Add(-time.Second), true) ||
		TopicEpochUsable(oldEpoch, boundary, true) ||
		!TopicEpochUsable(oldEpoch, boundary, false) ||
		TopicEpochUsable(oldEpoch, boundary.Add(60*time.Second), false) ||
		!TopicEpochUsable(newEpoch, boundary, true) {
		t.Fatal("topic epoch overlap behavior does not match the boundary rule")
	}
	oldAssertion := mustObject(t, mustObject(t, topicBoundary["old_epoch_assertion"])["value"])
	oldExpiry := mustWireTime(t, oldAssertion["expires_at"])
	if PreviousTopicEpochVerificationUsable(oldEpoch, boundary, oldExpiry, false) ||
		!PreviousTopicEpochVerificationUsable(oldEpoch, boundary, oldExpiry, true) ||
		PreviousTopicEpochVerificationUsable(oldEpoch, oldExpiry, oldExpiry, true) {
		t.Fatal("previous topic epoch did not require an accepted, unexpired assertion")
	}
	if _, v := CommitmentKeyAt(topicTransition, "TOPIC", &oldEpoch, boundary, false); !v.IsEligible() {
		t.Fatalf("old topic key unavailable during overlap: %+v", v)
	}
	if _, v := CommitmentKeyAt(topicTransition, "TOPIC", &oldEpoch, boundary.Add(60*time.Second), false); v.IsEligible() {
		t.Fatal("old topic key remained usable at erasure deadline")
	}
	if _, v := CommitmentKeyAt(topicTransition, "TOPIC", &newEpoch, boundary, true); !v.IsEligible() {
		t.Fatalf("new topic key unavailable at boundary: %+v", v)
	}

	for name, fixture := range map[string]map[string]any{
		"old": mustObject(t, topicBoundary["old_epoch_assertion"]),
		"new": mustObject(t, topicBoundary["new_epoch_assertion"]),
	} {
		t.Run(name+" boundary assertion", func(t *testing.T) {
			assertion := mustObject(t, fixture["value"])
			context := AssertionExpectations{
				Environment:           "dev",
				InstallationBindingID: mustString(t, assertion["installation_binding_id"]),
				RosterCommitment:      mustString(t, assertion["roster_commitment"]),
				TupleCommitment:       mustString(t, assertion["tuple_commitment"]),
				TopicBinding:          mustString(t, assertion["topic_binding"]),
				TopicKeyEpoch:         uint32(mustUint(t, assertion["topic_key_epoch"])),
				EvaluationTime:        mustWireTime(t, assertion["issued_at"]),
				Keyset:                topicTransition,
			}
			assertVerdict(t, ValidateAssertion(assertion, context), Eligible())
		})
	}
}

func TestPositiveJWTsAndRequestHashes(t *testing.T) {
	corpus := loadCorpus(t)
	keys := mustObject(t, corpus.positive["test_keys"])
	serviceSeed := mustB64(t, keys, "service_auth_private_seed_base64url", 32)
	keyset := mustObject(t, mustObject(t, corpus.positive["keyset"])["value"])

	fixtures := []struct {
		name, jwtName, bodyName string
	}{
		{"subscription", "service_jwt", "subscription_replace"},
		{"control", "control_apply_service_jwt", "control_upsert"},
		{"watermark", "watermark_apply_service_jwt", "watermark_current"},
	}
	for _, item := range fixtures {
		t.Run(item.name, func(t *testing.T) {
			jwt := mustObject(t, corpus.positive[item.jwtName])
			bodyVector := mustObject(t, corpus.positive[item.bodyName])
			bodyObject := mustObject(t, bodyVector["value"])
			body, err := Canonicalize(bodyObject)
			if err != nil {
				t.Fatal(err)
			}
			if expected, ok := bodyVector["canonical_body_utf8"].(string); ok && string(body) != expected {
				t.Fatalf("request canonical bytes mismatch")
			}
			if expected, ok := bodyVector["canonical_body_sha256"].(string); ok && SHA256LowerHex(body) != expected {
				t.Fatalf("request hash = %s, want %s", SHA256LowerHex(body), expected)
			}
			header := mustObject(t, jwt["header"])
			claims := mustObject(t, jwt["claims"])
			compact, signingInput, err := BuildJWT(header, claims, serviceSeed)
			if err != nil {
				t.Fatal(err)
			}
			if compact != mustString(t, jwt["compact"]) {
				t.Fatal("compact JWT mismatch")
			}
			if signingInput != mustString(t, jwt["signing_input_utf8"]) {
				t.Fatal("JWT signing input mismatch")
			}
			iat := int64(mustUint(t, claims["iat"]))
			assertVerdict(t, VerifyJWT(compact, JWTExpectations{
				Environment: "dev", Method: mustString(t, claims["method"]),
				Path: mustString(t, claims["path"]), RequestBody: body,
				Now: time.Unix(iat, 0).UTC(), Keyset: keyset, Replay: NewReplayStore(),
			}), Eligible())
		})
	}
}

func TestCryptoNegativeVectors(t *testing.T) {
	corpus := loadCorpus(t)
	positive := corpus.positive
	keys := mustObject(t, positive["test_keys"])
	assertionBase := mustObject(t, mustObject(t, positive["assertion"])["value"])
	keysetBase := mustObject(t, mustObject(t, positive["keyset"])["value"])
	commitments := mustObject(t, positive["commitments"])
	assertionContext := AssertionExpectations{
		Environment:           "dev",
		InstallationBindingID: mustString(t, assertionBase["installation_binding_id"]),
		RosterCommitment:      mustString(t, commitments["roster_commitment_base64url"]),
		TupleCommitment:       mustString(t, commitments["tuple_commitment_base64url"]),
		TopicBinding:          mustString(t, commitments["topic_binding_base64url"]),
		TopicKeyEpoch:         uint32(mustUint(t, commitments["topic_key_epoch"])),
		EvaluationTime:        mustWireTime(t, assertionBase["issued_at"]),
		Keyset:                keysetBase,
	}

	assertionMutationIDs := []string{
		"assertion_signature_one_byte", "assertion_unsigned_one_byte",
		"unknown_assertion_field", "padded_signature", "wrong_length_base64url",
		"wrong_environment_spelling", "wrong_audience", "welcome_purpose",
		"noncanonical_timestamp", "integer_as_float", "integer_overflow",
		"wrong_topic_binding", "wrong_roster_commitment", "wrong_tuple_commitment",
		"stale_topic_key_epoch", "unknown_signer",
	}
	for _, id := range assertionMutationIDs {
		t.Run(id, func(t *testing.T) {
			vector := corpus.negatives[id]
			mutated := cloneViaJCS(t, assertionBase)
			applyVectorPatch(t, mutated, mustObject(t, vector["mutation"]))
			assertVectorVerdict(t, vector, ValidateAssertion(mutated, assertionContext))
		})
	}

	t.Run("wrong_signature_domain", func(t *testing.T) {
		vector := corpus.negatives["wrong_signature_domain"]
		publicKey := mustB64(t, keys, "control_public_key_base64url", ed25519.PublicKeySize)
		assertVectorVerdict(t, vector, VerifyObject(assertionBase, "signature_base64url", ControlSignatureDomain, publicKey))
	})
	t.Run("duplicate_json_key", func(t *testing.T) {
		vector := corpus.negatives["duplicate_json_key"]
		raw := []byte(mustString(t, mustObject(t, vector["mutation"])["raw_utf8"]))
		_, verdict := ValidateStrictJSON(raw)
		assertVectorVerdict(t, vector, verdict)
	})
	t.Run("noncanonical_uuid", func(t *testing.T) {
		vector := corpus.negatives["noncanonical_uuid"]
		value := mustString(t, mustObject(t, vector["mutation"])["value"])
		_, err := ParseCanonicalUUID(value)
		verdict := Eligible()
		if err != nil {
			verdict = Invalid("FIELD_DOMAIN")
		}
		assertVectorVerdict(t, vector, verdict)
	})
	t.Run("tuple_source_account_mutation", func(t *testing.T) {
		vector := corpus.negatives["tuple_source_account_mutation"]
		source := cloneViaJCS(t, mustObject(t, positive["source_tuple"]))
		mutation := mustObject(t, vector["mutation"])
		source["account_incarnation_id"] = mutation["value"]
		roster, err := DecodeBase64URL(mustString(t, commitments["roster_commitment_base64url"]), 32)
		if err != nil {
			t.Fatal(err)
		}
		got, err := TupleCommitment(mustB64(t, keys, "tuple_hmac_key_base64url", 32), TupleInput{
			Environment:             mustString(t, source["environment"]),
			AccountIncarnationID:    mustString(t, source["account_incarnation_id"]),
			HytchConversationID:     mustString(t, source["hytch_conversation_id"]),
			ConversationGeneration:  uint32(mustUint(t, source["conversation_generation"])),
			RosterVersion:           uint32(mustUint(t, source["roster_version"])),
			RosterCommitment:        roster,
			TransportConversationID: mustString(t, source["transport_conversation_id"]),
		})
		if err != nil {
			t.Fatal(err)
		}
		verdict := Eligible()
		if !constantTimeStringEqual(EncodeBase64URL(got), mustString(t, assertionBase["tuple_commitment"])) {
			verdict = Invalid("TUPLE_COMMITMENT_MISMATCH")
		}
		assertVectorVerdict(t, vector, verdict)
	})
	t.Run("signer_not_yet_valid", func(t *testing.T) {
		vector := corpus.negatives["signer_not_yet_valid"]
		rotation := mustObject(t, positive["online_signer_rotation"])
		keyset := mustObject(t, mustObject(t, rotation["transition_keyset"])["value"])
		mutation := mustObject(t, vector["mutation"])
		_, verdict := OnlineKeyAt(keyset, mustString(t, mutation["signing_key_id"]), "A9_CONTROL", mustWireTime(t, mutation["evaluation_time"]))
		assertVectorVerdict(t, vector, verdict)
	})
	t.Run("signer_expired", func(t *testing.T) {
		vector := corpus.negatives["signer_expired"]
		rotation := mustObject(t, positive["online_signer_rotation"])
		keyset := mustObject(t, mustObject(t, rotation["cutover_keyset"])["value"])
		mutation := mustObject(t, vector["mutation"])
		_, verdict := OnlineKeyAt(keyset, mustString(t, mutation["signing_key_id"]), "A9_CONTROL", mustWireTime(t, mutation["evaluation_time"]))
		assertVectorVerdict(t, vector, verdict)
	})
	t.Run("expired_assertion", func(t *testing.T) {
		vector := corpus.negatives["expired_assertion"]
		context := assertionContext
		context.EvaluationTime = mustWireTime(t, mustObject(t, vector["mutation"])["evaluation_time"])
		assertVectorVerdict(t, vector, ValidateAssertion(assertionBase, context))
	})

	resolverIDs := []string{
		"noncanonical_transport_id_uppercase", "topic_wrong_length",
		"transport_topic_mismatch", "welcome_topic_kind",
	}
	for _, id := range resolverIDs {
		t.Run(id, func(t *testing.T) {
			vector := corpus.negatives[id]
			request := cloneViaJCS(t, mustObject(t, mustObject(t, positive["subscription_replace"])["value"]))
			applyVectorPatch(t, request, mustObject(t, vector["mutation"]))
			subscription := mustObject(t, mustArray(t, request["subscriptions"])[0])
			verdict := VerifyResolvedTopic(
				mustString(t, subscription["transport_conversation_id"]),
				mustString(t, subscription["topic_base64url"]),
			)
			assertVectorVerdict(t, vector, verdict)
		})
	}
	t.Run("cross_installation_assertion", func(t *testing.T) {
		vector := corpus.negatives["cross_installation_assertion"]
		request := cloneViaJCS(t, mustObject(t, mustObject(t, positive["subscription_replace"])["value"]))
		applyVectorPatch(t, request, mustObject(t, vector["mutation"]))
		verdict := Eligible()
		if mustString(t, request["installation_binding_id"]) != mustString(t, assertionBase["installation_binding_id"]) {
			verdict = Invalid("INSTALLATION_MISMATCH")
		}
		assertVectorVerdict(t, vector, verdict)
	})
	t.Run("cross_topic_assertion_hash", func(t *testing.T) {
		vector := corpus.negatives["cross_topic_assertion_hash"]
		request := cloneViaJCS(t, mustObject(t, mustObject(t, positive["subscription_replace"])["value"]))
		applyVectorPatch(t, request, mustObject(t, vector["mutation"]))
		subscription := mustObject(t, mustArray(t, request["subscriptions"])[0])
		expectedHash, err := AssertionHash(assertionBase)
		if err != nil {
			t.Fatal(err)
		}
		verdict := Eligible()
		if !constantTimeStringEqual(mustString(t, subscription["assertion_hash"]), expectedHash) {
			verdict = Invalid("ASSERTION_HASH_MISMATCH")
		}
		assertVectorVerdict(t, vector, verdict)
	})

	jwtVector := mustObject(t, positive["service_jwt"])
	body := mustCanonical(t, mustObject(t, mustObject(t, positive["subscription_replace"])["value"]))
	jwtClaims := mustObject(t, jwtVector["claims"])
	baseJWTExpectations := JWTExpectations{
		Environment: "dev", Method: mustString(t, jwtClaims["method"]),
		Path: mustString(t, jwtClaims["path"]), RequestBody: body,
		Now:    time.Unix(int64(mustUint(t, jwtClaims["iat"])), 0).UTC(),
		Keyset: keysetBase,
	}
	for _, id := range []string{"jwt_wrong_audience", "jwt_wrong_path", "jwt_wrong_body_hash"} {
		t.Run(id, func(t *testing.T) {
			vector := corpus.negatives[id]
			jwt := cloneViaJCS(t, jwtVector)
			applyVectorPatch(t, jwt, mustObject(t, vector["mutation"]))
			compact, _, err := BuildJWT(
				mustObject(t, jwt["header"]), mustObject(t, jwt["claims"]),
				mustB64(t, keys, "service_auth_private_seed_base64url", ed25519.SeedSize),
			)
			if err != nil {
				t.Fatal(err)
			}
			expected := baseJWTExpectations
			expected.Replay = NewReplayStore()
			assertVectorVerdict(t, vector, VerifyJWT(compact, expected))
		})
	}
	t.Run("jwt_reused_jti", func(t *testing.T) {
		vector := corpus.negatives["jwt_reused_jti"]
		expected := baseJWTExpectations
		expected.Replay = NewReplayStore()
		compact := mustString(t, jwtVector["compact"])
		assertVerdict(t, VerifyJWT(compact, expected), Eligible())
		assertVectorVerdict(t, vector, VerifyJWT(compact, expected))
	})
	t.Run("keyset_sequence_rollback", func(t *testing.T) {
		vector := corpus.negatives["keyset_sequence_rollback"]
		stored := mustUint(t, mustObject(t, vector["mutation"])["stored_keyset_sequence"])
		assertVectorVerdict(t, vector, ValidateKeysetSequence(keysetBase, stored, ""))
	})
}

func applyVectorPatch(t *testing.T, root map[string]any, mutation map[string]any) {
	t.Helper()
	op, hasOp := mutation["op"].(string)
	if !hasOp {
		return
	}
	if op != "replace" && op != "add" {
		t.Fatalf("unsupported mutation op %q", op)
	}
	rawPath := mustString(t, mutation["path"])
	parts := strings.Split(strings.TrimPrefix(rawPath, "/"), "/")
	var parent any = root
	for _, raw := range parts[:len(parts)-1] {
		part := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch node := parent.(type) {
		case map[string]any:
			parent = node[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				t.Fatalf("bad mutation path %q", rawPath)
			}
			parent = node[index]
		default:
			t.Fatalf("bad mutation path %q at %q", rawPath, part)
		}
	}
	last := strings.ReplaceAll(strings.ReplaceAll(parts[len(parts)-1], "~1", "/"), "~0", "~")
	switch node := parent.(type) {
	case map[string]any:
		node[last] = mutation["value"]
	case []any:
		index, err := strconv.Atoi(last)
		if err != nil || index < 0 || index >= len(node) {
			t.Fatalf("bad mutation path %q", rawPath)
		}
		node[index] = mutation["value"]
	default:
		t.Fatalf("bad mutation path %q", rawPath)
	}
}

func cloneViaJCS(t *testing.T, object map[string]any) map[string]any {
	t.Helper()
	raw := mustCanonical(t, object)
	value, err := ParseStrictJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return mustObject(t, value)
}

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := Canonicalize(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertVectorVerdict(t *testing.T, vector map[string]any, actual Verdict) {
	t.Helper()
	expected := mustObject(t, vector["expected"])
	assertVerdict(t, actual, Verdict{
		Terminal: mustString(t, expected["terminal"]),
		Reason:   mustString(t, expected["reason"]),
	})
}

func assertVerdict(t *testing.T, actual, expected Verdict) {
	t.Helper()
	if actual != expected {
		t.Fatalf("verdict = %+v, want %+v", actual, expected)
	}
}

func mustObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("got %T, want JSON object", value)
	}
	return object
}

func mustArray(t *testing.T, value any) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("got %T, want JSON array", value)
	}
	return array
}

func mustString(t *testing.T, value any) string {
	t.Helper()
	stringValue, ok := value.(string)
	if !ok {
		t.Fatalf("got %T, want string", value)
	}
	return stringValue
}

func mustUint(t *testing.T, value any) uint64 {
	t.Helper()
	n, verdict := nonnegativeInteger(value)
	if !verdict.IsEligible() {
		t.Fatalf("got %v (%T), want non-negative integer: %+v", value, value, verdict)
	}
	return n
}

func mustWireTime(t *testing.T, value any) time.Time {
	t.Helper()
	parsed, ok := parseWireTime(mustString(t, value))
	if !ok {
		t.Fatalf("not a wire timestamp: %v", value)
	}
	return parsed
}

func mustB64(t *testing.T, object map[string]any, field string, length int) []byte {
	t.Helper()
	decoded, err := DecodeBase64URL(mustString(t, object[field]), length)
	if err != nil {
		t.Fatalf("%s: %v", field, err)
	}
	return decoded
}

func TestJCSProfileIsIndependentAndStrict(t *testing.T) {
	value, verdict := ValidateStrictJSON([]byte(`{"z":0,"a":[true,null,"x"]}`))
	assertVerdict(t, verdict, Eligible())
	canonical, err := Canonicalize(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, []byte(`{"a":[true,null,"x"],"z":0}`)) {
		t.Fatalf("canonical = %s", canonical)
	}
	for name, raw := range map[string]string{
		"duplicate":          `{"a":1,"a":1}`,
		"float":              `{"a":1.0}`,
		"overflow":           `{"a":9007199254740992}`,
		"unpaired surrogate": `{"a":"\ud800"}`,
		"trailing token":     `{"a":1} []`,
		"trailing bytes":     `{"a":1} garbage`,
	} {
		t.Run(name, func(t *testing.T) {
			_, result := ValidateStrictJSON([]byte(raw))
			if result.IsEligible() {
				t.Fatalf("%s unexpectedly accepted", raw)
			}
		})
	}
}
