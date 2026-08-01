package a9trust

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9schema"
)

// ControlAction is the durable numeric representation used by the bridge
// vault. The values intentionally match migration 00012.
type ControlAction uint8

const (
	ControlActionUpsert ControlAction = 1
	ControlActionRevoke ControlAction = 2
)

// ControlReason is meaningful only for a denial-only REVOKE. The values
// intentionally match migration 00012.
type ControlReason uint8

const (
	ControlReasonNone              ControlReason = 0
	ControlReasonAuthorityRevoked  ControlReason = 1
	ControlReasonAuthorityExpired  ControlReason = 2
	ControlReasonAuthorityReplaced ControlReason = 3
)

// ControlExpectations are trusted request-local inputs. Keyset must be the
// exact current object returned by Manager.Verifier. EvaluationTime must come
// from the bridge clock and is evaluated with a closed upper expiry bound.
type ControlExpectations struct {
	Environment    string
	EvaluationTime time.Time
	Keyset         map[string]any
}

// VerifiedAssertion is the persistence-safe projection of an embedded signed
// assertion. It deliberately omits the complete signed object and signature,
// as well as every raw roster, tuple, transport, and provider-topic input.
type VerifiedAssertion struct {
	Hash                   [32]byte
	InstallationBindingID  [16]byte
	SequencerEpoch         [16]byte
	StreamSequence         uint64
	BindingID              [16]byte
	BindingVersion         uint64
	LeaseID                [16]byte
	TupleCommitment        [32]byte
	TupleCommitmentKeyID   [32]byte
	RosterCommitment       [32]byte
	RosterCommitmentKeyID  [32]byte
	TopicBinding           [32]byte
	TopicKeyEpoch          uint32
	TopicCommitmentKeyID   [32]byte
	ConversationGeneration uint32
	RosterVersion          uint32
	IssuedAt               time.Time
	ExpiresAt              time.Time
	SigningKeyID           [32]byte
	KeysetSequence         uint64
	KeysetHash             [32]byte
}

// VerifiedControl is a persistence-safe signed-control projection. Assertion
// is non-nil only for a fully verified UPSERT. A REVOKE therefore conveys only
// denial authority and never synthesizes a positive assertion.
type VerifiedControl struct {
	Environment              string
	IdempotencyKey           string
	InstallationBindingID    [16]byte
	SequencerEpoch           [16]byte
	StreamSequence           uint64
	ExpectedPreviousSequence uint64
	BindingID                [16]byte
	BindingVersion           uint64
	ExpectedBindingVersion   uint64
	Action                   ControlAction
	AssertionHash            [32]byte
	Reason                   ControlReason
	IssuedAt                 time.Time
	ExpiresAt                time.Time
	SigningKeyID             [32]byte
	SignedObjectHash         [32]byte
	KeysetSequence           uint64
	KeysetHash               [32]byte
	Assertion                *VerifiedAssertion
}

// VerifyControl strictly decodes and semantically verifies one complete A9
// control object. Every failure is represented only by a fixed verdict; no
// rejected value or parser/crypto error crosses this API boundary.
func VerifyControl(
	raw []byte,
	expected ControlExpectations,
) (VerifiedControl, Verdict) {
	object, err := a9schema.Decode(a9schema.ControlEventKind, raw)
	if err != nil {
		return VerifiedControl{}, verdictForSchemaError(err)
	}
	if !canonicalWireObject(raw, object) {
		return VerifiedControl{}, Invalid("FIELD_DOMAIN")
	}
	return verifyControlObject(object, expected)
}

func verifyControlObject(
	object map[string]any,
	expected ControlExpectations,
) (VerifiedControl, Verdict) {
	if expected.Environment != "dev" &&
		expected.Environment != "production" {
		return VerifiedControl{}, Inconclusive("KEY_STATE")
	}
	if objectString(object, "environment") != expected.Environment {
		return VerifiedControl{}, Invalid("FIELD_DOMAIN")
	}

	issued, expires, verdict := verifyLiveWindow(
		object,
		expected.EvaluationTime,
		"EXPIRED",
	)
	if !verdict.IsEligible() {
		return VerifiedControl{}, verdict
	}

	streamSequence, verdict := positiveInteger(object["stream_sequence"])
	if !verdict.IsEligible() {
		return VerifiedControl{}, verdict
	}
	expectedPrevious, verdict := nonnegativeInteger(
		object["expected_previous_sequence"],
	)
	if !verdict.IsEligible() {
		return VerifiedControl{}, verdict
	}
	if expectedPrevious == maxIJSONInteger {
		return VerifiedControl{}, Invalid("INTEGER_RANGE")
	}
	if streamSequence != expectedPrevious+1 {
		return VerifiedControl{}, Invalid("FIELD_DOMAIN")
	}

	bindingVersion, verdict := positiveInteger(object["binding_version"])
	if !verdict.IsEligible() {
		return VerifiedControl{}, verdict
	}
	expectedBinding, verdict := nonnegativeInteger(
		object["expected_binding_version"],
	)
	if !verdict.IsEligible() {
		return VerifiedControl{}, verdict
	}
	if expectedBinding == maxIJSONInteger {
		return VerifiedControl{}, Invalid("INTEGER_RANGE")
	}
	if bindingVersion != expectedBinding+1 {
		return VerifiedControl{}, Invalid("FIELD_DOMAIN")
	}

	keysetSequence, keysetHash, verdict := keysetProvenance(
		expected.Keyset,
		expected.Environment,
	)
	if !verdict.IsEligible() {
		return VerifiedControl{}, verdict
	}
	signingKeyID, ok := decodeKeyID(
		objectString(object, "signing_key_id"),
		"ed25519-sha256:",
	)
	if !ok {
		return VerifiedControl{}, Invalid("FIELD_DOMAIN")
	}
	publicKey, verdict := OnlineKeyAt(
		expected.Keyset,
		objectString(object, "signing_key_id"),
		"A9_CONTROL",
		issued,
	)
	if !verdict.IsEligible() {
		return VerifiedControl{}, verdict
	}
	if verdict = VerifyObject(
		object,
		"signature_base64url",
		ControlSignatureDomain,
		publicKey,
	); !verdict.IsEligible() {
		return VerifiedControl{}, verdict
	}

	signedObjectHash, ok := canonicalDigest(object)
	if !ok {
		return VerifiedControl{}, Invalid("FIELD_DOMAIN")
	}
	installationBindingID, ok := decodeFixed16(
		objectString(object, "installation_binding_id"),
	)
	if !ok {
		return VerifiedControl{}, Invalid("NONCANONICAL_BASE64URL")
	}
	sequencerEpoch, ok := decodeFixed16(
		objectString(object, "sequencer_epoch"),
	)
	if !ok {
		return VerifiedControl{}, Invalid("NONCANONICAL_BASE64URL")
	}
	bindingID, ok := decodeFixed16(objectString(object, "binding_id"))
	if !ok {
		return VerifiedControl{}, Invalid("NONCANONICAL_BASE64URL")
	}
	assertionHash, ok := decodeFixed32(
		objectString(object, "assertion_hash"),
	)
	if !ok {
		return VerifiedControl{}, Invalid("NONCANONICAL_BASE64URL")
	}

	verified := VerifiedControl{
		Environment:              expected.Environment,
		IdempotencyKey:           objectString(object, "idempotency_key"),
		InstallationBindingID:    installationBindingID,
		SequencerEpoch:           sequencerEpoch,
		StreamSequence:           streamSequence,
		ExpectedPreviousSequence: expectedPrevious,
		BindingID:                bindingID,
		BindingVersion:           bindingVersion,
		ExpectedBindingVersion:   expectedBinding,
		AssertionHash:            assertionHash,
		IssuedAt:                 issued,
		ExpiresAt:                expires,
		SigningKeyID:             signingKeyID,
		SignedObjectHash:         signedObjectHash,
		KeysetSequence:           keysetSequence,
		KeysetHash:               keysetHash,
	}

	switch objectString(object, "action") {
	case "UPSERT":
		verified.Action = ControlActionUpsert
		assertionObject, ok := object["assertion"].(map[string]any)
		if !ok || object["reason_code"] != nil {
			return VerifiedControl{}, Invalid("FIELD_DOMAIN")
		}
		assertion, assertionVerdict := verifyEmbeddedAssertion(
			assertionObject,
			object,
			expected,
			sequencerEpoch,
			keysetSequence,
			keysetHash,
			bindingVersion,
			streamSequence,
		)
		if !assertionVerdict.IsEligible() {
			return VerifiedControl{}, assertionVerdict
		}
		if subtle.ConstantTimeCompare(
			assertion.Hash[:],
			assertionHash[:],
		) != 1 {
			return VerifiedControl{}, Invalid("ASSERTION_HASH_MISMATCH")
		}
		verified.Assertion = &assertion
	case "REVOKE":
		verified.Action = ControlActionRevoke
		if object["assertion"] != nil {
			return VerifiedControl{}, Invalid("FIELD_DOMAIN")
		}
		switch objectString(object, "reason_code") {
		case "authority_revoked":
			verified.Reason = ControlReasonAuthorityRevoked
		case "authority_expired":
			verified.Reason = ControlReasonAuthorityExpired
		case "authority_replaced":
			verified.Reason = ControlReasonAuthorityReplaced
		default:
			return VerifiedControl{}, Invalid("FIELD_DOMAIN")
		}
	default:
		return VerifiedControl{}, Invalid("FIELD_DOMAIN")
	}

	return verified, Eligible()
}

func verifyEmbeddedAssertion(
	assertion map[string]any,
	control map[string]any,
	expected ControlExpectations,
	sequencerEpoch [16]byte,
	keysetSequence uint64,
	keysetHash [32]byte,
	controlBindingVersion uint64,
	controlStreamSequence uint64,
) (VerifiedAssertion, Verdict) {
	issued, expires, verdict := verifyLiveWindow(
		assertion,
		expected.EvaluationTime,
		"EXPIRED",
	)
	if !verdict.IsEligible() {
		return VerifiedAssertion{}, verdict
	}
	if verdict = ValidateAssertion(assertion, AssertionExpectations{
		Environment:           expected.Environment,
		InstallationBindingID: objectString(control, "installation_binding_id"),
		EvaluationTime:        expected.EvaluationTime,
		Keyset:                expected.Keyset,
	}); !verdict.IsEligible() {
		return VerifiedAssertion{}, verdict
	}

	for _, field := range []string{
		"environment",
		"installation_binding_id",
		"binding_id",
	} {
		if !constantTimeStringEqual(
			objectString(assertion, field),
			objectString(control, field),
		) {
			if field == "installation_binding_id" {
				return VerifiedAssertion{}, Invalid("INSTALLATION_MISMATCH")
			}
			return VerifiedAssertion{}, Invalid("FIELD_DOMAIN")
		}
	}
	assertionBindingVersion, verdict := positiveInteger(
		assertion["binding_version"],
	)
	if !verdict.IsEligible() ||
		assertionBindingVersion != controlBindingVersion {
		return VerifiedAssertion{}, Invalid("FIELD_DOMAIN")
	}
	assertionStreamSequence, verdict := positiveInteger(
		assertion["stream_sequence"],
	)
	if !verdict.IsEligible() ||
		assertionStreamSequence != controlStreamSequence {
		return VerifiedAssertion{}, Invalid("FIELD_DOMAIN")
	}

	assertionHash, ok := canonicalDigest(assertion)
	if !ok {
		return VerifiedAssertion{}, Invalid("FIELD_DOMAIN")
	}
	encodedAssertionHash, ok := decodeFixed32(
		objectString(control, "assertion_hash"),
	)
	if !ok || subtle.ConstantTimeCompare(
		assertionHash[:],
		encodedAssertionHash[:],
	) != 1 {
		return VerifiedAssertion{}, Invalid("ASSERTION_HASH_MISMATCH")
	}

	topicEpoch64, verdict := positiveInteger(assertion["topic_key_epoch"])
	if !verdict.IsEligible() || topicEpoch64 > uint64(^uint32(0)) {
		return VerifiedAssertion{}, Invalid("INTEGER_RANGE")
	}
	topicEpoch := uint32(topicEpoch64)
	_, verdict = commitmentKeyByIDAt(
		expected.Keyset,
		"ROSTER",
		objectString(assertion, "roster_commitment_key_id"),
		nil,
		issued,
	)
	if !verdict.IsEligible() {
		return VerifiedAssertion{}, verdict
	}
	_, verdict = commitmentKeyByIDAt(
		expected.Keyset,
		"TUPLE",
		objectString(assertion, "tuple_commitment_key_id"),
		nil,
		issued,
	)
	if !verdict.IsEligible() {
		return VerifiedAssertion{}, verdict
	}
	topicKey, verdict := CommitmentKeyAt(
		expected.Keyset,
		"TOPIC",
		&topicEpoch,
		issued,
		true,
	)
	if !verdict.IsEligible() {
		return VerifiedAssertion{}, verdict
	}

	installationBindingID, ok := decodeFixed16(
		objectString(assertion, "installation_binding_id"),
	)
	if !ok {
		return VerifiedAssertion{}, Invalid("NONCANONICAL_BASE64URL")
	}
	bindingID, ok := decodeFixed16(objectString(assertion, "binding_id"))
	if !ok {
		return VerifiedAssertion{}, Invalid("NONCANONICAL_BASE64URL")
	}
	leaseID, ok := decodeFixed16(objectString(assertion, "lease_id"))
	if !ok {
		return VerifiedAssertion{}, Invalid("NONCANONICAL_BASE64URL")
	}
	tupleCommitment, ok := decodeFixed32(
		objectString(assertion, "tuple_commitment"),
	)
	if !ok {
		return VerifiedAssertion{}, Invalid("NONCANONICAL_BASE64URL")
	}
	rosterCommitment, ok := decodeFixed32(
		objectString(assertion, "roster_commitment"),
	)
	if !ok {
		return VerifiedAssertion{}, Invalid("NONCANONICAL_BASE64URL")
	}
	topicBinding, ok := decodeFixed32(
		objectString(assertion, "topic_binding"),
	)
	if !ok {
		return VerifiedAssertion{}, Invalid("NONCANONICAL_BASE64URL")
	}
	tupleKeyID, ok := decodeKeyID(
		objectString(assertion, "tuple_commitment_key_id"),
		"hmac-sha256:",
	)
	if !ok {
		return VerifiedAssertion{}, Invalid("FIELD_DOMAIN")
	}
	rosterKeyID, ok := decodeKeyID(
		objectString(assertion, "roster_commitment_key_id"),
		"hmac-sha256:",
	)
	if !ok {
		return VerifiedAssertion{}, Invalid("FIELD_DOMAIN")
	}
	topicKeyID, ok := decodeKeyID(topicKey.KeyID, "hmac-sha256:")
	if !ok {
		return VerifiedAssertion{}, Invalid("KEY_STATE")
	}
	assertionSigningKeyID, ok := decodeKeyID(
		objectString(assertion, "signing_key_id"),
		"ed25519-sha256:",
	)
	if !ok {
		return VerifiedAssertion{}, Invalid("FIELD_DOMAIN")
	}
	conversationGeneration, verdict := positiveInteger(
		assertion["conversation_generation"],
	)
	if !verdict.IsEligible() ||
		conversationGeneration > uint64(^uint32(0)>>1) {
		return VerifiedAssertion{}, Invalid("INTEGER_RANGE")
	}
	rosterVersion, verdict := positiveInteger(assertion["roster_version"])
	if !verdict.IsEligible() || rosterVersion > uint64(^uint32(0)>>1) {
		return VerifiedAssertion{}, Invalid("INTEGER_RANGE")
	}

	return VerifiedAssertion{
		Hash:                   assertionHash,
		InstallationBindingID:  installationBindingID,
		SequencerEpoch:         sequencerEpoch,
		StreamSequence:         assertionStreamSequence,
		BindingID:              bindingID,
		BindingVersion:         assertionBindingVersion,
		LeaseID:                leaseID,
		TupleCommitment:        tupleCommitment,
		TupleCommitmentKeyID:   tupleKeyID,
		RosterCommitment:       rosterCommitment,
		RosterCommitmentKeyID:  rosterKeyID,
		TopicBinding:           topicBinding,
		TopicKeyEpoch:          topicEpoch,
		TopicCommitmentKeyID:   topicKeyID,
		ConversationGeneration: uint32(conversationGeneration),
		RosterVersion:          uint32(rosterVersion),
		IssuedAt:               issued,
		ExpiresAt:              expires,
		SigningKeyID:           assertionSigningKeyID,
		KeysetSequence:         keysetSequence,
		KeysetHash:             keysetHash,
	}, Eligible()
}

func verifyLiveWindow(
	object map[string]any,
	evaluationTime time.Time,
	expiredReason string,
) (time.Time, time.Time, Verdict) {
	issued, ok := parseWireTime(objectString(object, "issued_at"))
	if !ok {
		return time.Time{}, time.Time{}, Invalid("NONCANONICAL_TIME")
	}
	expires, ok := parseWireTime(objectString(object, "expires_at"))
	if !ok {
		return time.Time{}, time.Time{}, Invalid("NONCANONICAL_TIME")
	}
	if !expires.After(issued) || expires.Sub(issued) > 30*time.Second {
		return time.Time{}, time.Time{}, Invalid("FIELD_DOMAIN")
	}
	if evaluationTime.IsZero() ||
		evaluationTime.UTC().Before(issued) {
		return time.Time{}, time.Time{}, Inconclusive("CLOCK_UNCERTAIN")
	}
	if !evaluationTime.UTC().Before(expires) {
		if expiredReason == "WATERMARK_EXPIRED" {
			return time.Time{}, time.Time{}, Inconclusive(expiredReason)
		}
		return time.Time{}, time.Time{}, Invalid(expiredReason)
	}
	return issued, expires, Eligible()
}

func keysetProvenance(
	keyset map[string]any,
	environment string,
) (uint64, [32]byte, Verdict) {
	if keyset == nil ||
		a9schema.Validate(a9schema.KeysetKind, keyset) != nil ||
		objectString(keyset, "environment") != environment {
		return 0, [32]byte{}, Invalid("KEY_STATE")
	}
	sequence, verdict := positiveInteger(keyset["keyset_sequence"])
	if !verdict.IsEligible() {
		return 0, [32]byte{}, Invalid("KEY_STATE")
	}
	hash, ok := canonicalDigest(keyset)
	if !ok {
		return 0, [32]byte{}, Invalid("KEY_STATE")
	}
	return sequence, hash, Eligible()
}

func commitmentKeyByIDAt(
	keyset map[string]any,
	purpose string,
	keyID string,
	topicEpoch *uint32,
	at time.Time,
) (CommitmentKey, Verdict) {
	keys, ok := parseCommitmentKeys(keyset["commitment_keys"])
	if !ok {
		return CommitmentKey{}, Invalid("KEY_STATE")
	}
	var selected *CommitmentKey
	for index := range keys {
		key := &keys[index]
		if key.Purpose != purpose ||
			!constantTimeStringEqual(key.KeyID, keyID) ||
			!sameEpoch(key.TopicKeyEpoch, topicEpoch) {
			continue
		}
		if at.Before(key.NotBefore) || !at.Before(key.NotAfter) ||
			selected != nil {
			return CommitmentKey{}, Invalid("KEY_STATE")
		}
		selected = key
	}
	if selected == nil {
		return CommitmentKey{}, Invalid("KEY_STATE")
	}
	return *selected, Eligible()
}

func canonicalDigest(object map[string]any) ([32]byte, bool) {
	canonical, err := Canonicalize(object)
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(canonical), true
}

func canonicalWireObject(raw []byte, object map[string]any) bool {
	canonical, err := Canonicalize(object)
	return err == nil && bytes.Equal(canonical, raw)
}

func decodeFixed16(value string) ([16]byte, bool) {
	decoded, err := DecodeBase64URL(value, 16)
	if err != nil {
		return [16]byte{}, false
	}
	var fixed [16]byte
	copy(fixed[:], decoded)
	return fixed, true
}

func decodeFixed32(value string) ([32]byte, bool) {
	decoded, err := DecodeBase64URL(value, 32)
	if err != nil {
		return [32]byte{}, false
	}
	var fixed [32]byte
	copy(fixed[:], decoded)
	return fixed, true
}

func decodeKeyID(value, prefix string) ([32]byte, bool) {
	if len(value) != len(prefix)+64 || value[:len(prefix)] != prefix {
		return [32]byte{}, false
	}
	decoded, err := hex.DecodeString(value[len(prefix):])
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, false
	}
	var fixed [32]byte
	copy(fixed[:], decoded)
	return fixed, true
}

func verdictForSchemaError(err error) Verdict {
	terminal, reason, ok := a9schema.Verdict(err)
	if !ok {
		return Invalid("FIELD_DOMAIN")
	}
	return Verdict{Terminal: string(terminal), Reason: string(reason)}
}
