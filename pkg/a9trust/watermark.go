package a9trust

import (
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9schema"
)

// WatermarkStatus is the durable numeric representation used by migration
// 00012.
type WatermarkStatus uint8

const (
	WatermarkStatusCurrent   WatermarkStatus = 1
	WatermarkStatusUncertain WatermarkStatus = 2
)

// WatermarkUncertaintyReason is meaningful only for an UNCERTAIN watermark.
// The values intentionally match migration 00012.
type WatermarkUncertaintyReason uint8

const (
	WatermarkUncertaintyNone              WatermarkUncertaintyReason = 0
	WatermarkUncertaintySourceUnavailable WatermarkUncertaintyReason = 1
	WatermarkUncertaintyOutboxGap         WatermarkUncertaintyReason = 2
	WatermarkUncertaintyReplicaAmbiguity  WatermarkUncertaintyReason = 3
	WatermarkUncertaintyOverflow          WatermarkUncertaintyReason = 4
	WatermarkUncertaintyClock             WatermarkUncertaintyReason = 5
)

// WatermarkExpectations are trusted request-local inputs. Keyset must be the
// exact current object returned by Manager.Verifier.
type WatermarkExpectations struct {
	Environment    string
	EvaluationTime time.Time
	Keyset         map[string]any
}

// VerifiedWatermark is a persistence-safe signed-watermark projection. It
// omits canonical signed bytes and the signature itself; SignedObjectHash is
// the replay/conflict fence.
type VerifiedWatermark struct {
	Environment                    string
	InstallationBindingID          [16]byte
	SequencerEpoch                 [16]byte
	WatermarkSequence              uint64
	CommittedThroughStreamSequence uint64
	Status                         WatermarkStatus
	UncertaintyReason              WatermarkUncertaintyReason
	IssuedAt                       time.Time
	ExpiresAt                      time.Time
	SigningKeyID                   [32]byte
	SignedObjectHash               [32]byte
	KeysetSequence                 uint64
	KeysetHash                     [32]byte
}

// VerifyWatermark strictly decodes and semantically verifies one complete A9
// watermark object. Monotonic sequence, equal-sequence replay, epoch matching,
// and contiguous-control coverage deliberately remain vault responsibilities.
//
// A valid signed UNCERTAIN object returns a populated VerifiedWatermark plus
// its fixed INCONCLUSIVE verdict so the caller can atomically persist the
// denial latch without treating it as a positive watermark.
func VerifyWatermark(
	raw []byte,
	expected WatermarkExpectations,
) (VerifiedWatermark, Verdict) {
	object, err := a9schema.Decode(a9schema.WatermarkKind, raw)
	if err != nil {
		return VerifiedWatermark{}, verdictForSchemaError(err)
	}
	if !canonicalWireObject(raw, object) {
		return VerifiedWatermark{}, Invalid("FIELD_DOMAIN")
	}
	return verifyWatermarkObject(object, expected)
}

func verifyWatermarkObject(
	object map[string]any,
	expected WatermarkExpectations,
) (VerifiedWatermark, Verdict) {
	if expected.Environment != "dev" &&
		expected.Environment != "production" {
		return VerifiedWatermark{}, Inconclusive("KEY_STATE")
	}
	if objectString(object, "environment") != expected.Environment {
		return VerifiedWatermark{}, Invalid("FIELD_DOMAIN")
	}

	issued, expires, verdict := verifyLiveWindow(
		object,
		expected.EvaluationTime,
		"WATERMARK_EXPIRED",
	)
	if !verdict.IsEligible() {
		return VerifiedWatermark{}, verdict
	}

	watermarkSequence, verdict := positiveInteger(
		object["watermark_sequence"],
	)
	if !verdict.IsEligible() {
		return VerifiedWatermark{}, verdict
	}
	committedThrough, verdict := nonnegativeInteger(
		object["committed_through_stream_sequence"],
	)
	if !verdict.IsEligible() {
		return VerifiedWatermark{}, verdict
	}

	keysetSequence, keysetHash, verdict := keysetProvenance(
		expected.Keyset,
		expected.Environment,
	)
	if !verdict.IsEligible() {
		return VerifiedWatermark{}, verdict
	}
	signingKeyID, ok := decodeKeyID(
		objectString(object, "signing_key_id"),
		"ed25519-sha256:",
	)
	if !ok {
		return VerifiedWatermark{}, Invalid("FIELD_DOMAIN")
	}
	publicKey, verdict := OnlineKeyAt(
		expected.Keyset,
		objectString(object, "signing_key_id"),
		"A9_CONTROL",
		issued,
	)
	if !verdict.IsEligible() {
		return VerifiedWatermark{}, verdict
	}
	if verdict = VerifyObject(
		object,
		"signature_base64url",
		WatermarkSignatureDomain,
		publicKey,
	); !verdict.IsEligible() {
		return VerifiedWatermark{}, verdict
	}

	signedObjectHash, ok := canonicalDigest(object)
	if !ok {
		return VerifiedWatermark{}, Invalid("FIELD_DOMAIN")
	}
	installationBindingID, ok := decodeFixed16(
		objectString(object, "installation_binding_id"),
	)
	if !ok {
		return VerifiedWatermark{}, Invalid("NONCANONICAL_BASE64URL")
	}
	sequencerEpoch, ok := decodeFixed16(
		objectString(object, "sequencer_epoch"),
	)
	if !ok {
		return VerifiedWatermark{}, Invalid("NONCANONICAL_BASE64URL")
	}

	verified := VerifiedWatermark{
		Environment:                    expected.Environment,
		InstallationBindingID:          installationBindingID,
		SequencerEpoch:                 sequencerEpoch,
		WatermarkSequence:              watermarkSequence,
		CommittedThroughStreamSequence: committedThrough,
		IssuedAt:                       issued,
		ExpiresAt:                      expires,
		SigningKeyID:                   signingKeyID,
		SignedObjectHash:               signedObjectHash,
		KeysetSequence:                 keysetSequence,
		KeysetHash:                     keysetHash,
	}

	switch objectString(object, "status") {
	case "CURRENT":
		if objectString(object, "uncertainty_reason") != "NONE" {
			return VerifiedWatermark{}, Invalid("FIELD_DOMAIN")
		}
		verified.Status = WatermarkStatusCurrent
		verified.UncertaintyReason = WatermarkUncertaintyNone
		return verified, Eligible()
	case "UNCERTAIN":
		verified.Status = WatermarkStatusUncertain
		switch objectString(object, "uncertainty_reason") {
		case "SOURCE_UNAVAILABLE":
			verified.UncertaintyReason =
				WatermarkUncertaintySourceUnavailable
		case "OUTBOX_GAP":
			verified.UncertaintyReason =
				WatermarkUncertaintyOutboxGap
		case "REPLICA_AMBIGUITY":
			verified.UncertaintyReason =
				WatermarkUncertaintyReplicaAmbiguity
		case "OVERFLOW":
			verified.UncertaintyReason =
				WatermarkUncertaintyOverflow
		case "CLOCK_UNCERTAIN":
			verified.UncertaintyReason =
				WatermarkUncertaintyClock
		default:
			return VerifiedWatermark{}, Invalid("FIELD_DOMAIN")
		}
		return verified, Inconclusive(
			objectString(object, "uncertainty_reason"),
		)
	default:
		return VerifiedWatermark{}, Invalid("FIELD_DOMAIN")
	}
}
