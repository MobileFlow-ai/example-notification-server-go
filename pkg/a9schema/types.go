// Package a9schema provides the strict JSON and closed-shape validation used
// by the production A9 v1 adapter and its mirrored conformance vectors.
//
// It deliberately does not verify signatures, commitments, key state, stream
// state, or vault state. Callers must apply those checks after Decode succeeds.
package a9schema

import (
	"errors"
	"fmt"
)

// Kind identifies one of the six closed A9 v1 JSON schemas.
type Kind string

const (
	AssertionKind            Kind = "assertion.schema.json"
	ControlEventKind         Kind = "control_event.schema.json"
	KeysetKind               Kind = "keyset.schema.json"
	ResultKind               Kind = "result.schema.json"
	SubscriptionsReplaceKind Kind = "subscriptions_replace_request.schema.json"
	WatermarkKind            Kind = "watermark.schema.json"
)

// Terminal is a fixed contract terminal verdict.
type Terminal string

const (
	TerminalInvalid Terminal = "INVALID"
)

// Reason is a fixed contract failure reason.
type Reason string

const (
	ReasonFieldDomain                    Reason = "FIELD_DOMAIN"
	ReasonDuplicateKey                   Reason = "DUPLICATE_KEY"
	ReasonUnknownFieldRawRosterForbidden Reason = "UNKNOWN_FIELD_RAW_ROSTER_FORBIDDEN"
	ReasonNoncanonicalBase64URL          Reason = "NONCANONICAL_BASE64URL"
	ReasonNoncanonicalTime               Reason = "NONCANONICAL_TIME"
	ReasonNonIJSONNumber                 Reason = "NON_IJSON_NUMBER"
	ReasonIntegerRange                   Reason = "INTEGER_RANGE"
	ReasonWrongAudience                  Reason = "WRONG_AUDIENCE"
	ReasonWelcomeClosed                  Reason = "WELCOME_CLOSED"
	ReasonTopicResolver                  Reason = "TOPIC_RESOLVER"
	ReasonDuplicateSubscription          Reason = "DUPLICATE_SUBSCRIPTION"
)

// Object is the object representation returned by Decode. It is an alias so
// nested objects interoperate directly with the production trust verifier.
// JSON numbers remain json.Number values so callers never lose their exact
// integer spelling.
type Object = map[string]any

// Failure is a content-free strict-JSON or schema failure. Path identifies
// shape location only; it never includes rejected values.
type Failure struct {
	Terminal Terminal
	Reason   Reason
	Path     string
}

func (f *Failure) Error() string {
	return fmt.Sprintf("a9 schema %s/%s at %s", f.Terminal, f.Reason, f.Path)
}

func failure(reason Reason, path string) error {
	if path == "" {
		path = "$"
	}
	return &Failure{
		Terminal: TerminalInvalid,
		Reason:   reason,
		Path:     path,
	}
}

// Verdict extracts the fixed terminal and reason from a validation failure.
func Verdict(err error) (Terminal, Reason, bool) {
	var validationFailure *Failure
	if !errors.As(err, &validationFailure) {
		return "", "", false
	}
	return validationFailure.Terminal, validationFailure.Reason, true
}

// KindForProtocol maps a fixed v1 protocol discriminator to its schema.
func KindForProtocol(protocol string) (Kind, bool) {
	switch protocol {
	case "hytch.a9-bridge-assertion":
		return AssertionKind, true
	case "hytch.a9-bridge-control":
		return ControlEventKind, true
	case "hytch.a9-bridge-keyset":
		return KeysetKind, true
	case "hytch.a9-vault-cas-result":
		return ResultKind, true
	case "hytch.a9-subscription-replace":
		return SubscriptionsReplaceKind, true
	case "hytch.a9-control-watermark":
		return WatermarkKind, true
	default:
		return "", false
	}
}
