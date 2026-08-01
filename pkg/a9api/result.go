package a9api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/xmtp/example-notification-server-go/pkg/a9schema"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

var ErrInvalidResult = errors.New("a9 result invalid")

type ResultState string

const (
	ResultStateActive    ResultState = "ACTIVE"
	ResultStateRevoked   ResultState = "REVOKED"
	ResultStateUncertain ResultState = "UNCERTAIN"
)

type ResultOutcome string

const (
	ResultOutcomeApplied      ResultOutcome = "APPLIED"
	ResultOutcomeReplay       ResultOutcome = "REPLAY"
	ResultOutcomeStale        ResultOutcome = "STALE"
	ResultOutcomeGap          ResultOutcome = "GAP"
	ResultOutcomeConflict     ResultOutcome = "CONFLICT"
	ResultOutcomeInconclusive ResultOutcome = "INCONCLUSIVE"
)

// Result is the only identifier-bearing HTTP response emitted after a
// request has passed service authentication, strict artifact verification,
// and a vault transaction. Protocol, schema version, and replay truth are
// derived rather than caller-controlled.
type Result struct {
	Environment            string
	InstallationBindingID  [16]byte
	SequencerEpoch         [16]byte
	SubscriptionGeneration uint64
	State                  ResultState
	Outcome                ResultOutcome
	AcceptedStreamSequence uint64
}

// CanonicalJSON returns the exact JCS spelling of the closed result schema.
func (result Result) CanonicalJSON() ([]byte, error) {
	if !result.valid() {
		return nil, ErrInvalidResult
	}
	object := map[string]any{
		"protocol":                 "hytch.a9-vault-cas-result",
		"schema_version":           jsonNumber(1),
		"environment":              result.Environment,
		"installation_binding_id":  a9trust.EncodeBase64URL(result.InstallationBindingID[:]),
		"sequencer_epoch":          a9trust.EncodeBase64URL(result.SequencerEpoch[:]),
		"subscription_generation":  jsonNumber(result.SubscriptionGeneration),
		"state":                    string(result.State),
		"outcome":                  string(result.Outcome),
		"accepted_stream_sequence": jsonNumber(result.AcceptedStreamSequence),
		"idempotent_replay":        result.Outcome == ResultOutcomeReplay,
	}
	if err := a9schema.Validate(a9schema.ResultKind, object); err != nil {
		return nil, ErrInvalidResult
	}
	canonical, err := a9trust.Canonicalize(object)
	if err != nil {
		return nil, ErrInvalidResult
	}
	return canonical, nil
}

// HTTPStatus implements the contract's fixed outcome mapping.
func (result Result) HTTPStatus() (int, error) {
	if !result.valid() {
		return 0, ErrInvalidResult
	}
	switch result.Outcome {
	case ResultOutcomeApplied, ResultOutcomeReplay:
		return http.StatusOK, nil
	case ResultOutcomeStale, ResultOutcomeGap, ResultOutcomeConflict:
		return http.StatusConflict, nil
	case ResultOutcomeInconclusive:
		return http.StatusServiceUnavailable, nil
	default:
		return 0, ErrInvalidResult
	}
}

func (result Result) valid() bool {
	if result.Environment != "dev" &&
		result.Environment != "production" {
		return false
	}
	if result.SubscriptionGeneration > maxSafeInteger ||
		result.AcceptedStreamSequence > maxSafeInteger {
		return false
	}
	switch result.State {
	case ResultStateActive, ResultStateRevoked, ResultStateUncertain:
	default:
		return false
	}
	switch result.Outcome {
	case ResultOutcomeApplied,
		ResultOutcomeReplay,
		ResultOutcomeStale:
		return true
	case ResultOutcomeGap,
		ResultOutcomeConflict,
		ResultOutcomeInconclusive:
		return result.State == ResultStateUncertain
	default:
		return false
	}
}

func jsonNumber(value uint64) json.Number {
	return json.Number(strconv.FormatUint(value, 10))
}
