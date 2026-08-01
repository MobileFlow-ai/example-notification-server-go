package a9api

import (
	"bytes"
	"errors"
	"net/http"
	"testing"

	"github.com/xmtp/example-notification-server-go/pkg/a9schema"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

func TestResultMatchesPublishedVector(t *testing.T) {
	positive := readPositive(t)
	published := objectValue(t, positive["vault_cas_result"])
	result := Result{
		Environment:            stringValue(t, published["environment"]),
		InstallationBindingID:  resultFixed16(t, published["installation_binding_id"]),
		SequencerEpoch:         resultFixed16(t, published["sequencer_epoch"]),
		SubscriptionGeneration: integerValue(t, published["subscription_generation"]),
		State:                  ResultState(stringValue(t, published["state"])),
		Outcome:                ResultOutcome(stringValue(t, published["outcome"])),
		AcceptedStreamSequence: integerValue(t, published["accepted_stream_sequence"]),
	}

	got, err := result.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want, err := a9trust.Canonicalize(published)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("canonical result did not match the published vector")
	}
	status, err := result.HTTPStatus()
	if err != nil || status != http.StatusOK {
		t.Fatalf("HTTP status = %d, error = %v", status, err)
	}
}

func TestResultOutcomeStatusAndReplayTruth(t *testing.T) {
	tests := []struct {
		outcome ResultOutcome
		state   ResultState
		status  int
		replay  bool
	}{
		{ResultOutcomeApplied, ResultStateActive, http.StatusOK, false},
		{ResultOutcomeReplay, ResultStateRevoked, http.StatusOK, true},
		{ResultOutcomeStale, ResultStateActive, http.StatusConflict, false},
		{ResultOutcomeGap, ResultStateUncertain, http.StatusConflict, false},
		{ResultOutcomeConflict, ResultStateUncertain, http.StatusConflict, false},
		{ResultOutcomeInconclusive, ResultStateUncertain, http.StatusServiceUnavailable, false},
	}

	for _, test := range tests {
		t.Run(string(test.outcome), func(t *testing.T) {
			result := validTestResult()
			result.State = test.state
			result.Outcome = test.outcome
			raw, err := result.CanonicalJSON()
			if err != nil {
				t.Fatal(err)
			}
			value, err := a9schema.Decode(a9schema.ResultKind, raw)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := a9trust.Canonicalize(value)
			if err != nil || !bytes.Equal(canonical, raw) {
				t.Fatal("result was not the exact canonical schema spelling")
			}
			if replay, ok := value["idempotent_replay"].(bool); !ok ||
				replay != test.replay {
				t.Fatal("idempotent replay truth did not match the outcome")
			}
			status, err := result.HTTPStatus()
			if err != nil || status != test.status {
				t.Fatalf("HTTP status = %d, error = %v", status, err)
			}
		})
	}
}

func TestResultRejectsInvalidStateOutcomeAndBounds(t *testing.T) {
	tests := map[string]func(*Result){
		"environment": func(result *Result) {
			result.Environment = "staging"
		},
		"subscription generation": func(result *Result) {
			result.SubscriptionGeneration = maxSafeInteger + 1
		},
		"stream sequence": func(result *Result) {
			result.AcceptedStreamSequence = maxSafeInteger + 1
		},
		"state": func(result *Result) {
			result.State = ResultState("ABSENT")
		},
		"outcome": func(result *Result) {
			result.Outcome = ResultOutcome("SUCCESS")
		},
		"gap must be uncertain": func(result *Result) {
			result.Outcome = ResultOutcomeGap
		},
		"conflict must be uncertain": func(result *Result) {
			result.Outcome = ResultOutcomeConflict
			result.State = ResultStateRevoked
		},
		"inconclusive must be uncertain": func(result *Result) {
			result.Outcome = ResultOutcomeInconclusive
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := validTestResult()
			mutate(&result)
			if _, err := result.CanonicalJSON(); !errors.Is(
				err,
				ErrInvalidResult,
			) {
				t.Fatalf("CanonicalJSON error = %v", err)
			}
			if _, err := result.HTTPStatus(); !errors.Is(
				err,
				ErrInvalidResult,
			) {
				t.Fatalf("HTTPStatus error = %v", err)
			}
		})
	}
}

func validTestResult() Result {
	var installation, epoch [16]byte
	installation[0] = 1
	epoch[0] = 2
	return Result{
		Environment:            "dev",
		InstallationBindingID:  installation,
		SequencerEpoch:         epoch,
		SubscriptionGeneration: 12,
		State:                  ResultStateActive,
		Outcome:                ResultOutcomeApplied,
		AcceptedStreamSequence: 7,
	}
}

func resultFixed16(t *testing.T, value any) [16]byte {
	t.Helper()
	decoded, err := a9trust.DecodeBase64URL(stringValue(t, value), 16)
	if err != nil {
		t.Fatal(err)
	}
	var fixed [16]byte
	copy(fixed[:], decoded)
	return fixed
}
