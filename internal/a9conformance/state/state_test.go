package state

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

type negativeFile struct {
	Vectors []negativeVector `json:"vectors"`
}

type negativeVector struct {
	ID       string          `json:"id"`
	Mutation json.RawMessage `json:"mutation"`
	Expected Verdict         `json:"expected"`
}

type positiveFile struct {
	ControlUpsert struct {
		Value controlFixture `json:"value"`
	} `json:"control_upsert"`
	WatermarkCurrent struct {
		Value watermarkFixture `json:"value"`
	} `json:"watermark_current"`
	SubscriptionReplace struct {
		Value replaceFixture `json:"value"`
	} `json:"subscription_replace"`
}

type controlFixture struct {
	ID                    string `json:"idempotency_key"`
	StreamSequence        uint64 `json:"stream_sequence"`
	ExpectedPrevious      uint64 `json:"expected_previous_sequence"`
	BindingVersion        uint64 `json:"binding_version"`
	ExpectedBinding       uint64 `json:"expected_binding_version"`
	Action                string `json:"action"`
	InstallationBindingID string `json:"installation_binding_id"`
	SequencerEpoch        string `json:"sequencer_epoch"`
}

type watermarkFixture struct {
	SequencerEpoch        string `json:"sequencer_epoch"`
	WatermarkSequence     uint64 `json:"watermark_sequence"`
	CommittedThrough      uint64 `json:"committed_through_stream_sequence"`
	Status                string `json:"status"`
	UncertaintyReason     string `json:"uncertainty_reason"`
	ExpiresAt             string `json:"expires_at"`
	InstallationBindingID string `json:"installation_binding_id"`
}

type replaceFixture struct {
	InstallationBindingID          string         `json:"installation_binding_id"`
	SequencerEpoch                 string         `json:"sequencer_epoch"`
	ExpectedSubscriptionGeneration uint64         `json:"expected_subscription_generation"`
	SubscriptionGeneration         uint64         `json:"subscription_generation"`
	Subscriptions                  []routeFixture `json:"subscriptions"`
}

type routeFixture struct {
	TopicBinding  string `json:"topic_binding"`
	TopicKeyEpoch uint64 `json:"topic_key_epoch"`
	RouteKeyEpoch uint64 `json:"route_key_epoch"`
	BindingID     string `json:"binding_id"`
	HMACKeys      []struct {
		Period uint64 `json:"thirty_day_periods_since_epoch"`
	} `json:"hmac_keys"`
}

func TestPositiveControlWatermarkCASAndPreEgress(t *testing.T) {
	positive := readPositive(t)
	control := positive.ControlUpsert.Value
	controlState := ControlState{
		AppliedSequence:       control.ExpectedPrevious,
		HighestBindingVersion: control.ExpectedBinding,
	}
	controlVerdict := controlState.Apply(ControlEvent{
		IdempotencyKey:           control.ID,
		SignedBody:               []byte("positive-control-signed-bytes"),
		StreamSequence:           control.StreamSequence,
		ExpectedPreviousSequence: control.ExpectedPrevious,
		BindingVersion:           control.BindingVersion,
		ExpectedBindingVersion:   control.ExpectedBinding,
		Action:                   control.Action,
	})
	requireVerdict(t, controlVerdict, Verdict{Terminal: TerminalApplied})

	watermark := positive.WatermarkCurrent.Value
	expiresAt := mustTime(t, watermark.ExpiresAt)
	applied := make(map[uint64]bool, watermark.CommittedThrough)
	for sequence := uint64(1); sequence <= watermark.CommittedThrough; sequence++ {
		applied[sequence] = true
	}
	watermarkState := WatermarkState{
		SequencerEpoch:     watermark.SequencerEpoch,
		AppliedSequences:   applied,
		ContiguousSequence: watermark.CommittedThrough,
		WatermarkSequence:  watermark.WatermarkSequence - 1,
	}
	watermarkVerdict := watermarkState.Apply(Watermark{
		SequencerEpoch:                 watermark.SequencerEpoch,
		WatermarkSequence:              watermark.WatermarkSequence,
		CommittedThroughStreamSequence: watermark.CommittedThrough,
		Status:                         watermark.Status,
		UncertaintyReason:              watermark.UncertaintyReason,
		ExpiresAt:                      expiresAt,
		SignedBody:                     []byte("positive-watermark-signed-bytes"),
	}, expiresAt.Add(-time.Millisecond))
	requireVerdict(t, watermarkVerdict, Verdict{Terminal: TerminalApplied})

	replace := positive.SubscriptionReplace.Value
	routes := fixtureRoutes(replace.Subscriptions)
	vault := VaultState{
		InstallationBindingID:  replace.InstallationBindingID,
		SubscriptionGeneration: replace.ExpectedSubscriptionGeneration,
		SequencerEpoch:         replace.SequencerEpoch,
		TombstonedBindings:     make(map[string]bool),
	}
	replaceVerdict := vault.Replace(ReplaceRequest{
		InstallationBindingID:          replace.InstallationBindingID,
		SequencerEpoch:                 replace.SequencerEpoch,
		ExpectedSubscriptionGeneration: replace.ExpectedSubscriptionGeneration,
		SubscriptionGeneration:         replace.SubscriptionGeneration,
		Routes:                         routes,
	})
	requireVerdict(t, replaceVerdict, Verdict{Terminal: TerminalApplied})
	if vault.SubscriptionGeneration != replace.SubscriptionGeneration {
		t.Fatalf("generation = %d, want %d", vault.SubscriptionGeneration, replace.SubscriptionGeneration)
	}
	requireVerdict(t, PreEgress(EgressSnapshot{
		Gate6Allowed:       true,
		A9Current:          true,
		AuthorityAvailable: true,
	}), Verdict{Terminal: TerminalEligible})
}

func TestControlNegativeVerdictsAndDenialWins(t *testing.T) {
	positive := readPositive(t)
	negatives := readNegatives(t)
	base := positive.ControlUpsert.Value

	t.Run("control_gap_upsert", func(t *testing.T) {
		state := ControlState{AppliedSequence: 5, HighestBindingVersion: base.ExpectedBinding}
		got := state.Apply(baseControlEvent(base))
		requireVectorVerdict(t, negatives, "control_gap_upsert", got)
		if state.AppliedSequence != 5 || !state.Uncertain {
			t.Fatalf("gap mutated cursor or failed to latch uncertainty: %+v", state)
		}
	})

	t.Run("control_sequence_regression", func(t *testing.T) {
		state := ControlState{AppliedSequence: 8, HighestBindingVersion: base.BindingVersion}
		got := state.Apply(baseControlEvent(base))
		requireVectorVerdict(t, negatives, "control_sequence_regression", got)
		if state.AppliedSequence != 8 {
			t.Fatalf("regression moved cursor to %d", state.AppliedSequence)
		}
	})

	t.Run("revoke_across_gap", func(t *testing.T) {
		state := ControlState{AppliedSequence: 2, HighestBindingVersion: base.ExpectedBinding}
		event := baseControlEvent(base)
		event.Action = "REVOKE"
		got := state.Apply(event)
		requireVectorVerdict(t, negatives, "revoke_across_gap", got)
		if state.AppliedSequence != 2 || !state.Uncertain || !state.Tombstoned {
			t.Fatalf("denial-wins invariant failed: %+v", state)
		}
	})

	t.Run("idempotency_key_different_body", func(t *testing.T) {
		state := ControlState{
			AppliedSequence:       base.ExpectedPrevious,
			HighestBindingVersion: base.ExpectedBinding,
		}
		first := baseControlEvent(base)
		requireVerdict(t, state.Apply(first), Verdict{Terminal: TerminalApplied})
		first.SignedBody = []byte("different-signed-bytes")
		got := state.Apply(first)
		requireVectorVerdict(t, negatives, "idempotency_key_different_body", got)
		if !state.Uncertain {
			t.Fatal("idempotency conflict did not latch uncertainty")
		}
	})

	t.Run("upsert_after_tombstone", func(t *testing.T) {
		state := ControlState{
			AppliedSequence:       base.ExpectedPrevious,
			HighestBindingVersion: base.BindingVersion,
			Tombstoned:            true,
		}
		got := state.Apply(baseControlEvent(base))
		requireVectorVerdict(t, negatives, "upsert_after_tombstone", got)
	})
}

func TestWatermarkGapExpiryRollbackUncertaintyAndEpochChange(t *testing.T) {
	positive := readPositive(t)
	negatives := readNegatives(t)
	base := positive.WatermarkCurrent.Value
	expiresAt := mustTime(t, base.ExpiresAt)
	allApplied := map[uint64]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true}

	testCases := []struct {
		id    string
		state WatermarkState
		mark  Watermark
		now   time.Time
	}{
		{
			id:    "watermark_expired",
			state: watermarkState(base, allApplied, 40),
			mark:  baseWatermark(base),
			now:   expiresAt,
		},
		{
			id: "watermark_max_seen_with_gap",
			state: WatermarkState{
				SequencerEpoch:     base.SequencerEpoch,
				AppliedSequences:   map[uint64]bool{1: true, 2: true, 4: true, 5: true, 6: true, 7: true},
				ContiguousSequence: 2,
				WatermarkSequence:  40,
			},
			mark: baseWatermark(base),
			now:  expiresAt.Add(-time.Millisecond),
		},
		{
			id:    "watermark_sequence_rollback",
			state: watermarkState(base, allApplied, 42),
			mark:  baseWatermark(base),
			now:   expiresAt.Add(-time.Millisecond),
		},
		{
			id:    "watermark_uncertain",
			state: watermarkState(base, allApplied, 40),
			mark: func() Watermark {
				mark := baseWatermark(base)
				mark.Status = "UNCERTAIN"
				mark.UncertaintyReason = "SOURCE_UNAVAILABLE"
				return mark
			}(),
			now: expiresAt.Add(-time.Millisecond),
		},
		{
			id:    "sequencer_epoch_change",
			state: watermarkState(base, allApplied, 40),
			mark: func() Watermark {
				mark := baseWatermark(base)
				mark.SequencerEpoch = "Pz49PDs6OTg3NjU0MzIxMA"
				return mark
			}(),
			now: expiresAt.Add(-time.Millisecond),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.id, func(t *testing.T) {
			got := testCase.state.Apply(testCase.mark, testCase.now)
			requireVectorVerdict(t, negatives, testCase.id, got)
		})
	}
}

func TestRestartAmbiguityNeverBecomesValidZero(t *testing.T) {
	requireVectorVerdict(t, readNegatives(t), "restart_ambiguity", Restart(false))
}

func TestUncertainWatermarkCannotResetOrSelfRecover(t *testing.T) {
	positive := readPositive(t)
	base := positive.WatermarkCurrent.Value
	expiresAt := mustTime(t, base.ExpiresAt)
	allApplied := map[uint64]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true}

	t.Run("rollback uncertain does not reset sequence", func(t *testing.T) {
		state := watermarkState(base, allApplied, 42)
		mark := baseWatermark(base)
		mark.Status = "UNCERTAIN"
		mark.UncertaintyReason = "SOURCE_UNAVAILABLE"
		mark.WatermarkSequence = 1
		got := state.Apply(mark, expiresAt.Add(-time.Millisecond))
		requireVerdict(t, got, Verdict{
			Terminal: TerminalInconclusive,
			Reason:   "WATERMARK_ROLLBACK",
		})
		if state.WatermarkSequence != 42 {
			t.Fatalf("rollback reset watermark sequence to %d", state.WatermarkSequence)
		}
	})

	t.Run("current cannot clear same epoch uncertainty", func(t *testing.T) {
		state := watermarkState(base, allApplied, 40)
		uncertain := baseWatermark(base)
		uncertain.Status = "UNCERTAIN"
		uncertain.UncertaintyReason = "SOURCE_UNAVAILABLE"
		requireVerdict(t, state.Apply(uncertain, expiresAt.Add(-time.Millisecond)), Verdict{
			Terminal: TerminalInconclusive,
			Reason:   "SOURCE_UNAVAILABLE",
		})
		current := baseWatermark(base)
		current.WatermarkSequence++
		current.SignedBody = []byte("next-current-watermark")
		requireVerdict(t, state.Apply(current, expiresAt.Add(-time.Millisecond)), Verdict{
			Terminal: TerminalInconclusive,
			Reason:   "SOURCE_UNAVAILABLE",
		})
		if state.WatermarkSequence != base.WatermarkSequence {
			t.Fatalf("CURRENT advanced an uncertain state to %d", state.WatermarkSequence)
		}
	})
}

func TestVaultCASOrderingRollbackAmbiguityAndRevokeRace(t *testing.T) {
	positive := readPositive(t)
	negatives := readNegatives(t)
	fixture := positive.SubscriptionReplace.Value
	baseRoutes := fixtureRoutes(fixture.Subscriptions)
	oldRoutes := append([]Route(nil), baseRoutes...)
	oldRoutes[0].RouteKeyEpoch = baseRoutes[0].RouteKeyEpoch

	newVault := func() VaultState {
		return VaultState{
			InstallationBindingID:  fixture.InstallationBindingID,
			SubscriptionGeneration: fixture.ExpectedSubscriptionGeneration,
			SequencerEpoch:         fixture.SequencerEpoch,
			Routes:                 append([]Route(nil), oldRoutes...),
			TombstonedBindings:     make(map[string]bool),
		}
	}
	request := func() ReplaceRequest {
		return ReplaceRequest{
			InstallationBindingID:          fixture.InstallationBindingID,
			SequencerEpoch:                 fixture.SequencerEpoch,
			ExpectedSubscriptionGeneration: fixture.ExpectedSubscriptionGeneration,
			SubscriptionGeneration:         fixture.SubscriptionGeneration,
			Routes:                         append([]Route(nil), baseRoutes...),
		}
	}

	t.Run("route_key_epoch_rollback", func(t *testing.T) {
		vault := newVault()
		vault.Routes[0].RouteKeyEpoch = baseRoutes[0].RouteKeyEpoch + 1
		before := cloneVault(vault)
		got := vault.Replace(request())
		requireVectorVerdict(t, negatives, "route_key_epoch_rollback", got)
		requireVaultUnchanged(t, before, vault)
	})

	t.Run("partial_cas_failure", func(t *testing.T) {
		vault := newVault()
		before := cloneVault(vault)
		failAt := 0
		input := request()
		input.FailAfterValidatingEntry = &failAt
		got := vault.Replace(input)
		requireVectorVerdict(t, negatives, "partial_cas_failure", got)
		requireVaultUnchanged(t, before, vault)
	})

	t.Run("vault_commit_ambiguous", func(t *testing.T) {
		vault := newVault()
		before := cloneVault(vault)
		input := request()
		input.CommitAmbiguous = true
		got := vault.Replace(input)
		requireVectorVerdict(t, negatives, "vault_commit_ambiguous", got)
		requireVaultUnchanged(t, before, vault)
	})

	t.Run("revoke_refresh_race", func(t *testing.T) {
		vault := newVault()
		before := cloneVault(vault)
		input := request()
		input.ConcurrentRevokedBinding = baseRoutes[0].BindingID
		got := vault.Replace(input)
		requireVectorVerdict(t, negatives, "revoke_refresh_race", got)
		requireVaultUnchanged(t, before, vault)
	})

	t.Run("sender_hmac_period_duplicate", func(t *testing.T) {
		vault := newVault()
		before := cloneVault(vault)
		input := request()
		input.Routes[0].HMACPeriods = []uint64{688, 688}
		got := vault.Replace(input)
		requireVectorVerdict(t, negatives, "sender_hmac_period_duplicate", got)
		requireVaultUnchanged(t, before, vault)
	})

	t.Run("unsorted_subscriptions", func(t *testing.T) {
		vault := newVault()
		before := cloneVault(vault)
		input := request()
		first := input.Routes[0]
		first.TopicBinding = "X0gxiybdqEF1ebTXFHzdJ14k6W5rr32-6xp5lo9Xoow"
		first.BindingID = "ICIjJCUmJygpKissLS4vLw"
		input.Routes = []Route{first, input.Routes[0]}
		got := vault.Replace(input)
		requireVectorVerdict(t, negatives, "unsorted_subscriptions", got)
		requireVaultUnchanged(t, before, vault)
	})
}

func TestGate6AndA9AreIndependentPreEgressConjuncts(t *testing.T) {
	negatives := readNegatives(t)
	got := PreEgress(EgressSnapshot{
		Gate6Allowed:       false,
		A9Current:          true,
		AuthorityAvailable: true,
	})
	requireVectorVerdict(t, negatives, "gate6_independent_deny", got)

	got = PreEgress(EgressSnapshot{
		Gate6Allowed:       true,
		A9Current:          false,
		AuthorityAvailable: true,
	})
	requireVerdict(t, got, Verdict{Terminal: TerminalInconclusive, Reason: "A9_NOT_CURRENT"})
}

func baseControlEvent(base controlFixture) ControlEvent {
	return ControlEvent{
		IdempotencyKey:           base.ID,
		SignedBody:               []byte("positive-control-signed-bytes"),
		StreamSequence:           base.StreamSequence,
		ExpectedPreviousSequence: base.ExpectedPrevious,
		BindingVersion:           base.BindingVersion,
		ExpectedBindingVersion:   base.ExpectedBinding,
		Action:                   base.Action,
	}
}

func baseWatermark(base watermarkFixture) Watermark {
	return Watermark{
		SequencerEpoch:                 base.SequencerEpoch,
		WatermarkSequence:              base.WatermarkSequence,
		CommittedThroughStreamSequence: base.CommittedThrough,
		Status:                         base.Status,
		UncertaintyReason:              base.UncertaintyReason,
		ExpiresAt:                      mustTimeNoTest(base.ExpiresAt),
		SignedBody:                     []byte("positive-watermark-signed-bytes"),
	}
}

func watermarkState(base watermarkFixture, applied map[uint64]bool, sequence uint64) WatermarkState {
	return WatermarkState{
		SequencerEpoch:     base.SequencerEpoch,
		AppliedSequences:   applied,
		ContiguousSequence: base.CommittedThrough,
		WatermarkSequence:  sequence,
	}
}

func fixtureRoutes(fixtures []routeFixture) []Route {
	routes := make([]Route, len(fixtures))
	for index, fixture := range fixtures {
		routes[index] = Route{
			TopicBinding:  fixture.TopicBinding,
			TopicKeyEpoch: fixture.TopicKeyEpoch,
			RouteKeyEpoch: fixture.RouteKeyEpoch,
			BindingID:     fixture.BindingID,
			HMACPeriods:   make([]uint64, len(fixture.HMACKeys)),
		}
		for hmacIndex, key := range fixture.HMACKeys {
			routes[index].HMACPeriods[hmacIndex] = key.Period
		}
	}
	return routes
}

func cloneVault(vault VaultState) VaultState {
	cloned := vault
	cloned.Routes = cloneRoutes(vault.Routes)
	cloned.TombstonedBindings = make(map[string]bool, len(vault.TombstonedBindings))
	for key, value := range vault.TombstonedBindings {
		cloned.TombstonedBindings[key] = value
	}
	return cloned
}

func cloneRoutes(routes []Route) []Route {
	cloned := make([]Route, len(routes))
	for index, route := range routes {
		cloned[index] = route
		cloned[index].HMACPeriods = append([]uint64(nil), route.HMACPeriods...)
	}
	return cloned
}

func requireVaultUnchanged(t *testing.T, want, got VaultState) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("vault changed on negative outcome:\n got: %+v\nwant: %+v", got, want)
	}
}

func requireVectorVerdict(t *testing.T, vectors map[string]negativeVector, id string, got Verdict) {
	t.Helper()
	vector, ok := vectors[id]
	if !ok {
		t.Fatalf("negative vector %q not found", id)
	}
	requireVerdict(t, got, vector.Expected)
}

func requireVerdict(t *testing.T, got, want Verdict) {
	t.Helper()
	if got != want {
		t.Fatalf("verdict = %+v, want %+v", got, want)
	}
}

func readPositive(t *testing.T) positiveFile {
	t.Helper()
	var positive positiveFile
	readJSON(t, "../../../contracts/xmtp_push/a9_adapter/v1/vectors/positive.json", &positive)
	return positive
}

func readNegatives(t *testing.T) map[string]negativeVector {
	t.Helper()
	var file negativeFile
	readJSON(t, "../../../contracts/xmtp_push/a9_adapter/v1/vectors/negative.json", &file)
	vectors := make(map[string]negativeVector, len(file.Vectors))
	for _, vector := range file.Vectors {
		if _, exists := vectors[vector.ID]; exists {
			t.Fatalf("duplicate negative vector id %q", vector.ID)
		}
		vectors[vector.ID] = vector
	}
	return vectors
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}

func mustTimeNoTest(value string) time.Time {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil {
		panic(err)
	}
	return parsed
}
