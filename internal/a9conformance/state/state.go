// Package state is a deliberately small, side-effect-free reference model for
// the state-machine rules in the A9 adapter v1 conformance artifact. It is test
// evidence only; the bridge runtime does not import it.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"time"
)

const (
	TerminalApplied      = "APPLIED"
	TerminalReplay       = "REPLAY"
	TerminalEligible     = "ELIGIBLE"
	TerminalInvalid      = "INVALID"
	TerminalInconclusive = "INCONCLUSIVE"
	TerminalStale        = "STALE"
	TerminalRevoked      = "REVOKED"
)

type Verdict struct {
	Terminal string
	Reason   string
}

type receipt struct {
	bodyHash string
	verdict  Verdict
}

// ControlState models only durable state needed to prove ordering, replay, and
// denial-wins behavior. AppliedSequence is the last contiguous positive
// cursor; a revoke received across a gap never advances it.
type ControlState struct {
	AppliedSequence       uint64
	HighestBindingVersion uint64
	Uncertain             bool
	Tombstoned            bool
	receipts              map[string]receipt
}

type ControlEvent struct {
	IdempotencyKey           string
	SignedBody               []byte
	StreamSequence           uint64
	ExpectedPreviousSequence uint64
	BindingVersion           uint64
	ExpectedBindingVersion   uint64
	Action                   string
}

func (s *ControlState) Apply(event ControlEvent) Verdict {
	if s.receipts == nil {
		s.receipts = make(map[string]receipt)
	}
	bodyHash := hash(event.SignedBody)
	if prior, ok := s.receipts[event.IdempotencyKey]; ok {
		if prior.bodyHash == bodyHash {
			return Verdict{Terminal: TerminalReplay, Reason: prior.verdict.Reason}
		}
		s.Uncertain = true
		return Verdict{Terminal: TerminalInconclusive, Reason: "IDEMPOTENCY_CONFLICT"}
	}

	if event.StreamSequence == 0 ||
		event.BindingVersion == 0 ||
		event.StreamSequence != event.ExpectedPreviousSequence+1 ||
		event.BindingVersion != event.ExpectedBindingVersion+1 ||
		(event.Action != "UPSERT" && event.Action != "REVOKE") {
		return Verdict{Terminal: TerminalInvalid, Reason: "FIELD_DOMAIN"}
	}

	if s.Tombstoned && event.Action == "UPSERT" &&
		event.BindingVersion <= s.HighestBindingVersion {
		return Verdict{Terminal: TerminalRevoked, Reason: "TOMBSTONE_WINS"}
	}

	if event.StreamSequence <= s.AppliedSequence {
		return Verdict{Terminal: TerminalStale, Reason: "CONTROL_SEQUENCE_REGRESSION"}
	}

	if event.StreamSequence > s.AppliedSequence+1 {
		s.Uncertain = true
		if event.Action == "REVOKE" && event.BindingVersion > s.HighestBindingVersion {
			s.HighestBindingVersion = event.BindingVersion
			s.Tombstoned = true
			result := Verdict{
				Terminal: TerminalRevoked,
				Reason:   "DENY_APPLIES_AND_UNCERTAINTY_LATCHES",
			}
			s.receipts[event.IdempotencyKey] = receipt{bodyHash: bodyHash, verdict: result}
			return result
		}
		return Verdict{Terminal: TerminalInconclusive, Reason: "CONTROL_GAP"}
	}

	if event.ExpectedPreviousSequence != s.AppliedSequence ||
		event.ExpectedBindingVersion != s.HighestBindingVersion {
		s.Uncertain = true
		return Verdict{Terminal: TerminalInconclusive, Reason: "CONTROL_GAP"}
	}

	s.AppliedSequence = event.StreamSequence
	s.HighestBindingVersion = event.BindingVersion
	result := Verdict{Terminal: TerminalApplied}
	if event.Action == "REVOKE" {
		s.Tombstoned = true
		result = Verdict{Terminal: TerminalRevoked, Reason: "AUTHORITY_REVOKED"}
	}
	s.receipts[event.IdempotencyKey] = receipt{bodyHash: bodyHash, verdict: result}
	return result
}

type WatermarkState struct {
	SequencerEpoch     string
	AppliedSequences   map[uint64]bool
	ContiguousSequence uint64
	WatermarkSequence  uint64
	WatermarkHash      string
	Uncertain          bool
	UncertaintyReason  string
}

type Watermark struct {
	SequencerEpoch                 string
	WatermarkSequence              uint64
	CommittedThroughStreamSequence uint64
	Status                         string
	UncertaintyReason              string
	ExpiresAt                      time.Time
	SignedBody                     []byte
}

func (s *WatermarkState) Apply(mark Watermark, now time.Time) Verdict {
	if mark.Status != "CURRENT" && mark.Status != "UNCERTAIN" {
		return Verdict{Terminal: TerminalInvalid, Reason: "FIELD_DOMAIN"}
	}
	if mark.Status == "CURRENT" && mark.UncertaintyReason != "NONE" {
		return Verdict{Terminal: TerminalInvalid, Reason: "FIELD_DOMAIN"}
	}
	if mark.Status == "UNCERTAIN" &&
		(mark.UncertaintyReason == "" || mark.UncertaintyReason == "NONE") {
		return Verdict{Terminal: TerminalInvalid, Reason: "FIELD_DOMAIN"}
	}
	if mark.SequencerEpoch != s.SequencerEpoch {
		return s.latchUncertainty("EPOCH_MISMATCH")
	}
	if !now.Before(mark.ExpiresAt) {
		return s.latchUncertainty("WATERMARK_EXPIRED")
	}

	bodyHash := hash(mark.SignedBody)
	if mark.WatermarkSequence < s.WatermarkSequence {
		return s.latchUncertainty("WATERMARK_ROLLBACK")
	}
	if mark.WatermarkSequence == s.WatermarkSequence {
		if bodyHash == s.WatermarkHash {
			if s.Uncertain {
				return Verdict{
					Terminal: TerminalInconclusive,
					Reason:   s.uncertaintyReason(),
				}
			}
			return Verdict{Terminal: TerminalReplay}
		}
		return s.latchUncertainty("WATERMARK_ROLLBACK")
	}
	if s.WatermarkSequence != 0 && mark.WatermarkSequence != s.WatermarkSequence+1 {
		return s.latchUncertainty("WATERMARK_GAP")
	}

	if mark.Status == "UNCERTAIN" {
		s.WatermarkSequence = mark.WatermarkSequence
		s.WatermarkHash = bodyHash
		return s.latchUncertainty(mark.UncertaintyReason)
	}
	if s.Uncertain {
		return Verdict{
			Terminal: TerminalInconclusive,
			Reason:   s.uncertaintyReason(),
		}
	}
	if mark.CommittedThroughStreamSequence > s.ContiguousSequence ||
		!containsContiguous(s.AppliedSequences, mark.CommittedThroughStreamSequence) {
		return s.latchUncertainty("WATERMARK_GAP")
	}

	s.WatermarkSequence = mark.WatermarkSequence
	s.WatermarkHash = bodyHash
	return Verdict{Terminal: TerminalApplied}
}

func (s *WatermarkState) latchUncertainty(reason string) Verdict {
	s.Uncertain = true
	s.UncertaintyReason = reason
	return Verdict{Terminal: TerminalInconclusive, Reason: reason}
}

func (s *WatermarkState) uncertaintyReason() string {
	if s.UncertaintyReason == "" {
		return "SOURCE_UNAVAILABLE"
	}
	return s.UncertaintyReason
}

func containsContiguous(applied map[uint64]bool, through uint64) bool {
	for sequence := uint64(1); sequence <= through; sequence++ {
		if !applied[sequence] {
			return false
		}
	}
	return true
}

type Route struct {
	TopicBinding  string
	TopicKeyEpoch uint64
	RouteKeyEpoch uint64
	BindingID     string
	HMACPeriods   []uint64
}

type VaultState struct {
	InstallationBindingID  string
	SubscriptionGeneration uint64
	SequencerEpoch         string
	Routes                 []Route
	TombstonedBindings     map[string]bool
}

type ReplaceRequest struct {
	InstallationBindingID          string
	SequencerEpoch                 string
	ExpectedSubscriptionGeneration uint64
	SubscriptionGeneration         uint64
	Routes                         []Route
	FailAfterValidatingEntry       *int
	CommitAmbiguous                bool
	ConcurrentRevokedBinding       string
}

// Replace validates a complete replacement against a private candidate copy
// and publishes that copy only after every check succeeds. Thus every negative
// path leaves the observable vault state unchanged.
func (s *VaultState) Replace(request ReplaceRequest) Verdict {
	if request.InstallationBindingID != s.InstallationBindingID ||
		request.SequencerEpoch != s.SequencerEpoch {
		return Verdict{Terminal: TerminalInvalid, Reason: "INSTALLATION_MISMATCH"}
	}
	if request.ExpectedSubscriptionGeneration != s.SubscriptionGeneration ||
		request.SubscriptionGeneration != s.SubscriptionGeneration+1 {
		return Verdict{Terminal: TerminalStale, Reason: "SUBSCRIPTION_GENERATION"}
	}

	candidate := append([]Route(nil), request.Routes...)
	seenCAS := make(map[string]bool, len(candidate))
	seenBindings := make(map[string]bool, len(candidate))
	for index, route := range candidate {
		if request.ConcurrentRevokedBinding == route.BindingID ||
			s.TombstonedBindings[route.BindingID] {
			return Verdict{Terminal: TerminalRevoked, Reason: "TOMBSTONE_WINS"}
		}
		key := routeCASKey(request.InstallationBindingID, route)
		if seenCAS[key] || seenBindings[route.BindingID] {
			return Verdict{Terminal: TerminalInvalid, Reason: "DUPLICATE_SUBSCRIPTION"}
		}
		seenCAS[key] = true
		seenBindings[route.BindingID] = true
		for hmacIndex := 1; hmacIndex < len(route.HMACPeriods); hmacIndex++ {
			if route.HMACPeriods[hmacIndex] <= route.HMACPeriods[hmacIndex-1] {
				return Verdict{Terminal: TerminalInvalid, Reason: "HMAC_PERIOD_DUPLICATE"}
			}
		}
		if request.FailAfterValidatingEntry != nil &&
			index == *request.FailAfterValidatingEntry {
			return Verdict{
				Terminal: TerminalInconclusive,
				Reason:   "ATOMIC_ROLLBACK_NO_CHANGE",
			}
		}
	}
	if !sort.SliceIsSorted(candidate, func(i, j int) bool {
		return subscriptionLess(candidate[i], candidate[j])
	}) {
		return Verdict{Terminal: TerminalInvalid, Reason: "SUBSCRIPTION_ORDER"}
	}
	for _, route := range candidate {
		for _, stored := range s.Routes {
			if routeCASKey(request.InstallationBindingID, route) ==
				routeCASKey(request.InstallationBindingID, stored) &&
				route.RouteKeyEpoch < stored.RouteKeyEpoch {
				return Verdict{Terminal: TerminalStale, Reason: "ROUTE_KEY_EPOCH"}
			}
		}
	}
	if request.CommitAmbiguous {
		return Verdict{Terminal: TerminalInconclusive, Reason: "VAULT_COMMIT_AMBIGUOUS"}
	}

	s.Routes = candidate
	s.SubscriptionGeneration = request.SubscriptionGeneration
	return Verdict{Terminal: TerminalApplied}
}

type EgressSnapshot struct {
	Gate6Allowed       bool
	A9Current          bool
	WelcomeAuthorized  bool
	AuthorityAvailable bool
}

func PreEgress(snapshot EgressSnapshot) Verdict {
	if snapshot.WelcomeAuthorized {
		return Verdict{Terminal: TerminalInvalid, Reason: "WELCOME_CLOSED"}
	}
	if !snapshot.Gate6Allowed {
		return Verdict{Terminal: TerminalInconclusive, Reason: "GATE6_DENY"}
	}
	if !snapshot.A9Current || !snapshot.AuthorityAvailable {
		return Verdict{Terminal: TerminalInconclusive, Reason: "A9_NOT_CURRENT"}
	}
	return Verdict{Terminal: TerminalEligible}
}

func Restart(durableAppliedCursorAvailable bool) Verdict {
	if !durableAppliedCursorAvailable {
		return Verdict{Terminal: TerminalInconclusive, Reason: "REPLICA_AMBIGUITY"}
	}
	return Verdict{Terminal: TerminalApplied}
}

func routeCASKey(installationBindingID string, route Route) string {
	return installationBindingID + "\x00" +
		hex.EncodeToString(uint64Bytes(route.TopicKeyEpoch)) + "\x00" +
		route.TopicBinding
}

func subscriptionLess(left, right Route) bool {
	leftTopic, leftTopicErr := base64.RawURLEncoding.DecodeString(left.TopicBinding)
	rightTopic, rightTopicErr := base64.RawURLEncoding.DecodeString(right.TopicBinding)
	if leftTopicErr != nil || rightTopicErr != nil {
		return left.TopicBinding < right.TopicBinding
	}
	if comparison := bytes.Compare(leftTopic, rightTopic); comparison != 0 {
		return comparison < 0
	}
	leftBinding, leftBindingErr := base64.RawURLEncoding.DecodeString(left.BindingID)
	rightBinding, rightBindingErr := base64.RawURLEncoding.DecodeString(right.BindingID)
	if leftBindingErr != nil || rightBindingErr != nil {
		return left.BindingID < right.BindingID
	}
	return bytes.Compare(leftBinding, rightBinding) < 0
}

func uint64Bytes(value uint64) []byte {
	return []byte{
		byte(value >> 56), byte(value >> 48), byte(value >> 40), byte(value >> 32),
		byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value),
	}
}

func hash(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
