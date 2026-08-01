package a9trust

// Verdict is the terminal/reason pair used verbatim by the A9 contract and
// conformance vectors.
type Verdict struct {
	Terminal string
	Reason   string
}

func Eligible() Verdict {
	return Verdict{Terminal: "ELIGIBLE"}
}

func Invalid(reason string) Verdict {
	return Verdict{Terminal: "INVALID", Reason: reason}
}

func Inconclusive(reason string) Verdict {
	return Verdict{Terminal: "INCONCLUSIVE", Reason: reason}
}

func (v Verdict) IsEligible() bool {
	return v.Terminal == "ELIGIBLE"
}

// RequiresKeysetUncertainty reports failures that the runtime must durably
// latch before it can trust another artifact or permit egress. The terminal is
// intentionally not used for this decision: published vectors classify some
// unknown-key failures as INVALID, while a signature-valid artifact that
// references unavailable commitment metadata is INCONCLUSIVE.
func (v Verdict) RequiresKeysetUncertainty() bool {
	return v.Reason == "KEY_STATE" || v.Reason == "KEYSET_ROLLBACK"
}
