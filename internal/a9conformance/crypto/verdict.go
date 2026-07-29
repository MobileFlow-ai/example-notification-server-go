package crypto

// Verdict is the terminal/reason pair used verbatim by the conformance
// vectors.
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
