package match

import msemver "github.com/Masterminds/semver/v3"

// Interval comparison helpers used by the CPE resolver (CPER) to cross-validate
// OSV ranges against NVD ranges. Ported from Holmes' pkg/match/ranges.go.

// IntervalsAreSubsetOf reports whether every interval in sub has an equivalent
// in super (using the patch-predecessor bridge of intervalsEquivalent). Strict:
// used when the product name does NOT match, to avoid attributing the CPE of an
// unrelated chain-CVE neighbor.
func IntervalsAreSubsetOf(sub, super []Interval) bool {
	if len(sub) == 0 || len(super) == 0 {
		return false
	}
	for _, s := range sub {
		found := false
		for _, sp := range super {
			if intervalsEquivalent(s, sp) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// IntervalsShareConcreteRange reports whether a and b share at least one
// equivalent interval with a concrete bound (not the fully-unbounded "(*, *)").
// A single shared fingerprinted range is strong evidence both sides describe the
// same product — used when the product name matches.
func IntervalsShareConcreteRange(a, b []Interval) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for _, ai := range a {
		if ai.Lower == "*" && ai.Upper == "*" {
			continue // fully-unbounded ranges are too generic to fingerprint
		}
		for _, bj := range b {
			if intervalsEquivalent(ai, bj) {
				return true
			}
		}
	}
	return false
}

func intervalsEquivalent(a, b Interval) bool {
	return boundsEquivalent(a.Lower, a.LowerInc, b.Lower, b.LowerInc) &&
		boundsEquivalent(a.Upper, a.UpperInc, b.Upper, b.UpperInc)
}

// boundsEquivalent decides whether two endpoints describe the same edge. Literal
// match (same value + inclusivity) is the common case; the bridge handles
// "exclusive of X" ≡ "inclusive of patchPred(X)".
func boundsEquivalent(va string, incA bool, vb string, incB bool) bool {
	if va == vb && incA == incB {
		return true
	}
	// Cota sin límite: "[*" ≡ "(*" (y "*]" ≡ "*)"). La inclusividad de ±infinito
	// no cambia el conjunto — no hay versión por debajo/encima de "*".
	if va == "*" && vb == "*" {
		return true
	}
	if va == "*" || vb == "*" {
		return false
	}
	switch {
	case !incA && incB:
		return isPatchSuccessor(va, vb)
	case incA && !incB:
		return isPatchSuccessor(vb, va)
	}
	return false
}

// isPatchSuccessor returns true when x is the patch-level successor of y: same
// major/minor, x.Patch == y.Patch+1, neither carrying a prerelease tag.
func isPatchSuccessor(x, y string) bool {
	xv, err := msemver.NewVersion(x)
	if err != nil {
		return false
	}
	yv, err := msemver.NewVersion(y)
	if err != nil {
		return false
	}
	if xv.Prerelease() != "" || yv.Prerelease() != "" {
		return false
	}
	return xv.Major() == yv.Major() &&
		xv.Minor() == yv.Minor() &&
		xv.Patch() == yv.Patch()+1
}
