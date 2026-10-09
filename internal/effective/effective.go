package effective

import (
	"math"
	"strings"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
)

// Half-lives by category:
// runtime 3d, identity 30d, software 30d, project 90d, coverage 7d
const (
	HalfLifeRuntimeDays  = 3.0
	HalfLifeIdentityDays = 30.0
	HalfLifeSoftwareDays = 30.0
	HalfLifeProjectDays  = 90.0
	HalfLifeCoverageDays = 7.0
)

// Precedence levels
type Precedence int

const (
	PrecedenceObserved Precedence = iota
	PrecedenceInferred
	PrecedenceCorroborated
	PrecedenceContested
	PrecedenceVerified
)

func (p Precedence) String() string {
	switch p {
	case PrecedenceVerified:
		return "verified"
	case PrecedenceContested:
		return "contested"
	case PrecedenceCorroborated:
		return "corroborated"
	case PrecedenceInferred:
		return "inferred"
	default:
		return "observed"
	}
}

// StrengthLabel: High >= .85, Medium >= .60, Low >= .30, Weak otherwise
func StrengthLabel(strength float64) string {
	if strength >= 0.85 {
		return "High"
	}
	if strength >= 0.60 {
		return "Medium"
	}
	if strength >= 0.30 {
		return "Low"
	}
	return "Weak"
}

// GetPredicateHalfLifeDays returns the halflife in days for a predicate.
func GetPredicateHalfLifeDays(predicate string) float64 {
	switch {
	case strings.HasPrefix(predicate, "run."):
		return HalfLifeRuntimeDays
	case strings.HasPrefix(predicate, "coverage."):
		return HalfLifeCoverageDays
	case strings.HasPrefix(predicate, "identity.") || strings.HasPrefix(predicate, "entity.") || predicate == "same_as":
		return HalfLifeIdentityDays
	case strings.HasPrefix(predicate, "package.") || strings.HasPrefix(predicate, "artifact.") || strings.HasPrefix(predicate, "service."):
		return HalfLifeSoftwareDays
	case strings.HasPrefix(predicate, "project.") || strings.HasPrefix(predicate, "dataset."):
		return HalfLifeProjectDays
	default:
		return HalfLifeSoftwareDays
	}
}

// EffectiveClaimState holds the computed effective derived state for an entity's predicate.
type EffectiveClaimState struct {
	Subject           string          `json:"subject"`
	Predicate         string          `json:"predicate"`
	ObjectKind        string          `json:"object_kind"`
	ObjectValue       string          `json:"object_value"`
	Precedence        string          `json:"precedence"`
	UndecayedStrength float64         `json:"undecayed_strength"`
	DecayedStrength   float64         `json:"decayed_strength"`
	StrengthLabel     string          `json:"strength_label"`
	IsStale           bool            `json:"is_stale"`
	IsRetracted       bool            `json:"is_retracted"`
	IsHumanVerified   bool            `json:"is_human_verified"`
	IsContested       bool            `json:"is_contested"`
	SupportingClaims  []*claims.Claim `json:"supporting_claims"`
	ContestingClaims  []*claims.Claim `json:"contesting_claims"`
	LatestObservedAt  string          `json:"latest_observed_at"`
}

// ComputeCandidateStrength computes undecayed and decayed strength for a group of claims sharing the same object value.
// Formula:
// 1. Group claims by Source.Group.
// 2. Per source group: max reliability within the group r_g = max(reliability).
// 3. Across groups: strength = 1 - product(1 - r_g).
// 4. If any claim is human verified (Source.Group == "human" or "verifier"), strength = 1.0, no decay.
// 5. Time decay: strength *= 0.5^(age_days / halflife).
// 6. Stale: decayed_strength < 0.5 * undecayed_strength.
func ComputeCandidateStrength(claimList []*claims.Claim, asOf time.Time, halflifeDays float64) (undecayed float64, decayed float64, isHuman bool, isStale bool, latestTime time.Time) {
	if len(claimList) == 0 {
		return 0, 0, false, false, asOf
	}

	groupMax := make(map[string]float64)
	var maxTime time.Time

	for _, c := range claimList {
		obsTime, err := time.Parse(time.RFC3339, c.ObservedAt)
		if err != nil {
			obsTime = asOf
		}
		if obsTime.After(maxTime) {
			maxTime = obsTime
		}

		if c.Source.Group == "human" || c.Source.Group == "verifier" {
			isHuman = true
		}

		rel, _ := claims.GetSourceReliability(c.Source.Group)
		if rel > groupMax[c.Source.Group] {
			groupMax[c.Source.Group] = rel
		}
	}

	if isHuman {
		return 1.0, 1.0, true, false, maxTime
	}

	// 1 - product(1 - r_g)
	prod := 1.0
	for _, rg := range groupMax {
		prod *= (1.0 - rg)
	}
	undecayed = 1.0 - prod
	if undecayed < 0.0 {
		undecayed = 0.0
	}
	if undecayed > 1.0 {
		undecayed = 1.0
	}

	// Time decay based on latest observation age
	ageDays := asOf.Sub(maxTime).Hours() / 24.0
	if ageDays < 0 {
		ageDays = 0
	}

	decayFactor := math.Pow(0.5, ageDays/halflifeDays)
	decayed = undecayed * decayFactor
	if decayed < 0.0 {
		decayed = 0.0
	}

	// Stale when decayed strength < 50% of undecayed
	if undecayed > 0 && decayed < (0.5*undecayed) {
		isStale = true
	}

	return undecayed, decayed, false, isStale, maxTime
}
