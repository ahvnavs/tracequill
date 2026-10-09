package effective

import (
	"fmt"
	"sort"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
)

// ObjectString converts Claim Object into normalized comparable string.
func ObjectString(obj claims.Object) string {
	switch obj.Kind {
	case "int":
		return fmt.Sprintf("%d", obj.Value)
	case "bool":
		return fmt.Sprintf("%t", obj.Value)
	default:
		return fmt.Sprintf("%v", obj.Value)
	}
}

// ComputeEffectiveStates takes all claims in the ledger, processes retractions via `tq.meta.retracts`,
// partitions by (Subject, Predicate), resolves candidates, evaluates precedence, and returns effective states.
func ComputeEffectiveStates(allClaims []*claims.Claim, asOf time.Time) ([]*EffectiveClaimState, map[string]bool) {
	// 1. Identify retractions via `tq.meta.retracts`
	// A retraction claim has predicate `tq.meta.retracts` and object.value = target_claim_id (or ref).
	retractedClaimIDs := make(map[string]bool)
	for _, c := range allClaims {
		if c.Predicate == "tq.meta.retracts" {
			targetID := fmt.Sprintf("%v", c.Object.Value)
			retractedClaimIDs[targetID] = true
		}
	}

	// 2. Group active claims by (Subject, Predicate)
	type key struct {
		Subject   string
		Predicate string
	}
	grouped := make(map[key][]*claims.Claim)

	for _, c := range allClaims {
		if c.Predicate == "tq.meta.retracts" {
			continue
		}
		// Skip retracted claims
		if retractedClaimIDs[c.ClaimID] {
			continue
		}
		k := key{Subject: c.Subject, Predicate: c.Predicate}
		grouped[k] = append(grouped[k], c)
	}

	var results []*EffectiveClaimState

	// Process each (Subject, Predicate) deterministically
	var sortedKeys []key
	for k := range grouped {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		if sortedKeys[i].Subject == sortedKeys[j].Subject {
			return sortedKeys[i].Predicate < sortedKeys[j].Predicate
		}
		return sortedKeys[i].Subject < sortedKeys[j].Subject
	})

	for _, k := range sortedKeys {
		claimsList := grouped[k]
		if len(claimsList) == 0 {
			continue
		}

		hl := GetPredicateHalfLifeDays(k.Predicate)

		// Sub-group claims by distinct Object value
		byObjectVal := make(map[string][]*claims.Claim)
		for _, c := range claimsList {
			valStr := ObjectString(c.Object)
			byObjectVal[valStr] = append(byObjectVal[valStr], c)
		}

		type candidate struct {
			valStr    string
			objKind   string
			claims    []*claims.Claim
			undecayed float64
			decayed   float64
			isHuman   bool
			isStale   bool
			maxTime   time.Time
		}

		var candidates []candidate
		for valStr, clist := range byObjectVal {
			undec, dec, isH, isS, mTime := ComputeCandidateStrength(clist, asOf, hl)
			candidates = append(candidates, candidate{
				valStr:    valStr,
				objKind:   clist[0].Object.Kind,
				claims:    clist,
				undecayed: undec,
				decayed:   dec,
				isHuman:   isH,
				isStale:   isS,
				maxTime:   mTime,
			})
		}

		// Sort candidates by:
		// 1. isHuman (verified) desc
		// 2. decayed strength desc
		// 3. latest maxTime desc
		// 4. valStr asc (deterministic tie-breaker)
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].isHuman != candidates[j].isHuman {
				return candidates[i].isHuman
			}
			if mathAbsDiff(candidates[i].decayed, candidates[j].decayed) > 1e-9 {
				return candidates[i].decayed > candidates[j].decayed
			}
			if !candidates[i].maxTime.Equal(candidates[j].maxTime) {
				return candidates[i].maxTime.After(candidates[j].maxTime)
			}
			return candidates[i].valStr < candidates[j].valStr
		})

		winner := candidates[0]
		isContested := false
		var contestingClaims []*claims.Claim

		// Check if contested: another candidate exists with competing value and significant strength (>= 0.30 or close)
		if len(candidates) > 1 {
			for _, other := range candidates[1:] {
				if other.decayed >= 0.30 || other.isHuman {
					isContested = true
				}
				contestingClaims = append(contestingClaims, other.claims...)
			}
		}

		// Precedence: verified > contested > corroborated > inferred > observed
		prec := PrecedenceObserved
		if winner.isHuman {
			prec = PrecedenceVerified
		} else if isContested {
			prec = PrecedenceContested
		} else {
			// Check if corroborated: multiple independent source groups
			groups := make(map[string]bool)
			hasInferred := false
			for _, c := range winner.claims {
				groups[c.Source.Group] = true
				if c.Source.Group == "inferred" || c.Source.Method == "inference" {
					hasInferred = true
				}
			}
			if len(groups) > 1 {
				prec = PrecedenceCorroborated
			} else if hasInferred {
				prec = PrecedenceInferred
			} else {
				prec = PrecedenceObserved
			}
		}

		res := &EffectiveClaimState{
			Subject:           k.Subject,
			Predicate:         k.Predicate,
			ObjectKind:        winner.objKind,
			ObjectValue:       winner.valStr,
			Precedence:        prec.String(),
			UndecayedStrength: winner.undecayed,
			DecayedStrength:   winner.decayed,
			StrengthLabel:     StrengthLabel(winner.decayed),
			IsStale:           winner.isStale,
			IsRetracted:       false,
			IsHumanVerified:   winner.isHuman,
			IsContested:       isContested,
			SupportingClaims:  winner.claims,
			ContestingClaims:  contestingClaims,
			LatestObservedAt:  winner.maxTime.Format(time.RFC3339),
		}
		results = append(results, res)
	}

	return results, retractedClaimIDs
}

func mathAbsDiff(a, b float64) float64 {
	if a > b {
		return a - b
	}
	return b - a
}
