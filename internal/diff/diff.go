package diff

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/effective"
	"github.com/OWNER/bokuei/internal/store"
)

// DiffChange represents a single detected difference between two runs or time points.
type DiffChange struct {
	Subject       string          `json:"subject"`
	Predicate     string          `json:"predicate"`
	OldValue      string          `json:"old_value"`
	NewValue      string          `json:"new_value"`
	Status        string          `json:"status"` // "changed", "added", "not comparable", "stale_drop"
	OldPrecedence string          `json:"old_precedence"`
	NewPrecedence string          `json:"new_precedence"`
	Category      string          `json:"category"`
	ClaimsA       []*claims.Claim `json:"claims_a,omitempty"`
	ClaimsB       []*claims.Claim `json:"claims_b,omitempty"`
}

// CauseRule defines a ranking rule loaded from rules/causes.json.
type CauseRule struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Category       string `json:"category"`
	BaseWeight     int    `json:"base_weight"`
	MatchPredicate string `json:"match_predicate"`
	SubjectPrefix  string `json:"subject_prefix,omitempty"`
	ObjectPattern  string `json:"object_pattern,omitempty"`
	Explanation    string `json:"explanation"`
}

// RankedCause represents an attributed root cause explaining the diff.
type RankedCause struct {
	Rank             int             `json:"rank"`
	Weight           int             `json:"weight"`
	Category         string          `json:"category"`
	RuleID           string          `json:"rule_id"`
	Explanation      string          `json:"explanation"`
	Subject          string          `json:"subject"`
	Predicate        string          `json:"predicate"`
	OldValue         string          `json:"old_value"`
	NewValue         string          `json:"new_value"`
	SupportingClaims []*claims.Claim `json:"supporting_claims"`
}

// DiffResult encapsulates full diff comparison between A and B.
type DiffResult struct {
	TargetA      string        `json:"target_a"`
	TargetB      string        `json:"target_b"`
	IsTimeDiff   bool          `json:"is_time_diff"`
	TimeA        *time.Time    `json:"time_a,omitempty"`
	TimeB        *time.Time    `json:"time_b,omitempty"`
	Changes      []DiffChange  `json:"changes"`
	RankedCauses []RankedCause `json:"ranked_causes"`
}

// ParseTimeOrRef parses a diff target into either a run reference or a temporal cutoff.
// Supports RFC3339, relative durations ("1h", "24h", "7d"), or "ref://run/...".
func ParseTimeOrRef(target string, baseTime time.Time) (ref string, cutoff *time.Time, err error) {
	if strings.HasPrefix(target, "ref://") {
		return target, nil, nil
	}

	// Try relative duration: e.g. "1h", "24h", "7d", "30m"
	relRe := regexp.MustCompile(`^(\d+)([smhd])$`)
	if m := relRe.FindStringSubmatch(target); len(m) == 3 {
		qty, _ := strconv.Atoi(m[1])
		unit := m[2]
		var d time.Duration
		switch unit {
		case "s":
			d = time.Duration(qty) * time.Second
		case "m":
			d = time.Duration(qty) * time.Minute
		case "h":
			d = time.Duration(qty) * time.Hour
		case "d":
			d = time.Duration(qty) * 24 * time.Hour
		}
		t := baseTime.Add(-d)
		return "", &t, nil
	}

	// Try RFC3339
	if t, err := time.Parse(time.RFC3339, target); err == nil {
		return "", &t, nil
	}

	// Default fallback to ref
	return target, nil, nil
}

// LoadCauseRules loads causes ranking rules from a JSON file.
func LoadCauseRules(path string) ([]CauseRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []CauseRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// FetchClaimsForTarget fetches all claims relevant to a run ref or temporal cutoff.
// For a run ref: fetches claims where subject = runRef, plus host/env/dataset/package claims observed within scope.
func FetchClaimsForTarget(ctx context.Context, l *store.Ledger, ref string, cutoff *time.Time) ([]*claims.Claim, error) {
	var query string
	var args []interface{}

	if cutoff != nil {
		query = `
			SELECT claim_id, subject, predicate, object_kind, object_value,
			       observed_at, source_group, source_id, source_method,
			       scope, evidence_hash, redaction
			FROM claims
			WHERE observed_at <= ?
			ORDER BY observed_at ASC, seq ASC
		`
		args = append(args, cutoff.Format(time.RFC3339))
	} else {
		// Specific run ref: fetch run claims and dependencies observed up to the run time
		query = `
			SELECT claim_id, subject, predicate, object_kind, object_value,
			       observed_at, source_group, source_id, source_method,
			       scope, evidence_hash, redaction
			FROM claims
			WHERE subject = ?
			   OR (
			       (subject IN (SELECT object_value FROM claims WHERE subject = ? AND object_kind = 'ref')
			        OR scope IN (SELECT object_value FROM claims WHERE subject = ? AND predicate = 'run.ran_on'))
			       AND observed_at <= (SELECT max(observed_at) FROM claims WHERE subject = ?)
			   )
			ORDER BY observed_at ASC, seq ASC
		`
		args = append(args, ref, ref, ref, ref)
	}

	rows, err := l.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*claims.Claim
	for rows.Next() {
		var (
			claimID, subj, pred, objKind, objVal string
			obsAt, srcGrp, srcID, srcMeth        string
			scope, evHash, redact                string
		)
		if err := rows.Scan(
			&claimID, &subj, &pred, &objKind, &objVal,
			&obsAt, &srcGrp, &srcID, &srcMeth,
			&scope, &evHash, &redact,
		); err != nil {
			return nil, err
		}
		result = append(result, &claims.Claim{
			ClaimID:      claimID,
			Subject:      subj,
			Predicate:    pred,
			Object:       claims.Object{Kind: objKind, Value: objVal},
			ObservedAt:   obsAt,
			Source:       claims.Source{Group: srcGrp, ID: srcID, Method: srcMeth},
			Scope:        scope,
			EvidenceHash: evHash,
			Redaction:    redact,
		})
	}
	return result, rows.Err()
}

// CategorizeChange determines the diff category based on predicate and subject.
// CategorizeChange determines the diff category based on predicate and subject.
func CategorizeChange(predicate, subject string) string {
	switch {
	case strings.HasPrefix(subject, "ref://dataset/"):
		return "input/dataset change"
	case predicate == "package.version" && (strings.Contains(subject, "driver") || strings.Contains(subject, "nvidia") || strings.Contains(subject, "cuda")):
		return "GPU or driver"
	case predicate == "host.gpu":
		return "GPU or driver"
	case predicate == "package.version" || predicate == "run.loaded":
		return "library or runtime version"
	case strings.HasPrefix(predicate, "host.kernel"):
		return "kernel"
	case strings.HasPrefix(predicate, "host.cpu_feature"):
		return "CPU feature"
	case strings.HasPrefix(predicate, "run.command") || strings.HasPrefix(predicate, "artifact.sha256"):
		return "executable"
	case strings.HasPrefix(predicate, "run.env_name") && (strings.Contains(subject, "SEED") || strings.Contains(subject, "PYTHONHASHSEED")):
		return "nondeterminism hint"
	case strings.HasPrefix(predicate, "run.env_name"):
		return "environment variable"
	case strings.HasPrefix(subject, "ref://service/") && (predicate == "host.listens" || predicate == "service.endpoint"):
		return "service moves"
	case strings.HasPrefix(predicate, "host.listens") || strings.HasPrefix(predicate, "service.endpoint"):
		return "network endpoint"
	case strings.HasPrefix(predicate, "coverage."):
		return "coverage changes"
	case predicate == "same_as" || predicate == "cannot_link" || strings.HasPrefix(predicate, "identity."):
		return "identity merge changes"
	case strings.HasPrefix(subject, "ref://endpoint/") || strings.Contains(predicate, "unmodeled"):
		return "new unmodeled endpoints"
	default:
		return "system configuration"
	}
}

// ComputeDiff compares state A and state B and generates ranked causes.
func ComputeDiff(ctx context.Context, l *store.Ledger, targetA, targetB string, rulesDir string) (*DiffResult, error) {
	now := time.Now().UTC()
	refA, cutoffA, err := ParseTimeOrRef(targetA, now)
	if err != nil {
		return nil, fmt.Errorf("invalid target A: %w", err)
	}
	refB, cutoffB, err := ParseTimeOrRef(targetB, now)
	if err != nil {
		return nil, fmt.Errorf("invalid target B: %w", err)
	}

	claimsA, err := FetchClaimsForTarget(ctx, l, refA, cutoffA)
	if err != nil {
		return nil, fmt.Errorf("failed fetching claims for A: %w", err)
	}
	claimsB, err := FetchClaimsForTarget(ctx, l, refB, cutoffB)
	if err != nil {
		return nil, fmt.Errorf("failed fetching claims for B: %w", err)
	}

	asOfA := now
	if cutoffA != nil {
		asOfA = *cutoffA
	} else if len(claimsA) > 0 {
		// Set asOfA to latest observation of target A
		for _, c := range claimsA {
			if t, err := time.Parse(time.RFC3339, c.ObservedAt); err == nil {
				if t.After(asOfA) || asOfA == now {
					asOfA = t
				}
			}
		}
	}

	asOfB := now
	if cutoffB != nil {
		asOfB = *cutoffB
	} else if len(claimsB) > 0 {
		// Set asOfB to latest observation of target B
		for _, c := range claimsB {
			if t, err := time.Parse(time.RFC3339, c.ObservedAt); err == nil {
				if t.After(asOfB) || asOfB == now {
					asOfB = t
				}
			}
		}
	}

	effA, _ := effective.ComputeEffectiveStates(claimsA, asOfA)
	effB, _ := effective.ComputeEffectiveStates(claimsB, asOfB)

	mapA := make(map[string]*effective.EffectiveClaimState)
	for _, st := range effA {
		subjKey := st.Subject
		if refA != "" && st.Subject == refA {
			subjKey = "run-target"
		}
		key := fmt.Sprintf("%s|%s", subjKey, st.Predicate)
		mapA[key] = st
	}

	mapB := make(map[string]*effective.EffectiveClaimState)
	for _, st := range effB {
		subjKey := st.Subject
		if refB != "" && st.Subject == refB {
			subjKey = "run-target"
		}
		key := fmt.Sprintf("%s|%s", subjKey, st.Predicate)
		mapB[key] = st
	}

	// Union of all (Subject, Predicate) keys
	allKeysSet := make(map[string]bool)
	for k := range mapA {
		allKeysSet[k] = true
	}
	for k := range mapB {
		allKeysSet[k] = true
	}

	var allKeys []string
	for k := range allKeysSet {
		allKeys = append(allKeys, k)
	}
	sort.Strings(allKeys)

	var changes []DiffChange

	for _, k := range allKeys {
		stA := mapA[k]
		stB := mapB[k]

		parts := strings.SplitN(k, "|", 2)
		subj, pred := parts[0], parts[1]

		if stA != nil && stB != nil {
			if stA.ObjectValue != stB.ObjectValue {
				changes = append(changes, DiffChange{
					Subject:       subj,
					Predicate:     pred,
					OldValue:      stA.ObjectValue,
					NewValue:      stB.ObjectValue,
					Status:        "changed",
					OldPrecedence: stA.Precedence,
					NewPrecedence: stB.Precedence,
					Category:      CategorizeChange(pred, subj),
					ClaimsA:       stA.SupportingClaims,
					ClaimsB:       stB.SupportingClaims,
				})
			} else if stA.IsStale != stB.IsStale {
				changes = append(changes, DiffChange{
					Subject:       subj,
					Predicate:     pred,
					OldValue:      stA.ObjectValue,
					NewValue:      stB.ObjectValue,
					Status:        "stale_drop",
					OldPrecedence: stA.Precedence,
					NewPrecedence: stB.Precedence,
					Category:      "stale-strength drops",
					ClaimsA:       stA.SupportingClaims,
					ClaimsB:       stB.SupportingClaims,
				})
			}
		} else if stA != nil && stB == nil {
			// Observed in A, but not visible in B!
			// Invariant: A transition from observed to not visible is reported as "not comparable", NEVER "removed".
			changes = append(changes, DiffChange{
				Subject:       subj,
				Predicate:     pred,
				OldValue:      stA.ObjectValue,
				NewValue:      "not visible",
				Status:        "not comparable",
				OldPrecedence: stA.Precedence,
				NewPrecedence: "not visible",
				Category:      CategorizeChange(pred, subj),
				ClaimsA:       stA.SupportingClaims,
			})
		} else if stA == nil && stB != nil {
			// Not visible in A, observed in B
			changes = append(changes, DiffChange{
				Subject:       subj,
				Predicate:     pred,
				OldValue:      "not visible",
				NewValue:      stB.ObjectValue,
				Status:        "added",
				OldPrecedence: "not visible",
				NewPrecedence: stB.Precedence,
				Category:      CategorizeChange(pred, subj),
				ClaimsB:       stB.SupportingClaims,
			})
		}
	}

	// Load cause rules
	var causeRules []CauseRule
	if rulesDir != "" {
		p := filepath.Join(rulesDir, "causes.json")
		if r, err := LoadCauseRules(p); err == nil {
			causeRules = r
		}
	}

	// Rank causes
	var rankedCauses []RankedCause
	for _, ch := range changes {
		if ch.Status == "not comparable" && ch.NewValue == "not visible" {
			continue
		}

		bestWeight := 20
		bestRuleID := "generic-diff"
		explanation := fmt.Sprintf("%s changed: %s -> %s", ch.Predicate, ch.OldValue, ch.NewValue)
		category := ch.Category

		for _, cr := range causeRules {
			if cr.MatchPredicate == ch.Predicate {
				if cr.SubjectPrefix != "" && !strings.HasPrefix(ch.Subject, cr.SubjectPrefix) {
					continue
				}
				if cr.ObjectPattern != "" && !strings.Contains(ch.NewValue, cr.ObjectPattern) && !strings.Contains(ch.OldValue, cr.ObjectPattern) {
					continue
				}
				if cr.BaseWeight > bestWeight {
					bestWeight = cr.BaseWeight
					bestRuleID = cr.ID
					category = cr.Category
					exp := cr.Explanation
					exp = strings.ReplaceAll(exp, "{subject}", ch.Subject)
					exp = strings.ReplaceAll(exp, "{value}", ch.NewValue)
					explanation = exp
				}
			}
		}

		var supp []*claims.Claim
		supp = append(supp, ch.ClaimsB...)
		supp = append(supp, ch.ClaimsA...)

		rankedCauses = append(rankedCauses, RankedCause{
			Weight:           bestWeight,
			Category:         category,
			RuleID:           bestRuleID,
			Explanation:      explanation,
			Subject:          ch.Subject,
			Predicate:        ch.Predicate,
			OldValue:         ch.OldValue,
			NewValue:         ch.NewValue,
			SupportingClaims: supp,
		})
	}

	// Deterministic sorting of ranked causes:
	// 1. Weight descending
	// 2. Subject ascending
	// 3. Predicate ascending
	sort.Slice(rankedCauses, func(i, j int) bool {
		if rankedCauses[i].Weight != rankedCauses[j].Weight {
			return rankedCauses[i].Weight > rankedCauses[j].Weight
		}
		if rankedCauses[i].Subject != rankedCauses[j].Subject {
			return rankedCauses[i].Subject < rankedCauses[j].Subject
		}
		return rankedCauses[i].Predicate < rankedCauses[j].Predicate
	})

	for i := range rankedCauses {
		rankedCauses[i].Rank = i + 1
	}

	res := &DiffResult{
		TargetA:      targetA,
		TargetB:      targetB,
		IsTimeDiff:   (cutoffA != nil || cutoffB != nil),
		TimeA:        cutoffA,
		TimeB:        cutoffB,
		Changes:      changes,
		RankedCauses: rankedCauses,
	}

	return res, nil
}
