package infer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/effective"
	"github.com/OWNER/bokuei/internal/store"
)

// Condition defines a match operator and criteria for a rule.
type Condition struct {
	Op     string   `json:"op"` // "equals", "in", "exists", "port-listens"
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
	Port   int      `json:"port,omitempty"`
}

// EmitTemplate specifies the predicate and object of the inferred claim.
type EmitTemplate struct {
	Predicate string        `json:"predicate"`
	Object    claims.Object `json:"object"`
}

// Rule defines an inference rule.
type Rule struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	Description    string       `json:"description"`
	MatchPredicate string       `json:"match_predicate"`
	Condition      Condition    `json:"condition"`
	Emit           EmitTemplate `json:"emit"`
}

// LoadRules loads JSON inference rules from a file or byte slice.
func LoadRules(filePath string) ([]Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file %s: %w", filePath, err)
	}
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules JSON: %w", err)
	}
	return rules, nil
}

// Matches checks whether an effective claim state or claim matches the rule condition.
func (r *Rule) Matches(objVal string) bool {
	switch r.Condition.Op {
	case "exists":
		return objVal != ""
	case "equals":
		return objVal == r.Condition.Value
	case "in":
		for _, v := range r.Condition.Values {
			if objVal == v || strings.Contains(objVal, v) {
				return true
			}
		}
		return false
	case "port-listens":
		portSuffix := fmt.Sprintf(":%d", r.Condition.Port)
		return strings.HasSuffix(objVal, portSuffix)
	default:
		return false
	}
}

// InferredClaimWithLineage pairs an inferred claim with the claim_id(s) that support it.
type InferredClaimWithLineage struct {
	Claim          *claims.Claim
	SupportedByIDs []string
}

// RunInference evaluates loaded rules against ledger claims and effective states.
// Inference is strictly deterministic and idempotent.
func RunInference(allClaims []*claims.Claim, effectiveStates []*effective.EffectiveClaimState, rules []Rule) ([]InferredClaimWithLineage, error) {
	var inferred []InferredClaimWithLineage

	// Map each (Subject, Predicate) to supporting claims for lineage
	claimsBySubjPred := make(map[string][]*claims.Claim)
	for _, c := range allClaims {
		key := fmt.Sprintf("%s|%s", c.Subject, c.Predicate)
		claimsBySubjPred[key] = append(claimsBySubjPred[key], c)
	}

	// Sort rules deterministically by ID
	sortedRules := make([]Rule, len(rules))
	copy(sortedRules, rules)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].ID < sortedRules[j].ID
	})

	for _, rule := range sortedRules {
		// Evaluate rule against effective states
		for _, st := range effectiveStates {
			if st.Predicate != rule.MatchPredicate {
				continue
			}

			if rule.Matches(st.ObjectValue) {
				// Create inferred claim
				now := st.LatestObservedAt
				scope := "ref://host/localhost"
				var supportIDs []string

				key := fmt.Sprintf("%s|%s", st.Subject, st.Predicate)
				for _, sc := range claimsBySubjPred[key] {
					supportIDs = append(supportIDs, sc.ClaimID)
					scope = sc.Scope
				}

				newClaim := &claims.Claim{
					Subject:    st.Subject,
					Predicate:  rule.Emit.Predicate,
					Object:     rule.Emit.Object,
					ObservedAt: now,
					Source: claims.Source{
						Group:  "inferred",
						ID:     fmt.Sprintf("rule-%s", rule.ID),
						Method: "inference",
					},
					Scope:        scope,
					EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					Redaction:    "none",
				}

				cid, err := newClaim.ComputeID()
				if err != nil {
					return nil, fmt.Errorf("failed to compute inferred claim ID: %w", err)
				}
				newClaim.ClaimID = cid

				inferred = append(inferred, InferredClaimWithLineage{
					Claim:          newClaim,
					SupportedByIDs: supportIDs,
				})
			}
		}
	}

	return inferred, nil
}

// IngestInferredClaims ingests inferred claims into the ledger and writes claim_support links atomically.
func IngestInferredClaims(ctx context.Context, l *store.Ledger, inferred []InferredClaimWithLineage) (int, error) {
	if len(inferred) == 0 {
		return 0, nil
	}

	var rawClaims []*claims.Claim
	for _, inf := range inferred {
		rawClaims = append(rawClaims, inf.Claim)
	}

	res, err := l.IngestBatch(ctx, "batch-inference", rawClaims, nil)
	if err != nil {
		return 0, err
	}

	// Insert claim_support records
	stmtSupport, err := l.DB().PrepareContext(ctx, `
		INSERT OR IGNORE INTO claim_support (claim_id, supported_by_claim_id, relationship)
		VALUES (?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to prepare claim_support: %w", err)
	}
	defer stmtSupport.Close()

	for _, inf := range inferred {
		for _, supID := range inf.SupportedByIDs {
			if supID != "" {
				_, _ = stmtSupport.ExecContext(ctx, inf.Claim.ClaimID, supID, "derived_from")
			}
		}
	}

	return res.InsertedClaims, nil
}
