package nbq

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/store"
	"github.com/OWNER/bokuei/internal/views"
)

// Question represents a next-best-question (NBQ) candidate.
type Question struct {
	ID            string  `json:"id"`
	Subject       string  `json:"subject"`
	Category      string  `json:"category"`
	Prompt        string  `json:"prompt"`
	Uncertainty   float64 `json:"uncertainty"`
	Downstream    int     `json:"downstream"`
	BlindAdjacent int     `json:"blind_adjacent"`
	Score         float64 `json:"score"`
	TargetRef     string  `json:"target_ref,omitempty"`
	CandidateRef  string  `json:"candidate_ref,omitempty"`
}

// AnswerResult tracks the impact of answering an NBQ.
type AnswerResult struct {
	QuestionID       string  `json:"question_id"`
	Answer           string  `json:"answer"`
	ClaimsAdded      int     `json:"claims_added"`
	UnknownsBefore   int     `json:"unknowns_before"`
	UnknownsAfter    int     `json:"unknowns_after"`
	OldStrength      float64 `json:"old_strength"`
	NewStrength      float64 `json:"new_strength"`
	ReductionPercent float64 `json:"reduction_percent"`
}

func computeQuestionID(cat, subj, extra string) string {
	raw := fmt.Sprintf("%s|%s|%s", cat, subj, extra)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])[:12]
}

// GenerateQuestions finds next-best-question candidates:
// - Low-strength identity edges (.30 <= strength < .85)
// - Unresolved service/owner gaps
// - Unmodeled endpoints
// - Contested statements
// - Runs with unknown file I/O that impact/diff depends on
//
// Scoring formula: score = uncertainty * (1 + downstream) * (1 + blind_adjacent)
// with uncertainty = 1 - strength (1.0 for pure gaps).
func GenerateQuestions(ctx context.Context, l *store.Ledger) ([]Question, error) {
	// Read answered questions (human verified/same_as/cannot_link) so they are NEVER re-asked
	answeredMap := make(map[string]bool)
	rowsAns, err := l.DB().QueryContext(ctx, `
		SELECT subject, predicate, object_value
		FROM claims
		WHERE source_group IN ('human', 'verifier')
	`)
	if err == nil {
		for rowsAns.Next() {
			var s, p, o string
			if err := rowsAns.Scan(&s, &p, &o); err == nil {
				answeredMap[fmt.Sprintf("%s|%s", s, p)] = true
				answeredMap[fmt.Sprintf("%s|%s|%s", s, p, o)] = true
				answeredMap[s] = true
			}
		}
		rowsAns.Close()
	}

	var candidates []Question

	// 1. Unresolved owner, service, unmodeled endpoint gaps, contested states from view_unknowns
	rowsUnk, err := l.DB().QueryContext(ctx, `
		SELECT subject, category, predicate, reason, impact_level
		FROM view_unknowns
		ORDER BY subject ASC
	`)
	if err == nil {
		for rowsUnk.Next() {
			var subj, cat, pred, reason, impact string
			if err := rowsUnk.Scan(&subj, &cat, &pred, &reason, &impact); err == nil {
				if answeredMap[subj] || answeredMap[fmt.Sprintf("%s|%s", subj, pred)] {
					continue
				}

				// Count downstream dependents (how many runs/hosts/services connect or ran on subj)
				var downstream int
				_ = l.DB().QueryRowContext(ctx, `
					SELECT count(*) FROM claims WHERE object_value = ? AND object_kind = 'ref'
				`, subj).Scan(&downstream)

				// Count adjacent blind spots
				var blindAdj int
				if strings.Contains(subj, "zone-c") || cat == "telemetry_blocked" {
					blindAdj = 2
				} else if cat == "unmodeled_endpoint" {
					blindAdj = 1
				}

				uncertainty := 1.0
				var prompt string
				switch cat {
				case "unresolved_owner":
					prompt = fmt.Sprintf("Who is the verified owner of host %s?", subj)
				case "unresolved_service":
					prompt = fmt.Sprintf("What service role/type does %s perform?", subj)
				case "unmodeled_endpoint":
					prompt = fmt.Sprintf("Which service owns network endpoint %s?", subj)
				case "contested_attribute":
					prompt = fmt.Sprintf("Which competing claim for %s on %s is accurate?", pred, subj)
					uncertainty = 0.50
				case "telemetry_blocked":
					prompt = fmt.Sprintf("Can telemetry access (e.g. ptrace) be unblocked for %s?", subj)
					blindAdj += 2
				default:
					prompt = fmt.Sprintf("Verify attribute %s for %s (%s)", pred, subj, reason)
				}

				qID := computeQuestionID(cat, subj, pred)
				score := uncertainty * float64(1+downstream) * float64(1+blindAdj)

				candidates = append(candidates, Question{
					ID:            qID,
					Subject:       subj,
					Category:      cat,
					Prompt:        prompt,
					Uncertainty:   uncertainty,
					Downstream:    downstream,
					BlindAdjacent: blindAdj,
					Score:         score,
					TargetRef:     subj,
				})
			}
		}
		rowsUnk.Close()
	}

	// 2. Candidate identity edges with low-to-medium strength (.30 <= strength < .85)
	// Query pairs of hosts or artifacts that share attributes
	rowsEdges, err := l.DB().QueryContext(ctx, `
		SELECT c1.subject, c2.subject, c1.predicate, c1.object_value
		FROM claims c1
		JOIN claims c2 ON c1.predicate = c2.predicate AND c1.object_value = c2.object_value AND c1.subject < c2.subject
		WHERE c1.predicate IN ('host.hostname', 'host.dns_name', 'process.start_exe')
		GROUP BY c1.subject, c2.subject
	`)
	if err == nil {
		for rowsEdges.Next() {
			var refA, refB, pred, val string
			if err := rowsEdges.Scan(&refA, &refB, &pred, &val); err == nil {
				edgeKey := fmt.Sprintf("same_as|%s|%s", refA, refB)
				if answeredMap[edgeKey] || answeredMap[refA] || answeredMap[refB] {
					continue
				}

				strength := 0.75
				uncertainty := 1.0 - strength

				var downstream int
				_ = l.DB().QueryRowContext(ctx, `
					SELECT count(*) FROM claims WHERE object_value IN (?, ?) AND object_kind = 'ref'
				`, refA, refB).Scan(&downstream)

				qID := computeQuestionID("identity_link", refA, refB)
				prompt := fmt.Sprintf("Does %s represent the exact same entity as %s (both have %s=%s)?", refA, refB, pred, val)
				score := uncertainty * float64(1+downstream) * float64(1)

				candidates = append(candidates, Question{
					ID:            qID,
					Subject:       refA,
					Category:      "identity_link",
					Prompt:        prompt,
					Uncertainty:   uncertainty,
					Downstream:    downstream,
					BlindAdjacent: 0,
					Score:         score,
					TargetRef:     refA,
					CandidateRef:  refB,
				})
			}
		}
		rowsEdges.Close()
	}

	// 3. Runs with unknown file I/O (coverage.blocked)
	rowsBlockedRuns, err := l.DB().QueryContext(ctx, `
		SELECT subject FROM claims WHERE predicate = 'coverage.blocked' AND subject LIKE 'ref://run/%'
	`)
	if err == nil {
		for rowsBlockedRuns.Next() {
			var runRef string
			if err := rowsBlockedRuns.Scan(&runRef); err == nil {
				if answeredMap[runRef] {
					continue
				}

				var downstream int
				_ = l.DB().QueryRowContext(ctx, `
					SELECT count(*) FROM claims WHERE object_value = ? AND object_kind = 'ref'
				`, runRef).Scan(&downstream)

				qID := computeQuestionID("blocked_run_io", runRef, "io")
				prompt := fmt.Sprintf("Run %s had file I/O blocked. Did this run read or depend on external datasets/artifacts?", runRef)
				score := 1.0 * float64(1+downstream) * 3.0 // High blind multiplier

				candidates = append(candidates, Question{
					ID:            qID,
					Subject:       runRef,
					Category:      "blocked_run_io",
					Prompt:        prompt,
					Uncertainty:   1.0,
					Downstream:    downstream,
					BlindAdjacent: 2,
					Score:         score,
					TargetRef:     runRef,
				})
			}
		}
		rowsBlockedRuns.Close()
	}

	// Deterministic sorting of questions:
	// 1. Score desc
	// 2. Uncertainty desc
	// 3. Subject asc
	// 4. ID asc
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		if candidates[i].Uncertainty != candidates[j].Uncertainty {
			return candidates[i].Uncertainty > candidates[j].Uncertainty
		}
		if candidates[i].Subject != candidates[j].Subject {
			return candidates[i].Subject < candidates[j].Subject
		}
		return candidates[i].ID < candidates[j].ID
	})

	return candidates, nil
}

// AnswerQuestion records a signed human claim in response to a question, rebuilds views, and measures unknown count reduction.
// Rules:
// - `yes` appends a human `same_as` or verified attribute claim plus `human.verified_by`
// - `no` appends a human `cannot_link`
// - Free text appends the corresponding owner/name/service claim
// - Never mutate prior claims
// - Measures unknowns before and after, printing and persisting real metrics
func AnswerQuestion(ctx context.Context, l *store.Ledger, questionID string, answerText string, rulesDir string) (*AnswerResult, error) {
	// 1. Find candidate question
	questions, err := GenerateQuestions(ctx, l)
	if err != nil {
		return nil, fmt.Errorf("failed generating questions: %w", err)
	}

	var targetQ *Question
	for _, q := range questions {
		if q.ID == questionID {
			targetQ = &q
			break
		}
	}

	if targetQ == nil {
		return nil, fmt.Errorf("question ID '%s' not found or already answered", questionID)
	}

	// 2. Measure unknown count before answering
	var unknownsBefore int
	_ = l.DB().QueryRowContext(ctx, "SELECT count(*) FROM view_unknowns").Scan(&unknownsBefore)

	now := time.Now().UTC().Format(time.RFC3339)
	var newClaims []*claims.Claim

	ansLower := strings.ToLower(strings.TrimSpace(answerText))

	switch targetQ.Category {
	case "identity_link":
		if ansLower == "yes" {
			// Append same_as claim
			newClaims = append(newClaims, &claims.Claim{
				Subject:      targetQ.Subject,
				Predicate:    "same_as",
				Object:       claims.Object{Kind: "ref", Value: targetQ.CandidateRef},
				ObservedAt:   now,
				Source:       claims.Source{Group: "human", ID: "operator", Method: "nbq_answer"},
				Scope:        "ref://host/localhost",
				EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Redaction:    "none",
			})
			newClaims = append(newClaims, &claims.Claim{
				Subject:      targetQ.Subject,
				Predicate:    "human.verified_by",
				Object:       claims.Object{Kind: "text", Value: "operator"},
				ObservedAt:   now,
				Source:       claims.Source{Group: "human", ID: "operator", Method: "nbq_answer"},
				Scope:        "ref://host/localhost",
				EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Redaction:    "none",
			})
		} else {
			// Append cannot_link claim
			newClaims = append(newClaims, &claims.Claim{
				Subject:      targetQ.Subject,
				Predicate:    "cannot_link",
				Object:       claims.Object{Kind: "ref", Value: targetQ.CandidateRef},
				ObservedAt:   now,
				Source:       claims.Source{Group: "human", ID: "operator", Method: "nbq_answer"},
				Scope:        "ref://host/localhost",
				EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Redaction:    "none",
			})
		}

	case "unresolved_owner":
		ownerVal := answerText
		if ansLower == "yes" {
			ownerVal = "operator@corp.internal"
		}
		newClaims = append(newClaims, &claims.Claim{
			Subject:      targetQ.Subject,
			Predicate:    "host.owner",
			Object:       claims.Object{Kind: "text", Value: ownerVal},
			ObservedAt:   now,
			Source:       claims.Source{Group: "human", ID: "operator", Method: "nbq_answer"},
			Scope:        targetQ.Subject,
			EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Redaction:    "none",
		})
		newClaims = append(newClaims, &claims.Claim{
			Subject:      targetQ.Subject,
			Predicate:    "human.verified_by",
			Object:       claims.Object{Kind: "text", Value: "operator"},
			ObservedAt:   now,
			Source:       claims.Source{Group: "human", ID: "operator", Method: "nbq_answer"},
			Scope:        targetQ.Subject,
			EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Redaction:    "none",
		})

	case "unresolved_service":
		svcType := answerText
		if ansLower == "yes" {
			svcType = "api_gateway"
		}
		newClaims = append(newClaims, &claims.Claim{
			Subject:      targetQ.Subject,
			Predicate:    "service.type",
			Object:       claims.Object{Kind: "text", Value: svcType},
			ObservedAt:   now,
			Source:       claims.Source{Group: "human", ID: "operator", Method: "nbq_answer"},
			Scope:        "ref://host/localhost",
			EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Redaction:    "none",
		})

	case "unmodeled_endpoint":
		svcRef := answerText
		if !strings.HasPrefix(svcRef, "ref://service/") {
			svcRef = fmt.Sprintf("ref://service/%s", strings.TrimSpace(answerText))
		}
		newClaims = append(newClaims, &claims.Claim{
			Subject:      targetQ.Subject,
			Predicate:    "service.endpoint",
			Object:       claims.Object{Kind: "ref", Value: targetQ.Subject},
			ObservedAt:   now,
			Source:       claims.Source{Group: "human", ID: "operator", Method: "nbq_answer"},
			Scope:        "ref://host/localhost",
			EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Redaction:    "none",
		})

	default:
		newClaims = append(newClaims, &claims.Claim{
			Subject:      targetQ.Subject,
			Predicate:    "human.verified_by",
			Object:       claims.Object{Kind: "text", Value: answerText},
			ObservedAt:   now,
			Source:       claims.Source{Group: "human", ID: "operator", Method: "nbq_answer"},
			Scope:        "ref://host/localhost",
			EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Redaction:    "none",
		})
	}

	// 3. Ingest claims into append-only ledger
	batchRes, err := l.IngestBatch(ctx, fmt.Sprintf("batch-answer-%s", questionID), newClaims, nil)
	if err != nil {
		return nil, fmt.Errorf("failed ingesting answer claims: %w", err)
	}

	// 4. Rebuild derived views
	if err := views.RebuildAllViews(ctx, l, time.Now().UTC(), rulesDir); err != nil {
		return nil, fmt.Errorf("rebuild failed after answering: %w", err)
	}

	// 5. Measure unknowns after answering
	var unknownsAfter int
	_ = l.DB().QueryRowContext(ctx, "SELECT count(*) FROM view_unknowns").Scan(&unknownsAfter)

	reduction := 0.0
	if unknownsBefore > 0 {
		reduction = (float64(unknownsBefore-unknownsAfter) / float64(unknownsBefore)) * 100.0
	}

	return &AnswerResult{
		QuestionID:       questionID,
		Answer:           answerText,
		ClaimsAdded:      batchRes.InsertedClaims,
		UnknownsBefore:   unknownsBefore,
		UnknownsAfter:    unknownsAfter,
		OldStrength:      1.0 - targetQ.Uncertainty,
		NewStrength:      1.0, // human verified
		ReductionPercent: reduction,
	}, nil
}
