package impact

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/store"
)

// ConfidenceBand represents calibrated confidence levels.
type ConfidenceBand string

const (
	ConfidenceKnown    ConfidenceBand = "known"    // >= 0.85
	ConfidenceLikely   ConfidenceBand = "likely"   // 0.60 <= x < 0.85
	ConfidencePossible ConfidenceBand = "possible" // 0.30 <= x < 0.60
)

// Verdict types
const (
	VerdictSafeToProceed              = "Safe to proceed"
	VerdictProceedWithCaution         = "Proceed with caution"
	VerdictDoNotProceedUntilQuestions = "Do not proceed until questions answered"
)

// TargetDependent represents an entity affected by changes to the target ref.
type TargetDependent struct {
	Ref          string         `json:"ref"`
	Kind         string         `json:"kind"`
	Depth        int            `json:"depth"`
	Strength     float64        `json:"strength"`
	Confidence   ConfidenceBand `json:"confidence"`
	ViaPredicate string         `json:"via_predicate"`
	ViaParentRef string         `json:"via_parent_ref"`
}

// BlindSpot represents unobservable or blocked scope adjacent to the impact graph.
type BlindSpot struct {
	ScopeRef string `json:"scope_ref"`
	Reason   string `json:"reason"`
	Kind     string `json:"kind"` // "blocked_zone", "unmodeled_endpoint", "unobservable_run_io", "blocked_telemetry"
}

// ImpactResult summarizes the impact traversal, confidence bands, blind spots, and verdict.
type ImpactResult struct {
	TargetRef     string            `json:"target_ref"`
	Dependents    []TargetDependent `json:"dependents"`
	BlindSpots    []BlindSpot       `json:"blind_spots"`
	Verdict       string            `json:"verdict"`
	SummaryText   string            `json:"summary_text"`
	KnownCount    int               `json:"known_count"`
	LikelyCount   int               `json:"likely_count"`
	PossibleCount int               `json:"possible_count"`
}

func BandForStrength(s float64) ConfidenceBand {
	if s >= 0.85 {
		return ConfidenceKnown
	}
	if s >= 0.60 {
		return ConfidenceLikely
	}
	return ConfidencePossible
}

// ComputeImpact performs reverse dependency traversal using predicate impact directions up to max depth 20.
func ComputeImpact(ctx context.Context, l *store.Ledger, targetRef string) (*ImpactResult, error) {
	if err := claims.ValidateRef(targetRef); err != nil {
		return nil, fmt.Errorf("invalid target ref: %w", err)
	}

	const maxDepth = 20

	// 1. Query all dependency-relevant claims from ledger
	// Reverse impact:
	// If predicate is backward (e.g. run.read, run.loaded, run.ran_on, run.connected_to):
	// claim has (Subject=run, Object=target). The dependency flows Run -> Target.
	// So change in Target affects Subject (run).
	// If predicate is forward (e.g. run.wrote, host.listens):
	// claim has (Subject=target, Object=other). Dependency flows Target -> Other.
	// So change in Target affects other.
	// If bidirectional (e.g. same_as):
	// either direction impacts the other.
	rows, err := l.DB().QueryContext(ctx, `
		SELECT subject, predicate, object_kind, object_value, source_group
		FROM claims
		ORDER BY seq ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed querying ledger claims: %w", err)
	}
	defer rows.Close()

	type depEdge struct {
		fromRef   string
		toRef     string
		predicate string
		strength  float64
	}

	var edges []depEdge

	for rows.Next() {
		var subj, pred, objKind, objVal, srcGrp string
		if err := rows.Scan(&subj, &pred, &objKind, &objVal, &srcGrp); err != nil {
			return nil, err
		}

		if objKind != "ref" {
			continue
		}

		rel, _ := claims.GetSourceReliability(srcGrp)
		def, ok := claims.Catalog[pred]
		if !ok {
			continue
		}

		// What is the impact direction?
		// Reverse traversal: if target changes, what depends on target?
		switch def.ImpactDirection {
		case claims.ImpactDirectionBackward:
			// subj depends on objVal (e.g. run.read dataset, run.loaded library, run.ran_on host)
			// So change in objVal impacts subj!
			edges = append(edges, depEdge{
				fromRef:   objVal,
				toRef:     subj,
				predicate: pred,
				strength:  rel,
			})
		case claims.ImpactDirectionForward:
			// objVal depends on subj (e.g. run.wrote artifact, host.listens endpoint)
			// So change in subj impacts objVal!
			edges = append(edges, depEdge{
				fromRef:   subj,
				toRef:     objVal,
				predicate: pred,
				strength:  rel,
			})
		case claims.ImpactDirectionBidirectional:
			edges = append(edges, depEdge{
				fromRef:   subj,
				toRef:     objVal,
				predicate: pred,
				strength:  rel,
			})
			edges = append(edges, depEdge{
				fromRef:   objVal,
				toRef:     subj,
				predicate: pred,
				strength:  rel,
			})
		}
	}
	rows.Close()

	// Special package association:
	// A package is installed on a host or loaded by runs.
	// If targetRef is a ref://package/..., find host(s) or runs where package is recorded.
	// In demo/store, package claims can have Subject=host, Predicate="package.version", Object="package_name" (or ref).
	// Let's also check claims where subject or object matches targetRef.
	rowsPkg, err := l.DB().QueryContext(ctx, `
		SELECT subject, predicate, object_value, source_group
		FROM claims
		WHERE subject = ? OR object_value LIKE ?
	`, targetRef, "%"+strings.TrimPrefix(targetRef, "ref://package/")+"%")
	if err == nil {
		for rowsPkg.Next() {
			var subj, pred, objVal, srcGrp string
			if err := rowsPkg.Scan(&subj, &pred, &objVal, &srcGrp); err == nil {
				rel, _ := claims.GetSourceReliability(srcGrp)
				if strings.HasPrefix(subj, "ref://host/") {
					// package on host: changing package impacts host
					edges = append(edges, depEdge{
						fromRef:   targetRef,
						toRef:     subj,
						predicate: "package.installed_on",
						strength:  rel,
					})
				}
			}
		}
		rowsPkg.Close()
	}

	// Build adjacency list for forward traversal from targetRef
	adj := make(map[string][]depEdge)
	for _, e := range edges {
		adj[e.fromRef] = append(adj[e.fromRef], e)
	}

	// BFS traversal up to maxDepth
	type queueItem struct {
		ref       string
		depth     int
		strength  float64
		pred      string
		parentRef string
	}

	queue := []queueItem{{ref: targetRef, depth: 0, strength: 1.0}}
	visited := make(map[string]int) // ref -> min depth
	visited[targetRef] = 0

	var dependents []TargetDependent
	allReachedRefs := make(map[string]bool)
	allReachedRefs[targetRef] = true

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.depth > 0 {
			confBand := BandForStrength(curr.strength)
			refParts := strings.Split(strings.TrimPrefix(curr.ref, "ref://"), "/")
			kind := "unknown"
			if len(refParts) > 0 {
				kind = refParts[0]
			}

			dependents = append(dependents, TargetDependent{
				Ref:          curr.ref,
				Kind:         kind,
				Depth:        curr.depth,
				Strength:     curr.strength,
				Confidence:   confBand,
				ViaPredicate: curr.pred,
				ViaParentRef: curr.parentRef,
			})
			allReachedRefs[curr.ref] = true
		}

		if curr.depth >= maxDepth {
			continue
		}

		for _, e := range adj[curr.ref] {
			nextDepth := curr.depth + 1
			if prevD, seen := visited[e.toRef]; seen && prevD <= nextDepth {
				continue
			}
			visited[e.toRef] = nextDepth
			// Strength decays along path: child_strength = parent_strength * edge_strength
			childStrength := curr.strength * e.strength
			if childStrength < 0.30 {
				// below confidence threshold
				continue
			}
			queue = append(queue, queueItem{
				ref:       e.toRef,
				depth:     nextDepth,
				strength:  childStrength,
				pred:      e.predicate,
				parentRef: curr.ref,
			})
		}
	}

	// Deterministic sort of dependents:
	// 1. Depth asc
	// 2. Strength desc
	// 3. Ref asc
	sort.Slice(dependents, func(i, j int) bool {
		if dependents[i].Depth != dependents[j].Depth {
			return dependents[i].Depth < dependents[j].Depth
		}
		if dependents[i].Strength != dependents[j].Strength {
			return dependents[i].Strength > dependents[j].Strength
		}
		return dependents[i].Ref < dependents[j].Ref
	})

	// 2. Blind spot detection:
	// Detect adjacent not-visible scope from:
	// - Zone membership (e.g. ref://zone/zone-c which has coverage.blocked)
	// - Observed connections reaching unmodeled endpoints or blocked zones
	// - Runs in impact set with file I/O not visible (coverage.blocked ptrace_denied)
	// - Unmodeled endpoints
	var blindSpots []BlindSpot
	seenBlind := make(map[string]bool)

	// A. Check view_unknowns for reached entities or adjacent scopes
	for reachedRef := range allReachedRefs {
		rowsUnk, err := l.DB().QueryContext(ctx, `
			SELECT category, predicate, reason
			FROM view_unknowns
			WHERE subject = ?
		`, reachedRef)
		if err == nil {
			for rowsUnk.Next() {
				var cat, pr, rsn string
				if err := rowsUnk.Scan(&cat, &pr, &rsn); err == nil {
					key := fmt.Sprintf("%s|%s", reachedRef, rsn)
					if !seenBlind[key] {
						seenBlind[key] = true
						blindSpots = append(blindSpots, BlindSpot{
							ScopeRef: reachedRef,
							Reason:   rsn,
							Kind:     cat,
						})
					}
				}
			}
			rowsUnk.Close()
		}

		// B. Check if reachedRef connected to an endpoint in a blocked zone
		rowsConn, err := l.DB().QueryContext(ctx, `
			SELECT object_value FROM claims WHERE subject = ? AND predicate = 'run.connected_to'
		`, reachedRef)
		if err == nil {
			for rowsConn.Next() {
				var targetEp string
				if err := rowsConn.Scan(&targetEp); err == nil {
					// Check if targetEp is unmodeled or in blocked zone
					var count int
					_ = l.DB().QueryRowContext(ctx, "SELECT count(*) FROM view_unknowns WHERE subject = ?", targetEp).Scan(&count)
					if count > 0 || strings.Contains(targetEp, "zone-c") {
						key := fmt.Sprintf("%s|connected_to_%s", reachedRef, targetEp)
						if !seenBlind[key] {
							seenBlind[key] = true
							blindSpots = append(blindSpots, BlindSpot{
								ScopeRef: targetEp,
								Reason:   fmt.Sprintf("%s communicated with unmodeled/blocked endpoint %s", reachedRef, targetEp),
								Kind:     "blocked_zone_connection",
							})
						}
					}
				}
			}
			rowsConn.Close()
		}
	}

	// C. Directly check for Zone C or blocked zones connected to hosts
	for reachedRef := range allReachedRefs {
		if strings.HasPrefix(reachedRef, "ref://run/") {
			var blockedIO int
			_ = l.DB().QueryRowContext(ctx, "SELECT count(*) FROM claims WHERE subject = ? AND predicate = 'coverage.blocked'", reachedRef).Scan(&blockedIO)
			if blockedIO > 0 {
				key := fmt.Sprintf("%s|unobservable_file_io", reachedRef)
				if !seenBlind[key] {
					seenBlind[key] = true
					blindSpots = append(blindSpots, BlindSpot{
						ScopeRef: reachedRef,
						Reason:   "Run telemetry restricted (ptrace attachment denied); full file I/O not visible",
						Kind:     "unobservable_run_io",
					})
				}
			}
		}
	}

	// Deterministic sort of blind spots
	sort.Slice(blindSpots, func(i, j int) bool {
		if blindSpots[i].ScopeRef != blindSpots[j].ScopeRef {
			return blindSpots[i].ScopeRef < blindSpots[j].ScopeRef
		}
		return blindSpots[i].Reason < blindSpots[j].Reason
	})

	// Count confidence bands
	var knownCnt, likelyCnt, possibleCnt int
	for _, dep := range dependents {
		switch dep.Confidence {
		case ConfidenceKnown:
			knownCnt++
		case ConfidenceLikely:
			likelyCnt++
		case ConfidencePossible:
			possibleCnt++
		}
	}

	// Verdict formulation (deterministic):
	// - If any High impact blind spots or unobservable run I/O in path: "Do not proceed until questions answered"
	// - If blind spots exist or possible confidence: "Proceed with caution"
	// - Otherwise: "Safe to proceed"
	hasCriticalBlindSpot := false
	for _, bs := range blindSpots {
		if bs.Kind == "unobservable_run_io" || bs.Kind == "telemetry_blocked" || bs.Kind == "blocked_zone_connection" {
			hasCriticalBlindSpot = true
			break
		}
	}

	verdict := VerdictSafeToProceed
	if hasCriticalBlindSpot {
		verdict = VerdictDoNotProceedUntilQuestions
	} else if len(blindSpots) > 0 || possibleCnt > 0 {
		verdict = VerdictProceedWithCaution
	}

	res := &ImpactResult{
		TargetRef:     targetRef,
		Dependents:    dependents,
		BlindSpots:    blindSpots,
		Verdict:       verdict,
		KnownCount:    knownCnt,
		LikelyCount:   likelyCnt,
		PossibleCount: possibleCnt,
	}

	return res, nil
}
