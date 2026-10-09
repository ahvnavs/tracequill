package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/effective"
)

const MergeThreshold = 0.60

// Edge represents an identity link candidate between two member refs.
type Edge struct {
	RefA     string  `json:"ref_a"`
	RefB     string  `json:"ref_b"`
	Strength float64 `json:"strength"`
	Reason   string  `json:"reason"`
}

// CannotLinkPair represents a hard negative constraint between two refs.
type CannotLinkPair struct {
	RefA   string `json:"ref_a"`
	RefB   string `json:"ref_b"`
	Reason string `json:"reason"`
}

// Entity represents a resolved cluster of entity member references.
type Entity struct {
	EntityID   string   `json:"entity_id"`
	Members    []string `json:"members"`
	PrimaryRef string   `json:"primary_ref"`
}

// ComputeEntityID returns the lowercase hex SHA-256 of the smallest member ref (alphabetical).
func ComputeEntityID(members []string) string {
	if len(members) == 0 {
		return ""
	}
	sorted := make([]string, len(members))
	copy(sorted, members)
	sort.Strings(sorted)
	smallest := sorted[0]

	h := sha256.Sum256([]byte(smallest))
	return hex.EncodeToString(h[:])
}

// DisjointSet implements Union-Find with cannot_link constraint checking.
type DisjointSet struct {
	parent map[string]string
}

func NewDisjointSet() *DisjointSet {
	return &DisjointSet{parent: make(map[string]string)}
}

func (ds *DisjointSet) Find(x string) string {
	if _, ok := ds.parent[x]; !ok {
		ds.parent[x] = x
		return x
	}
	if ds.parent[x] != x {
		ds.parent[x] = ds.Find(ds.parent[x])
	}
	return ds.parent[x]
}

func (ds *DisjointSet) Union(x, y string) {
	rootX := ds.Find(x)
	rootY := ds.Find(y)
	if rootX != rootY {
		// Deterministic root choice: smaller string is parent
		if rootX < rootY {
			ds.parent[rootY] = rootX
		} else {
			ds.parent[rootX] = rootY
		}
	}
}

// ResolveEntities builds entities using Union-Find over positive edges in descending strength order,
// with hard `cannot_link` constraint checking and merge threshold >= 0.60.
// Rule: Never merge on a single weak edge (strength < 0.60).
func ResolveEntities(allRefs []string, positiveEdges []Edge, cannotLinks []CannotLinkPair) []*Entity {
	// Initialize union-find
	uf := NewDisjointSet()
	for _, r := range allRefs {
		uf.Find(r)
	}

	// Index cannot_link constraints
	// Two sets cannot be merged if any member in root(A) and any member in root(B) have a cannot_link
	cannotLinkSet := make(map[string]map[string]bool)
	addCannotLink := func(a, b string) {
		if cannotLinkSet[a] == nil {
			cannotLinkSet[a] = make(map[string]bool)
		}
		if cannotLinkSet[b] == nil {
			cannotLinkSet[b] = make(map[string]bool)
		}
		cannotLinkSet[a][b] = true
		cannotLinkSet[b][a] = true
	}

	for _, cl := range cannotLinks {
		addCannotLink(cl.RefA, cl.RefB)
	}

	// Sort positive edges in descending strength order (tie-break deterministically)
	sort.Slice(positiveEdges, func(i, j int) bool {
		if positiveEdges[i].Strength != positiveEdges[j].Strength {
			return positiveEdges[i].Strength > positiveEdges[j].Strength
		}
		if positiveEdges[i].RefA != positiveEdges[j].RefA {
			return positiveEdges[i].RefA < positiveEdges[j].RefA
		}
		return positiveEdges[i].RefB < positiveEdges[j].RefB
	})

	// Helper to check if union of root(A) and root(B) would violate cannot_link
	canMerge := func(a, b string) bool {
		rootA := uf.Find(a)
		rootB := uf.Find(b)
		if rootA == rootB {
			return true
		}

		// Find all members in cluster A and cluster B
		var membersA, membersB []string
		for _, r := range allRefs {
			if uf.Find(r) == rootA {
				membersA = append(membersA, r)
			} else if uf.Find(r) == rootB {
				membersB = append(membersB, r)
			}
		}

		for _, ma := range membersA {
			for _, mb := range membersB {
				if cannotLinkSet[ma][mb] {
					return false
				}
			}
		}
		return true
	}

	// Apply positive edges >= MergeThreshold
	for _, edge := range positiveEdges {
		if edge.Strength < MergeThreshold {
			continue // Never merge on a single weak edge (< 0.60)
		}
		if canMerge(edge.RefA, edge.RefB) {
			uf.Union(edge.RefA, edge.RefB)
		}
	}

	// Group into entities
	clusters := make(map[string][]string)
	for _, r := range allRefs {
		root := uf.Find(r)
		clusters[root] = append(clusters[root], r)
	}

	var entities []*Entity
	var sortedRoots []string
	for root := range clusters {
		sortedRoots = append(sortedRoots, root)
	}
	sort.Strings(sortedRoots)

	for _, root := range sortedRoots {
		members := clusters[root]
		sort.Strings(members)
		entityID := ComputeEntityID(members)
		entities = append(entities, &Entity{
			EntityID:   entityID,
			Members:    members,
			PrimaryRef: members[0],
		})
	}

	// Sort entities by EntityID
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].EntityID < entities[j].EntityID
	})

	return entities
}

// ExtractIdentityEdgesAndConstraints extracts positive candidate edges and cannot_link constraints from ledger claims.
func ExtractIdentityEdgesAndConstraints(rawClaims []*claims.Claim, effectiveStates []*effective.EffectiveClaimState) ([]Edge, []CannotLinkPair) {
	var edges []Edge
	var cannotLinks []CannotLinkPair

	// 1. Direct same_as and cannot_link claims
	for _, c := range rawClaims {
		if c.Predicate == "same_as" || c.Predicate == "identity.same_as" {
			targetRef := fmt.Sprintf("%v", c.Object.Value)
			rel, _ := claims.GetSourceReliability(c.Source.Group)
			edges = append(edges, Edge{
				RefA:     c.Subject,
				RefB:     targetRef,
				Strength: rel,
				Reason:   "same_as_claim",
			})
		} else if c.Predicate == "cannot_link" || c.Predicate == "identity.cannot_link" {
			targetRef := fmt.Sprintf("%v", c.Object.Value)
			cannotLinks = append(cannotLinks, CannotLinkPair{
				RefA:   c.Subject,
				RefB:   targetRef,
				Reason: "cannot_link_claim",
			})
		}
	}

	// 2. Candidate edges from exact-match attributes in effective states
	// Group refs by (Predicate, ObjectValue)
	type attrKey struct {
		Predicate   string
		ObjectValue string
	}
	attrToRefs := make(map[attrKey][]string)

	matchablePredicates := map[string]float64{
		"host.hostname":     0.85,
		"host.machine_id":   0.95,
		"host.dns_name":     0.80,
		"artifact.sha256":   0.90,
		"process.start_exe": 0.75,
	}

	for _, st := range effectiveStates {
		if baseStr, ok := matchablePredicates[st.Predicate]; ok {
			k := attrKey{Predicate: st.Predicate, ObjectValue: st.ObjectValue}
			attrToRefs[k] = append(attrToRefs[k], st.Subject)
			_ = baseStr
		}
	}

	for k, refs := range attrToRefs {
		if len(refs) > 1 {
			baseStr := matchablePredicates[k.Predicate]
			for i := 0; i < len(refs); i++ {
				for j := i + 1; j < len(refs); j++ {
					edges = append(edges, Edge{
						RefA:     refs[i],
						RefB:     refs[j],
						Strength: baseStr,
						Reason:   fmt.Sprintf("exact_match_%s", k.Predicate),
					})
				}
			}
		}
	}

	return edges, cannotLinks
}
