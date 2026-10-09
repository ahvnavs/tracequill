package resolve_test

import (
	"testing"

	"github.com/OWNER/bokuei/internal/resolve"
)

// TestCannotLinkNeverViolated asserts that cannot_link constraint is never violated even with high positive strength.
func TestCannotLinkNeverViolated(t *testing.T) {
	allRefs := []string{"ref://host/h1", "ref://host/h2"}
	edges := []resolve.Edge{
		{RefA: "ref://host/h1", RefB: "ref://host/h2", Strength: 0.99, Reason: "same_as"},
	}
	cannotLinks := []resolve.CannotLinkPair{
		{RefA: "ref://host/h1", RefB: "ref://host/h2", Reason: "distinct_hardware"},
	}

	entities := resolve.ResolveEntities(allRefs, edges, cannotLinks)
	if len(entities) != 2 {
		t.Fatalf("expected 2 distinct entities due to cannot_link, got %d", len(entities))
	}
}

// TestWrongSameAsUndoneByAppendedCannotLink asserts that appending cannot_link separates previously linked entities without modifying old claims.
func TestWrongSameAsUndoneByAppendedCannotLink(t *testing.T) {
	allRefs := []string{"ref://host/h1", "ref://host/h2"}
	edges := []resolve.Edge{
		{RefA: "ref://host/h1", RefB: "ref://host/h2", Strength: 0.85, Reason: "initial_guess"},
	}

	// Without constraint: they merge
	entities1 := resolve.ResolveEntities(allRefs, edges, nil)
	if len(entities1) != 1 {
		t.Fatalf("expected 1 merged entity, got %d", len(entities1))
	}

	// Now append cannot_link:
	cannotLinks := []resolve.CannotLinkPair{
		{RefA: "ref://host/h1", RefB: "ref://host/h2", Reason: "correction"},
	}
	entities2 := resolve.ResolveEntities(allRefs, edges, cannotLinks)
	if len(entities2) != 2 {
		t.Fatalf("expected separation into 2 entities after cannot_link, got %d", len(entities2))
	}
}

// TestNeverMergeOnSingleWeakEdge asserts that edges below merge threshold 0.60 do not cause a merge.
func TestNeverMergeOnSingleWeakEdge(t *testing.T) {
	allRefs := []string{"ref://host/h1", "ref://host/h2"}
	edges := []resolve.Edge{
		{RefA: "ref://host/h1", RefB: "ref://host/h2", Strength: 0.55, Reason: "weak_heuristic"},
	}

	entities := resolve.ResolveEntities(allRefs, edges, nil)
	if len(entities) != 2 {
		t.Fatalf("expected 2 entities because edge strength 0.55 < 0.60, got %d", len(entities))
	}
}

// TestDeterministicEntityID asserts that Entity ID = sha256(smallest member ref).
func TestDeterministicEntityID(t *testing.T) {
	members := []string{"ref://host/z-host", "ref://host/a-host", "ref://host/m-host"}
	id1 := resolve.ComputeEntityID(members)
	id2 := resolve.ComputeEntityID([]string{"ref://host/a-host", "ref://host/z-host"})

	// Since ref://host/a-host is the smallest in both sets, their IDs must be identical
	if id1 != id2 {
		t.Fatalf("expected identical Entity IDs based on smallest member ref, got %s and %s", id1, id2)
	}
}
