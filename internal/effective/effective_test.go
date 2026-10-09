package effective_test

import (
	"testing"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/effective"
)

func makeClaim(subj, pred, val string, srcGroup string, obsAt string) *claims.Claim {
	return &claims.Claim{
		ClaimID:      "",
		Subject:      subj,
		Predicate:    pred,
		Object:       claims.Object{Kind: "text", Value: val},
		ObservedAt:   obsAt,
		Source:       claims.Source{Group: srcGroup, ID: srcGroup + "-1", Method: "test"},
		Scope:        "ref://host/alpha",
		EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Redaction:    "none",
	}
}

// TestTenClaimsFromOneSourceGroupEqualOneClaimInStrength asserts the core invariant:
// 10 claims from the same source group do not artificially inflate strength beyond max reliability of that group.
func TestTenClaimsFromOneSourceGroupEqualOneClaimInStrength(t *testing.T) {
	now := time.Now().UTC()
	obsAt := now.Format(time.RFC3339)

	var single []*claims.Claim
	single = append(single, makeClaim("ref://host/h1", "host.os", "ubuntu", "agent", obsAt))

	var ten []*claims.Claim
	for i := 0; i < 10; i++ {
		ten = append(ten, makeClaim("ref://host/h1", "host.os", "ubuntu", "agent", obsAt))
	}

	undec1, dec1, _, _, _ := effective.ComputeCandidateStrength(single, now, 30.0)
	undec10, dec10, _, _, _ := effective.ComputeCandidateStrength(ten, now, 30.0)

	if undec1 != undec10 {
		t.Fatalf("expected strength of 10 claims from same group to equal 1 claim (%f), got %f", undec1, undec10)
	}
	if dec1 != dec10 {
		t.Fatalf("expected decayed strength of 10 claims to equal 1 claim (%f), got %f", dec1, dec10)
	}
}

// TestTimeDecayAndStaleness asserts decay over time and flag when decayed < 50% undecayed.
func TestTimeDecayAndStaleness(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Half-life is 3.0 days. After 3.0 days, decay is exactly 50%.
	// After 4.0 days, decay is < 50% (stale).
	cFresh := makeClaim("ref://run/r1", "run.status", "ok", "agent", t0.Format(time.RFC3339))

	// Fresh: as of t0 + 1 day
	asOfFresh := t0.Add(24 * time.Hour)
	_, _, _, isStaleFresh, _ := effective.ComputeCandidateStrength([]*claims.Claim{cFresh}, asOfFresh, 3.0)
	if isStaleFresh {
		t.Fatalf("expected fresh claim to not be stale at 1 day")
	}

	// Stale: as of t0 + 4 days
	asOfStale := t0.Add(4 * 24 * time.Hour)
	undec, decStale, _, isStaleStale, _ := effective.ComputeCandidateStrength([]*claims.Claim{cFresh}, asOfStale, 3.0)
	if !isStaleStale {
		t.Fatalf("expected claim to be stale at 4 days (halflife 3d), undec=%f dec=%f", undec, decStale)
	}
	if decStale >= (0.5 * undec) {
		t.Fatalf("expected decayed strength to be < 50%% of undecayed")
	}
}

// TestHumanVerificationNoDecay asserts human verification gives 1.0 with no decay.
func TestHumanVerificationNoDecay(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := makeClaim("ref://host/h1", "host.role", "database", "human", t0.Format(time.RFC3339))

	// As of 1 year later!
	asOf := t0.Add(365 * 24 * time.Hour)
	undec, dec, isHuman, isStale, _ := effective.ComputeCandidateStrength([]*claims.Claim{c}, asOf, 30.0)

	if !isHuman {
		t.Fatalf("expected isHuman=true")
	}
	if undec != 1.0 || dec != 1.0 {
		t.Fatalf("expected human verification strength=1.0 with no decay, got undec=%f, dec=%f", undec, dec)
	}
	if isStale {
		t.Fatalf("expected human verified claim never stale")
	}
}

// TestRetractionViaMetaRetracts asserts that tq.meta.retracts negates targeted claim without mutation.
func TestRetractionViaMetaRetracts(t *testing.T) {
	now := time.Now().UTC()
	obsAt := now.Format(time.RFC3339)

	c1 := makeClaim("ref://host/h1", "host.domain", "corp.internal", "agent", obsAt)
	c1.ClaimID = "claim-100"

	// Initial effective state
	states1, _ := effective.ComputeEffectiveStates([]*claims.Claim{c1}, now)
	if len(states1) != 1 || states1[0].ObjectValue != "corp.internal" {
		t.Fatalf("expected active effective state for c1")
	}

	// Append retraction claim: never modify c1!
	cRetract := &claims.Claim{
		ClaimID:      "claim-retract-1",
		Subject:      "ref://host/h1",
		Predicate:    "tq.meta.retracts",
		Object:       claims.Object{Kind: "text", Value: "claim-100"},
		ObservedAt:   obsAt,
		Source:       claims.Source{Group: "admin", ID: "admin-1", Method: "cli"},
		Scope:        "ref://host/alpha",
		EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Redaction:    "none",
	}

	states2, retractedIDs := effective.ComputeEffectiveStates([]*claims.Claim{c1, cRetract}, now)
	if !retractedIDs["claim-100"] {
		t.Fatalf("expected claim-100 to be in retractedIDs")
	}
	if len(states2) != 0 {
		t.Fatalf("expected 0 active states after retraction, got %d", len(states2))
	}
}
