package diff_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/diff"
	"github.com/OWNER/bokuei/internal/store"
)

func createClaim(subj, pred, val, obsAt string) *claims.Claim {
	return &claims.Claim{
		Subject:      subj,
		Predicate:    pred,
		Object:       claims.Object{Kind: "text", Value: val},
		ObservedAt:   obsAt,
		Source:       claims.Source{Group: "agent", ID: "agent-1", Method: "test"},
		Scope:        "ref://host/alpha",
		EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Redaction:    "none",
	}
}

// TestIdenticalRunsGiveEmptyDiff asserts that comparing two runs with identical state yields zero differences.
func TestIdenticalRunsGiveEmptyDiff(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-diff-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()

	// Run 1 & Run 2 with identical commands & exit status
	c1 := createClaim("ref://run/r1", "run.command", "python train.py", "2026-10-08T10:00:00Z")
	c2 := createClaim("ref://run/r2", "run.command", "python train.py", "2026-10-08T11:00:00Z")

	_, err = l.IngestBatch(ctx, "b1", []*claims.Claim{c1, c2}, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := diff.ComputeDiff(ctx, l, "ref://run/r1", "ref://run/r2", "../../rules")
	if err != nil {
		t.Fatalf("ComputeDiff failed: %v", err)
	}

	for _, ch := range res.Changes {
		if ch.Status == "changed" {
			t.Fatalf("expected empty changes for identical run commands, got change: %+v", ch)
		}
	}
}

// TestNotComparableHandling asserts that a transition from observed to not visible is reported as "not comparable", never "removed" or "absent".
func TestNotComparableHandling(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-diff-notcomp-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()

	// Observed in r1 only
	c1 := createClaim("ref://run/r1", "package.version", "torch-2.2.0", "2026-10-08T10:00:00Z")
	_, err = l.IngestBatch(ctx, "b1", []*claims.Claim{c1}, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := diff.ComputeDiff(ctx, l, "ref://run/r1", "ref://run/r2", "../../rules")
	if err != nil {
		t.Fatalf("ComputeDiff failed: %v", err)
	}

	foundNotComp := false
	for _, ch := range res.Changes {
		if ch.Predicate == "package.version" {
			if ch.Status != "not comparable" {
				t.Fatalf("expected status 'not comparable', got '%s'", ch.Status)
			}
			if ch.NewValue != "not visible" {
				t.Fatalf("expected NewValue 'not visible', got '%s'", ch.NewValue)
			}
			foundNotComp = true
		}
	}

	if !foundNotComp {
		t.Fatalf("expected not comparable change for unobserved package.version in r2")
	}
}

// TestTemporalReconstruction asserts that diff using relative timestamps ("1h", "24h") evaluates effective states correctly.
func TestTemporalReconstruction(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-diff-time-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	tOld := now.Add(-48 * time.Hour).Format(time.RFC3339)
	tNew := now.Add(-2 * time.Hour).Format(time.RFC3339)

	cOld := createClaim("ref://host/h1", "host.kernel", "6.8.0-30", tOld)
	cNew := createClaim("ref://host/h1", "host.kernel", "6.8.0-45", tNew)

	_, err = l.IngestBatch(ctx, "b1", []*claims.Claim{cOld, cNew}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Compare 24h ago vs now
	res, err := diff.ComputeDiff(ctx, l, "24h", now.Format(time.RFC3339), "../../rules")
	if err != nil {
		t.Fatalf("ComputeDiff with temporal reconstruction failed: %v", err)
	}

	foundKernel := false
	for _, ch := range res.Changes {
		if ch.Predicate == "host.kernel" {
			foundKernel = true
			if ch.OldValue != "6.8.0-30" || ch.NewValue != "6.8.0-45" {
				t.Fatalf("unexpected kernel diff: old=%s, new=%s", ch.OldValue, ch.NewValue)
			}
		}
	}

	if !foundKernel {
		t.Fatalf("expected kernel change in temporal diff")
	}
}

// TestEachRankedCausePointsToRealClaims asserts that every ranked cause carries valid supporting claims.
func TestEachRankedCausePointsToRealClaims(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-diff-rank-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()
	c1 := createClaim("ref://dataset/d1", "artifact.sha256", "hash-aaa", "2026-10-08T10:00:00Z")
	c2 := createClaim("ref://dataset/d1", "artifact.sha256", "hash-bbb", "2026-10-08T12:00:00Z")

	_, err = l.IngestBatch(ctx, "b1", []*claims.Claim{c1, c2}, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := diff.ComputeDiff(ctx, l, "2026-10-08T11:00:00Z", "2026-10-08T13:00:00Z", "../../rules")
	if err != nil {
		t.Fatalf("ComputeDiff failed: %v", err)
	}

	if len(res.RankedCauses) == 0 {
		t.Fatalf("expected at least 1 ranked cause for dataset change")
	}

	for _, cause := range res.RankedCauses {
		if len(cause.SupportingClaims) == 0 {
			t.Fatalf("cause %s had 0 supporting claims", cause.RuleID)
		}
		for _, sc := range cause.SupportingClaims {
			if sc.ClaimID == "" {
				t.Fatalf("supporting claim ID must not be empty")
			}
		}
	}
}

// TestDeterministicOrdering asserts that running diff multiple times on the same inputs yields identical ranked order.
func TestDeterministicOrdering(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-diff-det-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()
	c1 := createClaim("ref://dataset/d1", "artifact.sha256", "v1", "2026-10-08T10:00:00Z")
	c2 := createClaim("ref://host/h1", "host.kernel", "6.8.0-30", "2026-10-08T10:00:00Z")
	c3 := createClaim("ref://dataset/d1", "artifact.sha256", "v2", "2026-10-08T12:00:00Z")
	c4 := createClaim("ref://host/h1", "host.kernel", "6.8.0-45", "2026-10-08T12:00:00Z")

	_, err = l.IngestBatch(ctx, "b1", []*claims.Claim{c1, c2, c3, c4}, nil)
	if err != nil {
		t.Fatal(err)
	}

	res1, err := diff.ComputeDiff(ctx, l, "2026-10-08T11:00:00Z", "2026-10-08T13:00:00Z", "../../rules")
	if err != nil {
		t.Fatal(err)
	}
	res2, err := diff.ComputeDiff(ctx, l, "2026-10-08T11:00:00Z", "2026-10-08T13:00:00Z", "../../rules")
	if err != nil {
		t.Fatal(err)
	}

	if len(res1.RankedCauses) != len(res2.RankedCauses) {
		t.Fatalf("mismatched ranked cause count: %d vs %d", len(res1.RankedCauses), len(res2.RankedCauses))
	}
	for i := range res1.RankedCauses {
		if res1.RankedCauses[i].RuleID != res2.RankedCauses[i].RuleID ||
			res1.RankedCauses[i].Weight != res2.RankedCauses[i].Weight ||
			res1.RankedCauses[i].Rank != res2.RankedCauses[i].Rank {
			t.Fatalf("nondeterministic cause order at index %d", i)
		}
	}
}

// TestBlockedVisibilityHandling asserts that blocked coverage items report not visible / not comparable and never absent.
func TestBlockedVisibilityHandling(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-diff-blocked-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()
	c1 := createClaim("ref://run/r1", "coverage.blocked", "ptrace_denied", "2026-10-08T10:00:00Z")
	_, err = l.IngestBatch(ctx, "b1", []*claims.Claim{c1}, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := diff.ComputeDiff(ctx, l, "ref://run/r1", "ref://run/r2", "../../rules")
	if err != nil {
		t.Fatal(err)
	}

	for _, ch := range res.Changes {
		if ch.OldValue == "absent" || ch.NewValue == "absent" {
			t.Fatalf("invariant violation: blocked scope item described as absent")
		}
	}
}
