package impact_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/impact"
	"github.com/OWNER/bokuei/internal/store"
	"github.com/OWNER/bokuei/internal/testutil"
)

func createClaim(subj, pred, val string) *claims.Claim {
	return &claims.Claim{
		Subject:      subj,
		Predicate:    pred,
		Object:       claims.Object{Kind: "ref", Value: val},
		ObservedAt:   "2026-10-08T10:00:00Z",
		Source:       claims.Source{Group: "agent", ID: "agent-1", Method: "test"},
		Scope:        "ref://host/alpha",
		EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Redaction:    "none",
	}
}

// TestImpactBoundariesAndDepthLimit asserts that impact traversal terminates within max depth 20.
func TestImpactBoundariesAndDepthLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-impact-test-*")
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

	// Create a chain of 25 nodes (from n0 to n24)
	var chainClaims []*claims.Claim
	for i := 0; i < 25; i++ {
		parent := fmt.Sprintf("ref://artifact/node-%d", i)
		child := fmt.Sprintf("ref://run/run-%d", i+1)
		chainClaims = append(chainClaims, createClaim(child, "run.read", parent))
		if i+1 < 25 {
			nextArtifact := fmt.Sprintf("ref://artifact/node-%d", i+1)
			chainClaims = append(chainClaims, createClaim(child, "run.wrote", nextArtifact))
		}
	}

	_, err = l.IngestBatch(ctx, "b-chain", chainClaims, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := impact.ComputeImpact(ctx, l, "ref://artifact/node-0")
	if err != nil {
		t.Fatalf("ComputeImpact failed: %v", err)
	}

	for _, d := range res.Dependents {
		if d.Depth > 20 {
			t.Fatalf("depth exceeded limit of 20: got %d for %s", d.Depth, d.Ref)
		}
	}
}

// TestBlindSpotDetectionAndVerdictDeterminism asserts that unobservable runs trigger caution or do-not-proceed.
func TestBlindSpotDetectionAndVerdictDeterminism(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-impact-blind-*")
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

	// Artifact read by run-blocked which has coverage.blocked
	c1 := createClaim("ref://run/run-blocked", "run.read", "ref://dataset/ds-sensitive")
	c2 := &claims.Claim{
		Subject:      "ref://run/run-blocked",
		Predicate:    "coverage.blocked",
		Object:       claims.Object{Kind: "text", Value: "ptrace_denied"},
		ObservedAt:   "2026-10-08T10:00:00Z",
		Source:       claims.Source{Group: "agent", ID: "agent-1", Method: "test"},
		Scope:        "ref://host/alpha",
		EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Redaction:    "none",
	}

	_, err = l.IngestBatch(ctx, "b1", []*claims.Claim{c1, c2}, nil)
	if err != nil {
		t.Fatal(err)
	}

	res1, err := impact.ComputeImpact(ctx, l, "ref://dataset/ds-sensitive")
	if err != nil {
		t.Fatal(err)
	}

	if len(res1.BlindSpots) == 0 {
		t.Fatalf("expected blind spots for run with blocked file I/O")
	}

	if res1.Verdict != impact.VerdictDoNotProceedUntilQuestions {
		t.Fatalf("expected verdict '%s', got '%s'", impact.VerdictDoNotProceedUntilQuestions, res1.Verdict)
	}

	// Verify verdict determinism across multiple calls
	res2, err := impact.ComputeImpact(ctx, l, "ref://dataset/ds-sensitive")
	if err != nil {
		t.Fatal(err)
	}
	if res1.Verdict != res2.Verdict {
		t.Fatalf("verdict was not deterministic")
	}
}

// TestImpactDemoEstateEvaluation asserts reverse traversal against the demo dataset.
func TestImpactDemoEstateEvaluation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bokuei-impact-demo-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	l, _, err := testutil.SetupTestLedgerWithFixture(tmpDir, "../../rules")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	datasetRef := "ref://dataset/imagenet-subset-v1"
	firstRun := "ref://run/run-001"
	secondRun := "ref://run/run-004"

	res, err := impact.ComputeImpact(context.Background(), l, datasetRef)
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Dependents) == 0 {
		t.Fatalf("expected dependents for dataset %s", datasetRef)
	}

	foundFirst := false
	foundSecond := false
	for _, d := range res.Dependents {
		if d.Ref == firstRun {
			foundFirst = true
		}
		if d.Ref == secondRun {
			foundSecond = true
		}
	}

	if !foundFirst || !foundSecond {
		t.Fatalf("expected to find runs %s and %s in dependents", firstRun, secondRun)
	}
}
