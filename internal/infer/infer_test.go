package infer_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/effective"
	"github.com/OWNER/bokuei/internal/infer"
	"github.com/OWNER/bokuei/internal/store"
)

func TestInferenceEngineAndLineage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-infer-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatalf("OpenLedger failed: %v", err)
	}
	defer l.Close()

	ctx := context.Background()

	// Initial observation: run read PyTorch library
	c1 := &claims.Claim{
		Subject:      "ref://run/r-torch",
		Predicate:    "run.read",
		Object:       claims.Object{Kind: "ref", Value: "ref://artifact/torch"},
		ObservedAt:   "2026-10-07T12:00:00Z",
		Source:       claims.Source{Group: "agent", ID: "agent-1", Method: "ptrace"},
		Scope:        "ref://host/h1",
		EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Redaction:    "none",
	}

	_, err = l.IngestBatch(ctx, "b1", []*claims.Claim{c1}, nil)
	if err != nil {
		t.Fatal(err)
	}

	allClaims, err := l.GetClaimsBySubject(ctx, "ref://run/r-torch")
	if err != nil {
		t.Fatal(err)
	}

	effStates, _ := effective.ComputeEffectiveStates(allClaims, time.Now())

	rule := infer.Rule{
		ID:             "ml-job",
		Name:           "ML Job",
		MatchPredicate: "run.read",
		Condition: infer.Condition{
			Op:     "in",
			Values: []string{"ref://artifact/torch"},
		},
		Emit: infer.EmitTemplate{
			Predicate: "service.type",
			Object:    claims.Object{Kind: "text", Value: "python-ml-job"},
		},
	}

	inferred, err := infer.RunInference(allClaims, effStates, []infer.Rule{rule})
	if err != nil {
		t.Fatalf("RunInference failed: %v", err)
	}

	if len(inferred) != 1 {
		t.Fatalf("expected 1 inferred claim, got %d", len(inferred))
	}

	if inferred[0].Claim.Predicate != "service.type" || inferred[0].Claim.Object.Value != "python-ml-job" {
		t.Fatalf("unexpected inferred claim: %+v", inferred[0].Claim)
	}

	// Ingest inferred claims
	inserted, err := infer.IngestInferredClaims(ctx, l, inferred)
	if err != nil {
		t.Fatalf("IngestInferredClaims failed: %v", err)
	}
	if inserted != 1 {
		t.Fatalf("expected 1 inserted inferred claim, got %d", inserted)
	}

	// Verify claim_support lineage recorded
	var supCount int
	err = l.DB().QueryRowContext(ctx, `SELECT count(*) FROM claim_support WHERE claim_id = ?`, inferred[0].Claim.ClaimID).Scan(&supCount)
	if err != nil {
		t.Fatalf("failed to query claim_support: %v", err)
	}
	if supCount != 1 {
		t.Fatalf("expected 1 claim_support link, got %d", supCount)
	}

	// Re-run inference: must be idempotent!
	insertedAgain, err := infer.IngestInferredClaims(ctx, l, inferred)
	if err != nil {
		t.Fatalf("second IngestInferredClaims failed: %v", err)
	}
	if insertedAgain != 0 {
		t.Fatalf("expected 0 new claims on re-running inference (idempotent), got %d", insertedAgain)
	}
}
