package store_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/store"
)

func createTestClaim(subject, predicate, kind string, val interface{}, obsAt string) *claims.Claim {
	return &claims.Claim{
		Subject:   subject,
		Predicate: predicate,
		Object: claims.Object{
			Kind:  kind,
			Value: val,
		},
		ObservedAt: obsAt,
		Source: claims.Source{
			Group:  "agent",
			ID:     "agent-01",
			Method: "procfs",
		},
		Scope:        "ref://host/h1",
		EvidenceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Redaction:    "none",
	}
}

func TestAppendOnlyTriggers(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-store-test-*")
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
	c1 := createTestClaim("ref://run/r1", "run.command", "text", "echo hello", "2026-10-07T12:00:00Z")
	res, err := l.IngestBatch(ctx, "batch-1", []*claims.Claim{c1}, nil)
	if err != nil {
		t.Fatalf("IngestBatch failed: %v", err)
	}
	if res.InsertedClaims != 1 {
		t.Fatalf("expected 1 inserted claim, got %d", res.InsertedClaims)
	}

	// Attempt UPDATE on claims
	_, err = l.DB().Exec("UPDATE claims SET redaction = 'redacted' WHERE subject = 'ref://run/r1'")
	if err == nil {
		t.Fatal("expected UPDATE on claims table to be REJECTED, but succeeded")
	}

	// Attempt DELETE on claims
	_, err = l.DB().Exec("DELETE FROM claims WHERE subject = 'ref://run/r1'")
	if err == nil {
		t.Fatal("expected DELETE on claims table to be REJECTED, but succeeded")
	}
}

func TestStateChangeDeduplication(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-dedup-test-*")
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

	// Initial observation
	c1 := createTestClaim("ref://host/h1", "package.version", "text", "1.0.0", "2026-10-07T12:00:00Z")
	res1, err := l.IngestBatch(ctx, "batch-1", []*claims.Claim{c1}, nil)
	if err != nil {
		t.Fatalf("batch 1 failed: %v", err)
	}
	if res1.InsertedClaims != 1 {
		t.Fatalf("expected 1 inserted claim, got %d", res1.InsertedClaims)
	}

	// Re-ingest IDENTICAL observation (state deduplication test: creates zero new claims)
	c2 := createTestClaim("ref://host/h1", "package.version", "text", "1.0.0", "2026-10-07T12:05:00Z")
	res2, err := l.IngestBatch(ctx, "batch-2", []*claims.Claim{c2}, nil)
	if err != nil {
		t.Fatalf("batch 2 failed: %v", err)
	}
	if res2.InsertedClaims != 0 {
		t.Fatalf("expected 0 inserted claims on identical state re-ingest, got %d", res2.InsertedClaims)
	}
	if res2.DedupStateClaims != 1 {
		t.Fatalf("expected 1 deduped claim, got %d", res2.DedupStateClaims)
	}

	// New changed observation (package upgrade) -> MUST be inserted
	c3 := createTestClaim("ref://host/h1", "package.version", "text", "1.1.0", "2026-10-07T12:10:00Z")
	res3, err := l.IngestBatch(ctx, "batch-3", []*claims.Claim{c3}, nil)
	if err != nil {
		t.Fatalf("batch 3 failed: %v", err)
	}
	if res3.InsertedClaims != 1 {
		t.Fatalf("expected 1 inserted claim on state change, got %d", res3.InsertedClaims)
	}

	// Verify ledger sequence
	history, err := l.GetClaimsBySubject(ctx, "ref://host/h1")
	if err != nil {
		t.Fatalf("GetClaimsBySubject failed: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 total claims in ledger for host, got %d", len(history))
	}
}

func TestIdempotencyExactClaimID(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tq-idempotency-test-*")
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
	c1 := createTestClaim("ref://run/r1", "run.command", "text", "python script.py", "2026-10-07T12:00:00Z")
	res1, err := l.IngestBatch(ctx, "batch-1", []*claims.Claim{c1}, nil)
	if err != nil {
		t.Fatalf("batch 1 failed: %v", err)
	}
	if res1.InsertedClaims != 1 {
		t.Fatalf("expected 1 inserted claim, got %d", res1.InsertedClaims)
	}

	// Re-insert exact same claim object (same observed_at -> same claim_id)
	c1Again := createTestClaim("ref://run/r1", "run.command", "text", "python script.py", "2026-10-07T12:00:00Z")
	res2, err := l.IngestBatch(ctx, "batch-2", []*claims.Claim{c1Again}, nil)
	if err != nil {
		t.Fatalf("batch 2 failed: %v", err)
	}
	if res2.InsertedClaims != 0 {
		t.Fatalf("expected 0 inserted claims on identical claim_id, got %d", res2.InsertedClaims)
	}
	if res2.SkippedExisting != 1 {
		t.Fatalf("expected 1 skipped existing, got %d", res2.SkippedExisting)
	}
}

func BenchmarkIngestClaims(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "tq-bench-*")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		b.Fatalf("OpenLedger failed: %v", err)
	}
	defer l.Close()

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := createTestClaim("ref://run/r1", "run.command", "text", fmt.Sprintf("cmd-%d", i), fmt.Sprintf("2026-10-07T12:%02d:%02dZ", (i/60)%60, i%60))
		_, _ = l.IngestBatch(ctx, fmt.Sprintf("batch-%d", i), []*claims.Claim{c}, nil)
	}
}
