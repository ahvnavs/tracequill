package store_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/store"
)

type AgentBatch struct {
	BatchID   string          `json:"batch_id"`
	CreatedAt string          `json:"created_at"`
	Claims    []*claims.Claim `json:"claims"`
}

func findAgentBinary(t *testing.T) string {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	candidates := []string{
		filepath.Join(wd, "../../target/debug/bokuei-agent"),
		filepath.Join(wd, "../../target/release/bokuei-agent"),
		filepath.Join(wd, "../target/debug/bokuei-agent"),
		filepath.Join(wd, "target/debug/bokuei-agent"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("bokuei-agent binary not found, skipping cross-language test")
	return ""
}

// TestCrossLanguageAgentBatchIngest tests that the Rust agent writes claims in NDJSON/JSON batch,
// and the Go ledger ingests them with exact claim_id agreement and idempotency.
func TestCrossLanguageAgentBatchIngest(t *testing.T) {
	agentBin := findAgentBinary(t)

	tmpDir, err := os.MkdirTemp("", "tq-cross-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	outFile := filepath.Join(tmpDir, "agent_out.json")
	cmd := exec.Command(agentBin, "run", "--out", outFile, "--", "echo", "hello-bokuei")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent run failed: %v, output: %s", err, string(out))
	}

	batchBytes, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read agent output: %v", err)
	}

	var batch AgentBatch
	if err := json.Unmarshal(batchBytes, &batch); err != nil {
		t.Fatalf("failed to unmarshal agent batch: %v", err)
	}

	if len(batch.Claims) == 0 {
		t.Fatalf("agent produced 0 claims")
	}

	// Verify every claim has valid structure and claim_id matches Go computation
	for i, c := range batch.Claims {
		if err := c.Validate(); err != nil {
			t.Fatalf("claim %d validation failed: %v", i, err)
		}
		expectedID, err := c.ComputeID()
		if err != nil {
			t.Fatalf("claim %d ComputeID failed: %v", i, err)
		}
		if c.ClaimID != expectedID {
			t.Fatalf("claim %d id mismatch: Rust produced %s, Go computed %s", i, c.ClaimID, expectedID)
		}
	}

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatalf("OpenLedger failed: %v", err)
	}
	defer l.Close()

	ctx := context.Background()

	// Ingest batch first time
	res1, err := l.IngestBatch(ctx, batch.BatchID, batch.Claims, nil)
	if err != nil {
		t.Fatalf("IngestBatch 1 failed: %v", err)
	}
	if res1.InsertedClaims != len(batch.Claims) {
		t.Fatalf("expected %d inserted claims, got %d", len(batch.Claims), res1.InsertedClaims)
	}

	// Re-ingest the exact same batch: must create zero new claims!
	res2, err := l.IngestBatch(ctx, batch.BatchID, batch.Claims, nil)
	if err != nil {
		t.Fatalf("IngestBatch 2 failed: %v", err)
	}
	if res2.InsertedClaims != 0 {
		t.Fatalf("expected 0 new claims on re-ingesting same batch, got %d", res2.InsertedClaims)
	}
	if res2.SkippedExisting != len(batch.Claims) {
		t.Fatalf("expected %d skipped existing claims, got %d", len(batch.Claims), res2.SkippedExisting)
	}
}

// TestCollectAgentBatchIngest tests that `bokuei-agent collect --once` claims are valid and ingested by Go.
func TestCollectAgentBatchIngest(t *testing.T) {
	agentBin := findAgentBinary(t)

	tmpDir, err := os.MkdirTemp("", "tq-collect-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	outFile := filepath.Join(tmpDir, "host_out.json")
	cmd := exec.Command(agentBin, "collect", "--once", "--out", outFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent collect failed: %v, output: %s", err, string(out))
	}

	batchBytes, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read agent host output: %v", err)
	}

	var batch AgentBatch
	if err := json.Unmarshal(batchBytes, &batch); err != nil {
		t.Fatalf("failed to unmarshal agent batch: %v", err)
	}

	if len(batch.Claims) == 0 {
		t.Fatalf("agent collect produced 0 claims")
	}

	hasHostKernel := false
	hasHostRAM := false
	for _, c := range batch.Claims {
		if c.Predicate == "host.kernel" {
			hasHostKernel = true
		}
		if c.Predicate == "host.ram_bytes" {
			hasHostRAM = true
		}
		expectedID, err := c.ComputeID()
		if err != nil {
			t.Fatalf("host claim ComputeID failed: %v", err)
		}
		if c.ClaimID != expectedID {
			t.Fatalf("host claim id mismatch: Rust %s vs Go %s", c.ClaimID, expectedID)
		}
	}

	if !hasHostKernel {
		t.Errorf("expected host.kernel claim in collect batch")
	}
	if !hasHostRAM {
		t.Errorf("expected host.ram_bytes claim in collect batch")
	}

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatalf("OpenLedger failed: %v", err)
	}
	defer l.Close()

	res, err := l.IngestBatch(context.Background(), batch.BatchID, batch.Claims, nil)
	if err != nil {
		t.Fatalf("IngestBatch failed for collect claims: %v", err)
	}
	if res.InsertedClaims == 0 {
		t.Fatalf("expected > 0 inserted claims, got 0")
	}

	// Verify we can query by host ref
	var hostRef string
	for _, c := range batch.Claims {
		if strings.HasPrefix(c.Subject, "ref://host/") {
			hostRef = c.Subject
			break
		}
	}
	if hostRef != "" {
		hostClaims, err := l.GetClaimsBySubject(context.Background(), hostRef)
		if err != nil {
			t.Fatalf("GetClaimsBySubject failed: %v", err)
		}
		if len(hostClaims) == 0 {
			t.Fatalf("expected claims returned for host ref %s", hostRef)
		}
	}
}

// TestProbeAgentBatchIngest tests that `bokuei-agent probe` produces capability and interface claims
// verified with identical claim IDs in Go and correctly ingested into the ledger.
func TestProbeAgentBatchIngest(t *testing.T) {
	agentBin := findAgentBinary(t)

	tmpDir, err := os.MkdirTemp("", "bokuei-probe-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	outFile := filepath.Join(tmpDir, "probe_out.json")
	cmd := exec.Command(agentBin, "probe", "--out", outFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent probe failed: %v, output: %s", err, string(out))
	}

	batchBytes, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read agent probe output: %v", err)
	}

	var batch AgentBatch
	if err := json.Unmarshal(batchBytes, &batch); err != nil {
		t.Fatalf("failed to unmarshal agent batch: %v", err)
	}

	if len(batch.Claims) == 0 {
		t.Fatalf("agent probe produced 0 claims")
	}

	hasCapPred := false
	for _, c := range batch.Claims {
		if c.Predicate == "capability.can" || c.Predicate == "capability.cannot" {
			hasCapPred = true
		}
		expectedID, err := c.ComputeID()
		if err != nil {
			t.Fatalf("probe claim ComputeID failed: %v", err)
		}
		if c.ClaimID != expectedID {
			t.Fatalf("probe claim id mismatch: Rust produced %s vs Go %s", c.ClaimID, expectedID)
		}
	}

	if !hasCapPred {
		t.Fatalf("expected capability.can or capability.cannot in probe batch")
	}

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatalf("OpenLedger failed: %v", err)
	}
	defer l.Close()

	res, err := l.IngestBatch(context.Background(), batch.BatchID, batch.Claims, nil)
	if err != nil {
		t.Fatalf("IngestBatch failed for probe claims: %v", err)
	}
	if res.InsertedClaims == 0 {
		t.Fatalf("expected > 0 inserted claims from probe batch")
	}
}
