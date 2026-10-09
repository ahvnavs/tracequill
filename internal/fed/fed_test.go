package fed_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/fed"
	"github.com/OWNER/bokuei/internal/store"
	"github.com/OWNER/bokuei/internal/testutil"
)

func setupTestLedger(t *testing.T) (*store.Ledger, string) {
	t.Helper()
	tmpDir := t.TempDir()

	l, dbPath, err := testutil.SetupTestLedgerWithFixture(tmpDir, "")
	if err != nil {
		t.Fatalf("failed setting up test ledger with fixture: %v", err)
	}
	return l, dbPath
}

func TestExportImportRoundTrip(t *testing.T) {
	l1, _ := setupTestLedger(t)
	defer l1.Close()

	kp, err := fed.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed generating keypair: %v", err)
	}

	ctx := context.Background()

	// 1. Export batch 1 from ledger 1
	batch1, err := fed.ExportLedger(ctx, l1, kp, nil)
	if err != nil {
		t.Fatalf("export batch 1 failed: %v", err)
	}
	if batch1.SeqNo != 1 || batch1.ClaimsCount == 0 {
		t.Fatalf("invalid batch 1: seq %d, count %d", batch1.SeqNo, batch1.ClaimsCount)
	}

	// 2. Open clean target ledger 2
	tmpDir := t.TempDir()
	dbPath2 := filepath.Join(tmpDir, "ledger2.db")
	l2, err := store.OpenLedger(dbPath2)
	if err != nil {
		t.Fatalf("failed opening ledger 2: %v", err)
	}
	defer l2.Close()

	// 3. Import into ledger 2 with trusted key list
	res, err := fed.ImportBatch(ctx, l2, batch1, []string{kp.PublicKey}, false)
	if err != nil {
		t.Fatalf("import batch 1 failed: %v", err)
	}
	if res.InsertedClaims != batch1.ClaimsCount {
		t.Fatalf("expected %d inserted claims, got %d", batch1.ClaimsCount, res.InsertedClaims)
	}
	if !res.TrustedSigner || res.ValidationLabel != "trusted" {
		t.Errorf("expected trusted signer status, got %s", res.ValidationLabel)
	}

	// 4. Duplicate import idempotence
	resDup, err := fed.ImportBatch(ctx, l2, batch1, []string{kp.PublicKey}, false)
	if err != nil {
		t.Fatalf("duplicate import failed: %v", err)
	}
	if resDup.InsertedClaims != 0 || resDup.DedupedClaims != batch1.ClaimsCount {
		t.Errorf("expected idempotent no-op (0 inserted), got %d inserted", resDup.InsertedClaims)
	}
}

func TestTamperedBatchRejection(t *testing.T) {
	l1, _ := setupTestLedger(t)
	defer l1.Close()

	kp, _ := fed.GenerateKeyPair()
	batch, err := fed.ExportLedger(context.Background(), l1, kp, nil)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	tmpDir := t.TempDir()
	l2, _ := store.OpenLedger(filepath.Join(tmpDir, "target.db"))
	defer l2.Close()

	// Tamper case 1: Tamper a claim in payload
	tamperedPayloadBatch := *batch
	tamperedClaims := make([]*claims.Claim, len(batch.Claims))
	copy(tamperedClaims, batch.Claims)
	// Mutate first claim object value
	tamperedClaims[0].Object.Value = "TAMPERED_VAL"
	tamperedPayloadBatch.Claims = tamperedClaims

	_, err = fed.ImportBatch(context.Background(), l2, &tamperedPayloadBatch, nil, true)
	if err == nil || !strings.Contains(err.Error(), "TAMPERED_BATCH_REJECTED") {
		t.Fatalf("expected TAMPERED_BATCH_REJECTED on mutated claim payload, got: %v", err)
	}

	// Tamper case 2: Tamper signature
	tamperedSigBatch := *batch
	tamperedSigBatch.Signature = strings.Repeat("a", 128)
	_, err = fed.ImportBatch(context.Background(), l2, &tamperedSigBatch, nil, true)
	if err == nil || !strings.Contains(err.Error(), "TAMPERED_BATCH_REJECTED") {
		t.Fatalf("expected TAMPERED_BATCH_REJECTED on invalid signature, got: %v", err)
	}
}

func TestSequenceGapRejection(t *testing.T) {
	l1, _ := setupTestLedger(t)
	defer l1.Close()

	kp, _ := fed.GenerateKeyPair()
	ctx := context.Background()

	// Export batch 1
	batch1, _ := fed.ExportLedger(ctx, l1, kp, nil)

	// Append a new claim and export batch 2
	cNew := &claims.Claim{
		Subject:      "ref://host/gap-test",
		Predicate:    "host.kernel",
		Object:       claims.Object{Kind: "text", Value: "6.8.0-generic"},
		ObservedAt:   time.Now().UTC().Format(time.RFC3339),
		Source:       claims.Source{Group: "agent", ID: "gap-agent", Method: "uname"},
		Scope:        "ref://host/gap-test",
		EvidenceHash: strings.Repeat("1", 64),
		Redaction:    "none",
	}
	_, _ = l1.IngestBatch(ctx, "batch-gap", []*claims.Claim{cNew}, nil)

	batch2, err := fed.ExportLedger(ctx, l1, kp, nil)
	if err != nil {
		t.Fatalf("export batch 2 failed: %v", err)
	}
	if batch2.SeqNo != 2 {
		t.Fatalf("expected seq 2, got %d", batch2.SeqNo)
	}

	tmpDir := t.TempDir()
	l2, _ := store.OpenLedger(filepath.Join(tmpDir, "target.db"))
	defer l2.Close()

	// Try importing batch 2 directly without batch 1 -> MUST FAIL with sequence gap rejection
	_, err = fed.ImportBatch(ctx, l2, batch2, nil, true)
	if err == nil || !strings.Contains(err.Error(), "SEQUENCE_GAP_REJECTED") {
		t.Fatalf("expected SEQUENCE_GAP_REJECTED when skipping sequence 1, got: %v", err)
	}

	// Now import batch 1 successfully
	_, err = fed.ImportBatch(ctx, l2, batch1, nil, true)
	if err != nil {
		t.Fatalf("failed importing batch 1: %v", err)
	}

	// Now batch 2 must succeed
	res2, err := fed.ImportBatch(ctx, l2, batch2, nil, true)
	if err != nil {
		t.Fatalf("failed importing batch 2 after batch 1: %v", err)
	}
	if res2.InsertedClaims < 1 {
		t.Errorf("expected inserted claims in batch 2, got %d", res2.InsertedClaims)
	}
}

func TestPolicyTransformations(t *testing.T) {
	c1 := &claims.Claim{
		Subject:      "ref://host/worker-01",
		Predicate:    "host.ip",
		Object:       claims.Object{Kind: "text", Value: "10.0.1.45"},
		ObservedAt:   time.Now().UTC().Format(time.RFC3339),
		Source:       claims.Source{Group: "agent", ID: "net", Method: "ip"},
		Scope:        "ref://host/worker-01",
		EvidenceHash: strings.Repeat("0", 64),
		Redaction:    "none",
	}
	c2 := &claims.Claim{
		Subject:      "ref://host/internal-db",
		Predicate:    "secret.token",
		Object:       claims.Object{Kind: "text", Value: "supersecret"},
		ObservedAt:   time.Now().UTC().Format(time.RFC3339),
		Source:       claims.Source{Group: "agent", ID: "sec", Method: "env"},
		Scope:        "ref://host/internal-db",
		EvidenceHash: strings.Repeat("0", 64),
		Redaction:    "none",
	}

	policy := &fed.PolicyRule{
		Drop: []string{"secret.token"},
		Generalize: map[string]string{
			"10.0.*": "ref://zone/private-internal",
		},
		Pseudonymize:  []string{"ref://host/worker-01"},
		PseudonymSalt: "test-salt",
	}

	transformed := policy.ApplyPolicy([]*claims.Claim{c1, c2})
	if len(transformed) != 1 {
		t.Fatalf("expected 1 claim after drop policy, got %d", len(transformed))
	}

	tClaim := transformed[0]
	// Check drop
	if tClaim.Predicate == "secret.token" {
		t.Errorf("expected secret.token to be dropped")
	}
	// Check generalize
	if tClaim.Object.Value != "ref://zone/private-internal" {
		t.Errorf("expected IP generalized to zone, got: %v", tClaim.Object.Value)
	}
	// Check pseudonymize
	if !strings.HasPrefix(tClaim.Subject, "ref://host/anon-") {
		t.Errorf("expected pseudonymized subject, got: %s", tClaim.Subject)
	}
}
