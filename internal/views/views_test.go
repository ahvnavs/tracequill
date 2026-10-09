package views_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/store"
	"github.com/OWNER/bokuei/internal/testutil"
	"github.com/OWNER/bokuei/internal/views"
)

// hashViewTables computes deterministic hash of all records in all view_* tables.
func hashViewTables(t *testing.T, db *sql.DB) string {
	tables := []string{"view_entities", "view_entity_members", "view_effective_state", "view_unknowns"}
	hasher := sha256.New()

	for _, tbl := range tables {
		rows, err := db.Query(fmt.Sprintf("SELECT * FROM %s ORDER BY 1, 2", tbl))
		if err != nil {
			t.Fatalf("failed querying %s: %v", tbl, err)
		}
		defer rows.Close()

		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}

		vals := make([]interface{}, len(cols))
		valPtrs := make([]interface{}, len(cols))
		for i := range vals {
			valPtrs[i] = &vals[i]
		}

		for rows.Next() {
			if err := rows.Scan(valPtrs...); err != nil {
				t.Fatal(err)
			}
			for _, v := range vals {
				hasher.Write([]byte(fmt.Sprintf("%v|", v)))
			}
			hasher.Write([]byte("\n"))
		}
		rows.Close()
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

// TestRebuildTwiceByteIdentical asserts the non-negotiable architecture rule:
// Rebuilding derived views twice from the same ledger yields byte-identical views.
func TestRebuildTwiceByteIdentical(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bokuei-rebuild-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	l, _, err := testutil.SetupTestLedgerWithFixture(tmpDir, "")
	if err != nil {
		t.Fatalf("SetupTestLedgerWithFixture failed: %v", err)
	}
	defer l.Close()

	ctx := context.Background()
	fixedTime := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

	// First Rebuild
	if err := views.RebuildAllViews(ctx, l, fixedTime, "../../rules"); err != nil {
		t.Fatalf("First RebuildAllViews failed: %v", err)
	}
	hash1 := hashViewTables(t, l.DB())

	// Second Rebuild
	if err := views.RebuildAllViews(ctx, l, fixedTime, "../../rules"); err != nil {
		t.Fatalf("Second RebuildAllViews failed: %v", err)
	}
	hash2 := hashViewTables(t, l.DB())

	if hash1 != hash2 {
		t.Fatalf("Rebuild views is not deterministic! Hash 1: %s, Hash 2: %s", hash1, hash2)
	}
}

func TestCapabilityViewsAndUnknowns(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bokuei-cap-view-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "cap_test.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatalf("OpenLedger failed: %v", err)
	}
	defer l.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Ingest capability claims: one can, one cannot
	c1 := &claims.Claim{
		Subject:   "ref://host/h1",
		Predicate: "capability.can",
		Object:    claims.Object{Kind: "ref", Value: "ref://capability/sysfs_net"},
		ObservedAt: now.Format(time.RFC3339),
		Source: claims.Source{
			Group:  "agent",
			ID:     "bokuei-agent",
			Method: "read:/sys/class/net",
		},
		Scope:        "ref://host/h1",
		EvidenceHash: "0000000000000000000000000000000000000000000000000000000000000001",
		Redaction:    "none",
	}
	c2 := &claims.Claim{
		Subject:   "ref://capability/conntrack",
		Predicate: "capability.cannot",
		Object:    claims.Object{Kind: "text", Value: "permission_denied"},
		ObservedAt: now.Format(time.RFC3339),
		Source: claims.Source{
			Group:  "agent",
			ID:     "bokuei-agent",
			Method: "read:/proc/net/nf_conntrack",
		},
		Scope:        "ref://host/h1",
		EvidenceHash: "0000000000000000000000000000000000000000000000000000000000000002",
		Redaction:    "none",
	}

	_, err = l.IngestBatch(ctx, "batch-caps", []*claims.Claim{c1, c2}, nil)
	if err != nil {
		t.Fatalf("IngestBatch failed: %v", err)
	}

	if err := views.RebuildAllViews(ctx, l, now, "../../rules"); err != nil {
		t.Fatalf("RebuildAllViews failed: %v", err)
	}

	// Verify view_effective_state contains both claims
	var count int
	err = l.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM view_effective_state WHERE predicate IN ('capability.can', 'capability.cannot')").Scan(&count)
	if err != nil {
		t.Fatalf("QueryRow failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("Expected 2 capability claims in view_effective_state, got %d", count)
	}

	// Verify view_unknowns contains capability_denied for conntrack
	var category string
	err = l.DB().QueryRowContext(ctx, "SELECT category FROM view_unknowns WHERE subject = 'ref://capability/conntrack'").Scan(&category)
	if err != nil {
		t.Fatalf("QueryRow view_unknowns failed: %v", err)
	}
	if category != "capability_denied" {
		t.Fatalf("Expected category 'capability_denied', got %q", category)
	}
}
