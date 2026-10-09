package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/store"
	"github.com/OWNER/bokuei/internal/views"
)

// FixtureBatch matches the exported batch structure for test loading.
type FixtureBatch struct {
	BatchID     string          `json:"batch_id"`
	ClaimsCount int             `json:"claims_count"`
	Claims      []*claims.Claim `json:"claims"`
}

// FindFixturePath locates the minimal_estate.json fixture file regardless of caller directory.
func FindFixturePath() string {
	_, b, _, _ := runtime.Caller(0)
	base := filepath.Dir(b) // internal/testutil
	candidates := []string{
		filepath.Join(base, "..", "..", "testdata", "fixtures", "minimal_estate.json"),
		filepath.Join(base, "..", "testdata", "fixtures", "minimal_estate.json"),
		"testdata/fixtures/minimal_estate.json",
		"../../testdata/fixtures/minimal_estate.json",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "testdata/fixtures/minimal_estate.json"
}

// LoadMinimalEstate loads the minimal_estate.json fixture directly into the provided ledger.
func LoadMinimalEstate(ctx context.Context, l *store.Ledger) error {
	path := FindFixturePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed reading fixture at %s: %w", path, err)
	}

	var batch FixtureBatch
	if err := json.Unmarshal(data, &batch); err != nil {
		return fmt.Errorf("failed decoding fixture: %w", err)
	}

	if len(batch.Claims) == 0 {
		return fmt.Errorf("fixture contains zero claims")
	}

	_, err = l.IngestBatch(ctx, "fixture-minimal-estate", batch.Claims, nil)
	if err != nil {
		return fmt.Errorf("failed ingesting fixture batch: %w", err)
	}

	return nil
}

// SetupTestLedgerWithFixture creates a temporary ledger populated with the minimal estate fixture.
func SetupTestLedgerWithFixture(tmpDir string, rulesDir string) (*store.Ledger, string, error) {
	dbPath := filepath.Join(tmpDir, "test_fixture.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		return nil, "", err
	}

	ctx := context.Background()
	if err := LoadMinimalEstate(ctx, l); err != nil {
		l.Close()
		return nil, "", err
	}

	if rulesDir != "" {
		if err := views.RebuildAllViews(ctx, l, time.Now().UTC(), rulesDir); err != nil {
			l.Close()
			return nil, "", err
		}
	}

	return l, dbPath, nil
}
