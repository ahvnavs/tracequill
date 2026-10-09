package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OWNER/bokuei/internal/server"
	"github.com/OWNER/bokuei/internal/store"
	"github.com/OWNER/bokuei/internal/testutil"
)

func setupTestServer(t *testing.T) (*server.Server, *store.Ledger, string) {
	t.Helper()
	tmpDir := t.TempDir()
	rulesDir := filepath.Join("..", "..", "rules")

	l, dbPath, err := testutil.SetupTestLedgerWithFixture(tmpDir, rulesDir)
	if err != nil {
		t.Fatalf("failed setting up test ledger with fixture: %v", err)
	}

	srv := server.NewServer(l, rulesDir)
	return srv, l, dbPath
}

func TestNoExternalURLsInEmbeddedAssets(t *testing.T) {
	// Requirements: embedded assets contain no external URLs (test scans for http:// and https://)
	assetDir := filepath.Join("web")
	entries, err := os.ReadDir(assetDir)
	if err != nil {
		t.Fatalf("failed reading web asset dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(assetDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed reading file %s: %v", path, err)
		}
		content := string(data)

		// Note: http://www.w3.org/2000/svg is standard XML namespace for SVG elements created via createElementNS
		// We ensure NO external network CDNs, external web pages, or fonts (e.g. fonts.googleapis.com, cdnjs, etc.)
		lines := strings.Split(content, "\n")
		for lineNum, line := range lines {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
				// Allow pure XML namespaces for SVG if any
				if strings.Contains(line, "http://www.w3.org/2000/svg") {
					continue
				}
				t.Errorf("Forbidden external URL detected in %s:%d: %s", entry.Name(), lineNum+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestTimeSliderLeavesLedgerUnchanged(t *testing.T) {
	srv, l, dbPath := setupTestServer(t)
	defer l.Close()

	ctx := context.Background()

	// 1. Record pre-inspection claim count and database content hash
	var preCount int
	if err := l.DB().QueryRowContext(ctx, "SELECT count(*) FROM claims").Scan(&preCount); err != nil {
		t.Fatalf("failed counting claims: %v", err)
	}

	dbDataPre, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("failed reading pre db file: %v", err)
	}
	preHash := sha256.Sum256(dbDataPre)

	// 2. Fetch distinct timestamps
	rows, err := l.DB().QueryContext(ctx, "SELECT DISTINCT observed_at FROM claims ORDER BY observed_at ASC")
	if err != nil {
		t.Fatalf("failed fetching timestamps: %v", err)
	}
	var timestamps []string
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err == nil {
			timestamps = append(timestamps, ts)
		}
	}
	rows.Close()

	if len(timestamps) < 2 {
		t.Fatalf("expected at least 2 timestamps, got %d", len(timestamps))
	}

	// 3. Perform several time-slider requests at various historical points
	testCutoffs := []string{
		timestamps[0],
		timestamps[len(timestamps)/2],
		timestamps[len(timestamps)-1],
	}

	for _, cutoff := range testCutoffs {
		req := httptest.NewRequest(http.MethodGet, "/api/map?at="+cutoff, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK from /api/map?at=%s, got %d: %s", cutoff, rec.Code, rec.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid json response from /api/map: %v", err)
		}
		nodes, ok := resp["nodes"].([]any)
		if !ok || len(nodes) == 0 {
			t.Fatalf("expected nodes in historical map response, got 0")
		}
	}

	// 4. Verify post-inspection claim count and database content hash
	var postCount int
	if err := l.DB().QueryRowContext(ctx, "SELECT count(*) FROM claims").Scan(&postCount); err != nil {
		t.Fatalf("failed counting post claims: %v", err)
	}

	if preCount != postCount {
		t.Errorf("Time slider modified ledger! pre claim count = %d, post claim count = %d", preCount, postCount)
	}

	// Read database file and verify hash
	dbDataPost, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("failed reading post db file: %v", err)
	}
	postHash := sha256.Sum256(dbDataPost)

	if hex.EncodeToString(preHash[:]) != hex.EncodeToString(postHash[:]) {
		t.Errorf("Time slider modified database file bytes! Pre hash %x != Post hash %x", preHash, postHash)
	}
}

func TestServerAPIEndpoints(t *testing.T) {
	srv, l, _ := setupTestServer(t)
	defer l.Close()

	ctx := context.Background()

	// Find a sample host and run reference
	var hostRef, runRef string
	_ = l.DB().QueryRowContext(ctx, "SELECT subject FROM claims WHERE subject LIKE 'ref://host/%' LIMIT 1").Scan(&hostRef)
	_ = l.DB().QueryRowContext(ctx, "SELECT subject FROM claims WHERE subject LIKE 'ref://run/%' LIMIT 1").Scan(&runRef)

	if hostRef == "" || runRef == "" {
		t.Fatalf("failed finding test references in generated estate")
	}

	endpoints := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		checkJSON  func(t *testing.T, body []byte)
	}{
		{
			name:       "Static index.html",
			method:     http.MethodGet,
			path:       "/",
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				if !strings.Contains(string(b), "Bokuei") {
					t.Errorf("expected HTML body to contain 'Bokuei'")
				}
				if !strings.Contains(string(b), "not visible") {
					t.Errorf("expected HTML body to contain 'not visible'")
				}
			},
		},
		{
			name:       "/api/claims",
			method:     http.MethodGet,
			path:       "/api/claims?ref=" + hostRef,
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				var claims []any
				if err := json.Unmarshal(b, &claims); err != nil || len(claims) == 0 {
					t.Errorf("expected non-empty claims list, err: %v", err)
				}
			},
		},
		{
			name:       "/api/entity",
			method:     http.MethodGet,
			path:       "/api/entity?ref=" + hostRef,
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				var res map[string]any
				if err := json.Unmarshal(b, &res); err != nil || res["primary_ref"] == nil {
					t.Errorf("invalid entity response: %v", err)
				}
			},
		},
		{
			name:       "/api/explain",
			method:     http.MethodGet,
			path:       "/api/explain?ref=" + hostRef,
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				var res map[string]any
				if err := json.Unmarshal(b, &res); err != nil || res["target_ref"] != hostRef {
					t.Errorf("invalid explain response: %v", err)
				}
			},
		},
		{
			name:       "/api/history",
			method:     http.MethodGet,
			path:       "/api/history?ref=" + hostRef,
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				var items []any
				if err := json.Unmarshal(b, &items); err != nil || len(items) == 0 {
					t.Errorf("expected non-empty history, err: %v", err)
				}
			},
		},
		{
			name:       "/api/impact",
			method:     http.MethodGet,
			path:       "/api/impact?ref=" + hostRef,
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				var res map[string]any
				if err := json.Unmarshal(b, &res); err != nil || res["verdict"] == nil {
					t.Errorf("invalid impact response: %v", err)
				}
			},
		},
		{
			name:       "/api/unknowns",
			method:     http.MethodGet,
			path:       "/api/unknowns",
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				var res []map[string]any
				if err := json.Unmarshal(b, &res); err != nil {
					t.Errorf("invalid unknowns response: %v", err)
				}
				for _, unk := range res {
					if unk["status"] != "not visible" {
						t.Errorf("unknown item status must be 'not visible', got: %v", unk["status"])
					}
				}
			},
		},
		{
			name:       "/api/diff",
			method:     http.MethodGet,
			path:       "/api/diff?a=24h&b=1h",
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				var res map[string]any
				if err := json.Unmarshal(b, &res); err != nil {
					t.Errorf("invalid diff response: %v", err)
				}
			},
		},
		{
			name:       "/api/coverage",
			method:     http.MethodGet,
			path:       "/api/coverage",
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				var res map[string]any
				if err := json.Unmarshal(b, &res); err != nil || res["total_claims"] == nil {
					t.Errorf("invalid coverage response: %v", err)
				}
			},
		},
		{
			name:       "/api/map",
			method:     http.MethodGet,
			path:       "/api/map",
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				var res map[string]any
				if err := json.Unmarshal(b, &res); err != nil || res["nodes"] == nil {
					t.Errorf("invalid map response: %v", err)
				}
			},
		},
		{
			name:       "/api/ask",
			method:     http.MethodGet,
			path:       "/api/ask?n=5",
			wantStatus: http.StatusOK,
			checkJSON: func(t *testing.T, b []byte) {
				var res []map[string]any
				if err := json.Unmarshal(b, &res); err != nil {
					t.Errorf("invalid ask response: %v", err)
				}
			},
		},
	}

	for _, tt := range endpoints {
		t.Run(tt.name, func(t *testing.T) {
			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = bytes.NewBufferString(tt.body)
			}
			req := httptest.NewRequest(tt.method, tt.path, bodyReader)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("endpoint %s returned status %d, want %d: %s", tt.path, rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.checkJSON != nil {
				tt.checkJSON(t, rec.Body.Bytes())
			}
		})
	}
}

func TestServerAnswerEndpoint(t *testing.T) {
	srv, l, _ := setupTestServer(t)
	defer l.Close()

	// Get an active question
	reqAsk := httptest.NewRequest(http.MethodGet, "/api/ask?n=1", nil)
	recAsk := httptest.NewRecorder()
	srv.ServeHTTP(recAsk, reqAsk)

	var questions []map[string]any
	if err := json.Unmarshal(recAsk.Body.Bytes(), &questions); err != nil || len(questions) == 0 {
		t.Skip("No active questions in demo estate to answer")
	}

	qID := questions[0]["id"].(string)

	// Answer the question
	payload := map[string]string{
		"id":     qID,
		"answer": "yes",
	}
	bodyData, _ := json.Marshal(payload)
	reqAns := httptest.NewRequest(http.MethodPost, "/api/answer", bytes.NewReader(bodyData))
	reqAns.Header.Set("Content-Type", "application/json")
	recAns := httptest.NewRecorder()
	srv.ServeHTTP(recAns, reqAns)

	if recAns.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/answer, got %d: %s", recAns.Code, recAns.Body.String())
	}

	var ansRes map[string]any
	if err := json.Unmarshal(recAns.Body.Bytes(), &ansRes); err != nil {
		t.Fatalf("invalid answer json response: %v", err)
	}

	if ansRes["claims_added"] == nil || ansRes["claims_added"].(float64) < 1 {
		t.Errorf("expected claims_added >= 1, got %v", ansRes["claims_added"])
	}
}
