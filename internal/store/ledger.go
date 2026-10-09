package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/OWNER/bokuei/internal/claims"
	_ "modernc.org/sqlite"
)

const SchemaDDL = `
-- Sources registry
CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY,
    source_group TEXT NOT NULL,
    method TEXT NOT NULL,
    reliability REAL NOT NULL,
    first_seen_at TEXT NOT NULL
);

-- Evidence store: raw payloads backing claims
CREATE TABLE IF NOT EXISTS evidence (
    evidence_hash TEXT PRIMARY KEY,
    payload_type TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at TEXT NOT NULL
);

-- Claims ledger: append-only source of truth
CREATE TABLE IF NOT EXISTS claims (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    claim_id TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    predicate TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    object_value TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    source_group TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_method TEXT NOT NULL,
    scope TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    redaction TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    inserted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_claims_subject ON claims(subject);
CREATE INDEX IF NOT EXISTS idx_claims_predicate ON claims(predicate);
CREATE INDEX IF NOT EXISTS idx_claims_subject_predicate ON claims(subject, predicate);
CREATE INDEX IF NOT EXISTS idx_claims_claim_id ON claims(claim_id);

-- Claim Support: Lineage and derivation links between claims
CREATE TABLE IF NOT EXISTS claim_support (
    claim_id TEXT NOT NULL,
    supported_by_claim_id TEXT NOT NULL,
    relationship TEXT NOT NULL,
    PRIMARY KEY (claim_id, supported_by_claim_id),
    FOREIGN KEY(claim_id) REFERENCES claims(claim_id),
    FOREIGN KEY(supported_by_claim_id) REFERENCES claims(claim_id)
);

-- Ingest log: audit log of ingestion transactions
CREATE TABLE IF NOT EXISTS ingest_log (
    batch_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    claim_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    message TEXT
);

-- Append-only enforcement triggers on claims table
CREATE TRIGGER IF NOT EXISTS trg_claims_no_update
BEFORE UPDATE ON claims
BEGIN
    SELECT RAISE(ABORT, 'MUTATION_REJECTED: claims table is append-only, UPDATE disallowed');
END;

CREATE TRIGGER IF NOT EXISTS trg_claims_no_delete
BEFORE DELETE ON claims
BEGIN
    SELECT RAISE(ABORT, 'MUTATION_REJECTED: claims table is append-only, DELETE disallowed');
END;
`

// Ledger represents the SQLite ledger storage.
type Ledger struct {
	db *sql.DB
	mu sync.Mutex
}

// OpenLedger opens or creates the SQLite ledger database at dbPath.
func OpenLedger(dbPath string) (*Ledger, error) {
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
	}

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	if _, err := db.Exec(SchemaDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return &Ledger{db: db}, nil
}

// Close closes the database connection.
func (l *Ledger) Close() error {
	return l.db.Close()
}

// DB returns underlying sql.DB instance for testing or view generation.
func (l *Ledger) DB() *sql.DB {
	return l.db
}

// IngestBatchResult holds summary metrics from an ingestion batch.
type IngestBatchResult struct {
	BatchID          string `json:"batch_id"`
	TotalSubmitted   int    `json:"total_submitted"`
	InsertedClaims   int    `json:"inserted_claims"`
	DedupStateClaims int    `json:"dedup_state_claims"`
	SkippedExisting  int    `json:"skipped_existing"`
}

// IngestBatch atomically validates, canonicalizes, state-dedupes, and inserts a slice of claims.
func (l *Ledger) IngestBatch(ctx context.Context, batchID string, rawClaims []*claims.Claim, evidenceMap map[string][]byte) (*IngestBatchResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	result := &IngestBatchResult{
		BatchID:        batchID,
		TotalSubmitted: len(rawClaims),
	}

	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin tx: %w", err)
	}
	defer tx.Rollback()

	// Ingest evidence if provided
	if evidenceMap != nil {
		stmtEv, err := tx.PrepareContext(ctx, `
			INSERT OR IGNORE INTO evidence (evidence_hash, payload_type, payload, created_at)
			VALUES (?, ?, ?, datetime('now'))
		`)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare evidence insert: %w", err)
		}
		defer stmtEv.Close()

		for hash, payload := range evidenceMap {
			if _, err := stmtEv.ExecContext(ctx, hash, "raw", payload); err != nil {
				return nil, fmt.Errorf("failed to insert evidence %s: %w", hash, err)
			}
		}
	}

	stmtFindLatest, err := tx.PrepareContext(ctx, `
		SELECT object_kind, object_value, redaction
		FROM claims
		WHERE subject = ? AND predicate = ?
		ORDER BY observed_at DESC, seq DESC
		LIMIT 1
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare latest query: %w", err)
	}
	defer stmtFindLatest.Close()

	stmtExists, err := tx.PrepareContext(ctx, `
		SELECT 1 FROM claims WHERE claim_id = ?
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare exists query: %w", err)
	}
	defer stmtExists.Close()

	stmtInsertClaim, err := tx.PrepareContext(ctx, `
		INSERT INTO claims (
			claim_id, subject, predicate, object_kind, object_value,
			observed_at, source_group, source_id, source_method,
			scope, evidence_hash, redaction, canonical_json, inserted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare claim insert: %w", err)
	}
	defer stmtInsertClaim.Close()

	stmtInsertSource, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO sources (source_id, source_group, method, reliability, first_seen_at)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare source insert: %w", err)
	}
	defer stmtInsertSource.Close()

	for _, c := range rawClaims {
		if err := c.Validate(); err != nil {
			return nil, fmt.Errorf("validation failed for claim %s %s: %w", c.Subject, c.Predicate, err)
		}

		canonBytes, err := c.CanonicalBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to canonicalize claim: %w", err)
		}

		claimID, err := c.ComputeID()
		if err != nil {
			return nil, fmt.Errorf("failed to compute claim id: %w", err)
		}
		c.ClaimID = claimID

		// Check if claim_id already exists (idempotency check)
		var dummy int
		err = stmtExists.QueryRowContext(ctx, claimID).Scan(&dummy)
		if err == nil {
			// Already exists
			result.SkippedExisting++
			continue
		} else if err != sql.ErrNoRows {
			return nil, fmt.Errorf("failed to check existing claim: %w", err)
		}

		// State-change deduplication check:
		// If the entity's latest claim for this predicate has identical object_kind, object_value, and redaction,
		// re-ingesting identical observation produces zero new claims.
		var objValueStr string
		switch c.Object.Kind {
		case "int":
			switch v := c.Object.Value.(type) {
			case int:
				objValueStr = fmt.Sprintf("%d", v)
			case int32:
				objValueStr = fmt.Sprintf("%d", v)
			case int64:
				objValueStr = fmt.Sprintf("%d", v)
			case float64:
				objValueStr = fmt.Sprintf("%d", int64(v))
			}
		case "ref", "text":
			objValueStr, _ = c.Object.Value.(string)
		case "bool":
			b, _ := c.Object.Value.(bool)
			objValueStr = fmt.Sprintf("%t", b)
		case "json":
			jb, _ := json.Marshal(c.Object.Value)
			objValueStr = string(jb)
		}

		var latestKind, latestVal, latestRedaction string
		err = stmtFindLatest.QueryRowContext(ctx, c.Subject, c.Predicate).Scan(&latestKind, &latestVal, &latestRedaction)
		if err == nil {
			if latestKind == c.Object.Kind && latestVal == objValueStr && latestRedaction == c.Redaction {
				// State is unchanged; deduplicate!
				result.DedupStateClaims++
				continue
			}
		} else if err != sql.ErrNoRows {
			return nil, fmt.Errorf("failed to query latest claim: %w", err)
		}

		// Register source
		rel, _ := claims.GetSourceReliability(c.Source.Group)
		if _, err := stmtInsertSource.ExecContext(ctx, c.Source.ID, c.Source.Group, c.Source.Method, rel, c.ObservedAt); err != nil {
			return nil, fmt.Errorf("failed to register source: %w", err)
		}

		// Insert claim
		if _, err := stmtInsertClaim.ExecContext(
			ctx,
			c.ClaimID,
			c.Subject,
			c.Predicate,
			c.Object.Kind,
			objValueStr,
			c.ObservedAt,
			c.Source.Group,
			c.Source.ID,
			c.Source.Method,
			c.Scope,
			c.EvidenceHash,
			c.Redaction,
			string(canonBytes),
		); err != nil {
			return nil, fmt.Errorf("failed to insert claim %s: %w", c.ClaimID, err)
		}

		result.InsertedClaims++
	}

	// Record ingest log
	_, err = tx.ExecContext(ctx, `
		INSERT OR REPLACE INTO ingest_log (batch_id, source_id, claim_count, status, ingested_at, message)
		VALUES (?, ?, ?, ?, datetime('now'), ?)
	`, batchID, "batch", result.InsertedClaims, "SUCCESS", fmt.Sprintf("Inserted %d, deduped %d", result.InsertedClaims, result.DedupStateClaims))
	if err != nil {
		return nil, fmt.Errorf("failed to record ingest log: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit batch tx: %w", err)
	}

	return result, nil
}

// GetClaimsBySubject returns all claims where subject equals ref, ordered monotonically by seq.
func (l *Ledger) GetClaimsBySubject(ctx context.Context, subjectRef string) ([]*claims.Claim, error) {
	rows, err := l.db.QueryContext(ctx, `
		SELECT claim_id, subject, predicate, object_kind, object_value,
		       observed_at, source_group, source_id, source_method,
		       scope, evidence_hash, redaction
		FROM claims
		WHERE subject = ?
		ORDER BY seq ASC
	`, subjectRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*claims.Claim
	for rows.Next() {
		var (
			claimID, subj, pred, objKind, objVal string
			obsAt, srcGrp, srcID, srcMeth        string
			scope, evHash, redact                string
		)
		if err := rows.Scan(
			&claimID, &subj, &pred, &objKind, &objVal,
			&obsAt, &srcGrp, &srcID, &srcMeth,
			&scope, &evHash, &redact,
		); err != nil {
			return nil, err
		}

		var val interface{}
		switch objKind {
		case "int":
			var intVal int64
			fmt.Sscanf(objVal, "%d", &intVal)
			val = intVal
		case "bool":
			val = (objVal == "true")
		case "json":
			var jv interface{}
			_ = json.Unmarshal([]byte(objVal), &jv)
			val = jv
		default: // ref, text
			val = objVal
		}

		result = append(result, &claims.Claim{
			ClaimID:      claimID,
			Subject:      subj,
			Predicate:    pred,
			Object:       claims.Object{Kind: objKind, Value: val},
			ObservedAt:   obsAt,
			Source:       claims.Source{Group: srcGrp, ID: srcID, Method: srcMeth},
			Scope:        scope,
			EvidenceHash: evHash,
			Redaction:    redact,
		})
	}
	return result, rows.Err()
}
