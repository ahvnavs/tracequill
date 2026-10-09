package fed

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/store"
)

// KeyPair holds hex-encoded Ed25519 keys.
type KeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// GenerateKeyPair generates a new Ed25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating ed25519 key: %w", err)
	}
	return &KeyPair{
		PublicKey:  hex.EncodeToString(pub),
		PrivateKey: hex.EncodeToString(priv),
	}, nil
}

// SaveKeyToFile saves the private key file with mode 0600.
func (k *KeyPair) SaveKeyToFile(filePath string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}

// LoadKeyPair loads a keypair from file.
func LoadKeyPair(filePath string) (*KeyPair, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var kp KeyPair
	if err := json.Unmarshal(data, &kp); err != nil {
		return nil, fmt.Errorf("invalid key file format: %w", err)
	}
	return &kp, nil
}

// PolicyRule defines transformation rules for drop, generalize, and pseudonymize.
type PolicyRule struct {
	Drop          []string          `json:"drop,omitempty"`           // predicate exact or ref pattern prefixes to drop
	Generalize    map[string]string `json:"generalize,omitempty"`     // pattern -> target generalized value (e.g. "10.0.*" -> "ref://zone/private-net")
	Pseudonymize  []string          `json:"pseudonymize,omitempty"`   // prefixes of refs to pseudonymize via deterministic salted hash
	PseudonymSalt string            `json:"pseudonym_salt,omitempty"` // salt for pseudonymization
}

// LoadPolicy parses a JSON policy file.
func LoadPolicy(path string) (*PolicyRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pol PolicyRule
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("failed parsing export policy JSON: %w", err)
	}
	return &pol, nil
}

// ApplyPolicy transforms claims in place according to the policy rules before signing.
func (p *PolicyRule) ApplyPolicy(claimList []*claims.Claim) []*claims.Claim {
	if p == nil {
		return claimList
	}

	var filtered []*claims.Claim
	salt := p.PseudonymSalt
	if salt == "" {
		salt = "bokuei-default-salt"
	}

	pseudoCache := make(map[string]string)
	getPseudo := func(ref string) string {
		if val, ok := pseudoCache[ref]; ok {
			return val
		}
		parts := strings.Split(ref, "/")
		kind := "entity"
		if len(parts) >= 3 && strings.HasPrefix(ref, "ref://") {
			kind = parts[2]
		}
		h := sha256.Sum256([]byte(salt + ":" + ref))
		pseudo := fmt.Sprintf("ref://%s/anon-%s", kind, hex.EncodeToString(h[:8]))
		pseudoCache[ref] = pseudo
		return pseudo
	}

	for _, c := range claimList {
		// 1. Check Drop rules
		dropped := false
		for _, d := range p.Drop {
			if c.Predicate == d || strings.HasPrefix(c.Subject, d) {
				dropped = true
				break
			}
			if valStr, ok := c.Object.Value.(string); ok && strings.HasPrefix(valStr, d) {
				dropped = true
				break
			}
		}
		if dropped {
			continue
		}

		// Clone claim to avoid mutating original ledger memory
		cloned := *c

		// 2. Check Pseudonymize rules
		for _, prefix := range p.Pseudonymize {
			if strings.HasPrefix(cloned.Subject, prefix) {
				cloned.Subject = getPseudo(cloned.Subject)
			}
			if valStr, ok := cloned.Object.Value.(string); ok && strings.HasPrefix(valStr, prefix) {
				cloned.Object.Value = getPseudo(valStr)
			}
			if strings.HasPrefix(cloned.Scope, prefix) {
				cloned.Scope = getPseudo(cloned.Scope)
			}
		}

		// 3. Check Generalize rules (e.g. IP to zone)
		for pattern, genTarget := range p.Generalize {
			if valStr, ok := cloned.Object.Value.(string); ok {
				if matchGlobOrPrefix(pattern, valStr) {
					cloned.Object.Value = genTarget
					cloned.Object.Kind = "ref"
				}
			}
		}

		filtered = append(filtered, &cloned)
	}

	return filtered
}

func matchGlobOrPrefix(pattern, val string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(val, prefix)
	}
	return pattern == val
}

// ExportBatch represents an encrypted/signed package of claims exported from a ledger.
type ExportBatch struct {
	BatchID         string          `json:"batch_id"`
	SeqNo           int64           `json:"seq_no"`
	PrevHash        string          `json:"prev_hash"`
	Hash            string          `json:"hash"`
	Signature       string          `json:"signature"`
	PublicKey       string          `json:"public_key"`
	ExportedAt      string          `json:"exported_at"`
	ClaimsCount     int             `json:"claims_count"`
	Claims          []*claims.Claim `json:"claims"`
	CanonicalClaims string          `json:"canonical_claims,omitempty"`
}

// ComputeBatchHash computes hash = sha256(prev_hash || canonical_claims).
func ComputeBatchHash(prevHash string, claimsList []*claims.Claim) (string, string, error) {
	// Sort claims deterministically by ClaimID
	sorted := make([]*claims.Claim, len(claimsList))
	copy(sorted, claimsList)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ClaimID < sorted[j].ClaimID
	})

	var canonicalBuilder strings.Builder
	for i, c := range sorted {
		cJSON, err := c.CanonicalBytes()
		if err != nil {
			return "", "", fmt.Errorf("canonical JSON error on claim %s: %w", c.ClaimID, err)
		}
		if i > 0 {
			canonicalBuilder.WriteString("\n")
		}
		canonicalBuilder.Write(cJSON)
	}

	canonStr := canonicalBuilder.String()
	payload := []byte(prevHash + "\n" + canonStr)
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:]), canonStr, nil
}

// ExportLedger exports all claims inserted since the last export watermark into a signed .bq batch.
func ExportLedger(ctx context.Context, l *store.Ledger, kp *KeyPair, policy *PolicyRule) (*ExportBatch, error) {
	// Read current export sequence and previous hash
	var (
		lastSeq   int64
		prevHash  string
		lastSeqNo int64
	)
	_ = l.DB().QueryRowContext(ctx, `
		CREATE TABLE IF NOT EXISTS export_watermark (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			last_exported_claim_seq INTEGER NOT NULL,
			batch_seq_no INTEGER NOT NULL,
			last_batch_hash TEXT NOT NULL
		)
	`)

	err := l.DB().QueryRowContext(ctx, `
		SELECT last_exported_claim_seq, batch_seq_no, last_batch_hash
		FROM export_watermark WHERE id = 1
	`).Scan(&lastSeq, &lastSeqNo, &prevHash)

	if err != nil {
		lastSeq = 0
		lastSeqNo = 0
		prevHash = strings.Repeat("0", 64)
	}

	// Fetch claims newer than lastSeq
	rows, err := l.DB().QueryContext(ctx, `
		SELECT seq, claim_id, subject, predicate, object_kind, object_value,
		       observed_at, source_group, source_id, source_method,
		       scope, evidence_hash, redaction
		FROM claims
		WHERE seq > ?
		ORDER BY seq ASC
	`, lastSeq)
	if err != nil {
		return nil, fmt.Errorf("failed fetching unexported claims: %w", err)
	}
	defer rows.Close()

	var (
		claimsList []*claims.Claim
		maxSeq     int64
	)
	maxSeq = lastSeq

	for rows.Next() {
		var (
			sSeq                                                                          int64
			cid, subj, pred, objKind, objVal, obsAt, grp, srcID, meth, scope, evHash, red string
		)
		if err := rows.Scan(&sSeq, &cid, &subj, &pred, &objKind, &objVal, &obsAt, &grp, &srcID, &meth, &scope, &evHash, &red); err != nil {
			return nil, err
		}
		if sSeq > maxSeq {
			maxSeq = sSeq
		}

		var parsedVal interface{}
		switch objKind {
		case "int":
			var intVal int64
			fmt.Sscanf(objVal, "%d", &intVal)
			parsedVal = intVal
		case "bool":
			parsedVal = (objVal == "true")
		case "json":
			var jv interface{}
			_ = json.Unmarshal([]byte(objVal), &jv)
			parsedVal = jv
		default: // text, ref
			parsedVal = objVal
		}

		c := &claims.Claim{
			ClaimID:      cid,
			Subject:      subj,
			Predicate:    pred,
			Object:       claims.Object{Kind: objKind, Value: parsedVal},
			ObservedAt:   obsAt,
			Source:       claims.Source{Group: grp, ID: srcID, Method: meth},
			Scope:        scope,
			EvidenceHash: evHash,
			Redaction:    red,
		}
		claimsList = append(claimsList, c)
	}

	// Apply export privacy policy if present
	if policy != nil {
		claimsList = policy.ApplyPolicy(claimsList)
	}

	// Calculate batch hash
	bHash, canonStr, err := ComputeBatchHash(prevHash, claimsList)
	if err != nil {
		return nil, err
	}

	// Sign the batch hash using Ed25519 private key
	privBytes, err := hex.DecodeString(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	sigBytes := ed25519.Sign(privBytes, []byte(bHash))
	sigHex := hex.EncodeToString(sigBytes)

	newSeqNo := lastSeqNo + 1
	batchID := fmt.Sprintf("batch-%d-%s", newSeqNo, bHash[:12])

	batch := &ExportBatch{
		BatchID:         batchID,
		SeqNo:           newSeqNo,
		PrevHash:        prevHash,
		Hash:            bHash,
		Signature:       sigHex,
		PublicKey:       kp.PublicKey,
		ExportedAt:      time.Now().UTC().Format(time.RFC3339),
		ClaimsCount:     len(claimsList),
		Claims:          claimsList,
		CanonicalClaims: canonStr,
	}

	// Update watermark transactionally
	_, err = l.DB().ExecContext(ctx, `
		INSERT INTO export_watermark (id, last_exported_claim_seq, batch_seq_no, last_batch_hash)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			last_exported_claim_seq = excluded.last_exported_claim_seq,
			batch_seq_no = excluded.batch_seq_no,
			last_batch_hash = excluded.last_batch_hash
	`, maxSeq, newSeqNo, bHash)
	if err != nil {
		return nil, fmt.Errorf("failed updating export watermark: %w", err)
	}

	return batch, nil
}

// ImportResult reports metrics from an import operation.
type ImportResult struct {
	BatchID         string `json:"batch_id"`
	SeqNo           int64  `json:"seq_no"`
	TotalClaims     int    `json:"total_claims"`
	InsertedClaims  int    `json:"inserted_claims"`
	DedupedClaims   int    `json:"deduped_claims"`
	SignerKey       string `json:"signer_key"`
	TrustedSigner   bool   `json:"trusted_signer"`
	ValidationLabel string `json:"validation_label"`
}

// ImportBatch validates signature, chain continuity, sequence numbers, and hash before appending to the ledger.
func ImportBatch(ctx context.Context, l *store.Ledger, batch *ExportBatch, trustedKeys []string, allowUntrusted bool) (*ImportResult, error) {
	if batch == nil {
		return nil, fmt.Errorf("nil export batch provided")
	}

	// 1. Structure validation
	if batch.BatchID == "" || batch.Hash == "" || batch.Signature == "" || batch.PublicKey == "" {
		return nil, fmt.Errorf("tampered batch: missing required batch metadata fields")
	}

	// 2. Verify payload hash integrity
	computedHash, _, err := ComputeBatchHash(batch.PrevHash, batch.Claims)
	if err != nil {
		return nil, fmt.Errorf("failed computing batch hash: %w", err)
	}
	if computedHash != batch.Hash {
		return nil, fmt.Errorf("TAMPERED_BATCH_REJECTED: payload hash mismatch (computed %s != header %s)", computedHash, batch.Hash)
	}

	// 3. Verify Ed25519 signature
	pubBytes, err := hex.DecodeString(batch.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid signer public key hex: %w", err)
	}
	sigBytes, err := hex.DecodeString(batch.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid batch signature format: %w", err)
	}

	if !ed25519.Verify(pubBytes, []byte(batch.Hash), sigBytes) {
		return nil, fmt.Errorf("TAMPERED_BATCH_REJECTED: invalid Ed25519 signature for batch hash %s", batch.Hash)
	}

	// 4. Trusted Key Evaluation
	isTrusted := false
	if len(trustedKeys) == 0 {
		// When no keyfile is configured, all validly signed keys are permitted
		isTrusted = true
	} else {
		for _, tk := range trustedKeys {
			if strings.EqualFold(tk, batch.PublicKey) {
				isTrusted = true
				break
			}
		}
	}

	if !isTrusted && !allowUntrusted {
		return nil, fmt.Errorf("UNTRUSTED_KEY_REJECTED: key %s not in trusted keys list (use --allow-untrusted to import)", batch.PublicKey)
	}

	label := "trusted"
	if !isTrusted {
		label = "untrusted (allowed by operator flag)"
	}

	// 5. Sequence Gap and Continuity check
	_ = l.DB().QueryRowContext(ctx, `
		CREATE TABLE IF NOT EXISTS import_chain (
			public_key TEXT NOT NULL,
			last_seq_no INTEGER NOT NULL,
			last_hash TEXT NOT NULL,
			PRIMARY KEY (public_key)
		)
	`)

	var (
		lastImportedSeq  int64
		lastImportedHash string
	)
	err = l.DB().QueryRowContext(ctx, `
		SELECT last_seq_no, last_hash FROM import_chain WHERE public_key = ?
	`, batch.PublicKey).Scan(&lastImportedSeq, &lastImportedHash)

	if err == nil {
		// Existing chain from this key
		expectedSeq := lastImportedSeq + 1
		if batch.SeqNo < expectedSeq {
			// Duplicate or replayed batch
			return &ImportResult{
				BatchID:         batch.BatchID,
				SeqNo:           batch.SeqNo,
				TotalClaims:     len(batch.Claims),
				InsertedClaims:  0,
				DedupedClaims:   len(batch.Claims),
				SignerKey:       batch.PublicKey,
				TrustedSigner:   isTrusted,
				ValidationLabel: "duplicate batch (idempotent no-op)",
			}, nil
		}
		if batch.SeqNo > expectedSeq {
			return nil, fmt.Errorf("SEQUENCE_GAP_REJECTED: expected batch seq %d from key %s, got %d (skipped sequence numbers)", expectedSeq, batch.PublicKey, batch.SeqNo)
		}
		if batch.PrevHash != lastImportedHash {
			return nil, fmt.Errorf("CHAIN_CONTINUITY_REJECTED: prev_hash %s does not match last imported hash %s", batch.PrevHash, lastImportedHash)
		}
	} else {
		// First batch from this key. If seq_no > 1 and prev_hash != 000..., reject as gap
		if batch.SeqNo > 1 {
			return nil, fmt.Errorf("SEQUENCE_GAP_REJECTED: first batch from key %s has seq_no %d > 1", batch.PublicKey, batch.SeqNo)
		}
	}

	// 6. Ingest into ledger: dedupe by claim_id and keep source group
	res, err := l.IngestBatch(ctx, batch.BatchID, batch.Claims, nil)
	if err != nil {
		return nil, fmt.Errorf("failed ingesting claims into ledger: %w", err)
	}

	// Update import chain table
	_, err = l.DB().ExecContext(ctx, `
		INSERT INTO import_chain (public_key, last_seq_no, last_hash)
		VALUES (?, ?, ?)
		ON CONFLICT(public_key) DO UPDATE SET
			last_seq_no = excluded.last_seq_no,
			last_hash = excluded.last_hash
	`, batch.PublicKey, batch.SeqNo, batch.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed recording import chain: %w", err)
	}

	return &ImportResult{
		BatchID:         batch.BatchID,
		SeqNo:           batch.SeqNo,
		TotalClaims:     res.TotalSubmitted,
		InsertedClaims:  res.InsertedClaims,
		DedupedClaims:   res.DedupStateClaims,
		SignerKey:       batch.PublicKey,
		TrustedSigner:   isTrusted,
		ValidationLabel: label,
	}, nil
}
