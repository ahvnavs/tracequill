package views

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/effective"
	"github.com/OWNER/bokuei/internal/infer"
	"github.com/OWNER/bokuei/internal/resolve"
	"github.com/OWNER/bokuei/internal/store"
)

const ViewsDDL = `
-- Disposable derived views (rebuilt from ledger)
CREATE TABLE IF NOT EXISTS view_entities (
    entity_id TEXT PRIMARY KEY,
    primary_ref TEXT NOT NULL,
    member_count INTEGER NOT NULL,
    members_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS view_entity_members (
    entity_id TEXT NOT NULL,
    member_ref TEXT NOT NULL,
    PRIMARY KEY (entity_id, member_ref)
);

CREATE TABLE IF NOT EXISTS view_effective_state (
    entity_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    predicate TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    object_value TEXT NOT NULL,
    precedence TEXT NOT NULL,
    undecayed_strength REAL NOT NULL,
    decayed_strength REAL NOT NULL,
    strength_label TEXT NOT NULL,
    is_stale INTEGER NOT NULL,
    is_human_verified INTEGER NOT NULL,
    is_contested INTEGER NOT NULL,
    latest_observed_at TEXT NOT NULL,
    supporting_count INTEGER NOT NULL,
    PRIMARY KEY (subject, predicate)
);

CREATE TABLE IF NOT EXISTS view_unknowns (
    subject TEXT NOT NULL,
    category TEXT NOT NULL,
    predicate TEXT NOT NULL,
    reason TEXT NOT NULL,
    impact_level TEXT NOT NULL,
    PRIMARY KEY (subject, predicate)
);
`

// RebuildAllViews drops all derived view_* tables and rebuilds them byte-identically from the claims ledger.
func RebuildAllViews(ctx context.Context, l *store.Ledger, asOf time.Time, rulesDir string) error {
	tx, err := l.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin tx for rebuild: %w", err)
	}
	defer tx.Rollback()

	// 1. Drop existing view tables
	dropStatements := []string{
		"DROP TABLE IF EXISTS view_entities;",
		"DROP TABLE IF EXISTS view_entity_members;",
		"DROP TABLE IF EXISTS view_effective_state;",
		"DROP TABLE IF EXISTS view_unknowns;",
	}
	for _, stmt := range dropStatements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed dropping view table: %w", err)
		}
	}

	// 2. Re-create view schema
	if _, err := tx.ExecContext(ctx, ViewsDDL); err != nil {
		return fmt.Errorf("failed recreating view schema: %w", err)
	}

	// 3. Fetch all raw claims ordered deterministically by seq
	rows, err := tx.QueryContext(ctx, `
		SELECT claim_id, subject, predicate, object_kind, object_value,
		       observed_at, source_group, source_id, source_method,
		       scope, evidence_hash, redaction
		FROM claims
		ORDER BY seq ASC
	`)
	if err != nil {
		return fmt.Errorf("failed to query ledger claims: %w", err)
	}
	defer rows.Close()

	var allClaims []*claims.Claim
	allRefsSet := make(map[string]bool)

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
			return err
		}

		allClaims = append(allClaims, &claims.Claim{
			ClaimID:      claimID,
			Subject:      subj,
			Predicate:    pred,
			Object:       claims.Object{Kind: objKind, Value: objVal},
			ObservedAt:   obsAt,
			Source:       claims.Source{Group: srcGrp, ID: srcID, Method: srcMeth},
			Scope:        scope,
			EvidenceHash: evHash,
			Redaction:    redact,
		})
		allRefsSet[subj] = true
		if strings.HasPrefix(objVal, "ref://") {
			allRefsSet[objVal] = true
		}
	}
	rows.Close()

	// 4. Compute effective states
	effectiveStates, _ := effective.ComputeEffectiveStates(allClaims, asOf)

	// 5. Run inference if rules available
	var rules []infer.Rule
	if rulesDir != "" {
		packPath := filepath.Join(rulesDir, "inference_pack.json")
		if _, err := os.Stat(packPath); err == nil {
			if loaded, err := infer.LoadRules(packPath); err == nil {
				rules = loaded
			}
		}
	}

	if len(rules) > 0 {
		inferred, err := infer.RunInference(allClaims, effectiveStates, rules)
		if err == nil && len(inferred) > 0 {
			// Append inferred claims to effective state computation
			var inferredClaims []*claims.Claim
			for _, inf := range inferred {
				inferredClaims = append(inferredClaims, inf.Claim)
			}
			recomputed, _ := effective.ComputeEffectiveStates(append(allClaims, inferredClaims...), asOf)
			effectiveStates = recomputed
		}
	}

	// 6. Resolve Entities
	var allRefs []string
	for r := range allRefsSet {
		allRefs = append(allRefs, r)
	}
	sort.Strings(allRefs)

	edges, cannotLinks := resolve.ExtractIdentityEdgesAndConstraints(allClaims, effectiveStates)
	entities := resolve.ResolveEntities(allRefs, edges, cannotLinks)

	refToEntityID := make(map[string]string)
	stmtEntity, err := tx.PrepareContext(ctx, `
		INSERT INTO view_entities (entity_id, primary_ref, member_count, members_json)
		VALUES (?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmtEntity.Close()

	stmtMember, err := tx.PrepareContext(ctx, `
		INSERT INTO view_entity_members (entity_id, member_ref)
		VALUES (?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmtMember.Close()

	for _, ent := range entities {
		membersJSON := fmt.Sprintf(`["%s"]`, strings.Join(ent.Members, `","`))
		if _, err := stmtEntity.ExecContext(ctx, ent.EntityID, ent.PrimaryRef, len(ent.Members), membersJSON); err != nil {
			return err
		}
		for _, m := range ent.Members {
			refToEntityID[m] = ent.EntityID
			if _, err := stmtMember.ExecContext(ctx, ent.EntityID, m); err != nil {
				return err
			}
		}
	}

	// 7. Insert view_effective_state
	stmtEff, err := tx.PrepareContext(ctx, `
		INSERT INTO view_effective_state (
			entity_id, subject, predicate, object_kind, object_value,
			precedence, undecayed_strength, decayed_strength, strength_label,
			is_stale, is_human_verified, is_contested, latest_observed_at, supporting_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmtEff.Close()

	stmtUnknown, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO view_unknowns (subject, category, predicate, reason, impact_level)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmtUnknown.Close()

	// Track observed owners, services, endpoints for automatic gap detection
	hostHasOwner := make(map[string]bool)
	serviceHasType := make(map[string]bool)
	modeledEndpoints := make(map[string]bool)

	// Insert states and identify unknowns / blind spots
	for _, st := range effectiveStates {
		entID := refToEntityID[st.Subject]
		if entID == "" {
			entID = resolve.ComputeEntityID([]string{st.Subject})
		}

		isStaleInt := 0
		if st.IsStale {
			isStaleInt = 1
		}
		isHumanInt := 0
		if st.IsHumanVerified {
			isHumanInt = 1
		}
		isContestedInt := 0
		if st.IsContested {
			isContestedInt = 1
		}

		if _, err := stmtEff.ExecContext(
			ctx, entID, st.Subject, st.Predicate, st.ObjectKind, st.ObjectValue,
			st.Precedence, st.UndecayedStrength, st.DecayedStrength, st.StrengthLabel,
			isStaleInt, isHumanInt, isContestedInt, st.LatestObservedAt, len(st.SupportingClaims),
		); err != nil {
			return err
		}

		// Track attribute coverage
		if strings.HasPrefix(st.Subject, "ref://host/") {
			if st.Predicate == "host.owner" || st.Predicate == "inventory.owner" {
				hostHasOwner[st.Subject] = true
			}
		}
		if strings.HasPrefix(st.Subject, "ref://service/") {
			if st.Predicate == "service.type" {
				serviceHasType[st.Subject] = true
			}
		}
		if st.Predicate == "host.listens" || st.Predicate == "service.endpoint" {
			modeledEndpoints[st.ObjectValue] = true
		}

		// Unknowns detection: coverage.blocked, capability.cannot, stale attributes, contested claims
		if st.Predicate == "coverage.blocked" {
			_, _ = stmtUnknown.ExecContext(ctx, st.Subject, "telemetry_blocked", st.Predicate, st.ObjectValue, "High")
		} else if st.Predicate == "capability.cannot" {
			_, _ = stmtUnknown.ExecContext(ctx, st.Subject, "capability_denied", st.Predicate, st.ObjectValue, "High")
		} else if st.IsContested {
			_, _ = stmtUnknown.ExecContext(ctx, st.Subject, "contested_attribute", st.Predicate, fmt.Sprintf("Competing claims on %s", st.Predicate), "Medium")
		} else if st.IsStale {
			_, _ = stmtUnknown.ExecContext(ctx, st.Subject, "stale_state", st.Predicate, fmt.Sprintf("Decayed strength %s (< 50%%)", st.StrengthLabel), "Low")
		}
	}

	// 8. Auto-generate coverage gaps (unresolved owner, unresolved service, unmodeled endpoint)
	for _, ref := range allRefs {
		if strings.HasPrefix(ref, "ref://host/") && !hostHasOwner[ref] {
			_, _ = stmtUnknown.ExecContext(ctx, ref, "unresolved_owner", "host.owner", "Host missing verified owner attribution", "Medium")
		}
		if strings.HasPrefix(ref, "ref://service/") && !serviceHasType[ref] {
			_, _ = stmtUnknown.ExecContext(ctx, ref, "unresolved_service", "service.type", "Service role or type unclassified", "Medium")
		}
		if strings.HasPrefix(ref, "ref://endpoint/") && !modeledEndpoints[ref] {
			_, _ = stmtUnknown.ExecContext(ctx, ref, "unmodeled_endpoint", "endpoint.service", "Endpoint observed without owning service model", "Low")
		}
	}

	return tx.Commit()
}
