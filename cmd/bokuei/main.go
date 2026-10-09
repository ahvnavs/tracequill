package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"github.com/spf13/cobra"
	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/diff"
	"github.com/OWNER/bokuei/internal/fed"
	"github.com/OWNER/bokuei/internal/impact"
	"github.com/OWNER/bokuei/internal/infer"
	"github.com/OWNER/bokuei/internal/nbq"
	"github.com/OWNER/bokuei/internal/rehearse"
	"github.com/OWNER/bokuei/internal/server"
	"github.com/OWNER/bokuei/internal/store"
	"github.com/OWNER/bokuei/internal/views"
)

var (
	dbPath string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "bokuei",
		Short: "Bokuei - append-only claim/evidence ledger and dependency intelligence",
	}

	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "bokuei.db", "Path to SQLite ledger database")

	// claims command
	var jsonOutput bool
	claimsCmd := &cobra.Command{
		Use:   "claims <ref>",
		Short: "Query all claims for a given entity reference",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			subjectRef := args[0]
			if err := claims.ValidateRef(subjectRef); err != nil {
				return err
			}

			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			res, err := l.GetClaimsBySubject(context.Background(), subjectRef)
			if err != nil {
				return fmt.Errorf("failed to fetch claims: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			if len(res) == 0 {
				fmt.Printf("No claims observed for %s (status: not visible)\n", subjectRef)
				return nil
			}

			fmt.Printf("Claims for %s (%d observed):\n", subjectRef, len(res))
			fmt.Printf("%-18s %-20s %-30s %-20s %s\n", "CLAIM_ID[:8]", "PREDICATE", "OBJECT", "OBSERVED_AT", "SOURCE")
			for _, c := range res {
				cidShort := c.ClaimID
				if len(cidShort) > 8 {
					cidShort = cidShort[:8]
				}
				objStr := fmt.Sprintf("%v", c.Object.Value)
				if len(objStr) > 28 {
					objStr = objStr[:25] + "..."
				}
				fmt.Printf("%-18s %-20s %-30s %-20s %s (%s)\n",
					cidShort,
					c.Predicate,
					objStr,
					c.ObservedAt,
					c.Source.ID,
					c.Source.Group,
				)
			}
			return nil
		},
	}
	claimsCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output claims in JSON format")
	// run command
	var (
		runLedgerPath string
		recordArgs    bool
	)
	runCmd := &cobra.Command{
		Use:                "run [flags] -- <command...>",
		Short:              "Execute a command traced by bokuei-agent and record claims",
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("no command provided to run")
			}

			targetDB := dbPath
			if runLedgerPath != "" {
				targetDB = runLedgerPath
			}

			// Find bokuei-agent binary
			agentBin := "bokuei-agent"
			if p, err := exec.LookPath("bokuei-agent"); err == nil {
				agentBin = p
			} else {
				// Check local target directory
				wd, _ := os.Getwd()
				candidates := []string{
					filepath.Join(wd, "target/debug/bokuei-agent"),
					filepath.Join(wd, "target/release/bokuei-agent"),
					filepath.Join(wd, "../target/debug/bokuei-agent"),
				}
				for _, c := range candidates {
					if _, err := os.Stat(c); err == nil {
						agentBin = c
						break
					}
				}
			}

			tmpFile, err := os.CreateTemp("", "tq-run-*.json")
			if err != nil {
				return fmt.Errorf("failed to create temp file: %w", err)
			}
			tmpPath := tmpFile.Name()
			tmpFile.Close()
			defer os.Remove(tmpPath)

			var agentArgs []string
			agentArgs = append(agentArgs, "run", "--out", tmpPath)
			if recordArgs {
				agentArgs = append(agentArgs, "--record-args")
			}
			agentArgs = append(agentArgs, "--")
			agentArgs = append(agentArgs, args...)

			agentProc := exec.Command(agentBin, agentArgs...)
			agentProc.Stdin = os.Stdin
			agentProc.Stdout = os.Stdout
			agentProc.Stderr = os.Stderr

			runErr := agentProc.Run()
			var exitCode int
			if runErr != nil {
				if exitErr, ok := runErr.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					return fmt.Errorf("failed to execute bokuei-agent: %w", runErr)
				}
			}

			// Ingest batch
			batchData, err := os.ReadFile(tmpPath)
			if err != nil {
				return fmt.Errorf("failed to read agent output: %w", err)
			}

			type ClaimBatch struct {
				BatchID   string          `json:"batch_id"`
				CreatedAt string          `json:"created_at"`
				Claims    []*claims.Claim `json:"claims"`
			}

			var batch ClaimBatch
			if err := json.Unmarshal(batchData, &batch); err != nil {
				return fmt.Errorf("failed to parse claim batch: %w", err)
			}

			l, err := store.OpenLedger(targetDB)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", targetDB, err)
			}
			defer l.Close()

			res, err := l.IngestBatch(context.Background(), batch.BatchID, batch.Claims, nil)
			if err != nil {
				return fmt.Errorf("failed to ingest claims into ledger: %w", err)
			}

			// Find run ref
			runRef := ""
			for _, c := range batch.Claims {
				if strings.HasPrefix(c.Subject, "ref://run/") {
					runRef = c.Subject
					break
				}
			}

			fmt.Printf("\n--- Run Summary ---\n")
			fmt.Printf("Run Ref:         %s\n", runRef)
			fmt.Printf("Exit Status:     %d\n", exitCode)
			fmt.Printf("Ledger:          %s\n", targetDB)
			fmt.Printf("Claims Recorded: %d inserted (%d deduped, %d total in batch)\n",
				res.InsertedClaims, res.DedupStateClaims, res.TotalSubmitted)

			if exitCode != 0 {
				os.Exit(exitCode)
			}
			return nil
		},
	}
	runCmd.Flags().StringVar(&runLedgerPath, "ledger", "", "Path to SQLite ledger database (overrides --db)")
	runCmd.Flags().BoolVar(&recordArgs, "record-args", false, "Record full argv instead of redacting arguments")

	// collect command
	var (
		collectOnce    bool
		collectExplain bool
	)
	collectCmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect host-level claims from procfs and system state",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !collectOnce {
				return fmt.Errorf("currently only --once is supported for host collection")
			}

			agentBin := "bokuei-agent"
			if p, err := exec.LookPath("bokuei-agent"); err == nil {
				agentBin = p
			} else {
				wd, _ := os.Getwd()
				candidates := []string{
					filepath.Join(wd, "target/debug/bokuei-agent"),
					filepath.Join(wd, "target/release/bokuei-agent"),
					filepath.Join(wd, "../target/debug/bokuei-agent"),
				}
				for _, c := range candidates {
					if _, err := os.Stat(c); err == nil {
						agentBin = c
						break
					}
				}
			}

			tmpFile, err := os.CreateTemp("", "tq-collect-*.json")
			if err != nil {
				return fmt.Errorf("failed to create temp file: %w", err)
			}
			tmpPath := tmpFile.Name()
			tmpFile.Close()
			defer os.Remove(tmpPath)

			var agentArgs []string
			agentArgs = append(agentArgs, "collect", "--once", "--out", tmpPath)
			if collectExplain {
				agentArgs = append(agentArgs, "--explain")
			}

			agentProc := exec.Command(agentBin, agentArgs...)
			agentProc.Stdin = os.Stdin
			agentProc.Stdout = os.Stdout
			agentProc.Stderr = os.Stderr

			if err := agentProc.Run(); err != nil {
				return fmt.Errorf("failed to execute bokuei-agent collect: %w", err)
			}

			batchData, err := os.ReadFile(tmpPath)
			if err != nil {
				return fmt.Errorf("failed to read agent output: %w", err)
			}

			type ClaimBatch struct {
				BatchID   string          `json:"batch_id"`
				CreatedAt string          `json:"created_at"`
				Claims    []*claims.Claim `json:"claims"`
			}

			var batch ClaimBatch
			if err := json.Unmarshal(batchData, &batch); err != nil {
				return fmt.Errorf("failed to parse claim batch: %w", err)
			}

			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			res, err := l.IngestBatch(context.Background(), batch.BatchID, batch.Claims, nil)
			if err != nil {
				return fmt.Errorf("failed to ingest claims into ledger: %w", err)
			}

			hostRef := ""
			for _, c := range batch.Claims {
				if strings.HasPrefix(c.Subject, "ref://host/") {
					hostRef = c.Subject
					break
				}
			}

			fmt.Printf("Host collection complete.\n")
			fmt.Printf("Host Ref:        %s\n", hostRef)
			fmt.Printf("Ledger:          %s\n", dbPath)
			fmt.Printf("Claims Recorded: %d inserted (%d deduped, %d total in batch)\n",
				res.InsertedClaims, res.DedupStateClaims, res.TotalSubmitted)
			return nil
		},
	}
	collectCmd.Flags().BoolVar(&collectOnce, "once", false, "Collect host state once and exit")
	collectCmd.Flags().BoolVar(&collectExplain, "explain", false, "Print explanation of collected host claims")

	// rebuild command
	var rulesDir string
	rebuildCmd := &cobra.Command{
		Use:   "rebuild",
		Short: "Rebuild disposable derived view_* tables from the append-only ledger",
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			if rulesDir == "" {
				// Default rules dir
				rulesDir = "rules"
			}

			start := time.Now()
			if err := views.RebuildAllViews(context.Background(), l, time.Now().UTC(), rulesDir); err != nil {
				return fmt.Errorf("rebuild views failed: %w", err)
			}

			var (
				entCount, effCount, unkCount int
			)
			_ = l.DB().QueryRow("SELECT count(*) FROM view_entities").Scan(&entCount)
			_ = l.DB().QueryRow("SELECT count(*) FROM view_effective_state").Scan(&effCount)
			_ = l.DB().QueryRow("SELECT count(*) FROM view_unknowns").Scan(&unkCount)

			fmt.Printf("Derived views rebuilt successfully from ledger in %v.\n", time.Since(start).Round(time.Millisecond))
			fmt.Printf("Ledger:           %s\n", dbPath)
			fmt.Printf("Entities:         %d resolved\n", entCount)
			fmt.Printf("Effective States: %d computed\n", effCount)
			fmt.Printf("Unknowns:         %d recorded\n", unkCount)
			return nil
		},
	}
	rebuildCmd.Flags().StringVar(&rulesDir, "rules", "rules", "Path to rules directory containing inference_pack.json")

	// explain command
	explainCmd := &cobra.Command{
		Use:   "explain <ref>",
		Short: "Explain entity membership, lineage to evidence, strength, contradictions, and unknowns for a reference",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetRef := args[0]
			if err := claims.ValidateRef(targetRef); err != nil {
				return err
			}

			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			ctx := context.Background()

			// 1. Entity membership
			var entityID, primaryRef, membersJSON string
			err = l.DB().QueryRowContext(ctx, `
				SELECT e.entity_id, e.primary_ref, e.members_json
				FROM view_entities e
				JOIN view_entity_members m ON e.entity_id = m.entity_id
				WHERE m.member_ref = ?
			`, targetRef).Scan(&entityID, &primaryRef, &membersJSON)
			if err != nil {
				// Not yet resolved or no rebuild done yet
				fmt.Printf("=== Explanation for %s ===\n", targetRef)
				fmt.Printf("Entity: Not resolved in view_entities (run 'bokuei rebuild' to refresh)\n\n")
			} else {
				fmt.Printf("=== Explanation for %s ===\n", targetRef)
				fmt.Printf("Entity ID:   %s\n", entityID)
				fmt.Printf("Primary Ref: %s\n", primaryRef)
				fmt.Printf("Members:     %s\n\n", membersJSON)
			}

			// 2. Effective states & strength
			rowsEff, err := l.DB().QueryContext(ctx, `
				SELECT predicate, object_kind, object_value, precedence,
				       decayed_strength, strength_label, is_stale, is_contested, supporting_count
				FROM view_effective_state
				WHERE subject = ?
				ORDER BY predicate ASC
			`, targetRef)
			if err == nil {
				fmt.Printf("--- Derived Attributes & Strength ---\n")
				fmt.Printf("%-20s %-25s %-12s %-10s %-10s %s\n", "PREDICATE", "VALUE", "PRECEDENCE", "STRENGTH", "LABEL", "STATUS")
				var foundEff bool
				for rowsEff.Next() {
					foundEff = true
					var (
						pred, objKind, objVal, prec, sLabel string
						decayed                             float64
						isStale, isContested, supCount      int
					)
					if err := rowsEff.Scan(&pred, &objKind, &objVal, &prec, &decayed, &sLabel, &isStale, &isContested, &supCount); err == nil {
						status := "active"
						if isContested == 1 {
							status = "CONTESTED"
						} else if isStale == 1 {
							status = "STALE"
						}
						valStr := objVal
						if len(valStr) > 23 {
							valStr = valStr[:20] + "..."
						}
						fmt.Printf("%-20s %-25s %-12s %-10.2f %-10s %s (%d claims)\n",
							pred, valStr, prec, decayed, sLabel, status, supCount)
					}
				}
				rowsEff.Close()
				if !foundEff {
					fmt.Printf("No effective states recorded (status: not visible)\n")
				}
				fmt.Println()
			}

			// 3. Lineage to raw claims & evidence
			claimsList, err := l.GetClaimsBySubject(ctx, targetRef)
			if err == nil && len(claimsList) > 0 {
				fmt.Printf("--- Lineage & Supporting Evidence (%d claims) ---\n", len(claimsList))
				fmt.Printf("%-18s %-20s %-20s %-20s %s\n", "CLAIM_ID[:8]", "PREDICATE", "SOURCE", "METHOD", "EVIDENCE_HASH[:12]")
				for _, c := range claimsList {
					cidShort := c.ClaimID
					if len(cidShort) > 8 {
						cidShort = cidShort[:8]
					}
					evShort := c.EvidenceHash
					if len(evShort) > 12 {
						evShort = evShort[:12]
					}
					fmt.Printf("%-18s %-20s %-20s %-20s %s\n",
						cidShort, c.Predicate, c.Source.Group+" ("+c.Source.ID+")", c.Source.Method, evShort)
				}
				fmt.Println()
			}

			// 4. Unknowns / Blind Spots
			rowsUnk, err := l.DB().QueryContext(ctx, `
				SELECT category, predicate, reason, impact_level
				FROM view_unknowns
				WHERE subject = ?
			`, targetRef)
			if err == nil {
				fmt.Printf("--- Epistemic Unknowns & Blind Spots ---\n")
				var foundUnk bool
				for rowsUnk.Next() {
					foundUnk = true
					var cat, pred, reason, impact string
					if err := rowsUnk.Scan(&cat, &pred, &reason, &impact); err == nil {
						fmt.Printf("[%s] Category: %s | Predicate: %s | Reason: %s (status: not visible)\n",
							impact, cat, pred, reason)
					}
				}
				rowsUnk.Close()
				if !foundUnk {
					fmt.Printf("No active unknowns recorded for this subject.\n")
				}
			}

			return nil
		},
	}

	// unknowns command
	unknownsCmd := &cobra.Command{
		Use:   "unknowns",
		Short: "List all measured blind spots, blocked telemetry, contested states, and unknowns",
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			rows, err := l.DB().QueryContext(context.Background(), `
				SELECT subject, category, predicate, reason, impact_level
				FROM view_unknowns
				ORDER BY CASE impact_level WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, subject ASC
			`)
			if err != nil {
				return fmt.Errorf("failed querying view_unknowns (have you run 'bokuei rebuild'?): %w", err)
			}
			defer rows.Close()

			fmt.Printf("%-8s %-28s %-20s %-20s %s\n", "IMPACT", "SUBJECT", "CATEGORY", "PREDICATE", "REASON (STATUS: NOT VISIBLE)")
			var count int
			for rows.Next() {
				count++
				var subj, cat, pred, reason, impact string
				if err := rows.Scan(&subj, &cat, &pred, &reason, &impact); err == nil {
					subjShort := subj
					if len(subjShort) > 26 {
						subjShort = subjShort[:24] + "..."
					}
					fmt.Printf("%-8s %-28s %-20s %-20s %s\n",
						impact, subjShort, cat, pred, reason)
				}
			}
			if count == 0 {
				fmt.Printf("No unknowns recorded (or run 'bokuei rebuild' to generate views).\n")
			} else {
				fmt.Printf("\nTotal Unknowns: %d\n", count)
			}
			return nil
		},
	}

	// coverage command: reports capability coverage and visibility score for a host
	coverageCmd := &cobra.Command{
		Use:   "coverage [host_ref]",
		Short: "Display capability visibility table, status (observed / not visible), and 0-100 score for a host",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			ctx := context.Background()

			targetHost := ""
			if len(args) == 1 {
				targetHost = args[0]
			} else {
				// Query first known host in ledger
				_ = l.DB().QueryRowContext(ctx, `
					SELECT subject FROM claims
					WHERE subject LIKE 'ref://host/%' OR scope LIKE 'ref://host/%'
					ORDER BY seq ASC LIMIT 1
				`).Scan(&targetHost)
				if targetHost == "" {
					targetHost = "ref://host/localhost"
				}
			}

			// Core capabilities and weights per DECISIONS.md
			type capDef struct {
				Key    string
				Weight int
			}
			caps := []capDef{
				{Key: "ptrace", Weight: 20},
				{Key: "proc_other_users", Weight: 15},
				{Key: "conntrack", Weight: 15},
				{Key: "sysfs_net", Weight: 15},
				{Key: "package_db", Weight: 15},
				{Key: "net_ns_isolated", Weight: 10},
				{Key: "firewall", Weight: 10},
			}

			// Query latest capability claims
			type capRow struct {
				Name        string
				Status      string
				Reason      string
				LastChecked string
				Weight      int
			}

			var rowsOut []capRow
			var score int

			for _, cDef := range caps {
				capRef := fmt.Sprintf("ref://capability/%s", cDef.Key)
				var (
					pred   string
					reason string
					obsAt  string
				)
				err := l.DB().QueryRowContext(ctx, `
					SELECT predicate, object_value, observed_at
					FROM claims
					WHERE subject = ?
					ORDER BY observed_at DESC, seq DESC
					LIMIT 1
				`, capRef).Scan(&pred, &reason, &obsAt)

				status := "not visible"
				if err == nil {
					if pred == "capability.can" {
						status = "observed"
						score += cDef.Weight
					} else {
						// capability.cannot is explicitly not visible
						status = "not visible"
					}
				} else {
					reason = "unprobed"
					obsAt = "-"
				}

				rowsOut = append(rowsOut, capRow{
					Name:        cDef.Key,
					Status:      status,
					Reason:      reason,
					LastChecked: obsAt,
					Weight:      cDef.Weight,
				})
			}

			fmt.Printf("=== Host Coverage: %s ===\n", targetHost)
			fmt.Printf("Deterministic Visibility Score: %d / 100\n\n", score)
			fmt.Printf("%-20s %-16s %-36s %s\n", "CAPABILITY", "STATUS", "REASON", "LAST CHECKED")
			fmt.Println(strings.Repeat("-", 90))
			for _, r := range rowsOut {
				rReason := r.Reason
				if len(rReason) > 34 {
					rReason = rReason[:32] + "..."
				}
				fmt.Printf("%-20s %-16s %-36s %s\n",
					r.Name, r.Status, rReason, r.LastChecked)
			}
			return nil
		},
	}

	// rules command
	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage and test inference and identity rules",
	}

	rulesTestCmd := &cobra.Command{
		Use:   "test <file>",
		Short: "Validate and test rules file syntax and evaluation against active ledger",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]
			data, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read rules file %s: %w", filePath, err)
			}

			// Try parsing as inference rules
			var infRules []infer.Rule
			if err := json.Unmarshal(data, &infRules); err == nil && len(infRules) > 0 {
				fmt.Printf("PASS: Successfully parsed %d inference rules from %s\n", len(infRules), filePath)
				for _, r := range infRules {
					fmt.Printf(" - [%s] %s: matches %s (%s)\n", r.ID, r.Name, r.MatchPredicate, r.Condition.Op)
				}
				return nil
			}

			// Try parsing as identity rules
			type IDRule struct {
				Name         string  `json:"name"`
				Description  string  `json:"description"`
				Predicate    string  `json:"predicate"`
				BaseStrength float64 `json:"base_strength"`
			}
			var idRules []IDRule
			if err := json.Unmarshal(data, &idRules); err == nil && len(idRules) > 0 {
				fmt.Printf("PASS: Successfully parsed %d identity alias rules from %s\n", len(idRules), filePath)
				for _, r := range idRules {
					fmt.Printf(" - %s: predicate %s (base strength %.2f)\n", r.Name, r.Predicate, r.BaseStrength)
				}
				return nil
			}

			return fmt.Errorf("failed to parse %s as valid inference or identity rules JSON", filePath)
		},
	}
	rulesCmd.AddCommand(rulesTestCmd)

	// history command
	historyCmd := &cobra.Command{
		Use:   "history <ref>",
		Short: "Display chronological history of all claims, retractions, and absence claims for an entity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			subjectRef := args[0]
			if err := claims.ValidateRef(subjectRef); err != nil {
				return err
			}

			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			rows, err := l.DB().QueryContext(context.Background(), `
				SELECT claim_id, subject, predicate, object_kind, object_value,
				       observed_at, source_group, source_id, source_method,
				       scope, evidence_hash, redaction
				FROM claims
				WHERE subject = ? OR object_value = ?
				ORDER BY observed_at ASC, seq ASC
			`, subjectRef, subjectRef)
			if err != nil {
				return fmt.Errorf("failed querying history: %w", err)
			}
			defer rows.Close()

			fmt.Printf("Chronological History for %s:\n", subjectRef)
			fmt.Printf("%-20s %-12s %-12s %-20s %-28s %s\n", "OBSERVED_AT", "CLAIM_ID[:8]", "KIND", "PREDICATE", "VALUE", "SOURCE (METHOD)")
			var count int
			for rows.Next() {
				count++
				var (
					cid, subj, pred, objKind, objVal, obsAt, grp, srcID, meth, scope, evHash, redact string
				)
				if err := rows.Scan(&cid, &subj, &pred, &objKind, &objVal, &obsAt, &grp, &srcID, &meth, &scope, &evHash, &redact); err == nil {
					cidShort := cid
					if len(cidShort) > 8 {
						cidShort = cidShort[:8]
					}
					valStr := objVal
					if len(valStr) > 26 {
						valStr = valStr[:23] + "..."
					}
					// Classify claim type: ordinary, inferred, retraction, absence
					claimKind := "ordinary"
					switch {
					case pred == "tq.meta.retracts":
						claimKind = "retraction"
					case pred == "observed_absent":
						claimKind = "absence"
					case grp == "inferred" || meth == "inference":
						claimKind = "inferred"
					}
					fmt.Printf("%-20s %-12s %-12s %-20s %-28s %s (%s)\n",
						obsAt, cidShort, claimKind, pred, valStr, grp, meth)
				}
			}
			if count == 0 {
				fmt.Printf("No history observed for %s (status: not visible)\n", subjectRef)
			}
			return nil
		},
	}

	// diff command
	diffCmd := &cobra.Command{
		Use:   "diff <a> <b>",
		Short: "Compute diff and ranked causes between two runs or timestamps",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetA, targetB := args[0], args[1]

			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			res, err := diff.ComputeDiff(context.Background(), l, targetA, targetB, "rules")
			if err != nil {
				return fmt.Errorf("diff failed: %w", err)
			}

			fmt.Printf("=== Diff: %s -> %s ===\n", targetA, targetB)
			if len(res.Changes) == 0 {
				fmt.Printf("No differences observed (states identical).\n")
				return nil
			}

			fmt.Printf("\n--- State Differences (%d observed) ---\n", len(res.Changes))
			fmt.Printf("%-18s %-22s %-25s %-25s %s\n", "CATEGORY", "PREDICATE", "STATE A", "STATE B", "STATUS")
			for _, ch := range res.Changes {
				valA := ch.OldValue
				if len(valA) > 23 {
					valA = valA[:20] + "..."
				}
				valB := ch.NewValue
				if len(valB) > 23 {
					valB = valB[:20] + "..."
				}
				fmt.Printf("%-18s %-22s %-25s %-25s %s\n",
					ch.Category, ch.Predicate, valA, valB, ch.Status)
			}

			if len(res.RankedCauses) > 0 {
				fmt.Printf("\n--- Ranked Causes (Data-Driven Ordering) ---\n")
				fmt.Printf("%-5s %-8s %-25s %-35s %s\n", "RANK", "WEIGHT", "CATEGORY", "EXPLANATION", "SUPPORTING CLAIMS")
				for _, c := range res.RankedCauses {
					exp := c.Explanation
					if len(exp) > 33 {
						exp = exp[:30] + "..."
					}
					var suppIDs []string
					for _, sc := range c.SupportingClaims {
						cid := sc.ClaimID
						if len(cid) > 8 {
							cid = cid[:8]
						}
						suppIDs = append(suppIDs, cid)
					}
					suppStr := strings.Join(suppIDs, ", ")
					if len(suppStr) > 25 {
						suppStr = suppStr[:22] + "..."
					}
					fmt.Printf("#%-4d %-8d %-25s %-35s %s\n",
						c.Rank, c.Weight, c.Category, exp, suppStr)
				}
			}
			return nil
		},
	}

	// explain-diff command
	explainDiffCmd := &cobra.Command{
		Use:   "explain-diff <a> <b>",
		Short: "Narrative explanation of why run B differed from run A based strictly on rules and claims",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetA, targetB := args[0], args[1]

			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			res, err := diff.ComputeDiff(context.Background(), l, targetA, targetB, "rules")
			if err != nil {
				return fmt.Errorf("explain-diff failed: %w", err)
			}

			fmt.Printf("=== Root Cause Narrative: %s vs %s ===\n\n", targetA, targetB)
			if len(res.RankedCauses) == 0 {
				fmt.Printf("Runs behaved identically across all observed dependencies.\n")
				return nil
			}

			for _, c := range res.RankedCauses {
				fmt.Printf("[%d] %s (Weight: %d, Category: %s)\n", c.Rank, c.Explanation, c.Weight, c.Category)
				fmt.Printf("    Subject: %s | Predicate: %s\n", c.Subject, c.Predicate)
				fmt.Printf("    Transition: '%s' -> '%s'\n", c.OldValue, c.NewValue)
				fmt.Printf("    Evidence Lineage:\n")
				for _, sc := range c.SupportingClaims {
					cid := sc.ClaimID
					if len(cid) > 8 {
						cid = cid[:8]
					}
					ev := sc.EvidenceHash
					if len(ev) > 12 {
						ev = ev[:12]
					}
					fmt.Printf("      - Claim %s: observed at %s by %s (%s) [evidence: %s]\n",
						cid, sc.ObservedAt, sc.Source.Group, sc.Source.Method, ev)
				}
				fmt.Println()
			}

			// Report blind spots or non-comparable shifts
			var notComparable []diff.DiffChange
			for _, ch := range res.Changes {
				if ch.Status == "not comparable" {
					notComparable = append(notComparable, ch)
				}
			}
			if len(notComparable) > 0 {
				fmt.Printf("Epistemic Blind Spots (Not Comparable Transitions):\n")
				for _, nc := range notComparable {
					fmt.Printf("  - %s on %s was observed in %s but is not visible in %s (status: not comparable)\n",
						nc.Predicate, nc.Subject, targetA, targetB)
				}
			}

			return nil
		},
	}

	// impact command
	var impactJSON bool
	impactCmd := &cobra.Command{
		Use:   "impact <ref>",
		Short: "Perform reverse dependency traversal to find what depends on an artifact, package, driver, or host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetRef := args[0]
			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			res, err := impact.ComputeImpact(context.Background(), l, targetRef)
			if err != nil {
				return fmt.Errorf("impact analysis failed: %w", err)
			}

			if impactJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			fmt.Printf("=== Dependency Impact Analysis: %s ===\n\n", targetRef)
			fmt.Printf("Total Dependents: %d (Known >=.85: %d, Likely .60-.85: %d, Possible .30-.60: %d)\n",
				len(res.Dependents), res.KnownCount, res.LikelyCount, res.PossibleCount)
			fmt.Printf("Verdict:          %s\n\n", res.Verdict)

			if len(res.Dependents) > 0 {
				fmt.Printf("--- Downstream Dependents (Depth limit 20) ---\n")
				fmt.Printf("%-5s %-10s %-8s %-15s %-32s %s\n", "DEPTH", "CONFIDENCE", "STRENGTH", "PREDICATE", "DEPENDENT REF", "VIA")
				for _, d := range res.Dependents {
					fmt.Printf("%-5d %-10s %-8.2f %-15s %-32s (%s)\n",
						d.Depth, d.Confidence, d.Strength, d.ViaPredicate, d.Ref, d.ViaParentRef)
				}
				fmt.Println()
			} else {
				fmt.Printf("No downstream dependents observed for %s.\n\n", targetRef)
			}

			if len(res.BlindSpots) > 0 {
				fmt.Printf("--- Adjacent Epistemic Blind Spots (%d detected) ---\n", len(res.BlindSpots))
				fmt.Printf("WARNING: Dependents in adjacent blocked/unmodeled scopes are UNKNOWN (not visible).\n")
				for _, bs := range res.BlindSpots {
					fmt.Printf("  - [%s] %s: %s (status: not visible)\n", bs.Kind, bs.ScopeRef, bs.Reason)
				}
				fmt.Println()
			}

			return nil
		},
	}
	impactCmd.Flags().BoolVar(&impactJSON, "json", false, "Output impact analysis in JSON format")

	// ask command
	var (
		askLimit int
		askJSON  bool
	)
	askCmd := &cobra.Command{
		Use:   "ask",
		Short: "Rank next-best-questions to maximize reduction in unknowns",
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			questions, err := nbq.GenerateQuestions(context.Background(), l)
			if err != nil {
				return fmt.Errorf("failed to generate questions: %w", err)
			}

			if askLimit > 0 && len(questions) > askLimit {
				questions = questions[:askLimit]
			}

			if askJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(questions)
			}

			if len(questions) == 0 {
				fmt.Printf("No active epistemic questions (all observed items verified or zero unknowns).\n")
				return nil
			}

			fmt.Printf("=== Next-Best-Questions (Ranked by Measured Reduction in Unknowns) ===\n\n")
			fmt.Printf("%-14s %-8s %-12s %-10s %-8s %s\n", "QUESTION_ID", "SCORE", "UNCERTAINTY", "DOWNSTREAM", "BLIND", "QUESTION PROMPT")
			for _, q := range questions {
				fmt.Printf("%-14s %-8.2f %-12.2f %-10d %-8d %s\n",
					q.ID, q.Score, q.Uncertainty, q.Downstream, q.BlindAdjacent, q.Prompt)
			}
			fmt.Printf("\nAnswer a question with: bokuei answer <QUESTION_ID> yes|no|<text>\n")
			return nil
		},
	}
	askCmd.Flags().IntVar(&askLimit, "n", 5, "Maximum number of questions to display")
	askCmd.Flags().BoolVar(&askJSON, "json", false, "Output questions in JSON format")

	// answer command
	answerCmd := &cobra.Command{
		Use:   "answer <id> <yes|no|text>",
		Short: "Record human answer to a next-best-question and rebuild views with measured unknown reduction",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			qID, ansText := args[0], args[1]

			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			res, err := nbq.AnswerQuestion(context.Background(), l, qID, ansText, "rules")
			if err != nil {
				return fmt.Errorf("failed answering question: %w", err)
			}

			fmt.Printf("=== Human Verification Recorded ===\n\n")
			fmt.Printf("Question ID:    %s\n", res.QuestionID)
			fmt.Printf("Answer Value:   %s\n", res.Answer)
			fmt.Printf("Claims Added:   %d (append-only ledger, prior claims immutable)\n", res.ClaimsAdded)
			fmt.Printf("Epistemic Shift:\n")
			fmt.Printf("  Unknowns:     %d -> %d (%.1f%% reduction)\n",
				res.UnknownsBefore, res.UnknownsAfter, res.ReductionPercent)
			fmt.Printf("  Strength:     %.2f -> %.2f (verified by operator)\n",
				res.OldStrength, res.NewStrength)
			return nil
		},
	}

	// serve command
	var serveAddr string
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Bokuei HTTP server and embedded web UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			srv := server.NewServer(l, "rules")
			fmt.Printf("=== Bokuei Epistemic Intelligence Server ===\n")
			fmt.Printf("Ledger Database: %s\n", dbPath)
			fmt.Printf("Serving UI & API at: http://%s\n", serveAddr)
			fmt.Printf("Press Ctrl+C to stop.\n")
			return http.ListenAndServe(serveAddr, srv)
		},
	}
	// keygen command
	var keyOutPath string
	keygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate Ed25519 signing keypair with file mode 0600",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := fed.GenerateKeyPair()
			if err != nil {
				return err
			}
			if err := kp.SaveKeyToFile(keyOutPath); err != nil {
				return fmt.Errorf("failed saving key to %s: %w", keyOutPath, err)
			}
			fmt.Printf("=== Ed25519 Keypair Generated ===\n")
			fmt.Printf("Private Key: %s (mode 0600)\n", keyOutPath)
			fmt.Printf("Public Key:  %s\n", kp.PublicKey)
			return nil
		},
	}
	keygenCmd.Flags().StringVar(&keyOutPath, "out", "bokuei.key", "Path to save private keypair file")

	// export command
	var (
		exportOut    string
		exportKey    string
		exportPolicy string
	)
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export claims since last export as signed .bq batch",
		RunE: func(cmd *cobra.Command, args []string) error {
			if exportKey == "" {
				exportKey = "bokuei.key"
			}
			kp, err := fed.LoadKeyPair(exportKey)
			if err != nil {
				return fmt.Errorf("failed loading signing key from %s: %w (run 'bokuei keygen' first)", exportKey, err)
			}

			var policy *fed.PolicyRule
			if exportPolicy != "" {
				p, err := fed.LoadPolicy(exportPolicy)
				if err != nil {
					return fmt.Errorf("failed loading export policy from %s: %w", exportPolicy, err)
				}
				policy = p
			}

			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed opening database at %s: %w", dbPath, err)
			}
			defer l.Close()

			batch, err := fed.ExportLedger(context.Background(), l, kp, policy)
			if err != nil {
				return fmt.Errorf("export failed: %w", err)
			}

			data, err := json.MarshalIndent(batch, "", "  ")
			if err != nil {
				return err
			}
			if exportOut == "" {
				exportOut = fmt.Sprintf("export-%s.bq", batch.BatchID)
			}
			if err := os.WriteFile(exportOut, data, 0644); err != nil {
				return fmt.Errorf("failed writing export file: %w", err)
			}

			fmt.Printf("=== Export Complete ===\n")
			fmt.Printf("Batch ID:     %s\n", batch.BatchID)
			fmt.Printf("Sequence No:  %d\n", batch.SeqNo)
			fmt.Printf("Claims:       %d exported\n", batch.ClaimsCount)
			fmt.Printf("Batch Hash:   %s\n", batch.Hash)
			fmt.Printf("Signer Key:   %s\n", batch.PublicKey)
			fmt.Printf("Output File:  %s\n", exportOut)
			return nil
		},
	}
	exportCmd.Flags().StringVar(&exportOut, "out", "", "Output .bq file path")
	exportCmd.Flags().StringVar(&exportKey, "key", "bokuei.key", "Path to private key file")
	exportCmd.Flags().StringVar(&exportPolicy, "policy", "", "Path to export policy JSON file")

	// import command
	var (
		importTrustKeys string
		allowUntrusted  bool
	)
	importCmd := &cobra.Command{
		Use:   "import <file.bq|file.tq>",
		Short: "Import and verify a signed .bq batch (or legacy .tq) into the append-only ledger",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]
			data, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed reading %s: %w", filePath, err)
			}

			var batch fed.ExportBatch
			if err := json.Unmarshal(data, &batch); err != nil {
				return fmt.Errorf("invalid batch file (%s): %w", filePath, err)
			}

			var trustedKeys []string
			if importTrustKeys != "" {
				keyData, err := os.ReadFile(importTrustKeys)
				if err == nil {
					lines := strings.Split(string(keyData), "\n")
					for _, l := range lines {
						l = strings.TrimSpace(l)
						if l != "" && !strings.HasPrefix(l, "#") {
							trustedKeys = append(trustedKeys, l)
						}
					}
				}
			}

			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed opening database at %s: %w", dbPath, err)
			}
			defer l.Close()

			res, err := fed.ImportBatch(context.Background(), l, &batch, trustedKeys, allowUntrusted)
			if err != nil {
				return fmt.Errorf("import rejected: %w", err)
			}

			fmt.Printf("=== Import Successful ===\n")
			fmt.Printf("Batch ID:       %s\n", res.BatchID)
			fmt.Printf("Sequence No:    %d\n", res.SeqNo)
			fmt.Printf("Signer Status:  %s (Key: %s)\n", res.ValidationLabel, res.SignerKey)
			fmt.Printf("Claims Ingest:  %d inserted (%d deduped, %d total in batch)\n",
				res.InsertedClaims, res.DedupedClaims, res.TotalClaims)
			return nil
		},
	}
	importCmd.Flags().StringVar(&importTrustKeys, "trust", "", "Path to trusted public keys file")
	importCmd.Flags().BoolVar(&allowUntrusted, "allow-untrusted", false, "Permit import from unlisted signer keys")

	// migrate command: one-way migration from legacy tracequill.db to bokuei.db
	var migrateTargetDB string
	migrateCmd := &cobra.Command{
		Use:   "migrate [legacy_tracequill.db]",
		Short: "One-way migration of claims and support from legacy tracequill.db into bokuei.db",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcPath := "tracequill.db"
			if len(args) == 1 {
				srcPath = args[0]
			}
			if _, err := os.Stat(srcPath); err != nil {
				return fmt.Errorf("source legacy database '%s' not found: %w", srcPath, err)
			}

			dstPath := migrateTargetDB
			if dstPath == "" {
				dstPath = dbPath
			}

			// Open source database read-only
			srcDB, err := sql.Open("sqlite", srcPath)
			if err != nil {
				return fmt.Errorf("failed opening source database %s: %w", srcPath, err)
			}
			defer srcDB.Close()

			// Open destination bokuei ledger
			dstLedger, err := store.OpenLedger(dstPath)
			if err != nil {
				return fmt.Errorf("failed opening destination ledger %s: %w", dstPath, err)
			}
			defer dstLedger.Close()

			ctx := context.Background()
			// Read all claims from source
			rows, err := srcDB.QueryContext(ctx, `
				SELECT claim_id, subject, predicate, object_json, observed_at,
				       source_group, source_id, source_method, scope, evidence_hash,
				       redaction, canonical_json
				FROM claims ORDER BY seq_no ASC
			`)
			if err != nil {
				return fmt.Errorf("failed reading claims from %s: %w", srcPath, err)
			}
			defer rows.Close()

			var claimsToMigrate []*claims.Claim
			for rows.Next() {
				var (
					cid, subj, pred, objJSON, obsAt string
					sGrp, sID, sMeth, scope, evHash string
					redact, canonJSON               string
				)
				if err := rows.Scan(&cid, &subj, &pred, &objJSON, &obsAt, &sGrp, &sID, &sMeth, &scope, &evHash, &redact, &canonJSON); err != nil {
					return fmt.Errorf("scan claim error: %w", err)
				}
				var obj claims.Object
				if err := json.Unmarshal([]byte(objJSON), &obj); err != nil {
					return fmt.Errorf("unmarshal object error for claim %s: %w", cid, err)
				}
				c := &claims.Claim{
					Subject:      subj,
					Predicate:    pred,
					Object:       obj,
					ObservedAt:   obsAt,
					Source:       claims.Source{Group: sGrp, ID: sID, Method: sMeth},
					Scope:        scope,
					EvidenceHash: evHash,
					Redaction:    redact,
				}
				claimsToMigrate = append(claimsToMigrate, c)
			}
			rows.Close()

			// Read all claim_support from source if exists
			var supportRowsCount int
			type supportLink struct {
				inferredID string
				premiseID  string
				ruleID     string
			}
			var supports []supportLink
			suppRows, err := srcDB.QueryContext(ctx, `
				SELECT inferred_claim_id, premise_claim_id, rule_id
				FROM claim_support
			`)
			if err == nil {
				for suppRows.Next() {
					var inf, prem, rID string
					if err := suppRows.Scan(&inf, &prem, &rID); err == nil {
						supports = append(supports, supportLink{inferredID: inf, premiseID: prem, ruleID: rID})
					}
				}
				suppRows.Close()
			}

			// Ingest claims into destination ledger
			ingestRes, err := dstLedger.IngestBatch(ctx, fmt.Sprintf("migration-from-%s", filepath.Base(srcPath)), claimsToMigrate, nil)
			if err != nil {
				return fmt.Errorf("failed ingesting migrated claims: %w", err)
			}

			// Ingest support links into destination ledger
			for _, sup := range supports {
				_, err := dstLedger.DB().ExecContext(ctx, `
					INSERT OR IGNORE INTO claim_support (inferred_claim_id, premise_claim_id, rule_id)
					VALUES (?, ?, ?)
				`, sup.inferredID, sup.premiseID, sup.ruleID)
				if err == nil {
					supportRowsCount++
				}
			}

			fmt.Printf("=== Migration Complete ===\n")
			fmt.Printf("Source DB:         %s\n", srcPath)
			fmt.Printf("Destination Ledger: %s\n", dstPath)
			fmt.Printf("Claims Migrated:   %d inserted (%d deduped, %d total in source)\n",
				ingestRes.InsertedClaims, ingestRes.DedupStateClaims, len(claimsToMigrate))
			fmt.Printf("Support Links:     %d transferred\n", supportRowsCount)
			return nil
		},
	}
	migrateCmd.Flags().StringVar(&migrateTargetDB, "target", "", "Target bokuei ledger DB path (defaults to --db)")

	// rehearse command
	var (
		rehearseJSON  bool
		rehearseAt    string
		rehearseScore string
	)
	rehearseCmd := &cobra.Command{
		Use:   "rehearse [change]",
		Short: "Simulate a hypothetical system or network change before applying it",
		Long: `Simulate a hypothetical system or network change against ledger state.
Supported changes in v1:
  route-del <cidr>
  iface-down <name>
  service-stop <ref|pid>
  package-change <ref://package/...>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			l, err := store.OpenLedger(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
			}
			defer l.Close()

			if rehearseScore != "" {
				scoreReport, err := rehearse.ScoreRehearsal(ctx, l, rehearseScore)
				if err != nil {
					return err
				}
				fmt.Println(scoreReport)
				return nil
			}

			if len(args) == 0 {
				return fmt.Errorf("missing change argument (e.g. 'route-del 192.168.1.0/24' or 'iface-down eth0')")
			}

			changeStr := strings.Join(args, " ")
			asOf := time.Now().UTC()
			if rehearseAt != "" {
				parsed, err := time.Parse(time.RFC3339, rehearseAt)
				if err != nil {
					return fmt.Errorf("invalid --at timestamp (expected RFC3339): %w", err)
				}
				asOf = parsed
			}

			res, err := rehearse.ExecuteRehearsal(ctx, l, changeStr, asOf)
			if err != nil {
				return err
			}

			// Record rehearsal as claim in ledger
			_ = rehearse.RecordRehearsalClaim(ctx, l, res)

			if rehearseJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			fmt.Printf("=== Bokuei Change Rehearsal ===\n")
			fmt.Printf("Rehearsal ID:   %s\n", res.RehearsalID)
			fmt.Printf("Change:         %s %s\n", res.Change.Kind, res.Change.Target)
			fmt.Printf("Verdict:        %s\n", res.Verdict)
			if res.LifelineTriggered {
				fmt.Printf("LIFELINE:       %s\n", res.LifelineMessage)
			}
			fmt.Printf("\nCounts:\n")
			for k, v := range res.Counts {
				fmt.Printf("  %-15s %d\n", k+":", v)
			}

			fmt.Printf("\nConfidence Bands:\n")
			for k, v := range res.ConfidenceBands {
				fmt.Printf("  %-15s %d\n", k+":", v)
			}

			if len(res.AffectedConns) > 0 {
				fmt.Printf("\nAffected Connections (%d):\n", len(res.AffectedConns))
				fmt.Printf("%-15s %-25s %-25s %s\n", "STATUS", "LOCAL", "REMOTE", "DETAILS")
				for _, c := range res.AffectedConns {
					fmt.Printf("%-15s %-25s %-25s %s\n", c.Classification, c.LocalAddr, c.RemoteAddr, c.Reason)
				}
			}

			if len(res.AffectedEntities) > 0 {
				fmt.Printf("\nAffected Entities (%d):\n", len(res.AffectedEntities))
				for _, e := range res.AffectedEntities {
					fmt.Printf("  - %s\n", e)
				}
			}

			if len(res.BlindSpots) > 0 {
				fmt.Printf("\nBlind Spots / Unmodeled Scope (%d):\n", len(res.BlindSpots))
				for _, bs := range res.BlindSpots {
					fmt.Printf("  * %s\n", bs)
				}
			}

			fmt.Printf("\n%s\n", res.Narrative)
			return nil
		},
	}
	rehearseCmd.Flags().BoolVar(&rehearseJSON, "json", false, "Output rehearsal in JSON format")
	rehearseCmd.Flags().StringVar(&rehearseAt, "at", "", "Simulate change as of RFC3339 timestamp")
	rehearseCmd.Flags().StringVar(&rehearseScore, "score", "", "Score a previous prediction against observed state (rehearsal ID)")

	rootCmd.AddCommand(claimsCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(collectCmd)
	rootCmd.AddCommand(rebuildCmd)
	rootCmd.AddCommand(explainCmd)
	rootCmd.AddCommand(unknownsCmd)
	rootCmd.AddCommand(coverageCmd)
	rootCmd.AddCommand(rehearseCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(explainDiffCmd)
	rootCmd.AddCommand(impactCmd)
	rootCmd.AddCommand(askCmd)
	rootCmd.AddCommand(answerCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(migrateCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
