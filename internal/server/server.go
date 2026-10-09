package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/diff"
	"github.com/OWNER/bokuei/internal/effective"
	"github.com/OWNER/bokuei/internal/impact"
	"github.com/OWNER/bokuei/internal/nbq"
	"github.com/OWNER/bokuei/internal/resolve"
	"github.com/OWNER/bokuei/internal/store"
)

//go:embed web/*
var webFS embed.FS

// Server wraps the Bokuei HTTP server and routes.
type Server struct {
	ledger   *store.Ledger
	rulesDir string
	mux      *http.ServeMux
}

// NewServer initializes HTTP routes for Bokuei API and embedded Web UI.
func NewServer(ledger *store.Ledger, rulesDir string) *Server {
	s := &Server{
		ledger:   ledger,
		rulesDir: rulesDir,
		mux:      http.NewServeMux(),
	}

	// Embedded static UI assets
	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(subFS))
	s.mux.Handle("/", fileServer)

	// API JSON Endpoints
	s.mux.HandleFunc("/api/claims", s.handleClaims)
	s.mux.HandleFunc("/api/entity", s.handleEntity)
	s.mux.HandleFunc("/api/explain", s.handleExplain)
	s.mux.HandleFunc("/api/diff", s.handleDiff)
	s.mux.HandleFunc("/api/history", s.handleHistory)
	s.mux.HandleFunc("/api/impact", s.handleImpact)
	s.mux.HandleFunc("/api/unknowns", s.handleUnknowns)
	s.mux.HandleFunc("/api/ask", s.handleAsk)
	s.mux.HandleFunc("/api/answer", s.handleAnswer)
	s.mux.HandleFunc("/api/coverage", s.handleCoverage)
	s.mux.HandleFunc("/api/map", s.handleMap)

	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// 1. /api/claims?ref=...
func (s *Server) handleClaims(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, "missing 'ref' parameter")
		return
	}

	res, err := s.ledger.GetClaimsBySubject(r.Context(), ref)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// 2. /api/entity?ref=...
func (s *Server) handleEntity(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, "missing 'ref' parameter")
		return
	}

	ctx := r.Context()
	var entityID, primaryRef, membersJSON string
	err := s.ledger.DB().QueryRowContext(ctx, `
		SELECT e.entity_id, e.primary_ref, e.members_json
		FROM view_entities e
		JOIN view_entity_members m ON e.entity_id = m.entity_id
		WHERE m.member_ref = ?
	`, ref).Scan(&entityID, &primaryRef, &membersJSON)

	if err != nil {
		// Return single-ref entity if not resolved in views
		writeJSON(w, http.StatusOK, map[string]any{
			"entity_id":   resolve.ComputeEntityID([]string{ref}),
			"primary_ref": ref,
			"members":     []string{ref},
			"status":      "not resolved in view_entities",
		})
		return
	}

	var members []string
	_ = json.Unmarshal([]byte(membersJSON), &members)

	writeJSON(w, http.StatusOK, map[string]any{
		"entity_id":   entityID,
		"primary_ref": primaryRef,
		"members":     members,
	})
}

// 3. /api/explain?ref=...
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, "missing 'ref' parameter")
		return
	}

	ctx := r.Context()

	// 1. Entity resolution
	var entityID, primaryRef, membersJSON string
	_ = s.ledger.DB().QueryRowContext(ctx, `
		SELECT e.entity_id, e.primary_ref, e.members_json
		FROM view_entities e
		JOIN view_entity_members m ON e.entity_id = m.entity_id
		WHERE m.member_ref = ?
	`, ref).Scan(&entityID, &primaryRef, &membersJSON)

	var members []string
	if membersJSON != "" {
		_ = json.Unmarshal([]byte(membersJSON), &members)
	} else {
		members = []string{ref}
		primaryRef = ref
		entityID = resolve.ComputeEntityID([]string{ref})
	}

	// 2. Effective states
	type effRow struct {
		Predicate       string  `json:"predicate"`
		ObjectKind      string  `json:"object_kind"`
		ObjectValue     string  `json:"object_value"`
		Precedence      string  `json:"precedence"`
		DecayedStrength float64 `json:"decayed_strength"`
		StrengthLabel   string  `json:"strength_label"`
		IsStale         bool    `json:"is_stale"`
		IsContested     bool    `json:"is_contested"`
		SupportingCount int     `json:"supporting_count"`
	}
	var effectiveStates []effRow

	rowsEff, err := s.ledger.DB().QueryContext(ctx, `
		SELECT predicate, object_kind, object_value, precedence,
		       decayed_strength, strength_label, is_stale, is_contested, supporting_count
		FROM view_effective_state
		WHERE subject = ?
		ORDER BY predicate ASC
	`, ref)
	if err == nil {
		defer rowsEff.Close()
		for rowsEff.Next() {
			var r effRow
			var isStale, isContested int
			if err := rowsEff.Scan(&r.Predicate, &r.ObjectKind, &r.ObjectValue, &r.Precedence,
				&r.DecayedStrength, &r.StrengthLabel, &isStale, &isContested, &r.SupportingCount); err == nil {
				r.IsStale = (isStale == 1)
				r.IsContested = (isContested == 1)
				effectiveStates = append(effectiveStates, r)
			}
		}
	}

	// 3. Claims
	claimsList, _ := s.ledger.GetClaimsBySubject(ctx, ref)

	// 4. Unknowns
	type unkRow struct {
		Category    string `json:"category"`
		Predicate   string `json:"predicate"`
		Reason      string `json:"reason"`
		ImpactLevel string `json:"impact_level"`
	}
	var unknowns []unkRow
	rowsUnk, err := s.ledger.DB().QueryContext(ctx, `
		SELECT category, predicate, reason, impact_level
		FROM view_unknowns
		WHERE subject = ?
	`, ref)
	if err == nil {
		defer rowsUnk.Close()
		for rowsUnk.Next() {
			var u unkRow
			if err := rowsUnk.Scan(&u.Category, &u.Predicate, &u.Reason, &u.ImpactLevel); err == nil {
				unknowns = append(unknowns, u)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"target_ref":       ref,
		"entity_id":        entityID,
		"primary_ref":      primaryRef,
		"members":          members,
		"effective_states": effectiveStates,
		"claims":           claimsList,
		"unknowns":         unknowns,
	})
}

// 4. /api/diff?a=...&b=...
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	targetA := r.URL.Query().Get("a")
	targetB := r.URL.Query().Get("b")
	if targetA == "" || targetB == "" {
		writeError(w, http.StatusBadRequest, "parameters 'a' and 'b' are required")
		return
	}

	res, err := diff.ComputeDiff(r.Context(), s.ledger, targetA, targetB, s.rulesDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// 5. /api/history?ref=...
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, "missing 'ref' parameter")
		return
	}

	rows, err := s.ledger.DB().QueryContext(r.Context(), `
		SELECT claim_id, subject, predicate, object_kind, object_value,
		       observed_at, source_group, source_id, source_method,
		       scope, evidence_hash, redaction
		FROM claims
		WHERE subject = ? OR object_value = ?
		ORDER BY observed_at ASC, seq ASC
	`, ref, ref)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type historyItem struct {
		ClaimID      string `json:"claim_id"`
		Subject      string `json:"subject"`
		Predicate    string `json:"predicate"`
		ObjectKind   string `json:"object_kind"`
		ObjectValue  string `json:"object_value"`
		ObservedAt   string `json:"observed_at"`
		SourceGroup  string `json:"source_group"`
		SourceID     string `json:"source_id"`
		SourceMethod string `json:"source_method"`
		ClaimKind    string `json:"claim_kind"`
		EvidenceHash string `json:"evidence_hash"`
	}

	var items []historyItem
	for rows.Next() {
		var it historyItem
		var scope, redact string
		if err := rows.Scan(&it.ClaimID, &it.Subject, &it.Predicate, &it.ObjectKind, &it.ObjectValue,
			&it.ObservedAt, &it.SourceGroup, &it.SourceID, &it.SourceMethod, &scope, &it.EvidenceHash, &redact); err == nil {
			it.ClaimKind = "ordinary"
			switch {
			case it.Predicate == "tq.meta.retracts":
				it.ClaimKind = "retraction"
			case it.Predicate == "observed_absent":
				it.ClaimKind = "absence"
			case it.SourceGroup == "inferred" || it.SourceMethod == "inference":
				it.ClaimKind = "inferred"
			}
			items = append(items, it)
		}
	}

	writeJSON(w, http.StatusOK, items)
}

// 6. /api/impact?ref=...
func (s *Server) handleImpact(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, "missing 'ref' parameter")
		return
	}

	res, err := impact.ComputeImpact(r.Context(), s.ledger, ref)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// 7. /api/unknowns
func (s *Server) handleUnknowns(w http.ResponseWriter, r *http.Request) {
	rows, err := s.ledger.DB().QueryContext(r.Context(), `
		SELECT subject, category, predicate, reason, impact_level
		FROM view_unknowns
		ORDER BY CASE impact_level WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, subject ASC
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type unknownItem struct {
		Subject     string `json:"subject"`
		Category    string `json:"category"`
		Predicate   string `json:"predicate"`
		Reason      string `json:"reason"`
		ImpactLevel string `json:"impact_level"`
		Status      string `json:"status"`
	}

	var res []unknownItem
	for rows.Next() {
		var it unknownItem
		if err := rows.Scan(&it.Subject, &it.Category, &it.Predicate, &it.Reason, &it.ImpactLevel); err == nil {
			it.Status = "not visible"
			res = append(res, it)
		}
	}
	writeJSON(w, http.StatusOK, res)
}

// 8. /api/ask?n=...
func (s *Server) handleAsk(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("n")
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	questions, err := nbq.GenerateQuestions(r.Context(), s.ledger)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if len(questions) > limit {
		questions = questions[:limit]
	}

	writeJSON(w, http.StatusOK, questions)
}

// 9. /api/answer (POST {"id": "...", "answer": "..."})
func (s *Server) handleAnswer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST method required")
		return
	}

	var req struct {
		ID     string `json:"id"`
		Answer string `json:"answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.ID == "" || req.Answer == "" {
		writeError(w, http.StatusBadRequest, "both 'id' and 'answer' are required")
		return
	}

	res, err := nbq.AnswerQuestion(r.Context(), s.ledger, req.ID, req.Answer, s.rulesDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, res)
}

// 10. /api/coverage
func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var totalClaims, totalEvidence, totalSources int
	_ = s.ledger.DB().QueryRowContext(ctx, "SELECT count(*) FROM claims").Scan(&totalClaims)
	_ = s.ledger.DB().QueryRowContext(ctx, "SELECT count(*) FROM evidence").Scan(&totalEvidence)
	_ = s.ledger.DB().QueryRowContext(ctx, "SELECT count(*) FROM sources").Scan(&totalSources)

	var activeUnknowns int
	_ = s.ledger.DB().QueryRowContext(ctx, "SELECT count(*) FROM view_unknowns").Scan(&activeUnknowns)

	writeJSON(w, http.StatusOK, map[string]any{
		"total_claims":    totalClaims,
		"total_evidence":  totalEvidence,
		"total_sources":   totalSources,
		"active_unknowns": activeUnknowns,
		"status":          "epistemic ledger active",
	})
}

// 12. /api/map?at=...
// The time slider endpoint: MUST re-render historical effective state WITHOUT modifying the ledger.
func (s *Server) handleMap(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	atStr := r.URL.Query().Get("at")

	var (
		claimsList []*claims.Claim
		asOf       time.Time
	)

	if atStr != "" {
		parsed, err := time.Parse(time.RFC3339, atStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'at' format (RFC3339 required)")
			return
		}
		asOf = parsed

		// Query historical claims up to cutoff
		rows, err := s.ledger.DB().QueryContext(ctx, `
			SELECT claim_id, subject, predicate, object_kind, object_value,
			       observed_at, source_group, source_id, source_method,
			       scope, evidence_hash, redaction
			FROM claims
			WHERE observed_at <= ?
			ORDER BY seq ASC
		`, atStr)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer rows.Close()

		for rows.Next() {
			var c claims.Claim
			if err := rows.Scan(&c.ClaimID, &c.Subject, &c.Predicate, &c.Object.Kind, &c.Object.Value,
				&c.ObservedAt, &c.Source.Group, &c.Source.ID, &c.Source.Method,
				&c.Scope, &c.EvidenceHash, &c.Redaction); err == nil {
				claimsList = append(claimsList, &c)
			}
		}
	} else {
		asOf = time.Now().UTC()
		// Query all claims
		rows, err := s.ledger.DB().QueryContext(ctx, `
			SELECT claim_id, subject, predicate, object_kind, object_value,
			       observed_at, source_group, source_id, source_method,
			       scope, evidence_hash, redaction
			FROM claims
			ORDER BY seq ASC
		`)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer rows.Close()

		for rows.Next() {
			var c claims.Claim
			if err := rows.Scan(&c.ClaimID, &c.Subject, &c.Predicate, &c.Object.Kind, &c.Object.Value,
				&c.ObservedAt, &c.Source.Group, &c.Source.ID, &c.Source.Method,
				&c.Scope, &c.EvidenceHash, &c.Redaction); err == nil {
				claimsList = append(claimsList, &c)
			}
		}
	}

	// Compute effective state purely in-memory WITHOUT modifying any database tables!
	effStates, _ := effective.ComputeEffectiveStates(claimsList, asOf)

	type GraphNode struct {
		ID         string            `json:"id"`
		Label      string            `json:"label"`
		Kind       string            `json:"kind"`
		Strength   float64           `json:"strength"`
		IsStale    bool              `json:"is_stale"`
		NotVisible bool              `json:"not_visible"`
		Attributes map[string]string `json:"attributes"`
	}

	type GraphEdge struct {
		Source    string  `json:"source"`
		Target    string  `json:"target"`
		Predicate string  `json:"predicate"`
		Strength  float64 `json:"strength"`
	}

	type GraphRegion struct {
		ID     string `json:"id"`
		Label  string `json:"label"`
		X      int    `json:"x"`
		Y      int    `json:"y"`
		Width  int    `json:"width"`
		Height int    `json:"height"`
	}

	nodesMap := make(map[string]*GraphNode)
	var edges []GraphEdge

	ensureNode := func(ref string) *GraphNode {
		if n, ok := nodesMap[ref]; ok {
			return n
		}
		kind := "unknown"
		parts := strings.Split(ref, "/")
		if len(parts) >= 3 && strings.HasPrefix(ref, "ref://") {
			kind = parts[2]
		}
		label := ref
		if len(label) > 28 {
			label = "..." + label[len(label)-25:]
		}
		gn := &GraphNode{
			ID:         ref,
			Label:      label,
			Kind:       kind,
			Strength:   1.0,
			Attributes: make(map[string]string),
		}
		nodesMap[ref] = gn
		return gn
	}

	// Populate nodes and edges from effective state
	for _, st := range effStates {
		n := ensureNode(st.Subject)
		n.Strength = st.DecayedStrength
		if st.IsStale {
			n.IsStale = true
		}
		n.Attributes[st.Predicate] = fmt.Sprintf("%v", st.ObjectValue)

		// Create edge if object is another ref
		if strings.HasPrefix(st.ObjectValue, "ref://") {
			ensureNode(st.ObjectValue)
			edges = append(edges, GraphEdge{
				Source:    st.Subject,
				Target:    st.ObjectValue,
				Predicate: st.Predicate,
				Strength:  st.DecayedStrength,
			})
		}
	}

	// Regions: Not-visible scope regions
	var regions []GraphRegion
	regions = append(regions, GraphRegion{
		ID:     "region-unobserved",
		Label:  "not visible (scope unobserved)",
		X:      30,
		Y:      460,
		Width:  260,
		Height: 180,
	})

	var nodes []*GraphNode
	for _, n := range nodesMap {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	// Collect timestamps for slider
	var timestamps []string
	tsRows, err := s.ledger.DB().QueryContext(ctx, `
		SELECT DISTINCT observed_at FROM claims ORDER BY observed_at ASC
	`)
	if err == nil {
		defer tsRows.Close()
		for tsRows.Next() {
			var ts string
			if err := tsRows.Scan(&ts); err == nil {
				timestamps = append(timestamps, ts)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"as_of":      asOf.Format(time.RFC3339),
		"nodes":      nodes,
		"edges":      edges,
		"regions":    regions,
		"timestamps": timestamps,
	})
}
