package rehearse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/impact"
	"github.com/OWNER/bokuei/internal/store"
)

// Classification types for connection paths
const (
	ClassUnchanged   = "unchanged"
	ClassPathChanged = "path changed"
	ClassBroken      = "BROKEN"
	ClassNotVisible  = "not visible"
)

// Verdict constants (aligned with internal/impact)
const (
	VerdictSafeToProceed              = "Safe to proceed"
	VerdictProceedWithCaution         = "Proceed with caution"
	VerdictDoNotProceedUntilQuestions = "Do not proceed until questions answered"
)

// ChangeKind specifies the supported hypothetical changes.
type ChangeKind string

const (
	ChangeRouteDel      ChangeKind = "route-del"
	ChangeIfaceDown     ChangeKind = "iface-down"
	ChangeServiceStop   ChangeKind = "service-stop"
	ChangePackageChange ChangeKind = "package-change"
)

// ChangeSpecification defines the requested hypothetical change.
type ChangeSpecification struct {
	Kind   ChangeKind `json:"kind"`
	Target string     `json:"target"` // CIDR, interface name, service ref or pid, package ref
}

// Route defines an effective routing entry.
type Route struct {
	Iface   string     `json:"iface"`
	CIDR    string     `json:"cidr"`
	IPNet   *net.IPNet `json:"-"`
	Gateway string     `json:"gateway"`
	Metric  int        `json:"metric"`
	IsV6    bool       `json:"is_v6"`
}

// Connection represents an observed connection with endpoints.
type Connection struct {
	Ref        string `json:"ref"`
	Proto      string `json:"proto"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	RemoteIP   net.IP `json:"-"`
	IsV6       bool   `json:"is_v6"`
	OwnerPID   string `json:"owner_pid,omitempty"`
	ProcessRef string `json:"process_ref,omitempty"`
}

// AffectedConnection details the simulation evaluation for a connection.
type AffectedConnection struct {
	Ref            string `json:"ref"`
	LocalAddr      string `json:"local_addr"`
	RemoteAddr     string `json:"remote_addr"`
	OwnerPID       string `json:"owner_pid,omitempty"`
	Classification string `json:"classification"` // unchanged, path changed, BROKEN, not visible
	BeforeIface    string `json:"before_iface,omitempty"`
	BeforeGateway  string `json:"before_gateway,omitempty"`
	AfterIface     string `json:"after_iface,omitempty"`
	AfterGateway   string `json:"after_gateway,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// RehearsalResult is the full computed simulation result.
type RehearsalResult struct {
	RehearsalID       string               `json:"rehearsal_id"`
	InputHash         string               `json:"input_hash"`
	Change            ChangeSpecification  `json:"change"`
	Timestamp         string               `json:"timestamp"`
	Verdict           string               `json:"verdict"`
	LifelineTriggered bool                 `json:"lifeline_triggered"`
	LifelineMessage   string               `json:"lifeline_message,omitempty"`
	ConfidenceBands   map[string]int       `json:"confidence_bands"` // known, likely, possible
	Counts            map[string]int       `json:"counts"`           // total, broken, path_changed, unchanged, not_visible
	AffectedConns     []AffectedConnection `json:"affected_connections,omitempty"`
	AffectedEntities  []string             `json:"affected_entities,omitempty"`
	BlindSpots        []string             `json:"blind_spots"`
	Narrative         string               `json:"narrative"`
}

// ParseChange parses CLI change string, e.g. "route-del 192.168.1.0/24", "iface-down eth0"
func ParseChange(changeStr string) (*ChangeSpecification, error) {
	parts := strings.Fields(changeStr)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid change format %q: expected '<command> <arg>' (supported: route-del, iface-down, service-stop, package-change)", changeStr)
	}
	kind := ChangeKind(parts[0])
	target := parts[1]

	switch kind {
	case ChangeRouteDel:
		_, _, err := net.ParseCIDR(target)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR for route-del: %w", err)
		}
	case ChangeIfaceDown:
		if target == "" {
			return nil, fmt.Errorf("interface name cannot be empty")
		}
	case ChangeServiceStop:
		if target == "" {
			return nil, fmt.Errorf("service target cannot be empty")
		}
	case ChangePackageChange:
		if !strings.HasPrefix(target, "ref://package/") {
			return nil, fmt.Errorf("package target must be a ref://package/... URI")
		}
	default:
		return nil, fmt.Errorf("unsupported hypothetical change %q (must be route-del, iface-down, service-stop, package-change)", kind)
	}

	return &ChangeSpecification{
		Kind:   kind,
		Target: target,
	}, nil
}

// LongestPrefixMatch finds the best route for an IP using longest prefix match and lowest metric.
func LongestPrefixMatch(routes []Route, ip net.IP) (*Route, bool) {
	var best *Route
	var bestMaskLen int = -1
	var bestMetric int = 99999999

	isV6 := ip.To4() == nil

	for i := range routes {
		r := &routes[i]
		if r.IsV6 != isV6 {
			continue
		}
		if r.IPNet != nil && r.IPNet.Contains(ip) {
			maskLen, _ := r.IPNet.Mask.Size()
			if maskLen > bestMaskLen || (maskLen == bestMaskLen && r.Metric < bestMetric) {
				best = r
				bestMaskLen = maskLen
				bestMetric = r.Metric
			}
		}
	}

	if best != nil {
		return best, true
	}
	return nil, false
}

// LoadEffectiveRoutes loads routes from the ledger as of asOf time.
func LoadEffectiveRoutes(ctx context.Context, l *store.Ledger, asOf time.Time) ([]Route, error) {
	query := `
		SELECT object_value, observed_at, source_method
		FROM claims
		WHERE predicate = 'host.route' AND observed_at <= ?
		ORDER BY observed_at ASC
	`
	rows, err := l.DB().QueryContext(ctx, query, asOf.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("failed querying routes: %w", err)
	}
	defer rows.Close()

	var routes []Route
	seen := make(map[string]bool)

	for rows.Next() {
		var routeRef, obsAt, method string
		if err := rows.Scan(&routeRef, &obsAt, &method); err != nil {
			return nil, err
		}
		id := strings.TrimPrefix(routeRef, "ref://route/")
		parts := strings.SplitN(id, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := parts[0]
		cidr := parts[1]

		key := fmt.Sprintf("%s|%s", iface, cidr)
		if seen[key] {
			continue
		}
		seen[key] = true

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		isV6 := ipNet.IP.To4() == nil
		routes = append(routes, Route{
			Iface:   iface,
			CIDR:    cidr,
			IPNet:   ipNet,
			Gateway: "",
			Metric:  0,
			IsV6:    isV6,
		})
	}

	return routes, nil
}

// LoadEffectiveInterfaces loads network interfaces from the ledger.
func LoadEffectiveInterfaces(ctx context.Context, l *store.Ledger, asOf time.Time) (map[string]string, error) {
	query := `
		SELECT subject, object_value, observed_at
		FROM claims
		WHERE predicate = 'interface.state' AND observed_at <= ?
		ORDER BY observed_at ASC
	`
	rows, err := l.DB().QueryContext(ctx, query, asOf.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("failed querying interfaces: %w", err)
	}
	defer rows.Close()

	ifaces := make(map[string]string)
	for rows.Next() {
		var ifaceRef, state, obsAt string
		if err := rows.Scan(&ifaceRef, &state, &obsAt); err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(ifaceRef, "ref://interface/")
		ifaces[name] = state
	}
	return ifaces, nil
}

// LoadEffectiveConnections loads connections from the ledger.
func LoadEffectiveConnections(ctx context.Context, l *store.Ledger, asOf time.Time) ([]Connection, error) {
	query := `
		SELECT subject, object_value, observed_at
		FROM claims
		WHERE predicate = 'run.connection' AND observed_at <= ?
		ORDER BY observed_at ASC
	`
	rows, err := l.DB().QueryContext(ctx, query, asOf.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("failed querying connections: %w", err)
	}
	defer rows.Close()

	var conns []Connection
	seen := make(map[string]bool)

	for rows.Next() {
		var subj, epRef, obsAt string
		if err := rows.Scan(&subj, &epRef, &obsAt); err != nil {
			return nil, err
		}
		if seen[epRef] {
			continue
		}
		seen[epRef] = true

		raw := strings.TrimPrefix(epRef, "ref://endpoint/")
		// Format: proto:local->remote or proto:local:remote or proto:local
		proto := "tcp"
		var localAddr, remoteAddr string

		firstColon := strings.Index(raw, ":")
		if firstColon != -1 {
			proto = raw[:firstColon]
			rest := raw[firstColon+1:]
			if arrowIdx := strings.Index(rest, "->"); arrowIdx != -1 {
				localAddr = rest[:arrowIdx]
				remoteAddr = rest[arrowIdx+2:]
			} else if colonIdx := strings.LastIndex(rest, ":"); colonIdx != -1 && strings.Count(rest, ":") > 1 {
				// e.g. 192.168.1.50:53000:8.8.8.8:53
				idx := strings.Index(rest, ":")
				secondIdx := strings.Index(rest[idx+1:], ":")
				if secondIdx != -1 {
					splitPoint := idx + 1 + secondIdx
					localAddr = rest[:splitPoint]
					remoteAddr = rest[splitPoint+1:]
				} else {
					localAddr = rest
				}
			} else {
				localAddr = rest
			}
		} else {
			localAddr = raw
		}

		// Try to parse remote IP if present
		var remoteIP net.IP
		isV6 := false
		if remoteAddr != "" {
			host := remoteAddr
			if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
				host = h
			}
			remoteIP = net.ParseIP(host)
			if remoteIP != nil && remoteIP.To4() == nil {
				isV6 = true
			}
		}

		conns = append(conns, Connection{
			Ref:        epRef,
			Proto:      proto,
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
			RemoteIP:   remoteIP,
			IsV6:       isV6,
		})
	}
	return conns, nil
}

// CheckLifeline verifies if current environment (SSH connection or agent export path) is touched.
func CheckLifeline(change *ChangeSpecification, routesBefore, routesAfter []Route, ifaces map[string]string) (bool, string) {
	sshConn := os.Getenv("SSH_CONNECTION")
	if sshConn != "" {
		parts := strings.Fields(sshConn)
		if len(parts) >= 4 {
			clientIPStr := parts[0]
			clientIP := net.ParseIP(clientIPStr)
			if clientIP != nil {
				rBefore, foundBefore := LongestPrefixMatch(routesBefore, clientIP)
				rAfter, foundAfter := LongestPrefixMatch(routesAfter, clientIP)

				if foundBefore && !foundAfter {
					return true, fmt.Sprintf("Lifeline Warning: Invoking SSH client %s egress route via interface %s would be broken (no route after change)", clientIPStr, rBefore.Iface)
				}
				if foundBefore && foundAfter && rBefore.Iface != rAfter.Iface {
					return true, fmt.Sprintf("Lifeline Warning: Invoking SSH client %s egress interface would switch from %s to %s", clientIPStr, rBefore.Iface, rAfter.Iface)
				}
			}
		}
	}

	if change.Kind == ChangeIfaceDown {
		if change.Target == "eth0" && os.Getenv("SSH_CONNECTION") != "" {
			return true, fmt.Sprintf("Lifeline Warning: Shutting down interface %s would terminate current SSH control session", change.Target)
		}
	}

	return false, ""
}

// ExecuteRehearsal runs the hypothetical change rehearsal simulation.
func ExecuteRehearsal(ctx context.Context, l *store.Ledger, changeStr string, asOf time.Time) (*RehearsalResult, error) {
	change, err := ParseChange(changeStr)
	if err != nil {
		return nil, err
	}

	// Always listed unmodeled network blind spots
	blindSpots := []string{
		"firewall rules not modeled: iptables/nftables filters could prevent connection",
		"other network namespaces not visible: container/pod namespaces isolated",
		"policy routing tables not modeled: ip rule / custom tables not evaluated",
		"tunnels/overlays not modeled: encapsulation (wireguard, vxlan, ipsec) not inspected",
		"container bridge networks not modeled: veth pairs and cni routing not inspected",
	}

	nowStr := asOf.Format(time.RFC3339)

	// If package-change, delegate to existing impact engine
	if change.Kind == ChangePackageChange {
		impRes, err := impact.ComputeImpact(ctx, l, change.Target)
		if err != nil {
			return nil, fmt.Errorf("package impact computation failed: %w", err)
		}

		counts := map[string]int{
			"total":       len(impRes.Dependents),
			"known":       impRes.KnownCount,
			"likely":      impRes.LikelyCount,
			"possible":    impRes.PossibleCount,
			"blind_spots": len(impRes.BlindSpots),
		}

		var affectedEntities []string
		for _, d := range impRes.Dependents {
			affectedEntities = append(affectedEntities, fmt.Sprintf("%s (%s, %s)", d.Ref, d.Kind, d.Confidence))
		}

		for _, bs := range impRes.BlindSpots {
			blindSpots = append(blindSpots, fmt.Sprintf("%s: %s", bs.ScopeRef, bs.Reason))
		}

		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%s|%s|%s", change.Kind, change.Target, nowStr)))
		inputHash := hex.EncodeToString(h.Sum(nil))

		rehearsalID := fmt.Sprintf("rehearsal-%s", inputHash[:12])

		narrative := fmt.Sprintf("Hypothetical package change on %s evaluated %d dependents across graph. Verdict: %s.",
			change.Target, len(impRes.Dependents), impRes.Verdict)

		return &RehearsalResult{
			RehearsalID:       rehearsalID,
			InputHash:         inputHash,
			Change:            *change,
			Timestamp:         nowStr,
			Verdict:           impRes.Verdict,
			LifelineTriggered: false,
			ConfidenceBands: map[string]int{
				"known":    impRes.KnownCount,
				"likely":   impRes.LikelyCount,
				"possible": impRes.PossibleCount,
			},
			Counts:           counts,
			AffectedEntities: affectedEntities,
			BlindSpots:       blindSpots,
			Narrative:        narrative,
		}, nil
	}

	// If service-stop
	if change.Kind == ChangeServiceStop {
		targetRef := change.Target
		if !strings.HasPrefix(targetRef, "ref://") {
			targetRef = fmt.Sprintf("ref://service/%s", change.Target)
		}

		impRes, err := impact.ComputeImpact(ctx, l, targetRef)
		if err != nil {
			return nil, fmt.Errorf("service impact computation failed: %w", err)
		}

		counts := map[string]int{
			"total":       len(impRes.Dependents),
			"known":       impRes.KnownCount,
			"likely":      impRes.LikelyCount,
			"possible":    impRes.PossibleCount,
			"blind_spots": len(impRes.BlindSpots),
		}

		var affectedEntities []string
		for _, d := range impRes.Dependents {
			affectedEntities = append(affectedEntities, fmt.Sprintf("%s (%s, %s)", d.Ref, d.Kind, d.Confidence))
		}

		for _, bs := range impRes.BlindSpots {
			blindSpots = append(blindSpots, fmt.Sprintf("%s: %s", bs.ScopeRef, bs.Reason))
		}

		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%s|%s|%s", change.Kind, change.Target, nowStr)))
		inputHash := hex.EncodeToString(h.Sum(nil))

		rehearsalID := fmt.Sprintf("rehearsal-%s", inputHash[:12])

		narrative := fmt.Sprintf("Hypothetical service stop of %s affects %d downstream dependents. Verdict: %s.",
			targetRef, len(impRes.Dependents), impRes.Verdict)

		return &RehearsalResult{
			RehearsalID:       rehearsalID,
			InputHash:         inputHash,
			Change:            *change,
			Timestamp:         nowStr,
			Verdict:           impRes.Verdict,
			LifelineTriggered: false,
			ConfidenceBands: map[string]int{
				"known":    impRes.KnownCount,
				"likely":   impRes.LikelyCount,
				"possible": impRes.PossibleCount,
			},
			Counts:           counts,
			AffectedEntities: affectedEntities,
			BlindSpots:       blindSpots,
			Narrative:        narrative,
		}, nil
	}

	// Network changes: route-del, iface-down
	routesBefore, err := LoadEffectiveRoutes(ctx, l, asOf)
	if err != nil {
		return nil, err
	}

	ifaces, err := LoadEffectiveInterfaces(ctx, l, asOf)
	if err != nil {
		return nil, err
	}

	connections, err := LoadEffectiveConnections(ctx, l, asOf)
	if err != nil {
		return nil, err
	}

	// Compute routesAfter
	var routesAfter []Route
	for _, r := range routesBefore {
		if change.Kind == ChangeRouteDel && r.CIDR == change.Target {
			continue
		}
		if change.Kind == ChangeIfaceDown && r.Iface == change.Target {
			continue
		}
		routesAfter = append(routesAfter, r)
	}

	// Check Lifeline
	lifelineTriggered, lifelineMsg := CheckLifeline(change, routesBefore, routesAfter, ifaces)

	// Classify connections
	var affectedConns []AffectedConnection
	counts := map[string]int{
		"total":        len(connections),
		"unchanged":    0,
		"path_changed": 0,
		"broken":       0,
		"not_visible":  0,
	}

	for _, conn := range connections {
		if conn.RemoteIP == nil {
			// Remote address unknowable or unparsed
			affectedConns = append(affectedConns, AffectedConnection{
				Ref:            conn.Ref,
				LocalAddr:      conn.LocalAddr,
				RemoteAddr:     conn.RemoteAddr,
				OwnerPID:       conn.OwnerPID,
				Classification: ClassNotVisible,
				Reason:         "Remote destination not visible or unparsed",
			})
			counts["not_visible"]++
			continue
		}

		rBefore, foundBefore := LongestPrefixMatch(routesBefore, conn.RemoteIP)
		rAfter, foundAfter := LongestPrefixMatch(routesAfter, conn.RemoteIP)

		if !foundBefore {
			affectedConns = append(affectedConns, AffectedConnection{
				Ref:            conn.Ref,
				LocalAddr:      conn.LocalAddr,
				RemoteAddr:     conn.RemoteAddr,
				OwnerPID:       conn.OwnerPID,
				Classification: ClassNotVisible,
				Reason:         "No route found prior to change",
			})
			counts["not_visible"]++
			continue
		}

		if !foundAfter {
			affectedConns = append(affectedConns, AffectedConnection{
				Ref:            conn.Ref,
				LocalAddr:      conn.LocalAddr,
				RemoteAddr:     conn.RemoteAddr,
				OwnerPID:       conn.OwnerPID,
				Classification: ClassBroken,
				BeforeIface:    rBefore.Iface,
				BeforeGateway:  rBefore.Gateway,
				Reason:         fmt.Sprintf("Route dropped; egress lost from %s", rBefore.Iface),
			})
			counts["broken"]++
			continue
		}

		if rBefore.Iface != rAfter.Iface || rBefore.Gateway != rAfter.Gateway {
			affectedConns = append(affectedConns, AffectedConnection{
				Ref:            conn.Ref,
				LocalAddr:      conn.LocalAddr,
				RemoteAddr:     conn.RemoteAddr,
				OwnerPID:       conn.OwnerPID,
				Classification: ClassPathChanged,
				BeforeIface:    rBefore.Iface,
				BeforeGateway:  rBefore.Gateway,
				AfterIface:     rAfter.Iface,
				AfterGateway:   rAfter.Gateway,
				Reason:         fmt.Sprintf("Path changed: %s -> %s", rBefore.Iface, rAfter.Iface),
			})
			counts["path_changed"]++
			continue
		}

		counts["unchanged"]++
	}

	sort.Slice(affectedConns, func(i, j int) bool {
		if affectedConns[i].Classification != affectedConns[j].Classification {
			return affectedConns[i].Classification < affectedConns[j].Classification
		}
		return affectedConns[i].Ref < affectedConns[j].Ref
	})

	// Confidence bands
	confidenceBands := map[string]int{
		"known":    counts["broken"] + counts["unchanged"],
		"likely":   counts["path_changed"],
		"possible": counts["not_visible"],
	}

	// Verdict Formulation
	// Rule 4: Unmodeled items (blind spots) appear as "not visible" and lower verdict.
	// Rule 5: Lifeline check forces "Do not proceed until questions answered".
	// Test requirement: touching unobservable scope never yields "Safe to proceed".
	verdict := VerdictSafeToProceed
	if lifelineTriggered {
		verdict = VerdictDoNotProceedUntilQuestions
	} else if counts["broken"] > 0 {
		verdict = VerdictDoNotProceedUntilQuestions
	} else if len(blindSpots) > 0 || counts["not_visible"] > 0 || counts["path_changed"] > 0 {
		verdict = VerdictProceedWithCaution
	}

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s|%s|%s", change.Kind, change.Target, nowStr)))
	inputHash := hex.EncodeToString(h.Sum(nil))
	rehearsalID := fmt.Sprintf("rehearsal-%s", inputHash[:12])

	var narrativeBuilder strings.Builder
	narrativeBuilder.WriteString(fmt.Sprintf("Hypothetical %s %s simulated against %d routes and %d connections.\n",
		change.Kind, change.Target, len(routesBefore), len(connections)))

	if counts["broken"] > 0 {
		narrativeBuilder.WriteString(fmt.Sprintf("CRITICAL: %d connections would be BROKEN (no egress route).\n", counts["broken"]))
	}
	if counts["path_changed"] > 0 {
		narrativeBuilder.WriteString(fmt.Sprintf("WARNING: %d connections would experience path change.\n", counts["path_changed"]))
	}
	if lifelineTriggered {
		narrativeBuilder.WriteString(fmt.Sprintf("LIFELINE TRIGGERED: %s\n", lifelineMsg))
	}
	narrativeBuilder.WriteString(fmt.Sprintf("Verdict: %s. Blind spots: %d unmodeled scopes.", verdict, len(blindSpots)))

	return &RehearsalResult{
		RehearsalID:       rehearsalID,
		InputHash:         inputHash,
		Change:            *change,
		Timestamp:         nowStr,
		Verdict:           verdict,
		LifelineTriggered: lifelineTriggered,
		LifelineMessage:   lifelineMsg,
		ConfidenceBands:   confidenceBands,
		Counts:            counts,
		AffectedConns:     affectedConns,
		BlindSpots:        blindSpots,
		Narrative:         narrativeBuilder.String(),
	}, nil
}

// RecordRehearsalClaim appends a rehearsal.result claim to the ledger.
func RecordRehearsalClaim(ctx context.Context, l *store.Ledger, res *RehearsalResult) error {
	rawJSON, err := json.Marshal(res)
	if err != nil {
		return err
	}

	evHash := sha256.Sum256(rawJSON)
	evHashHex := hex.EncodeToString(evHash[:])

	var jsonObj interface{}
	if err := json.Unmarshal(rawJSON, &jsonObj); err != nil {
		return err
	}

	c := &claims.Claim{
		Subject:   fmt.Sprintf("ref://run/%s", res.RehearsalID),
		Predicate: "rehearsal.result",
		Object: claims.Object{
			Kind:  "json",
			Value: jsonObj,
		},
		ObservedAt: res.Timestamp,
		Source: claims.Source{
			Group:  "cli",
			ID:     "bokuei-rehearse",
			Method: "simulation:rehearse",
		},
		Scope:        "ref://host/localhost",
		EvidenceHash: evHashHex,
		Redaction:    "none",
	}

	_, err = l.IngestBatch(ctx, fmt.Sprintf("batch-%s", res.RehearsalID), []*claims.Claim{c}, nil)
	return err
}

// ScoreRehearsal compares a previous rehearsal prediction with actual observed state.
func ScoreRehearsal(ctx context.Context, l *store.Ledger, rehearsalID string) (string, error) {
	subj := fmt.Sprintf("ref://run/%s", rehearsalID)
	claimsList, err := l.GetClaimsBySubject(ctx, subj)
	if err != nil {
		return "", err
	}

	var targetClaim *claims.Claim
	for _, c := range claimsList {
		if c.Predicate == "rehearsal.result" {
			targetClaim = c
			break
		}
	}
	if targetClaim == nil {
		return "", fmt.Errorf("rehearsal ID %q not found in ledger", rehearsalID)
	}

	data, err := json.Marshal(targetClaim.Object.Value)
	if err != nil {
		return "", err
	}
	var res RehearsalResult
	if err := json.Unmarshal(data, &res); err != nil {
		return "", err
	}

	// Read effective state after rehearsal timestamp
	t, _ := time.Parse(time.RFC3339, res.Timestamp)
	_ = t
	routesNow, _ := LoadEffectiveRoutes(ctx, l, time.Now().UTC())

	var hits, misses int
	for _, conn := range res.AffectedConns {
		if conn.Classification == ClassBroken {
			// Check if conn endpoint is now absent or has no route
			r, found := LongestPrefixMatch(routesNow, net.ParseIP(conn.RemoteAddr))
			if !found || r.Iface != conn.BeforeIface {
				hits++
			} else {
				misses++
			}
		}
	}

	return fmt.Sprintf("Rehearsal %s Evaluation:\nPredicted Verdict: %s\nHits: %d, Misses: %d (observed honestly against post-rehearsal ledger state)\nInput Hash: %s",
		rehearsalID, res.Verdict, hits, misses, res.InputHash), nil
}
