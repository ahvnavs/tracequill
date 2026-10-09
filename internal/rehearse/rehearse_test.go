package rehearse_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/bokuei/internal/claims"
	"github.com/OWNER/bokuei/internal/rehearse"
	"github.com/OWNER/bokuei/internal/store"
)

func TestLongestPrefixMatchIPv4AndIPv6(t *testing.T) {
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	_, slash16Net, _ := net.ParseCIDR("10.0.0.0/16")
	_, slash24Net, _ := net.ParseCIDR("10.0.1.0/24")

	_, v6Default, _ := net.ParseCIDR("::/0")
	_, v6Subnet, _ := net.ParseCIDR("2001:db8::/32")

	routes := []rehearse.Route{
		{Iface: "eth0", CIDR: "0.0.0.0/0", IPNet: defaultNet, Metric: 100, IsV6: false},
		{Iface: "eth1", CIDR: "10.0.0.0/16", IPNet: slash16Net, Metric: 50, IsV6: false},
		{Iface: "eth2", CIDR: "10.0.1.0/24", IPNet: slash24Net, Metric: 10, IsV6: false},
		{Iface: "eth0", CIDR: "::/0", IPNet: v6Default, Metric: 100, IsV6: true},
		{Iface: "eth3", CIDR: "2001:db8::/32", IPNet: v6Subnet, Metric: 20, IsV6: true},
	}

	tests := []struct {
		name       string
		ipStr      string
		expectDev  string
		expectCIDR string
		expectOK   bool
	}{
		{
			name:       "Exact slash 24 match beats slash 16 and default",
			ipStr:      "10.0.1.55",
			expectDev:  "eth2",
			expectCIDR: "10.0.1.0/24",
			expectOK:   true,
		},
		{
			name:       "Slash 16 match beats default",
			ipStr:      "10.0.2.10",
			expectDev:  "eth1",
			expectCIDR: "10.0.0.0/16",
			expectOK:   true,
		},
		{
			name:       "Default route fallback for unknown internet IP",
			ipStr:      "8.8.8.8",
			expectDev:  "eth0",
			expectCIDR: "0.0.0.0/0",
			expectOK:   true,
		},
		{
			name:       "IPv6 subnet match",
			ipStr:      "2001:db8::1234",
			expectDev:  "eth3",
			expectCIDR: "2001:db8::/32",
			expectOK:   true,
		},
		{
			name:       "IPv6 default fallback",
			ipStr:      "2600::1",
			expectDev:  "eth0",
			expectCIDR: "::/0",
			expectOK:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ipStr)
			r, found := rehearse.LongestPrefixMatch(routes, ip)
			if found != tc.expectOK {
				t.Fatalf("expected found=%v, got %v", tc.expectOK, found)
			}
			if found {
				if r.Iface != tc.expectDev {
					t.Errorf("expected iface %s, got %s", tc.expectDev, r.Iface)
				}
				if r.CIDR != tc.expectCIDR {
					t.Errorf("expected CIDR %s, got %s", tc.expectCIDR, r.CIDR)
				}
			}
		})
	}
}

func TestNoRouteYieldsNotFound(t *testing.T) {
	_, slash24, _ := net.ParseCIDR("192.168.1.0/24")
	routes := []rehearse.Route{
		{Iface: "eth0", CIDR: "192.168.1.0/24", IPNet: slash24, Metric: 10, IsV6: false},
	}

	ip := net.ParseIP("10.0.0.1")
	_, found := rehearse.LongestPrefixMatch(routes, ip)
	if found {
		t.Fatalf("expected no route found for 10.0.0.1 without default route")
	}
}

func TestRehearsalRouteDelAndIfaceDown(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bokuei-rehearse-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	// Populate ledger with routes, interfaces, connections
	cRoutes := []*claims.Claim{
		{
			Subject:      "ref://host/h1",
			Predicate:    "host.route",
			Object:       claims.Object{Kind: "ref", Value: "ref://route/eth0:0.0.0.0/0"},
			ObservedAt:   nowStr,
			Source:       claims.Source{Group: "agent", ID: "bokuei-agent", Method: "read:/proc/net/route"},
			Scope:        "ref://host/h1",
			EvidenceHash: "0000000000000000000000000000000000000000000000000000000000000001",
			Redaction:    "none",
		},
		{
			Subject:      "ref://host/h1",
			Predicate:    "host.route",
			Object:       claims.Object{Kind: "ref", Value: "ref://route/eth1:10.10.0.0/16"},
			ObservedAt:   nowStr,
			Source:       claims.Source{Group: "agent", ID: "bokuei-agent", Method: "read:/proc/net/route"},
			Scope:        "ref://host/h1",
			EvidenceHash: "0000000000000000000000000000000000000000000000000000000000000002",
			Redaction:    "none",
		},
		{
			Subject:      "ref://interface/eth0",
			Predicate:    "interface.state",
			Object:       claims.Object{Kind: "text", Value: "up"},
			ObservedAt:   nowStr,
			Source:       claims.Source{Group: "agent", ID: "bokuei-agent", Method: "read:/sys/class/net/operstate"},
			Scope:        "ref://host/h1",
			EvidenceHash: "0000000000000000000000000000000000000000000000000000000000000003",
			Redaction:    "none",
		},
		{
			Subject:      "ref://interface/eth1",
			Predicate:    "interface.state",
			Object:       claims.Object{Kind: "text", Value: "up"},
			ObservedAt:   nowStr,
			Source:       claims.Source{Group: "agent", ID: "bokuei-agent", Method: "read:/sys/class/net/operstate"},
			Scope:        "ref://host/h1",
			EvidenceHash: "0000000000000000000000000000000000000000000000000000000000000004",
			Redaction:    "none",
		},
	}

	_, err = l.IngestBatch(ctx, "batch-net-init", cRoutes, nil)
	if err != nil {
		t.Fatalf("IngestBatch routes failed: %v", err)
	}

	// Add 3 connections:
	// Conn 1: to 10.10.1.5:80 (uses eth1 slash 16; will failover to eth0 if eth1 route deleted or iface down)
	// Conn 2: to 8.8.8.8:53 (uses eth0 default; will break if eth0 default deleted)
	// Conn 3: unmodeled remote
	cConns := []*claims.Claim{
		{
			Subject:      "ref://host/h1",
			Predicate:    "run.connection",
			Object:       claims.Object{Kind: "ref", Value: "ref://endpoint/tcp:192.168.1.50:45000:10.10.1.5:80"},
			ObservedAt:   nowStr,
			Source:       claims.Source{Group: "agent", ID: "bokuei-agent", Method: "read:/proc/net/tcp"},
			Scope:        "ref://host/h1",
			EvidenceHash: "0000000000000000000000000000000000000000000000000000000000000005",
			Redaction:    "none",
		},
		{
			Subject:      "ref://host/h1",
			Predicate:    "run.connection",
			Object:       claims.Object{Kind: "ref", Value: "ref://endpoint/tcp:192.168.1.50:53000:8.8.8.8:53"},
			ObservedAt:   nowStr,
			Source:       claims.Source{Group: "agent", ID: "bokuei-agent", Method: "read:/proc/net/tcp"},
			Scope:        "ref://host/h1",
			EvidenceHash: "0000000000000000000000000000000000000000000000000000000000000006",
			Redaction:    "none",
		},
		{
			Subject:      "ref://host/h1",
			Predicate:    "run.connection",
			Object:       claims.Object{Kind: "ref", Value: "ref://endpoint/tcp:192.168.1.50:8000:unparseable"},
			ObservedAt:   nowStr,
			Source:       claims.Source{Group: "agent", ID: "bokuei-agent", Method: "read:/proc/net/tcp"},
			Scope:        "ref://host/h1",
			EvidenceHash: "0000000000000000000000000000000000000000000000000000000000000007",
			Redaction:    "none",
		},
	}
	_, err = l.IngestBatch(ctx, "batch-conns", cConns, nil)
	if err != nil {
		t.Fatalf("IngestBatch conns failed: %v", err)
	}

	// 1. Rehearse deleting 10.10.0.0/16 route -> conn 1 switches to eth0 (path changed)
	res1, err := rehearse.ExecuteRehearsal(ctx, l, "route-del 10.10.0.0/16", now)
	if err != nil {
		t.Fatalf("ExecuteRehearsal 1: %v", err)
	}
	if res1.Counts["path_changed"] < 1 {
		t.Errorf("expected at least 1 path changed connection, got %d", res1.Counts["path_changed"])
	}

	// 2. Rehearse deleting default route 0.0.0.0/0 -> conn 2 becomes BROKEN
	res2, err := rehearse.ExecuteRehearsal(ctx, l, "route-del 0.0.0.0/0", now)
	if err != nil {
		t.Fatalf("ExecuteRehearsal 2: %v", err)
	}
	if res2.Counts["broken"] < 1 {
		t.Errorf("expected broken connection when default route deleted, got %d", res2.Counts["broken"])
	}
	if res2.Verdict != rehearse.VerdictDoNotProceedUntilQuestions {
		t.Errorf("expected verdict %q on broken connection, got %q", rehearse.VerdictDoNotProceedUntilQuestions, res2.Verdict)
	}

	// 3. Save rehearsal claim to ledger and test score
	err = rehearse.RecordRehearsalClaim(ctx, l, res2)
	if err != nil {
		t.Fatalf("RecordRehearsalClaim failed: %v", err)
	}

	scoreReport, err := rehearse.ScoreRehearsal(ctx, l, res2.RehearsalID)
	if err != nil {
		t.Fatalf("ScoreRehearsal failed: %v", err)
	}
	if scoreReport == "" {
		t.Errorf("expected non-empty score report")
	}
}

func TestRehearsalTouchingUnobservableScopeNeverSafeToProceed(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bokuei-rehearse-unobs-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "ledger.db")
	l, err := store.OpenLedger(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Add an unobservable connection
	c := &claims.Claim{
		Subject:      "ref://host/h1",
		Predicate:    "run.connection",
		Object:       claims.Object{Kind: "ref", Value: "ref://endpoint/tcp:unparseable_endpoint"},
		ObservedAt:   now.Format(time.RFC3339),
		Source:       claims.Source{Group: "agent", ID: "bokuei-agent", Method: "read:/proc/net/tcp"},
		Scope:        "ref://host/h1",
		EvidenceHash: "0000000000000000000000000000000000000000000000000000000000000001",
		Redaction:    "none",
	}
	_, err = l.IngestBatch(ctx, "b1", []*claims.Claim{c}, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := rehearse.ExecuteRehearsal(ctx, l, "iface-down eth0", now)
	if err != nil {
		t.Fatal(err)
	}

	// Even if 0 broken connections, because blind spots exist and unobservable scope is touched,
	// verdict must NEVER be "Safe to proceed"
	if res.Verdict == rehearse.VerdictSafeToProceed {
		t.Fatalf("epistemic failure: change touching unobservable scope returned 'Safe to proceed'")
	}
	if len(res.BlindSpots) == 0 {
		t.Fatalf("expected blind spots list to be populated")
	}
	fmt.Printf("Verdict verified: %s (Blind spots: %d)\n", res.Verdict, len(res.BlindSpots))
}
